// ==============================================================
// Unified YARA export from MISP attributes (type: yara)
// Generated: 2025-09-02T08:55:12.808766Z
// Filters: type_attribute=['yara'] deleted=False date_from=2020-09-03
// ==============================================================

// MISP event:1198 uuid:90c4a320-6dd4-4c15-a33e-c2363f68c506 org: to_ids:True tags:[]
rule regretlocker {
	meta:
		description = "YARA rule for RegretLocker"
		reference = "http://chuongdong.com/reverse%20engineering/2020/11/17/RegretLocker/"
		author = "@cPeterr"
		tlp = "white"
	strings:
		$str1 = "tor-lib.dll"
		$str2 = "http://regretzjibibtcgb.onion/input"
		$str3 = ".mouse"
		$cmd1 = "taskkill /F /IM \\"
		$cmd2 = "wmic SHADOWCOPY DELETE"
		$cmd3 = "wbadmin DELETE SYSTEMSTATEBACKUP"
		$cmd4 = "bcdedit.exe / set{ default } bootstatuspolicy ignoreallfailures"
		$cmd5 = "bcdedit.exe / set{ default } recoveryenabled No"
		$func1 = "open_virtual_drive()"
		$func2 = "smb_scanner()"
		$checklarge = { 81 fe 00 00 40 06 }
	condition:
		all of ($str*) and any of ($cmd*) and any of ($func*) and $checklarge
}

// MISP event:1202 uuid:2d93f1e4-e6a2-462f-9d98-1b580e925a53 org: to_ids:True tags:[]
rule BabukSabelt {
	meta:
	  	description = "YARA rule for Babuk Ransomware"
		reference = "http://chuongdong.com/reverse%20engineering/2021/01/03/BabukRansomware/"
		author = "@cPeterr"
		date = "2021-01-03"
		rule_version = "v1"
		malware_type = "ransomware"
		tlp = "white"
	strings:
		$lanstr1 = "-lanfirst"
		$lanstr2 = "-lansecond"
		$lanstr3 = "-nolan"
		$str1 = "BABUK LOCKER"
		$str2 = ".__NIST_K571__" wide
		$str3 = "How To Restore Your Files.txt" wide
		$str4 = "ecdh_pub_k.bin" wide
	condition:
		all of ($str*) and all of ($lanstr*)
}

// MISP event:1203 uuid:07bab0af-270c-4ecb-a635-7c60e7966178 org: to_ids:True tags:[]
rule Fujinama {
    meta:
        description = "Fujinama RAT used by Leonardo SpA Insider Threat"
        author = "ReaQta Threat Intelligence Team"
        ref1 = "https://reaqta.com/2021/01/fujinama-analysis-leonardo-spa"
        date = "2021-01-07"
        version = "1"   
    strings:
        $kaylog_1 = "SELECT" wide ascii nocase
        $kaylog_2 = "RIGHT" wide ascii nocase
        $kaylog_3 = "HELP" wide ascii nocase
        $kaylog_4 = "WINDOWS" wide ascii nocase
        $computername = "computername" wide ascii nocase
        $useragent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)" wide ascii nocase
        $pattern = "'()*+,G-./0123456789:" wide ascii nocase
        $function_1 = "t_save" wide ascii nocase
        $cftmon = "cftmon" wide ascii nocase
        $font = "Tahoma" wide ascii nocase
    condition:
        uint16(0) == 0x5a4d and all of them
}

// MISP event:1205 uuid:8988bfd4-f07e-43bd-a321-45dcc1976487 org: to_ids:True tags:[]
rule kobalos
{
    meta:
        description = "Kobalos malware"
        author = "Marc-Etienne M.Léveillé"
        date = "2020-11-02"
        reference = "http://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $encrypted_strings_sizes = {
            05 00 00 00 09 00 00 00  04 00 00 00 06 00 00 00
            08 00 00 00 08 00 00 00  02 00 00 00 02 00 00 00
            01 00 00 00 01 00 00 00  05 00 00 00 07 00 00 00
            05 00 00 00 05 00 00 00  05 00 00 00 0A 00 00 00
        }
        $password_md5_digest = { 3ADD48192654BD558A4A4CED9C255C4C }
        $rsa_512_mod_header = { 10 11 02 00 09 02 00 }
        $strings_rc4_key = { AE0E05090F3AC2B50B1BC6E91D2FE3CE }

    condition:
        any of them
}

// MISP event:1205 uuid:0be3f87d-26d0-4ef9-909f-9ab3a25afa66 org: to_ids:True tags:[]
rule kobalos_ssh_credential_stealer {
    meta:
        description = "Kobalos SSH credential stealer seen in OpenSSH client"
        author = "Marc-Etienne M.Léveillé"
        date = "2020-11-02"
        reference = "http://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

    condition:
        any of them
}

// MISP event:1209 uuid:592dbf66-c31f-4fef-b445-f75f0888864e org: to_ids:True tags:[]
/* configuration file */

rule exaramel_configuration_key {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Encryption key for the configuration file in sample e1ff72[...]"
		TLP = "White"

	strings:
		$ = "odhyrfjcnfkdtslt"

	condition:
		all of them
}

rule exaramel_configuration_name_encrypted {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Name of the configuration file in sample e1ff72[...]"
		TLP = "White"

	strings:
		$ = "configtx.json"

	condition:
		all of them
}

rule exaramel_configuration_file_plaintext {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Content of the configuration file (plaintext)"
		TLP = "White"

	strings:
		$ = /{"Hosts":\[".{10,512}"\],"Proxy":".{0,512}","Version":".{1,32}","Guid":"/

	condition:
		all of them
}

rule exaramel_configuration_file_ciphertext {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Content of the configuration file (encrypted with key odhyrfjcnfkdtslt, sample e1ff72[...]"
		TLP = "White"

	strings:
		$ = {6F B6 08 E9 A3 0C 8D 5E DD BE D4} // encrypted with key odhyrfjcnfkdtslt

	condition:
		all of them
}

/* persistence */

private rule exaramel_persistence_file_systemd {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Beginning of the file /etc/systemd/system/syslogd.service created for persistence with systemd"
		TLP = "White"

	strings:
		$ = /\[Unit\]\nDescription=Syslog daemon\n\n\[Service\]\nWorkingDirectory=.{1,512}\nExecStartPre=\/bin\/rm \-f \/tmp\/\.applocktx\n/

	condition:
		all of them
}

private rule exaramel_persistence_file_upstart {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Part of the file /etc/init/syslogd.conf created for persistence with upstart"
		TLP = "White"

	strings:
		$ = /start on runlevel \[2345\]\nstop on runlevel \[06\]\n\nrespawn\n\nscript\nrm \-f \/tmp\/\.applocktx\nchdir/

	condition:
		all of them
}

private rule exaramel_persistence_file_systemv {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Part of the file /etc/init.d/syslogd created for persistence with upstart"
		TLP = "White"

	strings:
		$ = "# Short-Description: Syslog service for monitoring \n### END INIT INFO\n\nrm -f /tmp/.applocktx && cd "

	condition:
		all of them
}

rule exaramel_persistence_file {

	meta:
		author = "FR/ANSSI/SDO"
		description = "File created for persistence. Depends on the environment"
		TLP = "White"

	condition:
		exaramel_persistence_file_systemd or exaramel_persistence_file_upstart or exaramel_persistence_file_systemv
}

/* misc */

rule exaramel_socket_path {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Path of the unix socket created to prevent concurrent executions"
		TLP = "White"

	strings:
		$ = "/tmp/.applocktx"

	condition:
		all of them
}

rule exaramel_task_names {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Name of the tasks received by the CC"
		TLP = "White"

	strings:
		$ = "App.Delete"
		$ = "App.SetServer"
		$ = "App.SetProxy"
		$ = "App.SetTimeout"
		$ = "App.Update"
		$ = "IO.ReadFile"
		$ = "IO.WriteFile"
		$ = "OS.ShellExecute"

	condition:
		all of them
}

rule exaramel_struct {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Beginning of type _type struct for some of the most important structs"
		TLP = "White"

	strings:
		$struct_le_config = {70 00 00 00 00 00 00 00 58 00 00 00 00 00 00 00 47 2d 28 42 0? [2] 19}
		$struct_le_worker = {30 00 00 00 00 00 00 00 30 00 00 00 00 00 00 00 46 6a 13 e2 0? [2] 19}
		$struct_le_client = {20 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 7b 6a 49 84 0? [2] 19}
		$struct_le_report = {30 00 00 00 00 00 00 00 28 00 00 00 00 00 00 00 bf 35 0d f9 0? [2] 19}
		$struct_le_task = {50 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 88 60 a1 c5 0? [2] 19}

	condition:
		any of them
}

private rule exaramel_strings_url {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Misc strings coming from URL parts"
		TLP = "White"

	strings:
		$url1 = "/tasks.get/"
		$url2 = "/time.get/"
		$url3 = "/time.set"
		$url4 = "/tasks.report"
		$url5 = "/attachment.get/"
		$url6 = "/auth/app"

	condition:
		5 of ($url*)
}

private rule exaramel_strings_typo {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Misc strings with typo"
		TLP = "White"

	strings:
		$typo1 = "/sbin/init |  awk "
		$typo2 = "Syslog service for monitoring \n"
		$typo3 = "Error.Can't update app! Not enough update archive."
		$typo4 = ":\"metod\""

	condition:
		3 of ($typo*)
}

private rule exaramel_strings_persistence {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Misc strings describing persistence methods"
		TLP = "White"

	strings:
		$ = "systemd"
		$ = "upstart"
		$ = "systemV"
		$ = "freebsd rc"

	condition:
		all of them
}

private rule exaramel_strings_report {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Misc strings coming from report file name"
		TLP = "White"

	strings:
		$ = "systemdupdate.rep"
		$ = "upstartupdate.rep"
		$ = "remove.rep"

	condition:
		all of them
}

rule exaramel_strings {

	meta:
		author = "FR/ANSSI/SDO"
		description = "Misc strings including URLs, typos, supported startup systems and report file names"
		TLP = "White"

	condition:
		exaramel_strings_typo or (exaramel_strings_url and exaramel_strings_persistence) or (exaramel_strings_persistence and exaramel_strings_report) or (exaramel_strings_url and exaramel_strings_report)
}

// MISP event:1209 uuid:a46a03a1-a7b6-4428-a638-c6cfa104ff19 org: to_ids:True tags:[]
rule PAS_webshell {

    meta:
        author = "FR/ANSSI/SDO"
        description = "Detects P.A.S. PHP webshell - Based on DHS/FBI JAR-16-2029 (Grizzly Steppe)"
        TLP = "White"

    strings:

        $php = "<?php"
        $base64decode = /='base'\.\(\d+(\*|\/)\d+\)\.'_de'\.'code'/
        $strreplace = "(str_replace("
        $md5 = ".substr(md5(strrev($" nocase
        $gzinflate = "gzinflate"
        $cookie = "_COOKIE"
        $isset = "isset"

    condition:

        (filesize > 20KB and filesize < 200KB) and
        #cookie == 2 and
        #isset == 3 and
        all of them
}

// MISP event:1209 uuid:3a1095bd-ab99-4788-b2cb-75032c64a669 org: to_ids:True tags:[]
rule PAS_webshell_PerlNetworkScript {

    meta:
        author = "FR/ANSSI/SDO"
        description = "Detects PERL scripts created by P.A.S. webshell to supports network functionnalities"
        TLP = "White"

    strings:
        $pl_start = "#!/usr/bin/perl\n$SIG{'CHLD'}='IGNORE'; use IO::Socket; use FileHandle;"
        $pl_status = "$o=\" [OK]\";$e=\"      Error: \""
        $pl_socket = "socket(SOCKET, PF_INET, SOCK_STREAM,$tcp) or die print \"$l$e$!$l"

        $msg1 = "print \"$l      OK! I\\'m successful connected.$l\""
        $msg2 = "print \"$l      OK! I\\'m accept connection.$l\""

    condition:
        filesize < 6000 and
        ($pl_start at 0 and all of ($pl*)) or
        any of ($msg*)
}

// MISP event:1209 uuid:1f621b12-fa60-462e-8912-20d74988095f org: to_ids:True tags:[]
rule PAS_webshell_SQLDumpFile {

    meta:
        author = "FR/ANSSI/SDO"
        description = "Detects SQL dump file created by P.A.S. webshell"
        TLP = "White"

     strings:
        $ = "-- [  SQL Dump created by P.A.S.  ] --"

     condition:
        all of them
}

// MISP event:1209 uuid:92105d22-0d89-45b3-bdf0-185bc5d2ff8e org: to_ids:True tags:[]
rule PAS_webshell_ZIPArchiveFile {

    meta:
        author = "FR/ANSSI/SDO"
        description = "Detects an archive file created by P.A.S. for download operation"
        TLP = "White"

    strings:
        $ = /Archive created by P\.A\.S\. v.{1,30}\nHost: : .{1,200}\nDate : [0-9]{1,2}-[0-9]{1,2}-[0-9]{4}/

    condition:
        all of them
}

// MISP event:1217 uuid:7c8863dc-7683-485a-bb49-f1e1d856bed3 org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_Webshell_PL_ATRIUM_1
{
    meta:
        author = "Mandiant"
        date_created = "2021-04-16"
        md5 = "ca0175d86049fa7c796ea06b413857a3"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $s1 = "CGI::param("
        $s2 = "system("
        $s3 = /if[\x09\x20]{0,32}\(CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)\)\s{0,128}\{[\x09\x20]{0,32}print [\x22\x27]Cache-Control: no-cache\\n[\x22\x27][\x09\x20]{0,32};\s{0,128}print [\x22\x27]Content-type: text\/html\\n\\n[\x22\x27][\x09\x20]{0,32};\s{0,128}my \$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)[\x09\x20]{0,32};\s{0,128}system\([\x22\x27]\$/
    condition:
        all of them
}

// MISP event:1217 uuid:5e918e09-7634-46a9-b33d-0cbb72ac48f9 org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_Trojan_SH_ATRIUM_1
{
    meta:
        author = "Mandiant"
        date_created = "2021-04-16"
        md5 = "a631b7a8a11e6df3fccb21f4d34dbd8a"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $s1 = "CGI::param("
        $s2 = "Cache-Control: no-cache"
        $s3 = "system("
        $s4 = /sed -i [^\r\n]{1,128}CGI::param\([^\r\n]{1,128}print[\x20\x09]{1,32}[^\r\n]{1,128}Cache-Control: no-cache[^\r\n]{1,128}print[\x20\x09]{1,32}[^\r\n]{1,128}Content-type: text\/html[^\r\n]{1,128}my [^\r\n]{1,128}=[\x09\x20]{0,32}CGI::param\([^\r\n]{1,128}system\(/
    condition:
        all of them
}

// MISP event:1217 uuid:da941f60-25f1-452e-a5b3-3d0e39eee059 org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Webshell_PL_HARDPULSE 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"      
        md5 = "980cba9e82faf194edb6f3cc20dc73ff"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $r1 = /if[\x09\x20]{0,32}\(\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27]\w{1,64}[\x22\x27]\)\s{0,128}\{\s{1,128}my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}\x3b\s{1,128}unless[\x09\x20]{0,32}\(open\(\$\w{1,64},[\x09\x20]{0,32}\$\w{1,64}\)\)\s{0,128}\{\s{1,128}goto[\x09\x20]{1,32}\w{1,64}[\x09\x20]{0,32}\x3b\s{1,128}return[\x09\x20]{1,32}0[\x09\x20]{0,32}\x3b\s{0,128}\}/ 
        $r2 = /open[\x09\x20]{0,32}\(\*\w{1,64}[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>/ 
        $r3 = /if[\x09\x20]{0,32}\(\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27]\w{1,64}[\x22\x27]\)\s{0,128}\{\s{1,128}print[\x09\x20]{0,32}[\x22\x27]Content-type/ 
        $s1 = "CGI::request_method()" 
        $s2 = "CGI::param(" 
        $s3 = "syswrite(" 
        $s4 = "print $_" 
    condition: 
        all of them 
}

// MISP event:1217 uuid:c4174751-2ba7-4633-bfc4-f2e3c698002a org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_Linux32_LOCKPICK_1
{
    meta:
        author = "Mandiant"
        date_created = "2021-04-16"
        md5 = "e8bfd3f5a2806104316902bbe1195ee8"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $sb1 = { 83 ?? 63 0F 84 [4] 8B 45 ?? 83 ?? 01 89 ?? 24 89 44 24 04 E8 [4] 85 C0 }
        $sb2 = { 83 [2] 63 74 ?? 89 ?? 24 04 89 ?? 24 E8 [4] 83 [2] 01 85 C0 0F [5] EB 00 8B ?? 04 83 F8 02 7? ?? 83 E8 01 C1 E0 02 83 C0 00 89 44 24 08 8D 83 [4] 89 44 24 04 8B ?? 89 04 24 E8 }
    condition:
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and (@sb1[1] < @sb2[1])
}

// MISP event:1217 uuid:f3991509-ef0a-4f91-8480-99f512140ad5 org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_Linux32_PACEMAKER 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"   
        md5 = "d7881c4de4d57828f7e1cab15687274b"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $s1 = "\x00/proc/%d/mem\x00" 
        $s2 = "\x00/proc/%s/maps\x00" 
        $s3 = "\x00/proc/%s/cmdline\x00" 
        $sb1 = { C7 44 24 08 10 00 00 00 C7 44 24 04 00 00 00 00 8D 45 E0 89 04 24 E8 [4] 8B 45 F4 83 C0 0B C7 44 24 08 10 00 00 00 89 44 24 04 8D 45 E0 89 04 24 E8 [4] 8D 45 E0 89 04 24 E8 [4] 85 C0 74 ?? 8D 45 E0 89 04 24 E8 [4] 85 C0 74 ?? 8D 45 E0 89 04 24 E8 [4] EB } 
        $sb2 = { 8B 95 [4] B8 [4] 8D 8D [4] 89 4C 24 10 8D 8D [4] 89 4C 24 0C 89 54 24 08 89 44 24 04 8D 85 [4] 89 04 24 E8 [4] C7 44 24 08 02 00 00 00 C7 44 24 04 00 00 00 00 8B 45 ?? 89 04 24 E8 [4] 89 45 ?? 8D 85 [4] 89 04 24 E8 [4] 89 44 24 08 8D 85 [4] 89 44 24 04 8B 45 ?? 89 04 24 E8 [4] 8B 45 ?? 89 45 ?? C7 45 ?? 00 00 00 00 [0-16] 83 45 ?? 01 8B 45 ?? 3B 45 0C } 
    condition: 
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them 
}

// MISP event:1217 uuid:5cf39ce1-27b2-485f-9ad2-e49970b71053 org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_Linux_PACEMAKER 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"     
        md5 = "d7881c4de4d57828f7e1cab15687274b"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $s1 = "\x00Name:%s || Pwd:%s || AuthNum:%s\x0a\x00" 
        $s2 = "\x00/proc/%d/mem\x00" 
        $s3 = "\x00/proc/%s/maps\x00" 
        $s4 = "\x00/proc/%s/cmdline\x00" 
    condition: 
        (uint32(0) == 0x464c457f) and all of them 
}

// MISP event:1217 uuid:19c91b92-4fd1-46ad-801a-f3823c11f5ad org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Webshell_PL_PULSECHECK_1 
{ 
    meta: 
        author = "Mandiant" 
        date_created = "2021-04-16"  
        sha256 = "a1dcdf62aafc36dd8cf64774dea80d79fb4e24ba2a82adf4d944d9186acd1cc1"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $r1 = /while[\x09\x20]{0,32}\(<\w{1,64}>\)[\x09\x20]{0,32}\{\s{1,256}\$\w{1,64}[\x09\x20]{0,32}\.=[\x09\x20]{0,32}\$_;\s{0,256}\}/ 
        $s1 = "use Crypt::RC4;" 
        $s2 = "use MIME::Base64" 
        $s3 = "MIME::Base64::decode(" 
        $s4 = "popen(" 
        $s5 = " .= $_;" 
        $s6 = "print MIME::Base64::encode(RC4(" 
        $s7 = "HTTP_X_" 
    condition: 
        $s1 and $s2 and (@s3[1] < @s4[1]) and (@s4[1] < @s5[1]) and (@s5[1] < @s6[1]) and (#s7 > 2) and $r1 
}

// MISP event:1217 uuid:f2392100-d4c8-4554-b7d9-20da95826507 org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_PULSEJUMP_1
{
    meta:
        author = "Mandiant"
        date_created = "2021-04-16"
        md5 = "91ee23ee24e100ba4a943bb4c15adb4c"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $s1 = "open("
        $s2 = ">>/tmp/"
        $s3 = "syswrite("
        $s4 = /\}[\x09\x20]{0,32}elsif[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27](Radius|Samba|AD)[\x22\x27][\x09\x20]{0,32}\)\s{0,128}\{\s{0,128}@\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}&/
    condition:
        all of them
}

// MISP event:1217 uuid:be80b924-9f86-4c8c-a5e5-28d7aef3a0b9 org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_QUIETPULSE 
{
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"       
        md5 = "00575bec8d74e221ff6248228c509a16"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $s1 = /open[\x09\x20]{0,32}\(\*STDOUT[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>&CLIENT[\x22\x27]\)/ 
        $s2 = /open[\x09\x20]{0,32}\(\*STDERR[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>&CLIENT[\x22\x27]\)/ 
        $s3 = /socket[\x09\x20]{0,32}\(SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}PF_UNIX[\x09\x20]{0,32},[\x09\x20]{0,32}SOCK_STREAM[\x09\x20]{0,32},[\x09\x20]{0,32}0[\x09\x20]{0,32}\)[\x09\x20]{0,32};\s{0,128}unlink/ 
        $s4 = /bind[\x09\x20]{0,32}\([\x09\x20]{0,32}SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}sockaddr_un\(/ 
        $s5 = /listen[\x09\x20]{0,32}\([\x09\x20]{0,32}SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}SOMAXCONN[\x09\x20]{0,32}\)[\x09\x20]{0,32};/ 
        $s6 = /my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}fork\([\x09\x20]{0,32}\)[\x09\x20]{0,32};\s{1,128}if[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{0,32}==[\x09\x20]{0,32}0[\x09\x20]{0,32}\)[\x09\x20]{0,32}\{\s{1,128}exec\(/ 
    condition: 
        all of them 
}

// MISP event:1217 uuid:0796b36d-d4d7-4379-b475-1ce462e5766a org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_RADIALPULSE_1 
{
    meta: 
        author = "Mandiant" 
        date_created = "2021-04-16"       
        sha256 = "d72daafedf41d484f7f9816f7f076a9249a6808f1899649b7daa22c0447bb37b"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"        
    strings: 
        $s1 = "->getRealmInfo()->{name}" 
        $s2 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>/ 
        $s3 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]realm=\$/ 
        $s4 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]username=\$/ 
        $s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]password=\$/ 
    condition: 
        (@s1[1] < @s2[1]) and (@s2[1] < @s3[1]) and $s4 and $s5 
}

// MISP event:1217 uuid:05fe3a12-d1eb-48de-af91-f21fab1a3200 org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_RADIALPULSE_2 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"       
        md5 = "4a2a7cbc1c8855199a27a7a7b51d0117"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $s1 = "open(*fd," 
        $s2 = "syswrite(*fd," 
        $s3 = "close(*fd);" 
        $s4 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>\/tmp\/[\w.]{1,128}[\x22\x27]\);[\x09\x20]{0,32}syswrite\(\*fd,[\x09\x20]{0,32}/ 
        $s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27][\w]{1,128}=\$\w{1,128} ?[\x22\x27],[\x09\x20]{0,32}5000\)/ 
    condition: 
        all of them 
}

// MISP event:1217 uuid:25930cf6-c47d-48c4-a3f1-5e3f66258200 org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_RADIALPULSE_3 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"  
        md5 = "4a2a7cbc1c8855199a27a7a7b51d0117"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $s1 = "open(*fd," 
        $s2 = "syswrite(*fd," 
        $s3 = "close(*fd);" 
        $s4 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>\/tmp\/dsstartssh\.statementcounters[\x22\x27]\);[\x09\x20]{0,32}syswrite\(\*fd,[\x09\x20]{0,32}/ 
        $s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27][\w]{1,128}=\$username ?[\x22\x27],[\x09\x20]{0,32}\d{4}\)/ 
    condition: 
        all of them 
}

// MISP event:1217 uuid:2e8d68ef-a463-4af8-9b32-3f5fa6f6d52b org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Backdoor_Linux32_SLOWPULSE_1 
{ 
    meta: 
        author = "Mandiant" 
        date_created = "2021-04-16"
        sha256 = "cd09ec795a8f4b6ced003500a44d810f49943514e2f92c81ab96c33e1c0fbd68"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"        
    strings: 
        $sb1 = {FC b9 [4] e8 00 00 00 00 5? 8d b? [4] 8b} 
        $sb2 = {f3 a6 0f 85 [4] b8 03 00 00 00 5? 5? 5?} 
        $sb3 = {9c 60 e8 00 00 00 00 5? 8d [5] 85 ?? 0f 8?} 
        $sb4 = {89 13 8b 51 04 89 53 04 8b 51 08 89 53 08} 
        $sb5 = {8d [5] b9 [4] f3 a6 0f 8?} 
    condition: 
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them 
}

// MISP event:1217 uuid:1040bf8f-d212-4d84-b89c-d8db89190042 org: to_ids:True tags:[]
rule FE_APT_Backdoor_Linux32_SLOWPULSE_2
{ 
    meta: 
        author = "Strozfriedberg" 
        date_created = "2021-04-16"
        sha256 = "cd09ec795a8f4b6ced003500a44d810f49943514e2f92c81ab96c33e1c0fbd68"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"        
    strings: 
        $sig = /[\x20-\x7F]{16}([\x20-\x7F\x00]+)\x00.{1,32}\xE9.{3}\xFF\x00+[\x20-\x7F][\x20-\x7F\x00]{16}/ 

        // TOI_MAGIC_STRING 
        $exc1 = /\xED\xC3\x02\xE9\x98\x56\xE5\x0C/ 
    condition:
        uint32(0) == 0x464C457F and (1 of ($sig*)) and (not (1 of ($exc*)))
}

// MISP event:1217 uuid:ea766dc1-2087-4a38-9046-1d5788dd7259 org: to_ids:True tags:[]
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Webshell_PL_STEADYPULSE_1
{  
    meta:  
        author = "Mandiant"  
        date_created = "2021-04-16"      
        sha256 = "168976797d5af7071df257e91fcc31ce1d6e59c72ca9e2f50c8b5b3177ad83cc"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"     
    strings:  
        $s1 = "parse_parameters" 
        $s2 = "s/\\+/ /g"  
        $s3 = "s/%(..)/pack("  
        $s4 = "MIME::Base64::encode($"  
        $s5 = "$|=1;" 
        $s6 = "RC4(" 
        $s7 = "$FORM{'cmd'}" 
    condition:  
        all of them  
}

// MISP event:1219 uuid:b91d3b13-b02f-436c-9264-9de11d15cee4 org: to_ids:True tags:[]
/* Via https://github.com/bartblaze/Yara-rules/blob/master/rules/ransomware/REvil_Cert.yar
*/

import "pe"
rule REvil_Cert
{
meta:
	description = "Identifies the digital certificate PB03 TRANSPORT LTD, used by REvil in the Kaseya supply chain attack."
	author = "@bartblaze"
	date = "2021-07"
	reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"
	tlp = "White"
	
condition:
	uint16(0) == 0x5a4d and
		for any i in (0 .. pe.number_of_signatures) : (
		pe.signatures[i].serial == "11:9a:ce:ad:66:8b:ad:57:a4:8b:4f:42:f2:94:f8:f0"
	)
}

// MISP event:1219 uuid:ee10752f-c432-48f3-9d1d-f798e0e7c5d9 org: to_ids:True tags:[]
/* Via https://github.com/bartblaze/Yara-rules/blob/master/rules/ransomware/REvil_Dropper.yar
*/

rule REvil_Dropper
{
meta:
	description = "Identifies the dropper used by REvil in the Kaseya supply chain attack."
	author = "@bartblaze"
	date = "2021-07"
	hash = "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e"
  	reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"
	tlp = "White"
	
strings:
  $ = { 55 8b ec 56 8b 35 24 d0 40 00 68 04 1c 41 00 6a 65 6a 00 ff 
  d6 85 c0 0f 84 98 00 00 00 50 6a 00 ff 15 20 d0 40 00 85 c0 0f 84 
  87 00 00 00 50 ff 15 18 d0 40 00 68 14 1c 41 00 6a 66 6a 00 a3 a0 
  43 41 00 ff d6 85 c0 74 6c 50 33 f6 56 ff 15 20 d0 40 00 85 c0 74 
  5e 50 ff 15 18 d0 40 00 68 24 1c 41 00 ba 88 55 0c 00 a3 a4 43 41 
  00 8b c8 e8 9a fe ff ff 8b 0d a0 43 41 00 ba d0 56 00 00 c7 04 ?4 
  38 1c 41 00 e8 83 fe ff ff c7 04 ?4 ec 43 41 00 68 a8 43 41 00 56 
  56 68 30 02 00 00 56 56 56 ff 75 10 c7 05 a8 43 41 00 44 00 00 00 
  50 ff 15 28 d0 40 00 }
	
condition:
	all of them
}

// MISP event:1219 uuid:c95a3cf3-048f-42a4-abad-afe87a3508c8 org: to_ids:True tags:[]
/* Via: https://github.com/Neo23x0/signature-base/blob/master/yara/crime_revil_general.yar
*/

rule APT_MAL_REvil_Kaseya_Jul21_2 {
   meta:
      description = "Detects malware used in the Kaseya supply chain attack"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b"
      date = "2021-07-02"
      hash1 = "0496ca57e387b10dfdac809de8a4e039f68e8d66535d5d19ec76d39f7d0a4402"
      hash2 = "8dd620d9aeb35960bb766458c8890ede987c33d239cf730f93fe49d90ae759dd"
      hash3 = "cc0cdc6a3d843e22c98170713abf1d6ae06e8b5e34ed06ac3159adafe85e3bd6"
      hash4 = "d5ce6f36a06b0dc8ce8e7e2c9a53e66094c2adfc93cfac61dd09efe9ac45a75f"
      hash5 = "d8353cfc5e696d3ae402c7c70565c1e7f31e49bcf74a6e12e5ab044f306b4b20"
      hash6 = "e2a24ab94f865caeacdf2c3ad015f31f23008ac6db8312c2cbfb32e4a5466ea2"
   strings:
      $opa1 = { 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 }
      $opa2 = { 89 45 f0 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 }
      $opa3 = { 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 0f b6 14 01 }
      $opa4 = { 89 45 f4 8b 0d ?? ?0 07 10 89 4d f8 8b 15 ?? ?1 07 10 89 55 fc ff 75 fc ff 75 f8 ff 55 f4 }

      $opb1 = { 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc cc }
      $opb2 = { 18 00 10 0e 19 00 10 cc cc cc cc 8b 44 24 04 }
      $opb3 = { 10 c4 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and ( 2 of ($opa*) or 3 of them )
}

// MISP event:1219 uuid:47a4fdbd-deda-4351-95d4-669b84cedf53 org: to_ids:True tags:[]
/* Via https://github.com/Neo23x0/signature-base/blob/e360605894c12859de36f28fda95140aa330694b/yara/crime_ransom_revil.yar
*/


rule MAL_RANSOM_REvil_Oct20_1 {
   meta:
      description = "Detects REvil ransomware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2020-10-13"
      hash1 = "5966c25dc1abcec9d8603b97919db57aac019e5358ee413957927d3c1790b7f4"
      hash2 = "f66027faea8c9e0ff29a31641e186cbed7073b52b43933ba36d61e8f6bce1ab5"
      hash3 = "f6857748c050655fb3c2192b52a3b0915f3f3708cd0a59bbf641d7dd722a804d"
      hash4 = "fc26288df74aa8046b4761f8478c52819e0fca478c1ab674da7e1d24e1cfa501"
   strings:
      $op1 = { 0f 8c 74 ff ff ff 33 c0 5f 5e 5b 8b e5 5d c3 8b }
      $op2 = { 8d 85 68 ff ff ff 50 e8 2a fe ff ff 8d 85 68 ff }
      $op3 = { 89 4d f4 8b 4e 0c 33 4e 34 33 4e 5c 33 8e 84 }
      $op4 = { 8d 85 68 ff ff ff 50 e8 05 06 00 00 8d 85 68 ff }
      $op5 = { 8d 85 68 ff ff ff 56 57 ff 75 0c 50 e8 2f }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      2 of them or 4 of them
}

// MISP event:1220 uuid:ca9e3e49-4a94-4256-8616-82e9b9b6804e org: to_ids:True tags:[]
import "pe"
rule DevilsTongue_HijackDll
{
meta:
description = "Detects SOURGUM's DevilsTongue hijack DLL"
author = "Microsoft Threat Intelligence Center (MSTIC)"
date = "2021-07-15"
strings:
$str1 = "windows.old\\windows" wide
$str2 = "NtQueryInformationThread"
$str3 = "dbgHelp.dll" wide
$str4 = "StackWalk64"
$str5 = "ConvertSidToStringSidW"
$str6 = "S-1-5-18" wide
$str7 = "SMNew.dll" // DLL original name
// Call check in stack manipulation
// B8 FF 15 00 00   mov     eax, 15FFh
// 66 39 41 FA      cmp     [rcx-6], ax
// 74 06            jz      short loc_1800042B9
// 80 79 FB E8      cmp     byte ptr [rcx-5], 0E8h ; 'è'
$code1 = {B8 FF 15 00 00 66 39 41 FA 74 06 80 79 FB E8}
// PRNG to generate number of times to sleep 1s before exiting
// 44 8B C0 mov r8d, eax
// B8 B5 81 4E 1B mov eax, 1B4E81B5h
// 41 F7 E8 imul r8d
// C1 FA 05 sar edx, 5
// 8B CA    mov ecx, edx
// C1 E9 1F shr ecx, 1Fh
// 03 D1    add edx, ecx
// 69 CA 2C 01 00 00 imul ecx, edx, 12Ch
// 44 2B C1 sub r8d, ecx
// 45 85 C0 test r8d, r8d
// 7E 19    jle  short loc_1800014D0
$code2 = {44 8B C0 B8 B5 81 4E 1B 41 F7 E8 C1 FA 05 8B CA C1 E9 1F 03 D1 69 CA 2C 01 00 00 44 2B C1 45 85 C0 7E 19}
condition:
filesize < 800KB and
uint16(0) == 0x5A4D and
(pe.characteristics & pe.DLL) and
(
4 of them or
($code1 and $code2) or
(pe.imphash() == "9a964e810949704ff7b4a393d9adda60")
)
}

// MISP event:1225 uuid:150de82b-b716-475b-a8c3-bd093c32c9db org: to_ids:True tags:[]
import "pe"
rule TinyTurla {
meta:
author = "Cisco Talos"
description = "Detects Tiny Turla backdoor DLL"
strings:
$a = "Title:" fullword wide
$b = "Hosts" fullword wide
$c = "Security" fullword wide
$d = "TimeLong" fullword wide
$e = "TimeShort" fullword wide
$f = "MachineGuid" fullword wide
$g = "POST" fullword wide
$h = "WinHttpSetOption" fullword ascii
$i = "WinHttpQueryDataAvailable" fullword ascii

condition:
pe.is_pe and
pe.characteristics & pe.DLL and
pe.exports("ServiceMain") and
all of them
}

// MISP event:1235 uuid:87bdab8d-c1f2-4996-86b6-b0c9ef9536eb org: to_ids:True tags:[]
rule MAL_HERMETIC_WIPER {
    meta:
      desc = "HermeticWiper - broad hunting rule"
      author = "Friends @ SentinelLabs"
      version = "1.0"
      last_modified = "02.23.2022"
      hash = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
    strings:
        $string1 = "DRV_XP_X64" wide ascii nocase
        $string2 = "EPMNTDRV\\%u" wide ascii nocase
        $string3 = "PhysicalDrive%u" wide ascii nocase
        $cert1 = "Hermetica Digital Ltd" wide ascii nocase
    condition:
      uint16(0) == 0x5A4D and
      all of them
}

// MISP event:1241 uuid:f82aab09-cd2b-4793-9d2c-b05fc4a2c423 org: to_ids:True tags:[]
import "pe"

rule SUSP_NVIDIA_LAPSUS_Leak_Compromised_Cert_Mar22_1 {
   meta:
      description = "Detects a binary signed with the leaked NVIDIA certifcate and compiled after March 1st 2022"
      author = "Florian Roth"
      date = "2022-03-03"
      modified = "2022-03-04"
      score = 70
      reference = "https://twitter.com/cyb3rops/status/1499514240008437762"
   condition:
      uint16(0) == 0x5a4d and filesize < 100MB and
      pe.timestamp > 1646092800 and  // comment out to find all files signed with that certificate
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "VeriSign Class 3 Code Signing 2010 CA" and (
            pe.signatures[i].serial == "43:bb:43:7d:60:98:66:28:6d:d8:39:e1:d0:03:09:f5" or
            pe.signatures[i].serial == "14:78:1b:c8:62:e8:dc:50:3a:55:93:46:f5:dc:c5:18"
         )
   )
}

// MISP event:1246 uuid:edd3bc7d-badf-47ad-bad1-94fc84344464 org: to_ids:True tags:[]
import "vt"
rule hunt_0day_msdt
{
    strings:
        $s1 = "!\" TargetMode=\"External\"/>" nocase wide ascii
    condition:
        new_file and all of ($s*) and vt.metadata.file_type == vt.FileType.DOCX
}

// MISP event:1251 uuid:641fa3ef-2015-4b92-b3b3-0313a0991173 org: to_ids:True tags:[]
rule CISA_10382580_03 : loader
{
	meta:
		Author = "CISA Code & Media Analysis"
		Incident = "10382580"
		Date = "2022-05-02"
		Last_Modified = "20220602_1200"
		Actor = "n/a"
		Category = "Loader"
		Family = "n/a"
		Description = "Detects loader samples"
		MD5_1 = "3764a0f1762a294f662f3bf86bac776f"
		SHA256_1 = "f7f7b059b6a7dbd75b30b685b148025a0d4ceceab405e553ca28cacdeae43fab"
		MD5_2 = "21fa1a043460c14709ef425ce24da4fd"
		SHA256_2 = "66966ceae7e3a8aace6c27183067d861f9d7267aed30473a95168c3fe19f2c16"
		MD5_3 = "e9c2b8bd1583baf3493824bf7b3ec51e"
		SHA256_3 = "7ea294d30903c0ab690bc02b64b20af0cfe66a168d4622e55dee4d6233783751"
		MD5_4 = "de0d57bdc10fee1e1e16e225788bb8de"
		SHA256_4 = "33b89b8915aaa59a3c9db23343e8c249b2db260b9b10e88593b6ff2fb5f71d2b"
		MD5_5 = "9b071311ecd1a72bfd715e34dbd1bd77"
		SHA256_5 = "3c2c835042a05f8d974d9b35b994bcf8d5a0ce19128ebb362804c2d0f3eb42c0"
		MD5_6 = "05d38bc82d362dd57190e3cb397f807d"
		SHA256_6 = "4cd7efdb1a7ac8c4387c515a7b1925931beb212b95c4f9d8b716dbe18f54624f"
	strings:
		$s0 = { B8 01 00 00 00 48 6B C0 00 C6 44 04 20 A8 B8 01 }
		$s1 = { 00 00 48 6B C0 01 C6 44 04 20 9A B8 01 00 00 }
		$s2 = { 48 6B C0 02 C6 44 04 20 93 B8 01 00 00 00 48 }
		$s3 = { C0 03 C6 44 04 20 9B B8 01 00 00 00 48 6B C0 }
	condition:
		all of them
}

// MISP event:1251 uuid:a74a5821-adea-4928-888c-446a8f6139f3 org: to_ids:True tags:[]
rule CISA_10382580_01 : rat
{
	meta:
		Author = "CISA Code & Media Analysis"
		Incident = "10382580"
		Date = "2022-05-25"
		Last_Modified = "20220602_1200"
		Actor = "n/a"
		Category = "Remote Access Tool"
		Family = "n/a"
		Description = "Detects Remote Access Tool samples"
		MD5_1 = "199a32712998c6d736a05b2dbd24a761"
		SHA256_1 = "88a5e4b24747648a4e3f0a2d5282b51683260f9208b06788fc858c44559da1e8"
	strings:
		$s0 = { 0F B6 40 0F 6B C8 47 41 0F B6 40 0B 02 D1 6B C8 }
		$s1 = { 35 41 0F B6 00 41 88 58 01 41 88 78 02 41 88 70 }
		$s2 = { 66 83 F8 1E }
		$s3 = { 66 83 F8 52 }
	condition:
		all of them
}

// MISP event:1253 uuid:537e39eb-37f4-42d5-8944-39022aa38b47 org: to_ids:True tags:[]
rule MAL_Github_Repo_Compromise_MyJino_Ru_Aug22 {
   meta:
      description = "Detects URL mentioned in report on compromised Github repositories in August 2022"
      author = "Florian Roth"
      reference = "https://twitter.com/stephenlacy/status/1554697077430505473"
      date = "2022-08-03"
      score = 90
   strings:
      $x1 = "curl http://ovz1.j19544519.pr46m.vps.myjino.ru" ascii wide
      $x2 = "http__.Post(\"http://ovz1.j19544519.pr46m.vps.myjino.ru" ascii wide
   condition:
      1 of them
}

// MISP event:1261 uuid:9f709927-e9e6-4328-a3a6-1cafb6f21d94 org: to_ids:True tags:[]
rule webshell_php_3b64command: Webshells PHP B64 {
  meta:
    Description= "Detects Possible PHP Webshell expecting triple base64 command"
    Category = "Malware"
    Author = "Arctic Wolf Labs"
    Date = "2022-09-12"
    Hash = "07838ac8fd5a59bb741aae0cf3abf48296677be7ac0864c4f124c2e168c0af94"
    Reference = "https://arcticwolf.com/resources/blog/lorenz-ransomware-chiseling-in"
  strings:
    $decode = "base64_decode(base64_decode(base64_decode(" ascii
    $encode = "base64_encode(base64_encode(base64_encode(" ascii
    $s1 = "popen(" ascii
    $s2 = "pclose" ascii
    $s3 = "fread(" ascii
    $s4 = "$_POST" ascii
  condition:
    $decode and $encode
    and 3 of ($s*)
    and filesize < 2KB
}

// MISP event:1261 uuid:66724ad2-81e5-4912-b0ad-0763dfcb123f org: to_ids:True tags:[]
rule hktl_chisel_artifacts: Chisel Hacktool Artifacts {
  meta:
    Description = "looks for hacktool chisel artifacts potentially left in memory or unallocated space"
    Category = "Tool"
    Author = "Arctic Wolf Labs"
    Date = "2022-09-12"
    Reference = "https://arcticwolf.com/resources/blog/lorenz-ransomware-chiseling-in"
  strings:
    $chisel = "chisel_1." ascii
    $s1 = "client" ascii
    $s2 = "--tls-skip-verify" ascii
    $s3 = "--fingerprint" ascii
    $s4 = "R:socks" ascii
  condition:
    $chisel or 3 of ($s*)
}

// MISP event:1263 uuid:b197be37-7a16-4400-bea6-a9a3f8a665cd org: to_ids:True tags:[]
rule win_x86_backdoor_plug_x_shellcode_loader_dll {
meta:
author = "Felipe Duarte, Security Joes"
description = "Detects the PlugX Shellcode Loader DLL for 32 bits systems"
sha256_reference = "5304d00250196a8cd5e9a81e053a886d1a291e4615484e49ff537bebecc13976"
strings:
// Code to set memory protections and launch shellcode
$opcode1 = { 8d ?? ?? 5? 6a 20 68 00 00 10 00 5? ff 15 ?? ?? ?? ?? 85 ?? 75 ?? 6a 43 e8 ?? ?? ?? ?? 83 c? ?? ff d? 3d ?? ?? ?? ?? 7d ?? 85 ?? 74 ?? 6a 4a e8 ?? ?? ?? ?? 83 c? ?? }
// Strings required to resolve depencies to load and execute the shellcode
$str1 = "kernel32" nocase
$str2 = "GetModuleFileNameW"
$str3 = "CreateFileW"
$str4 = "VirtualAlloc"
$str5 = "ReadFile"
$str6 = "VirtualProtect"
condition:
all of them
}

// MISP event:1263 uuid:d809b696-9de2-42cd-a174-dfba28fca044 org: to_ids:True tags:[]
rule win_x64_backdoor_plug_x_shellcode_loader_dll {
meta:
author = "Felipe Duarte, Security Joes"
description = "Detects the PlugX Shellcode Loader DLL for 64 bits systems"
sha256_reference = "6b8ae6f01ab31243a5176c9fd14c156e9d5c139d170115acb87e1bc65400d54f"
strings:
// Code to get file name of the current module and replaces the extension to .dat
$opcode1 = { 4? 8d 1d ?? ?? ?? ?? 41 b8 00 20 00 00 33 c9 4? 8b d3 ff d0 4? 8b cb 89 44 ?? ?? ff 15 ?? ?? ?? ?? b9 64 00 00 00 8d 50 fd 33 f6 66 89 0c ?? 8d 50 fe b9 61 00 00 00 66 89 0c ?? 8d 50 ff 8b c0 66 89 34 ?? 4? 8b 05 ?? ?? ?? ?? b9 74 00 00 00 66 89 0c ?? 4? 85 c0 75 ?? 4? 8b 05 ?? ?? ?? ?? 4? 85 c0 75 ?? 4? 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 4? 89 05 ?? ?? ?? ?? }
// Code to set memory protections and launch shellcode
$opcode2 = { 4? 8d 4c ?? ?? ba 00 00 10 00 41 b8 40 00 00 00 4? 8b cb ff d0 85 c0 74 ?? ff d3 83 c9 ff ff 15 ?? ?? ?? ?? }
// Strings required to resolve depencies to load and execute the shellcode
$str1 = "kernel32" nocase
$str2 = "GetModuleFileNameW"
$str3 = "CreateFileW"
$str4 = "VirtualAlloc"
$str5 = "ReadFile"
$str6 = "VirtualProtect"
condition:
all of them
}

// MISP event:1263 uuid:4595a5c5-3f9c-4775-acb4-7802b526d57c org: to_ids:True tags:[]
rule win_x86_backdoor_plug_x_shellcode {
meta:
author = "Felipe Duarte, Security Joes"
description = "Detects the PlugX Shellcode for 32 bits systems"
sha256_reference = "07ed636049be7bc31fb404da9cf12cff6af01d920ec245b4e087049bd9b5488d"
strings:
// Code of the decryption rutine
$opcode1 = { 8b ?? c1 e? 03 8d ?? ?? ?? ?? ?? ?? 8b ?? c1 e? 05 8d ?? ?? ?? ?? ?? ?? 8b ?? ?? c1 e? 07 b? 33 33 33 33 2b ?? 01 ?? ?? 8b ?? ?? c1 e? 09 b? 44 44 44 44 2b ?? 01 ?? ?? 8b ?? ?? 8d ?? ?? 02 ?? ?? 02 ?? ?? 32 ?? ?? 88 ?? 4? 4? 75 ?? }
// Stack strings for VirtualAlloc
$opcode2 = { c7 8? ?? ?? ?? ?? 56 69 72 74 c7 8? ?? ?? ?? ?? 75 61 6c 41 c7 8? ?? ?? ?? ?? 6c 6c 6f 63 88 ?? ?? ?? ?? ?? ff d? }
condition:
all of them
}

// MISP event:1263 uuid:e94b9835-d440-4f88-adec-3dcb7e4ce7c4 org: to_ids:True tags:[]
rule win_x64_backdoor_plug_x_shellcode {
meta:
author = "Felipe Duarte, Security Joes"
description = "Detects the PlugX Shellcode for 64 bits systems"
sha256_reference = "07ed636049be7bc31fb404da9cf12cff6af01d920ec245b4e087049bd9b5488d"
strings:
// Code of the decryption rutine
$opcode1 = { 41 8b ?? 41 8b ?? c1 e? 03 c1 e? 07 45 8d ?? ?? ?? ?? ?? ?? 41 8b ?? c1 e? 05 45 8d ?? ?? ?? ?? ?? ?? b? 33 33 33 33 2b ?? 41 8b ?? 44 03 ?? c1 e? 09 b? 44 44 44 44 2b ?? 44 03 ?? 43 8d ?? ?? 41 02 ?? 41 02 ?? 32 ?? ?? 88 ?? 4? ff c? 4? ff c? }
// Stack strings for VirtualAlloc
$opcode2 = { c6 4? ?? 56 c6 4? ?? 69 c6 4? ?? 72 c6 4? ?? 74 c6 4? ?? 75 c6 4? ?? 61 c6 4? ?? 6c c6 4? ?? 41 c6 4? ?? 6c c6 4? ?? 6c c6 4? ?? 6f c6 4? ?? 63 }
condition:
all of them
}

// MISP event:1263 uuid:c53e3631-b5b3-432e-b79d-517ee8046ab7 org: to_ids:True tags:[]
rule win_x86_backdoor_plug_x_uac_bypass {
meta:
author = "Felipe Duarte, Security Joes"
description = "Detects the PlugX UAC Bypass DLL for 32 bits systems"
sha256_reference = "9d51427f4f5b9f34050a502df3fbcea77f87d4e8f0cef29b05b543db03276e06"
strings:
// Main loop
$opcode1 = { 0f b7 ?? ?? ?? ?? ?? ?? 4? 66 85 ?? 75 ?? 8d ?? ?? ?? ?? ?? ?? 66 83 3? 00 74 ?? 5? e8 ?? ?? ?? ?? 5? c3 }
$str1 = "kernel32" nocase
$str2 = "GetCommandLineW"
$str3 = "CreateProcessW"
$str4 = "GetCurrentProcess"
$str5 = "TerminateProcess"
condition:
all of them
}

// MISP event:1263 uuid:f3958c22-6a1b-47ec-b181-92d55df3655c org: to_ids:True tags:[]
rule win_x86_backdoor_plug_x_core {
meta:
author = "Felipe Duarte, Security Joes"
description = "Detects the PlugX Core DLL for 32 bits systems"
sha256_reference = "fde1a930c6b12d7b00b6e95d52ce1b6536646a903713b1d3d37dc1936da2df88"
strings:
// Decryption routine
$opcode1 = { 8b ?? ?? 8b ?? c1 e? 03 8d ?? ?? ?? ?? ?? ?? 8b ?? c1 e? 05 8d ?? ?? ?? ?? ?? ?? 8b ?? c1 e? 07 b? 33 33 33 33 2b ?? 8b ?? ?? 03 ?? c1 e? 09 b? 44 44 44 44 2b ?? 01 ?? ?? 8d ?? ?? 02 ?? 02 ?? ?? 89 ?? ?? 8b 5? ?? 32 ?? 32 4? ff 4? ?? 88 ?? ?? 75 ?? 5? }
$str1 = "Mozilla/4.0 (compatible; MSIE " wide ascii
$str2 = "X-Session" ascii
$str3 = "Software\\CLASSES\\FAST" wide ascii
$str4 = "KLProc"
$str5 = "OlProcManager"
$str6 = "JoProcBroadcastRecv"
condition:
all of them
}

// MISP event:1263 uuid:eb541abb-c34a-48c6-969d-9f1f663ba4c7 org: to_ids:True tags:[]
rule win_x64_backdoor_plug_x_uac_bypass {
meta:
author = "Felipe Duarte, Security Joes"
description = "Detects the PlugX UAC Bypass DLL for 64 bits systems"
sha256_reference = "547b605673a2659fe2c8111c8f0c3005c532cab6b3ba638e2cdcd52fb62296d3"
strings:
// 360tray.exe stack strings
$opcode1 = { 4? 83 e? 48 b? 33 00 00 00 4? 8d ?? ?? ?? c7 44 ?? ?? 2e 00 65 00 66 89 ?? ?? ?? b? 36 00 00 00 c7 44 ?? ?? 78 00 65 00 66 89 ?? ?? ?? b? 30 00 00 00 66 89 ?? ?? ?? b? 74 00 00 00 66 89 ?? ?? ?? b? 72 00 00 00 66 89 ?? ?? ?? b? 61 00 00 00 66 89 ?? ?? ?? b? 79 00 00 00 66 89 ?? ?? ?? 33 ?? 66 89 ?? ?? ?? e8 ?? ?? ?? ?? }
$str1 = "Elevation:Administrator!new:%s" wide ascii
$str2 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide ascii
$str3 = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" wide ascii
$str4 = "CLSIDFromString"
$str5 = "CoGetObject"
condition:
all of them
}

// MISP event:1263 uuid:0ccdbb66-547e-45cb-9952-820f1697631e org: to_ids:True tags:[]
rule win_x64_backdoor_plug_x_core {
meta:
author = "Felipe Duarte, Security Joes"
description = "Detects the PlugX Core DLL for 64 bits systems"
sha256_reference = "af9cb318c4c28d7030f62a62f561ff612a9efb839c6934ead0eb496d49f73e03"
strings:
// Decryption routine
$opcode1 = { 41 8b ?? 8b ?? 4? ff c? c1 e? 03 c1 e? 07 45 8d ?? ?? ?? ?? ?? ?? 41 8b ?? c1 e? 05 45 8d ?? ?? ?? ?? ?? ?? b? 33 33 33 33 2b ?? 8b ?? 03 ?? c1 e? 09 b? 44 44 44 44 2b ?? 03 ?? 43 8d ?? ?? 02 ?? 40 02 ?? 43 32 ?? ?? ?? 4? ff c? 41 88 ?? ?? 75 ?? }
$str1 = "Mozilla/4.0 (compatible; MSIE " wide ascii
$str2 = "X-Session" wide ascii
$str3 = "Software\\CLASSES\\FAST" wide ascii
$str4 = "KLProc"
$str5 = "OlProcManager"
$str6 = "JoProcBroadcastRecv"
condition:
all of them
}

// MISP event:1280 uuid:a51eae60-e3c6-4fbe-a03e-c14334626315 org: to_ids:True tags:[]
rule APT29_SNOWYAMBER
{
meta:
description = "Detects APT29-linked SNOWYAMBER dropper"
strings:
// Payload decryption loop
// Custom algorithm based on XOR
$op_decrypt_payload = {49 8B 45 08 48 ?? ?? ?? 48 39 ?? 76 2B 48 89 C8 31 D2 4C 8B 4C 24 ?? 48 F7 74 24 ?? 49 8B 45
00 41 8A 14 11 32 54 08 10 89 C8 41 0F AF C0 31 C2 88 14 0B 48 FF C1}
// Decryption routine generated by Obfuscate library
$op_decrypt_string = {48 39 D0 74 19 48 89 C1 4D 89 C2 83 E1 07 48 C1 E1 03 49 D3 EA 45 30 14 01 48 FF C0 EB E2}
// Hardcoded inital value used as beaconing counter
$op_initialize_emoji = {C6 [3] A5 66 [4] F0 9F}
// src/json.hpp - string left in binary using nlohmann JSON
$str_nlohmann = {73 72 63 2F 6A 73 6F 6E 2E 68 70 70 00}
condition:
uint16(0) == 0x5A4D
and
filesize < 500KB
and
$str_nlohmann
and
$op_decrypt_string
and
($op_initialize_emoji or $op_decrypt_payload)
}

// MISP event:1281 uuid:3bbad14a-c57a-4778-8859-66a3e31088be org: to_ids:True tags:[]
rule APT29_HALFRIG_OBFUSCATION
{
meta:
description = "Detects obfuscation patterns used in HALFRIG. This rule wasn't tested against large dataset, it should be used for threat hunting and not on services like VTI."

strings:

// Decryption constants and decryption operation

$ = {48 BB 0B 91 09 19 4D FD 9B F3 }


$ = {4D 8D 40 01 48 8B CA 48 8B C2 48 C1 E9 38 48 83 C9 01 48 C1 E0 08 48 8B D1 48 33 D0}


$ = {C7 05 [3] 00 F7 91 4D 01 }

 condition:

uint16(0) == 0x5A4D

and

filesize < 500KB

and

all of them
}

// MISP event:1282 uuid:85308947-6c2f-4f91-ad0c-fa8c2657127d org: to_ids:True tags:[]
rule apt29_QUARTERRIG {
strings:
$str_dll_name = "hijacker.dll"
$str_import_name = "VCRUNTIME140.dll"
// 48 8B 15 39 6A 00 00
mov
rdx, cs:api_stuff.OpenThread
// 48 8D 0D FA 68 00 00
lea
rcx, api_stuff
// 8B D8
mov
ebx, eax
// E8 3F 25 00 00
call
load_api_addr
// 44 8B C3
mov
r8d, ebx
// 33 D2
xor
edx, edx
// B9 FF FF 1F 00
mov
ecx, 1FFFFFh
// FF D0
call
rax
$op_resolve_and_call_openthread = { 48 [6] 48 [6] 8B D8 E8 [4] [3] 33 D2 B9 FF FF 1F 00 FF D0 }
// E8 A0 25 00 00
call
load_api_addr
// 48 8B CB
mov
rcx, rbx
// FF D0
call
rax
// 83 F8 FF
cmp
eax, 0FFFFFFFFh
$op_resolve_and_call_suspendthread = { E8 [4] 48 8B CB FF D0 83 F8 FF }
condition:
all of them
}

// MISP event:1283 uuid:9521a1e1-903f-4a15-966c-d0999a2890e1 org: to_ids:True tags:[]
rule M_Hunting_3CXDesktopApp_Key {

  meta:

    disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

    description = "Detects a key found in a malicious 3CXDesktopApp file"

    md5 = "74bc2d0b6680faa1a5a76b27e5479cbc"

    date = "2023/03/29"

    version = "1"

  strings:

    $key = "3jB(2bsG#@c7" wide ascii

  condition:

    $key

}

// MISP event:1283 uuid:e7b39492-a458-4cb5-b385-29ec96f84f3e org: to_ids:True tags:[]
rule M_Hunting_3CXDesktopApp_Export {

  meta:

    disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

    description = "Detects an export used in 3CXDesktopApp malware"

    md5 = "7faea2b01796b80d180399040bb69835"

    date = "2023/03/31"

    version = "1"

  strings:

    $str1 = "DllGetClassObject" wide ascii

    $str2 = "3CXDesktopApp" wide ascii

  condition:

    all of ($str*)

}

// MISP event:1283 uuid:9ac291ed-fb3a-402b-81ff-097a5bc548c1 org: to_ids:True tags:[]
rule TAXHAUL
{
  meta:
  author = "Mandiant"
  created = "04/03/2023"
  modified = "04/03/2023"
  version = "1.0"
  strings:
    $p00_0 = {410f45fe4c8d3d[4]eb??4533f64c8d3d[4]eb??4533f64c8d3d[4]eb}
    $p00_1 = {4d3926488b01400f94c6ff90[4]41b9[4]eb??8bde4885c074}
  condition:
    uint16(0) == 0x5A4D and any of them
}

// MISP event:1283 uuid:482b3caa-594a-4c9e-b739-62c22f863b62 org: to_ids:True tags:[]
rule M_Hunting_MSI_Installer_3CX_1

{

meta:

author = "Mandiant"

md5 = "0eeb1c0133eb4d571178b2d9d14ce3e9, f3d4144860ca10ba60f7ef4d176cc736"

strings:

$ss1 = { 20 00 5F 64 33 64 63 6F 6D 70 69 6C 65 72 5F 34 37 2E 64 6C 6C 5F }

$ss2 = { 20 00 5F 33 43 58 44 65 73 6B 74 6F 70 41 70 70 2E }

$ss3 = { 20 00 5F 66 66 6D 70 65 67 2E 64 6C 6C 5F }

$ss4 = "3CX Ltd1" ascii

$sc1 = { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 }

$sc2 = "202303" ascii

condition:

(uint32(0) == 0xE011CFD0) and filesize > 90MB and filesize < 105MB and all of them

}

// MISP event:1283 uuid:047625c7-cd6d-49cc-b1c4-1d6036845705 org: to_ids:True tags:[]
rule M_Hunting_SigFlip_SigLoader_Native

{

meta:

author = "Mandiant"

disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

description = "Rule looks for strings present in SigLoader (Native)"

md5 = "a3ccc48db9eabfed7245ad6e3a5b203f"

strings:

$s1 = "[*]: Basic Loader..." ascii wide

$s2 = "[!]: Missing PE path or Encryption Key..." ascii wide

$s3 = "[!]: Usage: %s <PE_PATH> <Encryption_Key>" ascii wide

$s4 = "[*]: Loading/Parsing PE File '%s'" ascii wide

$s5 = "[!]: Could not read file %s" ascii wide

$s6 = "[!]: '%s' is not a valid PE file" ascii wide

$s7 = "[+]: Certificate Table RVA %x" ascii wide

$s8 = "[+]: Certificate Table Size %d" ascii wide

$s9 = "[*]: Tag Found 0x%x%x%x%x" ascii wide

$s10 = "[!]: Could not locate data/shellcode" ascii wide

$s11 = "[+]: Encrypted/Decrypted Data Size %d" ascii wide

condition:

filesize < 15MB and uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and 4 of ($s*)

}

// MISP event:1283 uuid:387a3373-5e01-467e-9a60-780fad94cbde org: to_ids:True tags:[]
rule M_Hunting_Raw64_DAVESHELL_Bootstrap

{

meta:

author = "Mandiant"

disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

description = "Rule looks for bootstrap shellcode (64 bit) present in DAVESHELL"

md5 = "8a34adda5b981498234be921f86dfb27"

strings:

$b6ba50888f08e4f39b43ef67da27521dcfc61f1e = { E8 00 00 00 00 59 49 89 C8 48 81 C1 ?? ?? ?? ?? BA ?? ?? ?? ?? 49 81 C0 ?? ?? ?? ?? 41 B9 ?? ?? ?? ?? 56 48 89 E6 48 83 E4 F0 48 83 EC 30 C7 44 24 20 ?? ?? ?? ?? E8 ?? 00 00 00 48 89 F4 5E C3 }

$e32abbe82e1f957fb058c3770375da3bf71a8cab = { E8 00 00 00 00 59 49 89 C8 BA ?? ?? ?? ?? 49 81 C0 ?? ?? ?? ?? 41 B9 ?? ?? ?? ?? 56 48 89 E6 48 83 E4 F0 48 83 EC 30 48 89 4C 24 28 48 81 C1 ?? ?? ?? ?? C7 44 24 20 ?? ?? ?? ?? E8 ?? 00 00 00 48 89 F4 5E C3 }

condition:

filesize < 15MB and any of them

}

// MISP event:1283 uuid:9364b556-cdcd-4a73-9dce-fe677eab0f40 org: to_ids:True tags:[]
rule M_Hunting_MSI_Installer_3CX_1

{

meta:

author = "Mandiant"

disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

description = "This rule looks for hardcoded values within the MSI installer observed in strings and signing certificate"

md5 = "0eeb1c0133eb4d571178b2d9d14ce3e9"

strings:

$ss1 = { 20 00 5F 64 33 64 63 6F 6D 70 69 6C 65 72 5F 34 37 2E 64 6C 6C 5F }

$ss2 = { 20 00 5F 33 43 58 44 65 73 6B 74 6F 70 41 70 70 2E }

$ss3 = { 20 00 5F 66 66 6D 70 65 67 2E 64 6C 6C 5F }

$ss4 = "3CX Ltd1" ascii

$sc1 = { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 }

$sc2 = "202303" ascii

condition:

(uint32(0) == 0xE011CFD0) and filesize > 90MB and filesize < 100MB and all of them

}

// MISP event:1283 uuid:3256e877-5056-4f7b-a5e4-a6a4714ff3b2 org: to_ids:True tags:[]
rule M_Hunting_VEILEDSIGNAL_1

{

meta:

author = "Mandiant"

disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

md5 = "404b09def6054a281b41d309d809a428, c6441c961dcad0fe127514a918eaabd4"

strings:

$rh1 = { 68 5D 7A D2 2C 3C 14 81 2C 3C 14 81 2C 3C 14 81 77 54 10 80 26 3C 14 81 77 54 17 80 29 3C 14 81 77 54 11 80 AB 3C 14 81 D4 4C 11 80 33 3C 14 81 D4 4C 10 80 22 3C 14 81 D4 4C 17 80 25 3C 14 81 77 54 15 80 27 3C 14 81 2C 3C 15 81 4B 3C 14 81 94 4D 1D 80 28 3C 14 81 94 4D 14 80 2D 3C 14 81 94 4D 16 80 2D 3C 14 81 }

$rh2 = { 00 E5 A0 2B 44 84 CE 78 44 84 CE 78 44 84 CE 78 1F EC CA 79 49 84 CE 78 1F EC CD 79 41 84 CE 78 1F EC CB 79 C8 84 CE 78 BC F4 CA 79 4A 84 CE 78 BC F4 CD 79 4D 84 CE 78 BC F4 CB 79 65 84 CE 78 1F EC CF 79 43 84 CE 78 44 84 CF 78 22 84 CE 78 FC F5 C7 79 42 84 CE 78 FC F5 CE 79 45 84 CE 78 FC F5 CC 79 45 84 CE 78}

$rh3 = { DA D2 21 22 9E B3 4F 71 9E B3 4F 71 9E B3 4F 71 C5 DB 4C 70 94 B3 4F 71 C5 DB 4A 70 15 B3 4F 71 C5 DB 4B 70 8C B3 4F 71 66 C3 4B 70 8C B3 4F 71 66 C3 4C 70 8F B3 4F 71 C5 DB 49 70 9F B3 4F 71 66 C3 4A 70 B0 B3 4F 71 C5 DB 4E 70 97 B3 4F 71 9E B3 4E 71 F9 B3 4F 71 26 C2 46 70 9F B3 4F 71 26 C2 B0 71 9F B3 4F 71 9E B3 D8 71 9F B3 4F 71 26 C2 4D 70 9F B3 4F 71 }

$rh4 = { CB 8A 35 66 8F EB 5B 35 8F EB 5B 35 8F EB 5B 35 D4 83 5F 34 85 EB 5B 35 D4 83 58 34 8A EB 5B 35 D4 83 5E 34 09 EB 5B 35 77 9B 5E 34 92 EB 5B 35 77 9B 5F 34 81 EB 5B 35 77 9B 58 34 86 EB 5B 35 D4 83 5A 34 8C EB 5B 35 8F EB 5A 35 D3 EB 5B 35 37 9A 52 34 8C EB 5B 35 37 9A 58 34 8E EB 5B 35 37 9A 5B 34 8E EB 5B 35 37 9A 59 34 8E EB 5B 35 }

condition:

uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and 1 of ($rh*)

}

// MISP event:1283 uuid:5f89c788-d148-4660-a1c3-5c403d30d481 org: to_ids:True tags:[]
rule M_Hunting_VEILEDSIGNAL_2

{

meta:

author = "Mandiant"

disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

md5 = "404b09def6054a281b41d309d809a428"

strings:

$sb1 = { C1 E0 05 4D 8? [2] 33 D0 45 69 C0 7D 50 BF 12 8B C2 41 FF C2 C1 E8 07 33 D0 8B C2 C1 E0 16 41 81 C0 87 D6 12 00 }

$si1 = "CryptBinaryToStringA" fullword

$si2 = "BCryptGenerateSymmetricKey" fullword

$si3 = "CreateThread" fullword

$ss1 = "ChainingModeGCM" wide

$ss2 = "__tutma" fullword

condition:

(uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them

}

// MISP event:1283 uuid:e634f810-56e6-4415-afc4-6aed3a1760ff org: to_ids:True tags:[]
rule M_Hunting_VEILEDSIGNAL_3

{

meta:

author = "Mandiant"

disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

md5 = "c6441c961dcad0fe127514a918eaabd4"

strings:

$ss1 = { 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6A 73 6F 6E 2C 20 74 65 78 74 2F 6A 61 76 61 73 63 72 69 70 74 2C 20 2A 2F 2A 3B 20 71 3D 30 2E 30 31 00 00 61 63 63 65 70 74 00 00 65 6E 2D 55 53 2C 65 6E 3B 71 3D 30 2E 39 00 00 61 63 63 65 70 74 2D 6C 61 6E 67 75 61 67 65 00 63 6F 6F 6B 69 65 00 00 }

$si1 = "HttpSendRequestW" fullword

$si2 = "CreateNamedPipeW" fullword

$si3 = "CreateThread" fullword

$se1 = "DllGetClassObject" fullword

condition:

(uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them

}

// MISP event:1283 uuid:e8443379-0e0e-4d81-9b6a-adca81cefdd5 org: to_ids:True tags:[]
rule M_Hunting_VEILEDSIGNAL_4

{

meta:

author = "Mandiant"

disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

md5 = "404b09def6054a281b41d309d809a428, c6441c961dcad0fe127514a918eaabd4"

strings:

$sb1 = { FF 15 FC 76 01 00 8B F0 85 C0 74 ?? 8D 50 01 [6-16] FF 15 [4] 48 8B D8 48 85 C0 74 ?? 89 ?? 24 28 44 8B CD 4C 8B C? 48 89 44 24 20 }

$sb2 = { 33 D2 33 C9 FF 15 [4] 4C 8B CB 4C 89 74 24 28 4C 8D 05 [2] FF FF 44 89 74 24 20 33 D2 33 C9 FF 15 }

$si1 = "CreateThread" fullword

$si2 = "MultiByteToWideChar" fullword

$si3 = "LocalAlloc" fullword

$se1 = "DllGetClassObject" fullword

condition:

(uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them

}

// MISP event:1283 uuid:e1a4f52e-3c35-4e46-b77e-617ead7108e0 org: to_ids:True tags:[]
rule M_Hunting_VEILEDSIGNAL_5

{

meta:

author = "Mandiant"

disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

md5 = "6727284586ecf528240be21bb6e97f88"

strings:

$sb1 = { 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D [3] 48 8B CB FF 15 [4] EB }

$ss1 = "chrome.exe" wide fullword

$ss2 = "firefox.exe" wide fullword

$ss3 = "msedge.exe" wide fullword

$ss4 = "\\\\.\\pipe\\*" ascii fullword

$ss5 = "FindFirstFileA" ascii fullword

$ss6 = "Process32FirstW" ascii fullword

$ss7 = "RtlAdjustPrivilege" ascii fullword

$ss8 = "GetCurrentProcess" ascii fullword

$ss9 = "NtWaitForSingleObject" ascii fullword

condition:

(uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them

}

// MISP event:1283 uuid:b93f1f3a-1ca5-4875-92f3-ef0e1e1b2762 org: to_ids:True tags:[]
rule M_Hunting_VEILEDSIGNAL_6

{

meta:

author = "Mandiant"

disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

md5 = "00a43d64f9b5187a1e1f922b99b09b77"

strings:

$ss1 = "C:\\Programdata\\" wide

$ss2 = "devobj.dll" wide fullword

$ss3 = "msvcr100.dll" wide fullword

$ss4 = "TpmVscMgrSvr.exe" wide fullword

$ss5 = "\\Microsoft\\Windows\\TPM" wide fullword

$ss6 = "CreateFileW" ascii fullword

condition:

(uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them

}

// MISP event:1283 uuid:09d0bd7d-fea4-4a22-bda5-df6fa77fcc10 org: to_ids:True tags:[]
rule M_Hunting_POOLRAT

{

meta:

author = "Mandiant"

disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

description = "Detects strings found in POOLRAT. "

md5 = "451c23709ecd5a8461ad060f6346930c"

strings:

$hex1 = { 6e 61 6d 65 3d 22 75 69 64 22 25 73 25 73 25 75 25 73 }

$hex_uni1 = { 6e 00 61 00 6d 00 65 00 3d 00 22 00 75 00 69 00 64 00 22 00 25 00 73 00 25 00 73 00 25 00 75 00 25 00 73 }

$hex2 = { 6e 61 6d 65 3d 22 73 65 73 73 69 6f 6e 22 25 73 25 73 25 75 25 73 }

$hex_uni2 = { 6e 00 61 00 6d 00 65 00 3d 00 22 00 73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 22 00 25 00 73 00 25 00 73 00 25 00 75 00 25 00 73 }

$hex3 = { 6e 61 6d 65 3d 22 61 63 74 69 6f 6e 22 25 73 25 73 25 73 25 73 }

$hex_uni3 = { 6e 00 61 00 6d 00 65 00 3d 00 22 00 61 00 63 00 74 00 69 00 6f 00 6e 00 22 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 }

$hex4 = { 6e 61 6d 65 3d 22 74 6f 6b 65 6e 22 25 73 25 73 25 75 25 73 }

$hex_uni4 = { 6e 00 61 00 6d 00 65 00 3d 00 22 00 74 00 6f 00 6b 00 65 00 6e 00 22 00 25 00 73 00 25 00 73 00 25 00 75 00 25 00 73 }

$str1 = "--N9dLfqxHNUUw8qaUPqggVTpX-" wide ascii nocase

condition:

any of ($hex*) or any of ($hex_uni*) or $str1

}

// MISP event:1283 uuid:94edac12-8a21-4b8a-83ab-3116f8ea12a4 org: to_ids:True tags:[]
rule M_Hunting_FASTREVERSEPROXY

{

      meta:

      author = "Mandiant"

      disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

      md5 = "19dbffec4e359a198daf4ffca1ab9165"

      strings:

      $ss1 = "Go build ID:" fullword

      $ss2 = "Go buildinf:" fullword

      $ss3 = "net/http/httputil.(*ReverseProxy)." ascii

      $ss4 = "github.com/fatedier/frp/client" ascii

      $ss5 = "\"server_port\"" ascii

      $ss6 = "github.com/armon/go-socks5.proxy" ascii

      condition:

      uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and all of them

}

// MISP event:1292 uuid:3e5f8fc0-da1f-47f0-8b6e-f4c4b033ce47 org: to_ids:True tags:[]
'namespace'='CISA_Consolidated.yara' rule_name=CISA_10452108_02 rule_content=rule CISA_10452108_02 : WHIRLPOOL backdoor communicates_with_c2 installs_other_components
{
	meta:
		Author = "CISA Code & Media Analysis"
		Incident = "10452108"
		Date = "2023-06-20"
		Last_Modified = "20230804_1730"
		Actor = "n/a"
		Family = "WHIRLPOOL"
		Capabilities = "communicates-with-c2 installs-other-components"
		Malware_Type = "backdoor"
		Tool_Type = "unknown"
		Description = "Detects malicious Linux WHIRLPOOL samples"
		SHA256_1 = "83ca636253fd1eb898b244855838e2281f257bbe8ead428b69528fc50b60ae9c"
		SHA256_2 = "8849a3273e0362c45b4928375d196714224ec22cb1d2df5d029bf57349860347"
	strings:
		$s0 = { 65 72 72 6f 72 20 2d 31 20 65 78 69 74 }
		$s1 = { 63 72 65 61 74 65 20 73 6f 63 6b 65 74 20 65 72 72 6f 72 3a 20 25 73 28 65 72 72 6f 72 3a 20 25 64 29 }
		$s2 = { c7 00 20 32 3e 26 66 c7 40 04 31 00 }
		$a3 = { 70 6c 61 69 6e 5f 63 6f 6e 6e 65 63 74 }
		$a4 = { 63 6f 6e 6e 65 63 74 20 65 72 72 6f 72 3a 20 25 73 28 65 72 72 6f 72 3a 20 25 64 29 }
		$a5 = { 73 73 6c 5f 63 6f 6e 6e 65 63 74 }
	condition:
		uint32(0) == 0x464c457f and 4 of them
}

// MISP event:1301 uuid:3bf820ba-bf26-4833-a4d7-e47ca110b839 org: to_ids:True tags:[]
rule MAL_WIPER_BiBi_Oct23 {
   meta:
      description = "Detects BiBi wiper samples for Windows and Linux"
      author = "Florian Roth"
      reference = "https://x.com/ESETresearch/status/1719437301900595444?s=20"
      date = "2023-11-01"
      hash1 = "23bae09b5699c2d5c4cb1b8aa908a3af898b00f88f06e021edcb16d7d558efad"
      hash2 = "40417e937cd244b2f928150cae6fa0eff5551fdb401ea072f6ecdda67a747e17"
   strings:
      $s1 = "send attempt while closed" ascii fullword
      $s2 = "[+] CPU cores: %d, Threads: %d" ascii fullword
      $s3 = "[+] Stats: %d | %d" ascii fullword

      $opw1 = { 33 c0 88 45 48 b8 01 00 00 00 86 45 48 45 8b f5 48 8d 3d de f5 ff ff 0f 57 c9 f3 0f 7f 4d b8 }
      $opw2 = { 2d ce b5 00 00 c5 fa e6 f5 e9 40 fe ff ff 0f 1f 44 00 00 75 2e c5 fb 10 0d 26 b4 00 00 44 8b 05 5f b6 00 00 e8 ca 0d 00 00 }

      $opl1 = { 4c 8d 44 24 08 48 89 f7 48 ff c2 48 83 c6 04 e8 c7 fb ff ff 41 89 c1 0f b6 42 ff 41 0f af c1 }
      $opl2 = { e8 6f fb ff ff 49 8d 78 f8 89 c0 48 01 c2 48 89 15 09 fb 24 00 e8 5a fb ff ff 49 8d 78 fc 6b f0 06 } 
   condition:
      ( uint16(0) == 0x5a4d or uint16(0) == 0x457f )
      and filesize < 4000KB
      and 2 of them
}

// MISP event:1306 uuid:5c12b30f-2ece-411a-a2b6-905006a34587 org: to_ids:True tags:[]
'namespace'='CISA_Consolidated.yara' rule_name=CISA_10478915_01 rule_content=rule CISA_10478915_01 : trojan installs_other_components
{
	meta:
		author = "CISA Code & Media Analysis"
		incident = "10478915"
		date = "2023-11-06"
		last_modified = "20231108_1500"
		actor = "n/a"
		family = "n/a"
		capabilities = "installs-other-components"
		malware_Type = "trojan"
		tool_type = "information-gathering"
		description = "Detects trojan .bat samples"
		sha256 = "98e79f95cf8de8ace88bf223421db5dce303b112152d66ffdf27ebdfcdf967e9"
	strings:
		$s1 = { 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c 7a 2e 74 78 74 }
		$s2 = { 72 65 67 20 73 61 76 65 20 68 6b 6c 6d 5c 73 79 73 74 65 6d 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c 65 6d }
		$s3 = { 6d 61 6b 65 63 61 62 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 61 2e 70 6e 67 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c 61 2e 63 61 62 }
	condition:
		all of them
}

// MISP event:1306 uuid:84aeb797-4299-4ef7-b7ae-57f916ee5721 org: to_ids:True tags:[]
'namespace'='CISA_Consolidated.yara' rule_name=CISA_10478915_02 rule_content=rule CISA_10478915_02 : trojan installs_other_components
{
	meta:
		author = "CISA Code & Media Analysis"
		incident = "10478915"
		date = "2023-11-06"
		last_modified = "20231108_1500"
		actor = "n/a"
		family = "n/a"
		capabilities = "installs-other-components"
		malware_type = "trojan"
		tool_type = "unknown"
		description = "Detects trojan PE32 samples"
		sha256 = "e557e1440e394537cca71ed3d61372106c3c70eb6ef9f07521768f23a0974068"
	strings:
		$s1 = { 57 72 69 74 65 46 69 6c 65 }
		$s2 = { 41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 }
		$s3 = { 6f 70 65 72 61 74 6f 72 20 63 6f 5f 61 77 61 69 74 }
		$s4 = { 43 6f 6d 70 6c 65 74 65 20 4f 62 6a 65 63 74 20 4c 6f 63 61 74 6f 72 }
		$s5 = { 64 65 6c 65 74 65 5b 5d }
		$s6 = { 4e 41 4e 28 49 4e 44 29 }
	condition:
		uint16(0) == 0x5a4d and pe.imphash() == "6e8ca501c45a9b85fff2378cffaa24b2" and pe.size_of_code == 84480 and all of them
}

// MISP event:1306 uuid:f6384914-d773-4d7e-b9ed-e1838371c145 org: to_ids:True tags:[]
'namespace'='CISA_Consolidated.yara' rule_name=CISA_10478915_03 rule_content=rule CISA_10478915_03 : trojan steals_authentication_credentials credential_exploitation
{
	meta:
		author = "CISA Code & Media Analysis"
		incident = "10478915"
		date = "2023-11-06"
		last_modified = "20231108_1500"
		actor = "n/a"
		family = "n/a"
		capabilities = "steals-authentication-credentials"
		malware_type = "trojan"
		tool_type = "credential-exploitation"
		description = "Detects trojan DLL samples"
		sha256 = "17a27b1759f10d1f6f1f51a11c0efea550e2075c2c394259af4d3f855bbcc994"
	strings:
		$s1 = { 64 65 6c 65 74 65 }
		$s2 = { 3c 2f 74 72 75 73 74 49 6e 66 6f 3e }
		$s3 = { 42 61 73 65 20 43 6c 61 73 73 20 44 65 73 63 72 69 70 74 6f 72 20 61 74 20 28 }
		$s4 = { 49 6e 69 74 69 61 6c 69 7a 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e 45 78 }
		$s5 = { 46 69 6e 64 46 69 72 73 74 46 69 6c 65 45 78 57 }
		$s6 = { 47 65 74 54 69 63 6b 43 6f 75 6e 74 }
	condition:
		uint16(0) == 0x5a4d and pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI and pe.size_of_code == 56832 and all of them
}

// MISP event:1306 uuid:e9f069da-febc-449d-b923-22793ec3f067 org: to_ids:True tags:[]
'namespace'='CISA_Consolidated.yara' rule_name=CISA_10478915_04 rule_content=rule CISA_10478915_04 : backdoor communicates_with_c2 remote_access
{
	meta:
		author = "CISA Code & Media Analysis"
		incident = "10478915"
		date = "2023-11-06"
		last_modified = "20231108_1500"
		actor = "n/a"
		family = "n/a"
		capabilities = "communicates-with-c2"
		malware_type = "backdoor"
		tool_type = "remote-access"
		description = "Detects trojan python samples"
		sha256 = "906602ea3c887af67bcb4531bbbb459d7c24a2efcb866bcb1e3b028a51f12ae6"
	strings:
		$s1 = { 70 6f 72 74 20 3d 20 34 34 33 20 69 66 20 22 68 74 74 70 73 22 } 
		$s2 = { 6b 77 61 72 67 73 2e 67 65 74 28 22 68 61 73 68 70 61 73 73 77 64 22 29 3a }
		$s3 = { 77 69 6e 72 6d 2e 53 65 73 73 69 6f 6e 20 62 61 73 69 63 20 65 72 72 6f 72 }
		$s4 = { 57 69 6e 64 77 6f 73 63 6d 64 2e 72 75 6e 5f 63 6d 64 28 73 74 72 28 63 6d 64 29 29 }
	condition:
		all of them
}

// MISP event:1310 uuid:4b571dc9-f9cc-4bcb-b65a-e17ab890cd1a org: to_ids:True tags:[]
rule hacktool_py_pysoxy
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-01-09"
        description = "SOCKS5 proxy tool used to relay connections."
        hash1 = "e192932d834292478c9b1032543c53edfc2b252fdf7e27e4c438f4b249544eeb"
        os = "all"
        os_arch = "all"
        reference = "https://github.com/MisterDaneel/pysoxy/blob/master/pysoxy.py"
        report = "TIB-20240109"
        scan_context = "file,memory"
        last_modified = "2024-01-09T13:45Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10065
        version = 3

    strings:
        $s1 = "proxy_loop" ascii
        $s2 = "connect_to_dst" ascii
        $s3 = "request_client" ascii
        $s4 = "subnegotiation_client" ascii
        $s5 = "bind_port" ascii

    condition:
        all of them
}

// MISP event:1310 uuid:a4afb9f4-d67b-46b9-80ce-a77892532bd5 org: to_ids:True tags:[]
rule webshell_aspx_regeorg
{
    meta:
        author = "threatintel@volexity.com"
        date = "2018-08-29"
        description = "Detects the reGeorg webshell based on common strings in the webshell. May also detect other webshells which borrow code from ReGeorg."
        hash = "9d901f1a494ffa98d967ee6ee30a46402c12a807ce425d5f51252eb69941d988"
        os = "win"
        os_arch = "all"
        reference = "https://github.com/L-codes/Neo-reGeorg/blob/master/templates/tunnel.aspx"
        report = "TIB-20231215"
        scan_context = "file,memory"
        last_modified = "2024-01-09T10:04Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 410
        version = 7

    strings:
        $a1 = "every office needs a tool like Georg" ascii
        $a2 = "cmd = Request.QueryString.Get(\"cmd\")" ascii
        $a3 = "exKak.Message" ascii

        $proxy1 = "if (rkey != \"Content-Length\" && rkey != \"Transfer-Encoding\")"

        $proxy_b1 = "StreamReader repBody = new StreamReader(response.GetResponseStream(), Encoding.GetEncoding(\"UTF-8\"));" ascii
        $proxy_b2 = "string rbody = repBody.ReadToEnd();" ascii
        $proxy_b3 = "Response.AddHeader(\"Content-Length\", rbody.Length.ToString());" ascii

    condition:
        any of ($a*) or
        $proxy1 or
        all of ($proxy_b*)
}

// MISP event:1310 uuid:33ae6f26-d8eb-4d52-9fa0-1b673a68e7a2 org: to_ids:True tags:[]
rule apt_webshell_aspx_glasstoken: UTA0178
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-12-12"
        description = "Detection for a custom webshell seen on external facing server. The webshell contains two functions, the first is to act as a Tunnel, using code borrowed from reGeorg, the second is custom code to execute arbitrary .NET code."
        hash1 = "26cbb54b1feb75fe008e36285334d747428f80aacdb57badf294e597f3e9430d"
        os = "win"
        os_arch = "all"
        report = "TIB-20231215"
        scan_context = "file,memory"
        last_modified = "2024-01-09T10:08Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9994
        version = 5

    strings:
        $s1 = "=Convert.FromBase64String(System.Text.Encoding.Default.GetString(" ascii
        $re = /Assembly\.Load\(errors\)\.CreateInstance\("[a-z0-9A-Z]{4,12}"\).GetHashCode\(\);/

    condition:
        for any i in (0..#s1):
            (
                $re in (@s1[i]..@s1[i]+512)
            )
}

// MISP event:1310 uuid:d122a589-41d1-4181-8f31-2cffc3186a0b org: to_ids:True tags:[]
rule apt_webshell_pl_complyshell: UTA0178
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-12-13"
        description = "Detection for the COMPLYSHELL webshell."
        hash1 = "8bc8f4da98ee05c9d403d2cb76097818de0b524d90bea8ed846615e42cb031d2"
        os = "linux"
        os_arch = "all"
        report = "TIB-20231215"
        scan_context = "file,memory"
        last_modified = "2024-01-09T10:05Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9995
        version = 4

    strings:
        $s = "eval{my $c=Crypt::RC4->new("

    condition:
        $s
}

// MISP event:1312 uuid:25579d73-a3f6-44c7-8bc2-0b3478c3b2be org: to_ids:True tags:[]
// KrustyLoader.yar
// Copyright (C) 2024 - Synacktiv, Théo Letailleur
// contact@synacktiv.com
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

rule Linux_Downloader_KrustyLoader
{
    meta:
        author = "Theo Letailleur, Synacktiv"
        source = "Synacktiv"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        category = "MALWARE"
        malware = "KrustyLoader"
        description = "Yara rule that detects Linux KrustyLoader"

    strings:
        $tokio_worker = "TOKIO_WORKER_THREADS"
        $tmpdir = "/tmp/"

        // Load "/proc/self/exe" string
        $proc_self_exe = {
            48 B? 73 65 6C 66 2F 65 78 65 // mov     r64, 6578652F666C6573h
            48 8D B4 24 ?? ?? 00 00       // lea     rsi, [rsp+????h]
            48 89 46 0?                   // mov     [rsi+6], r64
            48 B? 2F 70 72 6F 63 2F 73 65 // mov     r64, 65732F636F72702Fh
            48 89 0?                      // mov     [rsi], r64
        }

        $pipe_suffix = "|||||||||||||||||||||||||||"

        // AES key expansion
        $aeskeygenassist = {
            660F3ADF0601 // aeskeygenassist xmm0, xmmword ptr [rsi], 1
            660F7F07     // movdqa  xmmword ptr [rdi], xmm0
            C3           // retn
        }

        // AES InvMixColumns
        $aesinvmixcol = {
            660F38DB06  // aesimc  xmm0, xmmword ptr [rsi]
            660F7F07    // movdqa  xmmword ptr [rdi], xmm0
            C3          // retn
        }

    condition:
        uint32(0) == 0x464C457F and
        (
            all of them
        )
}

// MISP event:1313 uuid:6ba74c86-3769-4781-85cc-b59a7f8069e9 org: to_ids:True tags:[]
rule M_Hunting_Webshell_BUSHWALK_1 {

  meta:

    author = "Mandiant"

    description = "This rule detects BUSHWALK, a webshell written in Perl CGI that is embedded into a legitimate Pulse Secure file to enable file transfers"

 

  strings:

    $s1 = "SafariiOS" ascii

    $s2 = "command" ascii

    $s3 = "change" ascii

    $s4 = "update" ascii

    $s5 = "$data = RC4($key, $data);" ascii

  condition:

    filesize < 5KB

    and all of them

}

// MISP event:1313 uuid:cdeb7e25-9627-4f9f-b052-33a963e0c60b org: to_ids:True tags:[]
rule M_Hunting_Webshell_CHAINLINE_1 {

  meta:

    author = "Mandiant"

    description = "This rule detects the CHAINLINE webshell, which receives 
RC4 encrypted commands and returns the execution result"

    md5 = "3045f5b3d355a9ab26ab6f44cc831a83"

  strings:

    $s1 = "crypt(command: str)" ascii

    $s2 = "tmp[i] = chr(ord(tmp[i])" ascii

    $s3 = "ord(RC4_KEY[i % len(RC4_KEY)])" ascii

    $s4 = "class Health(Resource)" ascii

    $s5 = "crypt(base64.b64decode(command.encode(" ascii

    $s6 = "base64.b64encode(crypt(result)" ascii

    $s7 = "{\"message\": 'ok', \"stats\": result}" ascii

  condition:

    filesize < 100KB and

    any of them

}

// MISP event:1313 uuid:3914badc-3425-46ae-a4a8-542b1cf9ca6b org: to_ids:True tags:[]
rule M_HUNTING_APT_Webshell_FRAMESTING_result

{

    meta:

        author = "Mandiant"

        description = "Detects strings associated with FRAMESTING webshell"

        md5 = "465600cece80861497e8c1c86a07a23e"

    strings:

        $s1 = "exec(zlib.decompress(aes.decrypt(base64.b64decode(data))),{'request':request,'cache'"

        $s2 = "result={'message':'','action':0}"

 

    condition:

        any of them

}

// MISP event:1313 uuid:ae0c740d-b365-4bd4-bac9-4e13b25a7d4a org: to_ids:True tags:[]
rule M_Hunting_Webshell_LIGHTWIRE_4 {

  meta:

    author = "Mandiant"

    description = "Detects LIGHTWIRE based on the RC4 
decoding and execution 1-liner."

    md5 = "3d97f55a03ceb4f71671aa2ecf5b24e9"

  strings:

    $re1 = /eval\{my.{1,20}Crypt::RC4->new\(\".{1,50}->RC4\(decode_base64\(CGI::param\(\'.{1,30};eval\s\$.{1,30}\"Compatibility\scheck:\s\$@\";\}/

  condition:

    filesize < 1MB and all of them

}

// MISP event:1313 uuid:4144ca75-4269-409c-8e6c-084d33bf1d65 org: to_ids:True tags:[]
rule M_Hunting_CredTheft_WARPWIRE_strings

{

    meta:

        author = "Mandiant"

        description = "Detects strings within WARPWIRE credential harvester"

        md5 = "b15f47e234b5d26fb2cc81fc6fd89775"

    strings:

        $header = "function SetLastRealm(sValue) {"

 

        // password fields

        $username = "document.frmLogin.username.value;"

        $password = "document.frmLogin.password.value;"

 

        // post version

        $btoa = "btoa("

        $xhr_post = /xhr.open\(.POST.,( )?url,/

 

        // get version

        $xhr_get = /xhr.open\(.GET.,( )?url,/

        $xhr_send = "xhr.send(null);"

 

    condition:

        $header in (0..100) 

        and $password in (@username[1]..@username[1]+100)

        and ((#btoa > 1 and $xhr_post) or ($xhr_send in (@xhr_get[1]..@xhr_get[1]+50)))

}

// MISP event:1317 uuid:dd965a0a-5f6e-4e04-a47e-418f6034e312 org: to_ids:True tags:[]
rule Phobos_CrypterBinary {
   meta:
      description = "Phobos Ransomware Crypter Binary"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-12"
      hash1 = "396a2f2dd09c936e93d250e8467ac7a9c0a923ea7f9a395e63c375b877a399a6"
   strings:
      $s1 = "\\.#* 0_" fullword ascii
      $s2 = "9F:b:{:" fullword ascii 
      $s3 = "D$(Y_^[" fullword ascii 
      $s4 = "tEWVVVV" fullword ascii
      $s5 = "YSVWj(j" fullword ascii
      $s6 = "^yMQb O8y" fullword ascii
      $s7 = "tjWWVhKE@" fullword ascii
      $s8 = "D$LPVVVWVVV" fullword ascii
      $s9 = "D$PPSj" fullword ascii 
      $s10 = "YY9\\$0t" fullword ascii 
      $s11 = "8$8/8|8" fullword ascii 
      $s12 = "SVWj23" fullword ascii 
      $s13 = "\\\\?\\X:" fullword wide
      $s14 = "\\\\?\\ :" fullword wide
      $s15 = "\\\\?\\UNC\\\\\\e-" fullword wide
      $s16 = "D$HY_^[" fullword ascii
      $s17 = "L{gYm+" fullword ascii
      $s18 = "2*262H2Q2^2j2" fullword ascii
      $s19 = "9\\$Pt." fullword ascii
      $s20 = "Y9\\$4t&9\\$Xt " fullword ascii

      $op0 = { 53 e8 34 7d 00 00 59 89 45 dc 8d 45 cc 50 68 06 }
      $op1 = { 39 5c 24 34 74 0a 39 5c 24 44 0f 84 af }
      $op2 = { 6a 18 c7 46 34 00 00 01 00 c7 46 30 00 00 10 00 }

      $ap0 = "MPR.dll" fullword ascii
      $ap1 = "WS2_32.dll" fullword ascii
      $ap2 = "WINHTTP.dll" fullword ascii
      $ap3 = "KERNEL32.dll" fullword ascii
      $ap4 = "USER32.dll" fullword ascii
      $ap5 = "ADVAPI32.dll" fullword ascii
      $ap6 = "SHELL32.dll" fullword ascii
      $ap7 = "ole32.dll" fullword ascii
      $ap8 = "GetTickCount" fullword ascii
      $ap9 = "GetIpAddrTable" fullword ascii

   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( 8 of them and all of ($op*) and all of ($ap*) )
}

// MISP event:1317 uuid:f9b4199b-2632-4b9a-a5e3-0f5351bcdc53 org: to_ids:True tags:[]
rule Phobos_kprocesshacker {
   meta:
      description = "Phobos kprocesshacker.sys"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-14"
      hash1 = "70211a3f90376bbc61f49c22a63075d1d4ddd53f0aefa976216c46e6ba39a9f4"
   strings:
      $x1 = "d:\\projects\\processhacker2\\kprocesshacker\\bin\\amd64\\kprocesshacker.pdb" fullword ascii
      $x2 = "kprocesshacker.sys" fullword wide
      $s3 = ":http://crl3.digicert.com/DigiCertHighAssuranceEVRootCA.crl0O" fullword ascii
      $s4 = ":http://crl4.digicert.com/DigiCertHighAssuranceEVRootCA.crl0@" fullword ascii
      $s5 = "\\Device\\KProcessHacker3" fullword wide
      $s6 = "KProcessHacker" fullword wide
      $s7 = "www.digicert.com1503" fullword ascii
      $s8 = "http://ocsp.digicert.com0R" fullword ascii
      $s9 = "Fhttp://cacerts.digicert.com/DigiCertSHA2HighAssuranceCodeSigningCA.crt0" fullword ascii
      $s10 = "*http://crl3.digicert.com/sha2-ha-cs-g1.crl00" fullword ascii
      $s11 = "*http://crl4.digicert.com/sha2-ha-cs-g1.crl0L" fullword ascii
      $s12 = "DynamicConfiguration" fullword wide
      $s13 = "Sydney1" fullword ascii
      $s14 = "\\CDvQbX/0" fullword ascii
      $s15 = " Microsoft Code Verification Root0" fullword ascii
      $s16 = "SHA256" fullword wide /* Goodware String - occured 507 times */
      $s17 = "New South Wales1" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "CIQh't%" fullword ascii
      $s19 = "DigiCert, Inc.1*0(" fullword ascii
      $s20 = "Licensed under the GNU GPL, v3." fullword wide

      $op0 = { 8c 99 00 00 58 20 00 00 c0 90 }

      $ap0 = "PsGetCurrentProcessId" fullword ascii
      $ap1 = "SePrivilegeCheck" fullword ascii
      $ap2 = "PsInitialSystemProcess" fullword ascii
      $ap3 = "ZwQuerySystemInformation" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) and all of ($ap*))
}

// MISP event:1317 uuid:a888b9bc-f30d-4d28-bd07-92b3f85d6f4b org: to_ids:True tags:[]
rule Phobos_mimikatz_drv {
   meta:
      description = "mimidrv.sys"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "d43520128871c83b904f3136542ea46644ac81a62d51ae9d3c3a3f32405aad96"
   strings:
      $s1 = "powershell.exe" fullword ascii
      $s2 = "$http://blog.gentilkiwi.com/mimikatz 0" fullword ascii
      $s3 = "mimikatz.exe" fullword ascii
      $s4 = "c:\\security\\mimikatz\\mimidrv\\objfre_wnet_amd64\\amd64\\mimidrv.pdb" fullword ascii
      $s5 = "mimidrv.sys" fullword wide
      $s6 = "!http://ocsp.globalsign.com/rootr103" fullword ascii
      $s7 = "\"http://crl.globalsign.com/root.crl0c" fullword ascii
      $s8 = " ! ZwSetInformationProcess 0x%08x for %u/%-14S" fullword wide
      $s9 = "MmProbeAndLockProcessPages" fullword wide
      $s10 = "PsSetCreateProcessNotifyRoutine" fullword wide
      $s11 = "PostOperation : " fullword wide
      $s12 = "KeServiceDescriptorTable : 0x%p (%u)" fullword wide
      $s13 = "Raw command (not implemented yet) : %s" fullword wide
      $s14 = "* Callback [type %u] - Handle 0x%p (@ 0x%p)" fullword wide
      $s15 = "SeRegisterLogonSessionTerminatedRoutineEx" fullword wide
      $s16 = "RtlGetSystemBootStatus" fullword wide
      $s17 = "Copyright (c) 2007 - 2020 gentilkiwi (Benjamin DELPY)" fullword wide
      $s18 = "*mimikatz driver 2.2." fullword wide
      $s19 = "\\DosDevices\\mimidrv" fullword wide
      $s20 = "ObReferenceSecurityDescriptor" fullword wide

      $op0 = { f8 b4 00 00 30 50 00 00 c0 b0 }
      $op1 = { 61 01 49 6f 44 65 6c 65 74 65 53 79 6d 62 6f 6c }
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:0c319653-d93c-4a1c-a74f-86aa928b06e9 org: to_ids:True tags:[]
rule Phobos_mimikatz_drv_32 {
   meta:
      description = "mimidrv_32.sys"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "d032001eab6cad4fbef19aab418650ded00152143bd14507e17d62748297c23f"
   strings:
      $s1 = "powershell.exe" fullword ascii
      $s2 = "$http://blog.gentilkiwi.com/mimikatz 0" fullword ascii
      $s3 = "mimikatz.exe" fullword ascii
      $s4 = "c:\\security\\mimikatz\\mimidrv\\objfre_wnet_x86\\i386\\mimidrv.pdb" fullword ascii
      $s5 = "mimidrv.sys" fullword wide
      $s6 = "PsCreateSystemProcess" fullword wide
      $s7 = "!http://ocsp.globalsign.com/rootr103" fullword ascii
      $s8 = "\"http://crl.globalsign.com/root.crl0c" fullword ascii
      $s9 = " ! ZwSetInformationProcess 0x%08x for %u/%-14S" fullword wide
      $s10 = "PsSetCreateProcessNotifyRoutine" fullword wide
      $s11 = "PsGetThreadSessionId" fullword wide
      $s12 = "NtSetInformationProcess" fullword wide
      $s13 = "PostOperation : " fullword wide
      $s14 = "KeServiceDescriptorTable : 0x%p (%u)" fullword wide
      $s15 = "Raw command (not implemented yet) : %s" fullword wide
      $s16 = "* Callback [type %u] - Handle 0x%p (@ 0x%p)" fullword wide
      $s17 = "Copyright (c) 2007 - 2020 gentilkiwi (Benjamin DELPY)" fullword wide
      $s18 = "*mimikatz driver 2.2." fullword wide
      $s19 = "\\DosDevices\\mimidrv" fullword wide
      $s20 = "CREATE_NAMED_PIPE" fullword wide

      $op0 = { a1 88 64 01 00 b9 4e e6 40 bb 85 c0 74 04 3b c1 }
      $op1 = { 3c 84 00 00 18 40 00 00 8c 80 }
      $op2 = { 96 84 00 00 7e 84 00 00 62 84 00 00 4a 84 00 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:f656eac6-facf-4872-b561-defcf9b3cc04 org: to_ids:True tags:[]
rule Phobos_BulletsPassView64 {
   meta:
      description = "BulletsPassView64.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "e71cda5e7c018f18aefcdfbce171cfeee7b8d556e5036d8b8f0864efc5f2156b"
   strings:
      $s1 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"am" ascii
      $s2 = "BulletsPassView.exe" fullword wide
      $s3 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword wide
      $s4 = "c:\\Projects\\VS2005\\BulletsPassView\\x64\\Release\\BulletsPassView.pdb" fullword ascii
      $s5 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"am" ascii
      $s6 = "Process Description" fullword wide
      $s7 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword wide
      $s8 = "Process Path" fullword wide
      $s9 = "ScanIEPasswords" fullword wide
      $s10 = "ScanWindowsPasswords" fullword wide
      $s11 = "Scan Internet Explorer Passwords" fullword wide
      $s12 = "Scan Standard Password Text-Boxes" fullword wide
      $s13 = "AddExportHeaderLine" fullword wide
      $s14 = "<html><head>%s<title>%s</title></head>" fullword wide
      $s15 = "UnmaskPasswordBox" fullword wide
      $s16 = "BeepOnNewPassword" fullword wide
      $s17 = "&Clear Passwords List" fullword wide
      $s18 = "Copy Selected &Password" fullword wide
      $s19 = "&Unmask Password Text Box" fullword wide
      $s20 = "Beep On New Password" fullword wide

      $op0 = { 48 8b 08 66 44 89 34 91 66 85 ff 0f 85 f9 01 00 }
      $op1 = { 48 c7 c6 ff ff ff ff 89 0d 06 04 01 00 c7 05 00 }
      $op2 = { 48 8b d8 74 34 48 83 25 e6 fb }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:d6fe7b68-9633-4c7b-93ca-bbda36f4a54e org: to_ids:True tags:[]
rule Phobos_SniffPass64 {
   meta:
      description = "SniffPass64.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620"
   strings:
      $x1 = "Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"amd64\" publicKeyToken=\"6595b641" ascii
      $x2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
      $s3 = "c:\\Projects\\VS2005\\SniffPass\\x64\\Release\\SniffPass.pdb" fullword ascii
      $s4 = "npptools.dll" fullword ascii
      $s5 = "NmApi.dll" fullword ascii
      $s6 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword ascii
      $s7 = "nmwifi.exe" fullword ascii
      $s8 = "Pwpcap.dll" fullword ascii
      $s9 = "Sniffed PasswordsCFailed to start capturing packets from the current network adapter.9Do you want to stop the capture and exit f" wide
      $s10 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword ascii
      $s11 = "login " fullword ascii
      $s12 = "AddExportHeaderLine" fullword ascii
      $s13 = "NirSoft SniffPass" fullword ascii
      $s14 = "NmGetFrame" fullword ascii
      $s15 = "NmGetRawFrame" fullword ascii
      $s16 = "NmGetFrameCount" fullword ascii
      $s17 = "NmGetRawFrameLength" fullword ascii
      $s18 = "Software\\NirSoft\\SniffPass" fullword ascii
      $s19 = "BeepOnNewPassword" fullword ascii
      $s20 = "<html><head>%s<title>%s</title></head>" fullword ascii

      $op0 = { 48 8b 08 66 44 89 34 91 66 85 ff 0f 85 f9 01 00 }
      $op1 = { 48 8d 4c 24 20 41 83 c8 ff c7 44 24 34 00 01 00 }
      $op2 = { 48 8d 91 24 01 00 00 4c 8d 0d 34 00 01 00 45 33 }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:853228a8-74b2-428e-9523-8d7fa48cb033 org: to_ids:True tags:[]
rule Phobos_mimikatz {
   meta:
      description = "mimik.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc"
   strings:
      $x1 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide
      $x2 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx user (%s)" fullword wide
      $x3 = "ERROR kuhl_m_lsadump_update_dc_password ; A /target argument is needed" fullword wide
      $x4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" fullword wide
      $x5 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" fullword wide
      $x6 = "ERROR kuhl_m_lsadump_lsa ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide
      $x7 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" fullword wide
      $x8 = "ERROR kuhl_m_lsadump_trust ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide
      $x9 = "ERROR kuhl_m_lsadump_dcsync ; kull_m_rpc_drsr_ProcessGetNCChangesReply" fullword wide
      $x10 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
      $x11 = "ERROR kuhl_m_kernel_processProtect ; Argument /process:program.exe or /pid:processid needed" fullword wide
      $x12 = "ERROR kuhl_m_lsadump_netsync ; I_NetServerTrustPasswordsGet (0x%08x)" fullword wide
      $x13 = "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; Checksums don't match (C:0x%08x - R:0x%08x)" fullword wide
      $x14 = "ERROR kuhl_m_lsadump_sam ; kull_m_registry_RegOpenKeyEx (SAM) (0x%08x)" fullword wide
      $x15 = "ERROR kuhl_m_lsadump_getHash ; Unknow SAM_HASH revision (%hu)" fullword wide
      $x16 = "ERROR kuhl_m_lsadump_changentlm ; Argument /oldpassword: or /oldntlm: is needed" fullword wide
      $x17 = "ERROR kuhl_m_lsadump_enumdomains_users ; /user or /rid is needed" fullword wide
      $x18 = "ERROR kuhl_m_lsadump_zerologon ; Missing /account argument, usually a DC$ account" fullword wide
      $x19 = "ERROR kuhl_m_lsadump_update_dc_password ; A /account argument is needed" fullword wide
      $x20 = "livessp.dll" fullword wide /* reversed goodware string 'lld.pssevil' */

      $op0 = { 45 3b c8 72 34 4c 8d 4c 24 30 48 8b d7 4c 89 7c }
      $op1 = { e8 1b 18 0c 00 8b 4b 30 4c 8d 5f 34 4c 89 5b 34 }
      $op2 = { 48 89 44 24 28 4c 89 64 24 20 ff 15 34 6b 0c 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      ( 1 of ($x*) and all of ($op*) )
}

// MISP event:1317 uuid:33092846-bf41-463f-9645-b5e773053f46 org: to_ids:True tags:[]
rule Phobos_mimikatzlib {
   meta:
      description = "mimilib.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "59756c8f4c760f1b29311a5732cb3fdd41d4b5bc9c88cd77c560e27b6e59780c"
   strings:
      $x1 = "0: kd> !process 0 0 lsass.exe" fullword ascii
      $s2 = "$http://blog.gentilkiwi.com/mimikatz 0" fullword ascii
      $s3 = "0: kd> .process /r /p <EPROCESS address>" fullword ascii
      $s4 = "mimilib.dll" fullword wide
      $s5 = "# Search for LSASS process" fullword ascii
      $s6 = " '## v ##'   https://blog.gentilkiwi.com/mimikatz             (oe.eo)" fullword ascii
      $s7 = "%p - lsasrv!LogonSessionList" fullword ascii
      $s8 = "%p - lsasrv!LogonSessionListCount" fullword ascii
      $s9 = "kiwidns.log" fullword wide
      $s10 = "kiwifilter.log" fullword wide
      $s11 = "kiwinp.log" fullword wide
      $s12 = "kiwissp.log" fullword wide
      $s13 = "kiwisub.log" fullword wide
      $s14 = "masterkey" fullword ascii
      $s15 = " * Password : " fullword ascii
      $s16 = "%p - lsasrv!h3DesKey" fullword ascii
      $s17 = "Unknown version in Kerberos credentials structure" fullword ascii
      $s18 = "lsasrv!g_fSystemCredsInitialized" fullword ascii
      $s19 = "dpapisrv!g_fSystemCredsInitialized" fullword ascii
      $s20 = "%p - lsasrv!hAesKey" fullword ascii

      $op0 = { b8 79 ff ff ff 3b c8 7f 5e 74 54 81 f9 6b ff ff }
      $op1 = { 4c 3b f3 48 8d 3d 34 5c 00 00 48 8d 05 b5 3f 00 }
      $op2 = { 8b 4d 28 e8 a0 fc ff ff 89 45 34 eb 07 c7 45 34 }
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:f0754bdf-4e56-400a-98d1-d9eec76b7d02 org: to_ids:True tags:[]
rule Phobos_WirelessKeyView64 {
   meta:
      description = "WirelessKeyView64.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "48b77c1efbc3197128391a35d0e1ed0b5cc3a05b96dd12c98ac73ffc6a886fc8"
   strings:
      $x1 = "Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"amd64\" publicKeyToken=\"6595b641" ascii
      $x2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
      $x3 = "Windows Protect folder for getting the encryption keys, For example: G:\\windows\\system32\\Microsoft\\Protect" fullword wide
      $s4 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword ascii
      $s5 = "Windows Registry hives folder, for example: k:\\windows\\system32\\config" fullword wide
      $s6 = "SYSTEM\\%s\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection" fullword ascii
      $s7 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword ascii
      $s8 = "system32\\config\\Software" fullword ascii
      $s9 = "system32\\config" fullword ascii
      $s10 = "Load the wireless keys of the current logged-on user" fullword wide
      $s11 = "/Running WirelessKeyView as SYSTEM user (Faster)%Directly decrypting the wireless keys" fullword wide
      $s12 = "SYSTEM\\%s\\Enum\\%s" fullword ascii
      $s13 = "AddExportHeaderLine" fullword ascii
      $s14 = "<html><head>%s<title>%s</title></head>" fullword ascii
      $s15 = "/GetKeys" fullword ascii
      $s16 = "<tr><td%s nowrap><b>%s</b><td bgcolor=#%s%s>%s" fullword ascii
      $s17 = "report.html" fullword ascii
      $s18 = " Type Descriptor'" fullword ascii
      $s19 = "Load wireless keys from remote system (Windows Vista or later, requires full admin rights)" fullword wide
      $s20 = "Windows Directory: (For example: K:\\Windows  )" fullword wide

      $op0 = { 48 8b 08 66 44 89 34 91 66 85 ff 0f 85 f9 01 00 }
      $op1 = { 48 8d 4c 24 20 41 83 c8 ff c7 44 24 34 00 01 00 }
      $op2 = { 49 89 83 28 ff ff ff 49 89 83 30 ff ff ff c7 84 }
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:c3b0dd13-d9a1-4256-966c-6dde9e3d1a19 org: to_ids:True tags:[]
rule Phobos_netpass64 {
   meta:
      description = "netpass64.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "6a87226ed5cca8e072507d6c24289c57757dd96177f329a00b00e40427a1d473"
   strings:
      $x1 = "Windows Protect folder for getting the encryption keys, For example: F:\\Users\\Nir\\AppData\\Roaming\\Microsoft\\Protect" fullword wide
      $x2 = "Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"amd64\" publicKeyToken=\"6595b641" ascii
      $x3 = "Windows Credentials folder: (For exmaple: C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Credentials )" fullword wide
      $x4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
      $s5 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword ascii
      $s6 = "c:\\Projects\\VS2005\\netpass\\x64\\Release\\netpass.pdb" fullword ascii
      $s7 = "User Profile Folder: (For example: K:\\users\\admin )" fullword wide
      $s8 = "Bad file structure !UFailed to decrypt the key file. It's possible that the supplied password is incorrect" fullword wide
      $s9 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword ascii
      $s10 = "Failed to load the executable file !" fullword ascii
      $s11 = "Export Raw Passwords Data" fullword wide
      $s12 = "Windows Login Password:" fullword wide
      $s13 = "+Failed to find the encryption key filename.-The structure of the key filename is invalid./The structure of the protected data i" wide
      $s14 = "AppData\\Roaming" fullword ascii
      $s15 = "AppData\\Roaming\\Microsoft\\Protect" fullword ascii
      $s16 = " Network Password Recovery" fullword wide
      $s17 = " Network  Password  Recovery" fullword wide
      $s18 = "AddExportHeaderLine" fullword ascii
      $s19 = "<html><head>%s<title>%s</title></head>" fullword ascii
      $s20 = "Domain Password" fullword wide

      $op0 = { 48 8b 08 66 44 89 34 91 66 85 ff 0f 85 f9 01 00 }
      $op1 = { 48 8d 4c 24 20 41 83 c8 ff c7 44 24 34 00 01 00 }
      $op2 = { 04 45 88 ab 21 ff ff ff 45 88 ab 22 ff ff ff 45 }
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:8c728a5f-33f2-4e42-9aee-a5ca90148c80 org: to_ids:True tags:[]
rule Phobos_PasswordFox64 {
   meta:
      description = "PasswordFox64.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "7fee96ae0ed1972a80abbd4529dc81ec033083857455bbf3c803c4f47e1ac31c"
   strings:
      $s1 = "SELECT id, hostname, httpRealm, formSubmitURL, usernameField, passwordField, encryptedUsername, encryptedPassword, timeCreated, " ascii
      $s2 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"am" ascii
      $s3 = "c:\\Projects\\VS2005\\PasswordFox\\x64\\Release\\PasswordFox.pdb" fullword ascii
      $s4 = "SELECT id, hostname, httpRealm, formSubmitURL, usernameField, passwordField, encryptedUsername, encryptedPassword, timeCreated, " ascii
      $s5 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword wide
      $s6 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"am" ascii
      $s7 = "\\sqlite3.dll" fullword wide
      $s8 = "\\mozsqlite3.dll" fullword wide
      $s9 = "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"" fullword ascii
      $s10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe" fullword wide
      $s11 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Waterfox.exe" fullword wide
      $s12 = "encryptedPassword" fullword wide
      $s13 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword wide
      $s14 = "xpwwwx" fullword ascii /* reversed goodware string 'xwwwpx' */
      $s15 = "timeLastUsed, timePasswordChanged, timesUsed FROM moz_logins" fullword ascii
      $s16 = "Password Use Count" fullword wide
      $s17 = "%programfiles%\\Mozilla Firefox" fullword wide
      $s18 = "AddExportHeaderLine" fullword wide
      $s19 = "<html><head>%s<title>%s</title></head>" fullword wide
      $s20 = "Password Field" fullword wide

      $op0 = { 48 8b cf ff 15 4d 5c 01 00 ba ec ff ff ff 48 8b }
      $op1 = { f2 41 0f 58 fa eb 34 41 83 fb 06 7c 14 41 83 fb }
      $op2 = { e9 39 01 00 00 48 8b 05 85 b7 01 00 83 b8 34 0c }
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:6cc8c143-41fa-4387-911c-03899fc742fc org: to_ids:True tags:[]
rule Phobos_mimikatzlib_32 {
   meta:
      description = "mimilib_32.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "a6527183e3cbf81602de16f3448a8754f6cecd05dc3568fa2795de534b366da4"
   strings:
      $x1 = "0: kd> !process 0 0 lsass.exe" fullword ascii
      $s2 = "$http://blog.gentilkiwi.com/mimikatz 0" fullword ascii
      $s3 = "0: kd> .process /r /p <EPROCESS address>" fullword ascii
      $s4 = "mimilib.dll" fullword wide
      $s5 = "# Search for LSASS process" fullword ascii
      $s6 = " '## v ##'   https://blog.gentilkiwi.com/mimikatz             (oe.eo)" fullword ascii
      $s7 = "%p - lsasrv!LogonSessionList" fullword ascii
      $s8 = "%p - lsasrv!LogonSessionListCount" fullword ascii
      $s9 = "kiwidns.log" fullword wide
      $s10 = "kiwifilter.log" fullword wide
      $s11 = "kiwinp.log" fullword wide
      $s12 = "kiwissp.log" fullword wide
      $s13 = "kiwisub.log" fullword wide
      $s14 = "masterkey" fullword ascii
      $s15 = " * Password : " fullword ascii
      $s16 = "%p - lsasrv!h3DesKey" fullword ascii
      $s17 = "Unknown version in Kerberos credentials structure" fullword ascii
      $s18 = "lsasrv!g_fSystemCredsInitialized" fullword ascii
      $s19 = "dpapisrv!g_fSystemCredsInitialized" fullword ascii
      $s20 = "%p - lsasrv!hAesKey" fullword ascii

      $op0 = { 6a 34 5b ff 75 e4 6a 40 8b 3d 54 50 00 10 ff d7 }
      $op1 = { 8b be 44 54 00 10 0f af 7c 24 34 57 6a 40 ff d3 }
      $op2 = { 8b 59 04 8b 3d 34 50 00 10 89 45 0c 50 be 38 88 }
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:24ef87ef-84e0-4080-97d2-33cbcca8a8a4 org: to_ids:True tags:[]
rule Phobos_mimilove_32 {
   meta:
      description = "mimilove_32.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "b42725211240828ccc505d193d8ea5915e395c9f43e71496ff0ece4f72e3e4ab"
   strings:
      $s1 = "$http://blog.gentilkiwi.com/mimikatz 0" fullword ascii
      $s2 = "mimilove.exe" fullword wide
      $s3 = " '## v ##'   https://blog.gentilkiwi.com/mimikatz             (oe.eo)" fullword wide
      $s4 = "ERROR wmain ; OpenProcess (0x%08x)" fullword wide
      $s5 = "ERROR mimilove_lsasrv ; kull_m_memory_copy / KIWI_MSV1_0_LOGON_SESSION_TABLE_50 (0x%08x)" fullword wide
      $s6 = "ERROR mimilove_lsasrv ; LogonSessionTable is NULL" fullword wide
      $s7 = "ERROR mimilove_kerberos ; kull_m_memory_copy / KERB_HASHPASSWORD_5 (0x%08x)" fullword wide
      $s8 = "ERROR mimilove_kerberos ; kull_m_memory_copy / KIWI_KERBEROS_LOGON_SESSION_50 (0x%08x)" fullword wide
      $s9 = "ERROR mimilove_kerberos ; KerbLogonSessionList is NULL" fullword wide
      $s10 = "ERROR mimilove_kerberos ; kull_m_memory_copy / KIWI_KERBEROS_KEYS_LIST_5 (0x%08x)" fullword wide
      $s11 = "Copyright (c) 2007 - 2020 gentilkiwi (Benjamin DELPY)" fullword wide
      $s12 = "ERROR kull_m_kernel_ioctl_handle ; DeviceIoControl (0x%08x) : 0x%08x" fullword wide
      $s13 = "UndefinedLogonType" fullword wide
      $s14 = "ERROR wmain ; GetVersionEx (0x%08x)" fullword wide
      $s15 = "ERROR mimilove_lsasrv ; kull_m_memory_copy / KIWI_MSV1_0_PRIMARY_CREDENTIALS (0x%08x)" fullword wide
      $s16 = "ERROR mimilove_lsasrv ; kull_m_memory_copy / KIWI_MSV1_0_CREDENTIALS (0x%08x)" fullword wide
      $s17 = "KERBEROS Credentials (no tickets, sorry)" fullword wide
      $s18 = "benjamin@gentilkiwi.com0" fullword ascii
      $s19 = " * Username : %wZ" fullword wide
      $s20 = "http://subca.ocsp-certum.com01" fullword ascii

      $op0 = { 89 45 cc 6a 34 8d 45 cc 50 8d 45 c4 8d 4d 80 50 }
      $op1 = { 89 45 b8 c7 45 bc f7 ff ff ff 89 5d d4 89 5d f4 }
      $op2 = { 89 45 d4 c7 45 d8 f8 ff ff ff 89 7d f0 89 7d f4 }
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:381937fa-30e6-4437-8649-bb8faf7fda8a org: to_ids:True tags:[]
rule Phobos_mimik_32 {
   meta:
      description = "mimik_32.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "66b4a0681cae02c302a9b6f1d611ac2df8c519d6024abdb506b4b166b93f636a"
   strings:
      $x1 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide
      $x2 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx user (%s)" fullword wide
      $x3 = "ERROR kuhl_m_lsadump_update_dc_password ; A /target argument is needed" fullword wide
      $x4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" fullword wide
      $x5 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" fullword wide
      $x6 = "ERROR kuhl_m_lsadump_lsa ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide
      $x7 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" fullword wide
      $x8 = "ERROR kuhl_m_lsadump_trust ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide
      $x9 = "ERROR kuhl_m_lsadump_dcsync ; kull_m_rpc_drsr_ProcessGetNCChangesReply" fullword wide
      $x10 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
      $x11 = "ERROR kuhl_m_kernel_processProtect ; Argument /process:program.exe or /pid:processid needed" fullword wide
      $x12 = "ERROR kuhl_m_lsadump_netsync ; I_NetServerTrustPasswordsGet (0x%08x)" fullword wide
      $x13 = "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; Checksums don't match (C:0x%08x - R:0x%08x)" fullword wide
      $x14 = "ERROR kuhl_m_lsadump_sam ; kull_m_registry_RegOpenKeyEx (SAM) (0x%08x)" fullword wide
      $x15 = "ERROR kuhl_m_lsadump_getHash ; Unknow SAM_HASH revision (%hu)" fullword wide
      $x16 = "ERROR kuhl_m_lsadump_changentlm ; Argument /oldpassword: or /oldntlm: is needed" fullword wide
      $x17 = "ERROR kuhl_m_lsadump_enumdomains_users ; /user or /rid is needed" fullword wide
      $x18 = "ERROR kuhl_m_lsadump_zerologon ; Missing /account argument, usually a DC$ account" fullword wide
      $x19 = "ERROR kuhl_m_lsadump_update_dc_password ; A /account argument is needed" fullword wide
      $x20 = "livessp.dll" fullword wide /* reversed goodware string 'lld.pssevil' */

      $op0 = { 8b 55 0c 6a 01 8d 85 00 ff ff ff 50 ff 75 08 8d }
      $op1 = { 8b 45 08 8b f0 83 c0 34 6a 0d 59 8b fb f3 a5 8b }
      $op2 = { 89 74 24 0c 39 73 34 76 66 89 74 24 10 6a 20 6a }
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( 1 of ($x*) and all of ($op*) )
}

// MISP event:1317 uuid:6a484892-2c0d-44a5-b684-12dccfc10737 org: to_ids:True tags:[]
rule Phobos_pspv {
   meta:
      description = "pspv.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "64788b6f74875aed53ca80669b06f407e132d7be49586925dbb3dcde56cbca9c"
   strings:
      $s1 = "SMTP Password" fullword ascii
      $s2 = "pspv.exe" fullword wide
      $s3 = "xwwwwwpwwww" fullword ascii /* reversed goodware string 'wwwwpwwwwwx' */
      $s4 = "SMTP User" fullword ascii
      $s5 = "inetcomm server passwords" fullword ascii
      $s6 = "POP3 Password" fullword ascii
      $s7 = "<tr><td nowrap>&nbsp;<a href=\"%s\" target=\"new1\">%s</a> <td nowrap>&nbsp;%s<td nowrap>&nbsp;%s <td nowrap>&nbsp;%s" fullword ascii
      $s8 = "IMAP Password" fullword ascii
      $s9 = "ms ie ftp Passwords" fullword ascii
      $s10 = "HTTP User" fullword ascii
      $s11 = "HTTP Password" fullword ascii
      $s12 = "&AutoComplete Passwords" fullword wide
      $s13 = "AutoComplete Passwords" fullword wide
      $s14 = "Protected Storage Raw Data2Select a filename for exporting the passwords list2Select a filename for importing the passwords list" wide
      $s15 = "4Select a text filename for saving the passwords listBSelect a filename for saving the raw data of the Protected Storage Protect" wide
      $s16 = "wininetcachecredentials" fullword ascii
      $s17 = "IMAP User" fullword ascii
      $s18 = "Outlook Account Manager Passwords" fullword ascii
      $s19 = "<html><head><title>%s</title>%s</head>" fullword ascii
      $s20 = "ShowPasswordProtected" fullword ascii

      $op0 = { ff 75 10 e8 7d ff ff ff 85 c0 59 0f 85 83 }
      $op1 = { 8d 85 f8 fe ff ff 50 e8 75 ff ff ff 59 59 5f c9 }
      $op2 = { ff 15 70 80 40 00 83 bd 6c ff ff ff 01 75 07 68 }
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:e752fe13-a36e-4997-95ff-3349f67b5a45 org: to_ids:True tags:[]
rule Phobos_mailpv {
   meta:
      description = "mailpv.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "16c6af4ae2d8ca8e7a3f2051b913fa1cb7e1fbd0110b0736614a1e02bbbbceaf"
   strings:
      $s1 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s2 = "www.google.com/Please log in to your Gmail account" fullword wide
      $s3 = "www.google.com:443/Please log in to your Gmail account" fullword wide
      $s4 = "www.google.com/Please log in to your Google Account" fullword wide
      $s5 = "www.google.com:443/Please log in to your Google Account" fullword wide
      $s6 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword ascii
      $s7 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s8 = "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"" fullword ascii
      $s9 = "%s@yahoo.com" fullword ascii
      $s10 = "logins.json" fullword ascii
      $s11 = "%s@gmail.com" fullword ascii
      $s12 = "smtpserver" fullword ascii
      $s13 = "SMTPAccount" fullword ascii
      $s14 = "ESMTPPassword" fullword ascii
      $s15 = "SMTP User" fullword ascii
      $s16 = "PopPassword" fullword ascii
      $s17 = "SMTP USer Name" fullword ascii
      $s18 = "Passport.Net\\*" fullword ascii
      $s19 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword ascii
      $s20 = "Failed to load the executable file !" fullword ascii

      $op0 = { 89 46 2c 89 46 34 89 46 14 e8 33 fd ff ff 8b 46 }
      $op1 = { e9 4a ff ff ff 83 7e 24 05 75 23 80 fb 20 76 0f }
      $op2 = { e9 00 ff ff ff e8 79 fb ff ff c7 46 24 05 }
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:c60b667b-50aa-49f5-bfa5-1ffbcc051df2 org: to_ids:True tags:[]
rule Phobos_WirelessKeyView {
   meta:
      description = "WirelessKeyView.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "12f13d129579c68ec3cc05bef69880b6a891296fa9fce69b979b1c04998f125c"
   strings:
      $x1 = "Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKeyToken=\"6595b64144" ascii
      $x2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
      $x3 = "Windows Protect folder for getting the encryption keys, For example: G:\\windows\\system32\\Microsoft\\Protect" fullword wide
      $s4 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword ascii
      $s5 = "Windows Registry hives folder, for example: k:\\windows\\system32\\config" fullword wide
      $s6 = "SYSTEM\\%s\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection" fullword ascii
      $s7 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword ascii
      $s8 = "system32\\config\\Software" fullword ascii
      $s9 = "system32\\config" fullword ascii
      $s10 = "Load the wireless keys of the current logged-on user" fullword wide
      $s11 = "/Running WirelessKeyView as SYSTEM user (Faster)%Directly decrypting the wireless keys" fullword wide
      $s12 = "SYSTEM\\%s\\Enum\\%s" fullword ascii
      $s13 = "AddExportHeaderLine" fullword ascii
      $s14 = "<html><head>%s<title>%s</title></head>" fullword ascii
      $s15 = "/GetKeys" fullword ascii
      $s16 = "<tr><td%s nowrap><b>%s</b><td bgcolor=#%s%s>%s" fullword ascii
      $s17 = "report.html" fullword ascii
      $s18 = " Type Descriptor'" fullword ascii
      $s19 = "Load wireless keys from remote system (Windows Vista or later, requires full admin rights)" fullword wide
      $s20 = "Windows Directory: (For example: K:\\Windows  )" fullword wide

      $op0 = { 56 8d 85 01 ff ff ff 53 50 88 9d 00 ff ff ff e8 }
      $op1 = { 57 8d 85 70 ff ff ff 50 53 8d 45 f0 50 6a 01 be }
      $op2 = { 8b c6 50 e8 41 ff ff ff 83 c4 10 5e c9 c3 55 8b }
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:5480b7c2-b78f-41e3-b8bb-0abc407b3037 org: to_ids:True tags:[]
rule Phobos_ChromePass {
   meta:
      description = "ChromePass.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "c4304f7bb6ef66c0676c6b94d25d3f15404883baa773e94f325d8126908e1677"
   strings:
      $x1 = "Windows Protect folder for getting the encryption keys, For example: F:\\Users\\Nir\\AppData\\Roaming\\Microsoft\\Protect" fullword wide
      $s2 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s3 = "Chrome User Data folder where the password file is stored , for example: G:\\Users\\Nir\\AppData\\Local\\Google\\Chrome\\User Da" wide
      $s4 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword wide
      $s5 = "<entries ext=\"Password Exporter\" extxmlversion=\"1.1\" type=\"saved\" encrypt=\"false\">" fullword ascii
      $s6 = "<entry host=\"%s\" user=\"%s\" password=\"%s\" formSubmitURL=\"%s\" httpRealm=\"%s\" userFieldName=\"%s\" passFieldName=\"%s\"/>" wide
      $s7 = "c:\\Projects\\VS2005\\ChromePass\\Release\\ChromePass.pdb" fullword ascii
      $s8 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s9 = "Windows User Profile Path, For example: K:\\Users\\Admin  " fullword wide
      $s10 = "@netmsg.dll" fullword wide
      $s11 = "Opera Software\\Opera Stable\\Login Data" fullword wide
      $s12 = "@crypt32.dll" fullword wide
      $s13 = "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"" fullword ascii
      $s14 = "om logins " fullword ascii
      $s15 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword wide
      $s16 = "Windows Login Password:" fullword wide
      $s17 = "SELECT origin_url, action_url, username_element, username_value, password_element, password_value, signon_realm, date_created fr" ascii
      $s18 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" fullword wide
      $s19 = "Vivaldi\\User Data\\Default\\Login Data" fullword wide
      $s20 = "KeePass csv file,Password Exporter Firefox Extension XML File" fullword wide

      $op0 = { 55 8b ec 51 56 33 f6 66 89 33 8a 07 eb 29 34 42 }
      $op1 = { c7 46 54 ff ff ff 00 e8 ae fd ff ff 5f 5e 5b c9 }
      $op2 = { 56 8d 85 01 ff ff ff 53 50 88 9d 00 ff ff ff e8 }
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:73f54551-b1e0-4f8f-a671-a55a8bbce197 org: to_ids:True tags:[]
rule Phobos_SniffPass {
   meta:
      description = "SniffPass.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "1e13fd79ad54fe98e08d9ffca2c287a470c50c2876608edce2fe38e07c245266"
   strings:
      $x1 = "Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKeyToken=\"6595b64144" ascii
      $x2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
      $s3 = "c:\\Projects\\VS2005\\SniffPass\\Release\\SniffPass.pdb" fullword ascii
      $s4 = "npptools.dll" fullword ascii
      $s5 = "NmApi.dll" fullword ascii
      $s6 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword ascii
      $s7 = "nmwifi.exe" fullword ascii
      $s8 = "Pwpcap.dll" fullword ascii
      $s9 = "Sniffed PasswordsCFailed to start capturing packets from the current network adapter.9Do you want to stop the capture and exit f" wide
      $s10 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword ascii
      $s11 = "login " fullword ascii
      $s12 = "AddExportHeaderLine" fullword ascii
      $s13 = "NirSoft SniffPass" fullword ascii
      $s14 = "NmGetFrame" fullword ascii
      $s15 = "NmGetRawFrame" fullword ascii
      $s16 = "NmGetFrameCount" fullword ascii
      $s17 = "NmGetRawFrameLength" fullword ascii
      $s18 = "Software\\NirSoft\\SniffPass" fullword ascii
      $s19 = "BeepOnNewPassword" fullword ascii
      $s20 = "<html><head>%s<title>%s</title></head>" fullword ascii

      $op0 = { 56 8d 85 01 ff ff ff 53 50 88 9d 00 ff ff ff e8 }
      $op1 = { c7 45 f8 fe ff ff ff 29 5d f8 8d 53 02 8a 42 ff }
      $op2 = { ff 15 9c c0 40 00 8b c6 5e c3 e8 d7 ff ff ff 33 }
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:a8fe47c3-1325-4df6-ba51-e1b40d86acf7 org: to_ids:True tags:[]
rule Phobos_WebBrowserPassView {
   meta:
      description = "WebBrowserPassView.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "b556d90b30f217d5ef20ebe3f15cce6382c4199e900b5ad2262a751909da1b34"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii
      $x2 = "https://www.google.com/accounts/servicelogin" fullword wide
      $s3 = "https://login.yahoo.com/config/login" fullword wide
      $s4 = "ncy><dependentAssembly><assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processor" ascii
      $s5 = "Web Browser Passwords%Choose another Firefox profile folder)Choose the installation folder of Firefox,Choose another profile of " wide
      $s6 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword wide
      $s7 = "com.apple.WebKit2WebProcess" fullword ascii
      $s8 = "Opera Login file:" fullword wide
      $s9 = "http://www.facebook.com/" fullword wide
      $s10 = "Opera Password File" fullword wide
      $s11 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword wide
      $s12 = "Ghistory.dat" fullword wide
      $s13 = "<html><head>%s<title>%s</title></head>" fullword wide
      $s14 = "ASTCOLUMNCOMMITCONFLICTCROSSCURRENT_TIMESTAMPRIMARYDEFERREDISTINCTDROPFAILFROMFULLGLOBYIFISNULLORDERESTRICTOUTERIGHTROLLBACKROWU" ascii
      $s15 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s16 = "Mozilla\\SeaMonkey\\Profiles" fullword wide
      $s17 = "Mozilla\\SeaMonkey" fullword wide
      $s19 = "%d Passwords" fullword wide
      $s20 = "Internet Explorer 4.0 - 6.0" fullword wide

      $op0 = { 8d 4c 24 20 51 8d 54 24 1c 52 50 8b 44 24 34 50 }
      $op1 = { 89 74 24 34 89 74 24 40 89 74 24 38 89 74 24 44 }
      $op2 = { 89 4c 24 3c 89 7c 24 30 89 4c 24 34 ff d5 85 c0 }
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:442a2df8-b280-40ac-9648-821fb9912cdf org: to_ids:True tags:[]
rule Phobos_Dialupass {
   meta:
      description = "Dialupass.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "598555a7e053c7456ee8a06a892309386e69d473c73284de9bbc0ba73b17e70a"
   strings:
      $x1 = "Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKeyToken=\"6595b64144" ascii
      $x2 = "Profiles base folder or phonebook folder:  (For example:  f:\\Documents and Settings, f:\\users , K:\\users\\admin\\AppData\\Roa" wide
      $x3 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
      $s4 = "ycomctl32.dll" fullword wide
      $s5 = "Dialupass.exe /setpass \"%s\" \"%s\" \"%s\" \"%s\" \"%s\"" fullword wide
      $s6 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword wide
      $s7 = "Copy /setpass Command-Line" fullword wide
      $s8 = "Windows Directory or Registry hives folder (SYSTEM and SECURITY hives are needed), For example:  E:\\Windows or E:\\Windows\\Sys" wide
      $s9 = "@advapi32.dll" fullword wide
      $s10 = "@netmsg.dll" fullword wide
      $s11 = "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"" fullword ascii
      $s12 = "AppData\\Roaming\\Microsoft\\Network\\Connections\\Pbk" fullword wide
      $s13 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword wide
      $s14 = "system32\\ras\\rasphone.pbk" fullword wide
      $s15 = "  Failed to load the executable file !  " fullword wide
      $s16 = "Extract the dialup passwords list from your local system" fullword wide
      $s17 = "ShowItemsNoPassword" fullword wide
      $s18 = "AddExportHeaderLine" fullword wide
      $s19 = "L$_RasConnectionCredentials#0" fullword wide
      $s20 = "<html><head>%s<title>%s</title></head>" fullword wide

      $op0 = { 55 8b ec 51 56 33 f6 66 89 33 8a 07 eb 29 34 42 }
      $op1 = { eb 34 8d 85 8c f1 ff ff 50 e8 79 f8 ff ff 89 45 }
      $op2 = { 53 56 8d 5f 34 8b 45 fc 8d 4f 24 e8 c7 ea ff ff }
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:d3c77626-f778-4a8c-8789-7f6880fdbc31 org: to_ids:True tags:[]
rule Phobos_BulletsPassView {
   meta:
      description = "BulletsPassView.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "b19dfe440e515c39928b475a946656a12b1051e98e0df36c016586b34a766d5c"
   strings:
      $s1 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s2 = "BulletsPassView.exe" fullword wide
      $s3 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword wide
      $s4 = "c:\\Projects\\VS2005\\BulletsPassView\\Release\\BulletsPassView.pdb" fullword ascii
      $s5 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s6 = "@netmsg.dll" fullword wide
      $s7 = "Process Description" fullword wide
      $s8 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword wide
      $s9 = "Process Path" fullword wide
      $s10 = "ScanIEPasswords" fullword wide
      $s11 = "ScanWindowsPasswords" fullword wide
      $s12 = "Scan Internet Explorer Passwords" fullword wide
      $s13 = "Scan Standard Password Text-Boxes" fullword wide
      $s14 = "AddExportHeaderLine" fullword wide
      $s15 = "<html><head>%s<title>%s</title></head>" fullword wide
      $s16 = "UnmaskPasswordBox" fullword wide
      $s17 = "BeepOnNewPassword" fullword wide
      $s18 = "&Clear Passwords List" fullword wide
      $s19 = "Copy Selected &Password" fullword wide
      $s20 = "&Unmask Password Text Box" fullword wide

      $op0 = { 55 8b ec 51 56 33 f6 66 89 33 8a 07 eb 29 34 42 }
      $op1 = { 56 8d 85 01 ff ff ff 53 50 88 9d 00 ff ff ff e8 }
      $op2 = { 43 3b 5c 24 14 0f 82 47 ff ff ff e9 c8 }
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:611c4ea4-b0c1-4a38-a8b3-8307eea37954 org: to_ids:True tags:[]
rule Phobos_rdpv {
   meta:
      description = "rdpv.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "205818e10c13d2e51b4c0196ca30111276ca1107fc8e25a0992fe67879eab964"
   strings:
      $s1 = "rdpv.exe" fullword wide
      $s2 = "Password Recovery for Remote Desktop" fullword wide
      $s3 = "<description>NirSoft</description> " fullword ascii
      $s4 = "Remote Desktop PassView" fullword wide
      $s5 = " 2006 - 2014 Nir Sofer" fullword wide
      $s6 = "-~W:\\P" fullword ascii
      $s7 = "Desktop PassVieww" fullword ascii
      $s8 = "hars5=%s'>?=bl" fullword ascii
      $s9 = "<meta http-e" fullword ascii
      $s10 = "zcr*t3$dll" fullword ascii
      $s11 = "name=\"NirSoft\" " fullword ascii
      $s12 = "quiv='con5" fullword ascii
      $s13 = "lobalAl" fullword ascii
      $s14 = "v%HmsgivX" fullword ascii
      $s15 = ".QhF(z" fullword ascii
      $s16 = "mZCo)lsEx" fullword ascii
      $s17 = "RSDSK&^" fullword ascii
      $s18 = "STATIC;0T" fullword ascii
      $s19 = "Lemote " fullword ascii
      $s20 = "CTYPE HTMLWUBLB \"-v" fullword ascii

      $op0 = { ff ff ff ff 55 8b ec 51 53 33 db 88 1f 8a 06 eb }
      $op1 = { ff 60 be 00 b0 40 00 8d be 00 60 ff ff 57 83 cd }
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:098ca740-8637-4feb-833d-d98a7adf65c6 org: to_ids:True tags:[]
rule Phobos_netpass {
   meta:
      description = "netpass.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "de374c1b9a05c2203e66917202c42d11eac4368f635ccaaadf02346035e82562"
   strings:
      $x1 = "Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKeyToken=\"6595b64144" ascii
      $x2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
      $s3 = " Network Password Recovery" fullword wide
      $s4 = " Network  Password  Recovery" fullword wide
      $s5 = "vapi3ydll" fullword ascii
      $s6 = " 2005 - 2016 Nir Sofer" fullword wide
      $s7 = "requestedPrivileges>" fullword ascii
      $s8 = "support@nirsoft.net0" fullword ascii
      $s9 = "5 Hashoshanim st.1" fullword ascii
      $s10 = "K6Network Pass" fullword ascii
      $s11 = "a http-equiv='" fullword ascii
      $s12 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
      $s13 = "SpofResou0" fullword ascii
      $s14 = "Gush Dan1" fullword ascii
      $s15 = "Ramat Gan1" fullword ascii
      $s16 = "yzRRzRK" fullword ascii
      $s17 = "=%s'>?=ble dir=\"" fullword ascii
      $s18 = "!DOCTYPE HTML" fullword ascii
      $s19 = "HlobalUn" fullword ascii
      $s20 = "ewPEfw;" fullword ascii

      $op0 = { ff ff ff ff 55 8b ec 51 53 33 db 88 1f 8a 06 eb }
      $op1 = { db dc cd 5c 8a 00 1b 85 1e 49 35 10 78 fb 3f ec }
      $op2 = { 60 be 00 00 41 00 8d be 00 10 ff ff 57 83 cd ff }
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:6ddd82b9-f2b0-43ae-a83c-37b09ec62ee8 org: to_ids:True tags:[]
rule Phobos_RouterPassView {
   meta:
      description = "RouterPassView.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "ae474417854ac1b6190e15cc514728433a26cc815fdc6d12150ef55e92d643ea"
   strings:
      $s1 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s2 = "RouterPassView.exe" fullword wide
      $s3 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s4 = "$)7622/%$#" fullword ascii /* hex encoded string 'v"' */
      $s5 = "d[5DlLIE@???2!6:Bqib" fullword ascii
      $s6 = " 2010 - 2019 Nir Sofer" fullword wide
      $s7 = ".pdb/p@" fullword ascii
      $s8 = "ohttp_Gd" fullword ascii
      $s9 = "P-CONFIGWLB[bZX" fullword ascii
      $s10 = "RouterPassView" fullword wide
      $s11 = "icKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity>" fullword ascii
      $s12 = "Decrypts Router files." fullword wide
      $s13 = "WuruxK5" fullword ascii
      $s14 = "jjgeba" fullword ascii
      $s15 = "GetAdapters" fullword ascii
      $s16 = "password" fullword ascii /* Goodware String - occured 519 times */
      $s17 = "IK@0STzKpB%" fullword ascii
      $s18 = "-Iartup|" fullword ascii
      $s19 = "!/FpvvtpnkTk^`fh" fullword ascii
      $s20 = "eYdhLPX&" fullword ascii

      $op0 = { 5f fe ff ff 55 8b ec 51 56 33 f6 66 89 33 8a 07 }
      $op1 = { 60 be 00 c0 41 00 8d be 00 50 fe ff 57 83 cd ff }
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:9c510412-0467-4fdd-a4f6-f3bd973c49ad org: to_ids:True tags:[]
rule Phobos_PstPassword {
   meta:
      description = "PstPassword.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "5e85446910e732111ca9ac90f9ed8b1dee13c3314d2c5117dcf672994ce73bd6"
   strings:
      $s1 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s2 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s3 = "PstPasswordf" fullword ascii
      $s4 = "PST Password Recovery" fullword wide
      $s5 = "PstPassword" fullword wide
      $s6 = " PstPassword" fullword wide
      $s7 = " 2006  - 2017 Nir Sofer" fullword wide
      $s8 = "ReadMemoq" fullword ascii
      $s9 = "fTs[G:\"" fullword ascii
      $s10 = "icKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity>" fullword ascii
      $s11 = "\\Microsoft\\Outbn" fullword ascii
      $s12 = "!DOCTYPE HTML" fullword ascii
      $s13 = "ysdaopmck/,p" fullword ascii
      $s14 = "-BruI%+F" fullword ascii
      $s15 = "FGTQgfl" fullword ascii
      $s16 = "gUSPo0irJx{" fullword ascii
      $s17 = "<meta \\tp-equiv='conZ" fullword ascii
      $s18 = "lGlobchk Plc" fullword ascii
      $s19 = "atYhx6n" fullword ascii
      $s20 = "HKiTGt>h" fullword ascii

      $op0 = { ff ff ff ff 55 8b ec 51 53 33 db 88 1f 8a 06 eb }
      $op1 = { 60 be 00 b0 40 00 8d be 00 60 ff ff 57 83 cd ff }
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:af814d99-5c66-4c05-8107-41a8619062fc org: to_ids:True tags:[]
rule Phobos_OperaPassView {
   meta:
      description = "OperaPassView.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "8e4b218bdbd8e098fff749fe5e5bbf00275d21f398b34216a573224e192094b8"
   strings:
      $s1 = "OperaPassView.exe" fullword wide
      $s2 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s3 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s4 = "ccount\",\"Login Name" fullword ascii
      $s5 = "OperaPassView" fullword wide
      $s6 = "NexProcess " fullword ascii
      $s7 = "36333222(\"" fullword ascii /* hex encoded string '632"' */
      $s8 = "MGetFBase`7t" fullword ascii
      $s9 = "55553333(" fullword ascii /* hex encoded string 'UU33' */
      $s10 = " 2010 - 2013 Nir Sofer" fullword wide
      $s11 = "RRRRRRRRRPPPPOOONN" fullword ascii
      $s12 = "TTTSTSSSRRRRRR" fullword ascii
      $s13 = "icKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity>" fullword ascii
      $s14 = "Lartuprmi" fullword ascii
      $s15 = "Password" fullword ascii /* Goodware String - occured 715 times */
      $s16 = "8eLibrKyA" fullword ascii
      $s17 = "Cddd|xp" fullword ascii
      $s18 = "JLLOOQQRRTTWWXX[[]]^^aabbddgghhk" fullword ascii
      $s19 = "nnpppuuvvyyzz||" fullword ascii
      $s20 = "@DDDCCC?" fullword ascii

      $op0 = { 5f fe ff ff 55 8b ec 51 56 33 f6 66 89 33 8a 07 }
      $op1 = { 60 be 00 e0 40 00 8d be 00 30 ff ff 57 83 cd ff }
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:5c99ef9b-6181-46d7-b80f-938671a94012 org: to_ids:True tags:[]
rule Phobos_mspass {
   meta:
      description = "mspass.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "7a313840d25adf94c7bf1d17393f5b991ba8baf50b8cacb7ce0420189c177e26"
   strings:
      $x1 = "lyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKey" ascii
      $x2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
      $s3 = "mspass.exe" fullword wide
      $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
      $s5 = "IM Password Recovery" fullword wide
      $s6 = " 2004 - 2014 Nir Sofer" fullword wide
      $s7 = "oftware" fullword wide
      $s8 = "mspass" fullword wide
      $s9 = "TalKeySt" fullword ascii
      $s10 = " MessenPass" fullword wide
      $s11 = "re=\"X86\" name=\"NirSoft\" type=\"win32\"></assemblyIdentity><description>NirSoft</description><dependency><dependentAssembly><" ascii
      $s12 = "Gbrvbar" fullword ascii
      $s13 = "~,\"Log8 Name" fullword ascii
      $s14 = "iiethn" fullword ascii
      $s15 = "\\Digsby\\d" fullword ascii
      $s16 = "aaaarr" fullword ascii
      $s17 = "fddptx" fullword ascii
      $s18 = "8>qg(= " fullword ascii /* Goodware String - occured 1 times */
      $s19 = "ilterIndex" fullword ascii
      $s20 = "fmaj]b0" fullword ascii

      $op0 = { ff ff ff ff 55 8b ec 51 53 33 db 88 1f 8a 06 eb }
      $op1 = { 60 be 00 40 41 00 8d be 00 d0 fe ff 57 83 cd ff }
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:32a2cc2f-82d3-49a4-a2d4-19263c180c67 org: to_ids:True tags:[]
rule Phobos_NetRouteView {
   meta:
      description = "NetRouteView.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "91041b616969e1526ee6dce23f8d18afdd353786ac6afa0b6611903263ee6f63"
   strings:
      $s1 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s2 = "NetRouteView.exe" fullword wide
      $s3 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s4 = " 2010 - 2015 Nir Sofer" fullword wide
      $s5 = "AetIpForwardE" fullword ascii
      $s6 = "support@nirsoft.net0" fullword ascii
      $s7 = "5 Hashoshanim st.1" fullword ascii
      $s8 = "Read8[U" fullword ascii
      $s9 = "icKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity>" fullword ascii
      $s10 = "Laseoize" fullword ascii
      $s11 = "urrent" fullword ascii
      $s12 = "xce /Y" fullword ascii
      $s13 = "jKXEAT1" fullword ascii
      $s14 = "Gush Dan1" fullword ascii
      $s15 = "Ramat Gan1" fullword ascii
      $s16 = "kFBaseNameW" fullword ascii
      $s17 = "XAnImAi;" fullword ascii
      $s18 = "ctfWz7b" fullword ascii
      $s19 = "reaGCTab_" fullword ascii
      $s20 = "View\\R|" fullword ascii

      $op0 = { 5f fe ff ff 55 8b ec 51 56 33 f6 66 89 33 8a 07 }
      $op1 = { 60 be 00 f0 40 00 8d be 00 20 ff ff 57 83 cd ff }
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:68282800-9783-42a2-9052-1e72a6c2cbef org: to_ids:True tags:[]
rule Phobos_iepv {
   meta:
      description = "iepv.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "dbe98193aced7285a01c18b7da8e4540fb4e5b0625debcfbabcab7ea90f5685d"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii
      $s2 = "ncy><dependentAssembly><assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processor" ascii
      $s3 = "iepv.exe" fullword wide
      $s4 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s5 = "IE Passwords Viewer" fullword wide
      $s6 = "ecture=\"X86\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity></dependentAssembly></dependency><asmv3:app" ascii
      $s7 = "CredentialsFi" fullword ascii
      $s8 = " 2006 - 2016 Nir Sofer" fullword wide
      $s9 = "A$TempaU" fullword ascii
      $s10 = "support@nirsoft.net0" fullword ascii
      $s11 = "5 Hashoshanim st.1" fullword ascii
      $s12 = "/'ml;chars5=%s'>?" fullword ascii
      $s13 = "E http-equiv='" fullword ascii
      $s14 = "IE Pass View" fullword wide
      $s15 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii
      $s16 = "Gush Dan1" fullword ascii
      $s17 = "Ramat Gan1" fullword ascii
      $s18 = "008deee3d3f0" ascii
      $s19 = "PdHP~(z@" fullword ascii
      $s20 = "UUUUU\\@" fullword ascii

      $op0 = { ff ff ff ff 55 8b ec 51 53 33 db 88 1f 8a 06 eb }
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:04e86dd1-86e6-4f13-8c54-3c2375a288c1 org: to_ids:True tags:[]
rule Phobos_PasswordFox {
   meta:
      description = "PasswordFox.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "e01b0e7feadd08a7ea87c1cde44e7b97daf9632eaee8311ef6967f33258d03c1"
   strings:
      $s1 = "SELECT id, hostname, httpRealm, formSubmitURL, usernameField, passwordField, encryptedUsername, encryptedPassword, timeCreated, " ascii
      $s2 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s3 = "c:\\Projects\\VS2005\\PasswordFox\\Release\\PasswordFox.pdb" fullword ascii
      $s4 = "SELECT id, hostname, httpRealm, formSubmitURL, usernameField, passwordField, encryptedUsername, encryptedPassword, timeCreated, " ascii
      $s5 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword wide
      $s6 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s7 = "\\sqlite3.dll" fullword wide
      $s8 = "\\mozsqlite3.dll" fullword wide
      $s9 = "@netmsg.dll" fullword wide
      $s10 = "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"" fullword ascii
      $s11 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe" fullword wide
      $s12 = "@nss3.dll" fullword wide
      $s13 = "encryptedPassword" fullword wide
      $s14 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword wide
      $s15 = "xpwwwx" fullword ascii /* reversed goodware string 'xwwwpx' */
      $s16 = "timeLastUsed, timePasswordChanged, timesUsed FROM moz_logins" fullword ascii
      $s17 = "Password Use Count" fullword wide
      $s18 = "%programfiles%\\Mozilla Firefox" fullword wide
      $s19 = "AddExportHeaderLine" fullword wide
      $s20 = "<html><head>%s<title>%s</title></head>" fullword wide

      $op0 = { 89 4c 24 3c 89 7c 24 30 89 4c 24 34 ff d5 85 c0 }
      $op1 = { 89 44 24 34 c7 44 24 38 06 08 08 00 89 4c 24 40 }
      $op2 = { 89 7c 24 24 89 7c 24 28 c7 44 24 34 00 40 00 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:7bdc83d1-99b6-4f5f-acbc-76e6070d498e org: to_ids:True tags:[]
rule Phobos_VNCPassView {
   meta:
      description = "VNCPassView.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "816d7616238958dfe0bb811a063eb3102efd82eff14408f5cab4cb5258bfd019"
   strings:
      $x1 = "lyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKey" ascii
      $x2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
      $s3 = "VNCPassView.exe" fullword wide
      $s4 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword ascii
      $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
      $s6 = "c:\\Projects\\VS2005\\VNCPassView\\Release\\VNCPassView.pdb" fullword ascii
      $s7 = "<meta http-equiv='content-type' content='text/html;charset=%s'>" fullword ascii
      $s8 = "BasicProg.cfg" fullword ascii
      $s9 = "ultravnc" fullword ascii
      $s10 = "<html><head>%s<title>%s</title></head>" fullword ascii
      $s11 = "VNC Passwords" fullword wide
      $s12 = "Password Type" fullword wide
      $s13 = "<tr><td%s nowrap><b>%s</b><td bgcolor=#%s%s>%s" fullword ascii
      $s14 = "report.html" fullword ascii
      $s15 = "ultravnc.ini" fullword ascii
      $s16 = "dialog_%d" fullword ascii
      $s17 = " 2007 - 2014  Nir Sofer" fullword wide
      $s18 = "xpwwwwwwwwwwwx" fullword ascii
      $s19 = "<th%s>%s%s%s" fullword ascii
      $s20 = "<td bgcolor=#%s nowrap>%s" fullword ascii

      $op0 = { 56 8d 85 01 ff ff ff 53 50 88 9d 00 ff ff ff e8 }
      $op1 = { 8b c6 50 e8 41 ff ff ff 83 c4 10 5e c9 c3 55 8b }
      $op2 = { 56 8d 85 01 ff ff ff 6a 00 50 8b f9 c6 85 00 ff }
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:e2976683-8f43-49de-a994-23ad71d11b12 org: to_ids:True tags:[]
rule Phobos_pars {
   meta:
      description = "pars.vbs"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "04cc60eba7041e0cef2deb1bec9a087432344737dd2e5141c9cda981506ca1a5"
   strings:
      $s1 = "str_SavePath = Replace(obj_FSO.GetFile(str_LogFile), obj_FSO.GetFileName(str_LogFile), \"\", 1, -1, vbTextCompare)" fullword ascii
      $s2 = "Gl_WorkDir = Replace(WScript.ScriptFullName, WScript.ScriptName, \"\", 1, -1, vbTextCompare)" fullword ascii
      $s3 = "SaveReportToSMB str_SavePath, \"Users.txt\", Join(ListUsers, vbCrLf)" fullword ascii
      $s4 = "SaveReportToSMB str_SavePath, \"Passwords.txt\", Join(ListPasswords, vbCrLf)" fullword ascii
      $s5 = "Str = Replace(Replace(Replace(Str, \" * password : \", \"\"), \" * Password : \", \"\"), \" * PASSWORD : \", \"\")" fullword ascii
      $s6 = "If (InStr(1, Str, \"password :\", vbTextCompare) <> 0) Then" fullword ascii
      $s7 = "If (InStr(1, ListUsers(IndUsers2), Str, vbTextCompare) <> 0) Then" fullword ascii
      $s8 = "If (InStr(1, ListPasswords(IndPass2), Str, vbBinaryCompare) <> 0) Then" fullword ascii
      $s9 = "If (InStr(1, Str, \"cur/text:\", vbTextCompare) <> 0) Or (InStr(1, Str, \"old/text:\", vbTextCompare) <> 0) Then" fullword ascii
      $s10 = "SaveReportToSMB str_SavePath, \"NewPassTest.txt\", Join(Listtext, vbCrLf)" fullword ascii
      $s11 = "SaveReportToSMB str_SavePath, \"HASHES.txt\", Join(ListNTLM, vbCrLf)" fullword ascii
      $s12 = "For IndUsers2=0 To IndUsers1" fullword ascii
      $s13 = "Str = Replace(Replace(Replace(Str, \" password : \", \"\"), \" Password : \", \"\"), \" PASSWORD : \", \"\")" fullword ascii
      $s14 = "Dim IndUsers1: IndUsers1=-1" fullword ascii
      $s15 = "Str = Replace(Replace(Replace(Str, \"password : \", \"\"), \"Password : \", \"\"), \"PASSWORD : \", \"\")" fullword ascii
      $s16 = "Dim ListPasswords(): ReDim ListPasswords(0)" fullword ascii
      $s17 = "Redim Preserve rdirs(ubound(rdirs) - 1)" fullword ascii
      $s18 = "ReDim Preserve ListPasswords(IndPass1)" fullword ascii
      $s19 = "ReDim Preserve ListUsers(IndUsers1)" fullword ascii
      $s20 = "If (IndUsers1 < 0) or NeedAdd Then" fullword ascii
   condition:
      uint16(0) == 0x6944 and filesize < 30KB and
      8 of them
}

// MISP event:1317 uuid:161c61c3-01f5-48c9-895a-5fc661dfd2c2 org: to_ids:True tags:[]
rule Phobos_ToolStatus {
   meta:
      description = "ToolStatus.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "5713d40dec146dbc819230daefe1b886fa6d6f6dbd619301bb8899562195cbab"
   strings:
      $x1 = "D:\\Projects\\processhacker2\\bin\\Release64\\plugins\\ToolStatus.pdb" fullword ascii
      $s2 = "ToolStatus.dll" fullword wide
      $s3 = "ProcessHacker.ToolStatus.Config" fullword wide
      $s4 = "ProcessHacker.ToolStatus.RebarConfig" fullword wide
      $s5 = "ProcessHacker.ToolStatus.ToolbarConfig" fullword wide
      $s6 = "ProcessHacker.ToolStatus.StatusbarConfig" fullword wide
      $s7 = "Modern Toolbar icons by http://www.icons8.com" fullword wide
      $s8 = "https://wj32.org/processhacker/forums/viewtopic.php?t=1119" fullword wide
      $s9 = "PhGetFilterSupportProcessTreeList" fullword ascii
      $s10 = "ProcessHacker.ToolStatus.ToolbarDisplayStyle" fullword wide
      $s11 = "ProcessHacker.ToolStatus.SearchBoxDisplayMode" fullword wide
      $s12 = "ProcessHacker.ToolStatus.ToolbarTheme" fullword wide
      $s13 = "ProcessHacker.ToolStatus" fullword wide
      $s14 = "PhGetProcessPriorityClassString" fullword ascii
      $s15 = "PhCreateProcessPropContext" fullword ascii
      $s16 = "PhFindProcessNode" fullword ascii
      $s17 = "PhSetSelectThreadIdProcessPropContext" fullword ascii
      $s18 = "PhExpandAllProcessNodes" fullword ascii
      $s19 = "PhUiTerminateProcesses" fullword ascii
      $s20 = "PhReferenceProcessItem" fullword ascii

      $op0 = { 24 04 89 4c 24 24 c7 44 24 20 ff ff ff ff 41 0f }
      $op1 = { 33 d2 ff 15 dc ea 00 00 8b 46 34 41 b9 05 }
      $op2 = { 83 e8 10 74 76 83 f8 03 0f 85 6b ff ff ff 80 3d }
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:ba13cea3-3f1f-41c0-afe7-9c5c70902874 org: to_ids:True tags:[]
rule Phobos_ProcessHacker {
   meta:
      description = "ProcessHacker.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "bd2c2cf0631d881ed382817afcce2b093f4e412ffb170a719e2762f250abfea4"
   strings:
      $x1 = "D:\\Projects\\processhacker2\\bin\\Release64\\ProcessHacker.pdb" fullword ascii
      $x2 = "ProcessHacker.exe" fullword wide
      $x3 = "kprocesshacker.sys" fullword wide
      $x4 = "ntdll.dll!NtDelayExecution" fullword wide
      $x5 = "ntdll.dll!ZwDelayExecution" fullword wide
      $s6 = "PhUiInjectDllProcess" fullword ascii
      $s7 = "PhInjectDllProcess" fullword ascii
      $s8 = "Executable files (*.exe;*.dll;*.ocx;*.sys;*.scr;*.cpl)" fullword wide
      $s9 = "The process is 32-bit, but the 32-bit version of Process Hacker could not be located. A 64-bit dump will be created instead. Do " wide
      $s10 = "PhExecuteRunAsCommand2" fullword ascii
      $s11 = "\\x86\\ProcessHacker.exe" fullword wide
      $s12 = "user32.dll!NtUserGetMessage" fullword wide
      $s13 = "ntdll.dll!NtWaitForKeyedEvent" fullword wide
      $s14 = "ntdll.dll!ZwWaitForKeyedEvent" fullword wide
      $s15 = "ntdll.dll!NtReleaseKeyedEvent" fullword wide
      $s16 = "ntdll.dll!ZwReleaseKeyedEvent" fullword wide
      $s17 = "\\kprocesshacker.sys" fullword wide
      $s18 = "\\SystemRoot\\system32\\drivers\\ntfs.sys" fullword wide
      $s19 = "PhShellExecuteUserString" fullword ascii
      $s20 = "The process will be restarted with the same command line and working directory, but if it is running under a different user it w" wide

      $op0 = { 48 8b d9 33 d2 48 8d 4c 24 34 41 b8 9c }
      $op1 = { 8b 41 08 89 44 24 34 0f b7 41 18 66 c1 c8 08 0f }
      $op2 = { 48 8b 0d 34 9c 15 00 48 85 c9 75 37 bb 37 00 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:b9847164-48ad-42f4-9c01-c6f7d9aa3d4e org: to_ids:True tags:[]
rule Phobos_OnlineChecks {
   meta:
      description = "OnlineChecks.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "7336d66588bbcfea63351a2eb7c8d83bbd49b5d959ba56a94b1fe2e905a5b5de"
   strings:
      $x1 = "D:\\Projects\\processhacker2\\bin\\Release64\\plugins\\OnlineChecks.pdb" fullword ascii
      $s2 = "OnlineChecks.dll" fullword wide
      $s3 = "virustotal.com" fullword wide
      $s4 = "https://wj32.org/processhacker/forums/viewtopic.php?t=1118" fullword wide
      $s5 = "http://www.virustotal.com/file/%s/analysis/" fullword wide
      $s6 = "PhShellExecute" fullword ascii
      $s7 = "ProcessHacker.OnlineChecks" fullword wide
      $s8 = "camas.comodo.com" fullword wide
      $s9 = "ProcessHacker_" fullword wide
      $s10 = "Online Checks plugin for Process Hacker" fullword wide
      $s11 = "http://camas.comodo.com%.*S" fullword wide
      $s12 = "http://camas.comodo.com/cgi-bin/submit?file=%s" fullword wide
      $s13 = "PhGetPhVersion" fullword ascii
      $s14 = "virusscan.jotti.org" fullword wide
      $s15 = "Content-Type: application/x-msdownload" fullword wide
      $s16 = "http://virusscan.jotti.org%hs" fullword wide
      $s17 = "PhGetBaseName" fullword ascii
      $s18 = "PhGetFileSize" fullword ascii
      $s19 = "Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"" fullword wide
      $s20 = "Unable to add request headers" fullword wide

      $op0 = { eb 1f 44 39 7e 18 75 34 44 39 7e 14 74 2e 48 8b }
      $op1 = { e9 46 ff ff ff cc 45 33 d2 4c 8b ca 66 44 39 11 }
      $op2 = { 49 8b f0 48 8b fa 48 8b d9 e8 c8 ff ff ff 4c 89 }
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:ff7abf7c-18ff-45cd-8634-223bc3e0ed3e org: to_ids:True tags:[]
rule Phobos_Updater {
   meta:
      description = "Updater.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "0c11cdc3765ffb53ba9707b6f99ec17ae4f7334578a935ba7bcbbc9c7bdeed2e"
   strings:
      $x1 = "D:\\Projects\\processhacker2\\bin\\Release64\\plugins\\Updater.pdb" fullword ascii
      $s2 = "%s%s\\processhacker-%lu.%lu-setup.exe" fullword wide
      $s3 = "http://processhacker.sourceforge.net/downloads.php" fullword wide
      $s4 = "Updater.dll" fullword wide
      $s5 = "https://wj32.org/processhacker/forums/viewtopic.php?t=1121" fullword wide
      $s6 = "processhacker.sourceforge.net" fullword wide
      $s7 = "PhShellExecute" fullword ascii
      $s8 = "ProcessHacker.UpdateChecker.PromptStart" fullword wide
      $s9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Process_Hacker2_is1" fullword wide
      $s10 = "ProcessHacker.UpdateChecker.LastUpdateCheckTime" fullword wide
      $s11 = "ProcessHacker.UpdateChecker" fullword wide
      $s12 = "/processhacker/update.php" fullword wide
      $s13 = "Plugin for checking new Process Hacker releases via the Help menu." fullword wide
      $s14 = "ProcessHacker-Build: " fullword wide
      $s15 = "ProcessHacker-OsBuild: " fullword wide
      $s16 = "Process Hacker %lu.%lu.%lu" fullword wide
      $s17 = "Update checker plugin for Process Hacker" fullword wide
      $s18 = "Process Hacker Updater" fullword wide
      $s19 = "PhGetOwnTokenAttributes" fullword ascii
      $s20 = "PhGetPhVersionNumbers" fullword ascii

      $op0 = { e8 34 ee ff ff eb b7 48 8d 59 08 40 32 f6 40 88 }
      $op1 = { 48 8b d8 e8 34 e2 ff ff 48 3b c3 74 c1 8b cf e8 }
      $op2 = { 48 85 c0 0f 84 11 03 00 00 4c 8d 05 11 34 01 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:68b4f63b-8ade-4d76-a8cf-2c807a9a440f org: to_ids:True tags:[]
rule Phobos_ExtendedServices {
   meta:
      description = "ExtendedServices.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "5ae7c0972fd4e4c4ae14c0103602ca854377fefcbccd86fa68cfc5a6d1f99f60"
   strings:
      $x1 = "D:\\Projects\\processhacker2\\bin\\Release64\\plugins\\ExtendedServices.pdb" fullword ascii
      $s2 = "Executable files (*.exe;*.cmd;*.bat)" fullword wide
      $s3 = "ExtendedServices.dll" fullword wide
      $s4 = "https://wj32.org/processhacker/forums/viewtopic.php?t=1113" fullword wide
      $s5 = "ProcessHacker.ExtendedServices.EnableServicesMenu" fullword wide
      $s6 = "ProcessHacker.ExtendedServices" fullword wide
      $s7 = "*.exe;*.cmd;*.bat" fullword wide
      $s8 = "PhGetListViewItemParam" fullword ascii
      $s9 = "PhGetSelectedListViewItemParam" fullword ascii
      $s10 = "PhGetServiceConfig" fullword ascii
      $s11 = "Extended Services for Process Hacker" fullword wide
      $s12 = "Enable Services submenu for processes" fullword wide
      $s13 = "PhGetFileDialogFileName" fullword ascii
      $s14 = "Append /fail=%1% to pass the fail count to the program." fullword wide
      $s15 = "The service has %lu failure actions configured, but this program only supports editing 3. If you save the recovery information u" wide
      $s16 = "PhGetOwnTokenAttributes" fullword ascii
      $s17 = "PhGetComboBoxString" fullword ascii
      $s18 = "PhLookupPrivilegeDisplayName" fullword ascii
      $s19 = "Service (%s)" fullword wide
      $s20 = "The selected privilege has already been added." fullword wide

      $op0 = { 48 8b f8 48 8b cd 48 8d 44 24 34 4c 8b c7 48 89 }
      $op1 = { 48 8b 05 34 a6 01 00 48 33 c4 48 89 45 1f 4c 89 }
      $op2 = { 48 8d 44 24 34 41 8b d1 48 89 44 24 20 4c 8d 44 }
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:7e304cc6-4046-4bae-99b3-a21e401e9d85 org: to_ids:True tags:[]
rule Phobos_DotNetTools {
   meta:
      description = "DotNetTools.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "b4cc0280e2caa0335361172cb7d673f745defc78299ded808426ffbc2458e4d9"
   strings:
      $x1 = "D:\\Projects\\processhacker2\\bin\\Release64\\plugins\\DotNetTools.pdb" fullword ascii
      $s2 = "\\Microsoft.NET\\Framework64\\v4.0.30319\\mscordacwks.dll" fullword wide
      $s3 = "\\Microsoft.NET\\Framework64\\v2.0.50727\\mscordacwks.dll" fullword wide
      $s4 = "DotNetTools.dll" fullword wide
      $s5 = "# of Filters Executed" fullword wide
      $s6 = "# of Finallys Executed" fullword wide
      $s7 = "https://wj32.org/processhacker/forums/viewtopic.php?t=1111" fullword wide
      $s8 = "PhGetProcessIsDotNet" fullword ascii
      $s9 = "PhGetProcessIsSuspended" fullword ascii
      $s10 = "PhGetProcessIsDotNetEx" fullword ascii
      $s11 = "ProcessHacker.DotNetTools.AsmTreeListColumns" fullword wide
      $s12 = "ProcessHacker.DotNetTools.DotNetListColumns" fullword wide
      $s13 = "ProcessHacker.DotNetTools.DotNetShowByteSizes" fullword wide
      $s14 = "ProcessHacker.DotNetTools" fullword wide
      $s15 = ".NET tools plugin for Process Hacker" fullword wide
      $s16 = "PhGetSystemRoot" fullword ascii
      $s17 = "PhEnumProcessModules32" fullword ascii
      $s18 = "PhOpenProcess" fullword ascii
      $s19 = "ProcessQueryAccess" fullword ascii
      $s20 = "PhFindProcessInformation" fullword ascii

      $op0 = { 48 8b d8 e8 34 e2 ff ff 48 3b c3 74 c1 8b cf e8 }
      $op1 = { c7 45 f7 fe ff ff ff 44 89 7d fb ff 15 ff ea 00 }
      $op2 = { 48 8b 4e 18 45 33 c9 ba ff ff ff 7f 4e 8b 04 03 }
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:4b2d1204-f006-4667-b629-f1447d8a5dfb org: to_ids:True tags:[]
rule Phobos_HardwareDevices {
   meta:
      description = "HardwareDevices.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "acd49f2aa36d4efb9c4949e2d3cc2bd7aee384c2ced7aa9e66063da4150fcb00"
   strings:
      $x1 = "D:\\Projects\\processhacker2\\bin\\Release64\\plugins\\HardwareDevices.pdb" fullword ascii
      $s2 = "Count of reallocated sectors. When the hard drive finds a read/write/verification error, it marks that sector as \"reallocated\"" wide
      $s3 = "HardwareDevices.dll" fullword wide
      $s4 = "https://wj32.org/processhacker/forums/viewtopic.php?t=1820" fullword wide
      $s5 = "ProcessHacker.HardwareDevices.EnableNDIS" fullword wide
      $s6 = "ProcessHacker.HardwareDevices.DiskList" fullword wide
      $s7 = "ProcessHacker.HardwareDevices.NetworkList" fullword wide
      $s8 = "ProcessHacker.HardwareDevices" fullword wide
      $s9 = "Uncorrected read errors reported to the operating system." fullword wide
      $s10 = "PhGetListViewItemParam" fullword ascii
      $s11 = "PhGetSelectedListViewItemParam" fullword ascii
      $s12 = "PhProcessesUpdatedEvent" fullword ascii
      $s13 = "This attribute stores a total count of the spin start attempts to reach the fully operational speed (under the condition that th" wide
      $s14 = "Hardware Devices plugin for Process Hacker" fullword wide
      $s15 = "Average performance of seek operations of the magnetic heads." fullword wide
      $s16 = "PhGetOwnTokenAttributes" fullword ascii
      $s17 = "LogFile reads" fullword wide
      $s18 = "LogFile read bytes" fullword wide
      $s19 = "%I64u - %I64u" fullword wide
      $s20 = "Command Timeout" fullword wide

      $op0 = { b2 01 ff 15 15 4d 01 00 48 8b c8 ff 15 34 4d 01 }
      $op1 = { b2 01 ff 15 15 4b 01 00 48 8b c8 ff 15 34 4b 01 }
      $op2 = { 48 8b 47 08 4c 8b 34 d8 49 63 0e 4c 8b c9 e8 6d }
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:7eb7c76c-0062-4379-ace5-4aa008ff26ab org: to_ids:True tags:[]
rule Phobos_WindowExplorer {
   meta:
      description = "WindowExplorer.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "282696487ea5dc781788d5d8477b977f72b7c70f201c2af0cfe7e1a9fd8d749a"
   strings:
      $x1 = "ProcessHacker.exe" fullword wide
      $x2 = "D:\\Projects\\processhacker2\\bin\\Release64\\plugins\\WindowExplorer.pdb" fullword ascii
      $s3 = "WindowExplorer.dll" fullword wide
      $s4 = "https://wj32.org/processhacker/forums/viewtopic.php?t=1116" fullword wide
      $s5 = "(%d, %d) - (%d, %d) [%dx%d]" fullword wide
      $s6 = "ProcessHacker.WindowExplorer" fullword wide
      $s7 = "ProcessHacker.WindowExplorer.ShowDesktopWindows" fullword wide
      $s8 = "ProcessHacker.WindowExplorer.WindowTreeListColumns" fullword wide
      $s9 = "ProcessHacker.WindowExplorer.WindowsWindowPosition" fullword wide
      $s10 = "ProcessHacker.WindowExplorer.WindowsWindowSize" fullword wide
      $s11 = "PhCreateProcessPropContext" fullword ascii
      $s12 = "PhSetSelectThreadIdProcessPropContext" fullword ascii
      $s13 = "PhReferenceProcessItem" fullword ascii
      $s14 = "PhShowProcessProperties" fullword ascii
      $s15 = "PhOpenProcess" fullword ascii
      $s16 = "ProcessQueryAccess" fullword ascii
      $s17 = "The process does not exist." fullword wide
      $s18 = "Windows - Thread %lu" fullword wide
      $s19 = "Windows - Desktop \"%s\"" fullword wide
      $s20 = "Window Explorer plugin for Process Hacker" fullword wide

      $op0 = { ff 15 1a fb 00 00 ba e8 ff ff ff 48 8b cb 85 ff }
      $op1 = { ff 15 34 c0 01 00 41 b8 c8 }
      $op2 = { ff 15 f7 e2 00 00 83 63 34 fd 4c 8b cb 48 8b 0f }
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:c75ccfbc-3290-470e-a20e-6d6db2af3375 org: to_ids:True tags:[]
rule Phobos_ExtendedTools {
   meta:
      description = "ExtendedTools.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "f2805e0f81513641a440f1a21057a664961c22192cb33fca3870362c8f872d87"
   strings:
      $x1 = "D:\\Projects\\processhacker2\\bin\\Release64\\plugins\\ExtendedTools.pdb" fullword ascii
      $s2 = "ExtendedTools.dll" fullword wide
      $s3 = "https://wj32.org/processhacker/forums/viewtopic.php?t=1114" fullword wide
      $s4 = "PhEtKernelLogger" fullword wide
      $s5 = "ProcessHacker.ToolStatus" fullword wide
      $s6 = "ProcessHacker.ExtendedTools.DiskTreeListColumns" fullword wide
      $s7 = "ProcessHacker.ExtendedTools.DiskTreeListSort" fullword wide
      $s8 = "ProcessHacker.ExtendedTools.EnableEtwMonitor" fullword wide
      $s9 = "ProcessHacker.ExtendedTools.EnableGpuMonitor" fullword wide
      $s10 = "ProcessHacker.ExtendedTools.GpuNodeBitmap" fullword wide
      $s11 = "ProcessHacker.ExtendedTools.GpuLastNodeCount" fullword wide
      $s12 = "ProcessHacker.ExtendedTools" fullword wide
      $s13 = "Disk monitoring requires Process Hacker to be restarted with administrative privileges." fullword wide
      $s14 = "PhShellProcessHacker" fullword ascii
      $s15 = "PhEtRundownLogger" fullword wide
      $s16 = "PhFindProcessNode" fullword ascii
      $s17 = "PhReferenceProcessItem" fullword ascii
      $s18 = "PhFindProcessRecord" fullword ascii
      $s19 = "PhShowProcessRecordDialog" fullword ascii

      $op0 = { c7 44 24 40 ff ff ff 7f 48 89 44 24 30 45 33 c0 }
      $op1 = { e8 03 00 00 48 8d 0d 3d 34 02 00 ff 15 f7 a6 01 }
      $op2 = { 8b c1 49 8b 14 c1 f6 02 02 0f 85 3c ff ff ff ff }
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:8c28802c-bc3f-413d-84eb-9d1befb47679 org: to_ids:True tags:[]
rule Phobos_ExtendedNotifications {
   meta:
      description = "ExtendedNotifications.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "61e8cd8de80a5c0d7ced280fe04ad8387a846a7bf2ee51bcbba96b971c7c1795"
   strings:
      $x1 = "C:\\Windows\\system32\\cmd.exe" fullword wide
      $s2 = "D:\\Projects\\processhacker2\\bin\\Release64\\plugins\\ExtendedNotifications.pdb" fullword ascii
      $s3 = "https://wj32.org/processhacker/forums/viewtopic.php?t=1112" fullword wide
      $s4 = "ExtendedNotifications.dll" fullword wide
      $s5 = "note*.exe" fullword wide
      $s6 = "ProcessHacker.ExtendedNotifications.LogFileName" fullword wide
      $s7 = "The process %s (%lu) was started by %s." fullword wide
      $s8 = "The process %s (%lu) was terminated." fullword wide
      $s9 = "an unknown process" fullword wide
      $s10 = "Log files (*.txt;*.log)" fullword wide
      $s11 = "PhReferenceProcessItemForParent" fullword ascii
      $s12 = "Process Created" fullword ascii
      $s13 = "Process Hacker" fullword ascii
      $s14 = "Process Terminated" fullword ascii
      $s15 = "Changes will require a restart of Process Hacker." fullword wide
      $s16 = "PhGetFileDialogFileName" fullword ascii
      $s17 = "dProcessHacker.ExtendedNotifications" fullword wide
      $s18 = "ProcessHacker.ExtendedNotifications.EnableGrowl" fullword wide
      $s19 = "ProcessHacker.ExtendedNotifications.ProcessList" fullword wide
      $s20 = "ProcessHacker.ExtendedNotifications.ServiceList" fullword wide

      $op0 = { 48 8d 4c 24 28 48 8b 34 e8 b8 65 }
      $op1 = { 48 8b 47 08 41 b0 01 8b cb 48 8b d5 4c 8b 34 c8 }
      $op2 = { 81 7d 10 36 ff ff ff 0f 85 80 }
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:5d0c59b7-11d2-4b88-8eff-e5d813aaa555 org: to_ids:True tags:[]
rule Phobos_peview {
   meta:
      description = "peview.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "4259e53d48a3fed947f561ff04c7f94446bedd64c87f52400b2cb47a77666aaa"
   strings:
      $x1 = "D:\\Projects\\processhacker2\\bin\\Release64\\peview.pdb" fullword ascii
      $s2 = "peview.exe" fullword wide
      $s3 = "mscorlib.ni.dll" fullword wide
      $s4 = "Supported files (*.exe;*.dll;*.ocx;*.sys;*.scr;*.cpl;*.ax;*.acm;*.lib;*.winmd;*.efi)" fullword wide
      $s5 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\KnownFunctionTableDlls" fullword wide
      $s6 = "*.exe;*.dll;*.ocx;*.sys;*.scr;*.cpl;*.ax;*.acm;*.lib;*.winmd;*.efi" fullword wide
      $s7 = "Executable, " fullword wide
      $s8 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s9 = "Process Hacker" fullword wide
      $s10 = "Uni-processor only, " fullword wide
      $s11 = "Process affinity mask" fullword wide
      $s12 = "Process heap flags" fullword wide
      $s13 = "Target machine:" fullword wide
      $s14 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s15 = "\\Microsoft.NET\\Framework\\" fullword wide
      $s16 = "\\Microsoft.NET\\Framework64\\" fullword wide
      $s17 = "    processorArchitecture=\"*\"" fullword ascii
      $s18 = "        processorArchitecture=\"*\"" fullword ascii
      $s19 = "  <description>PE Viewer</description>" fullword ascii
      $s20 = "EFI Boot Service Driver" fullword wide

      $op0 = { 85 ff 74 51 49 8b 10 8b df 48 8d 34 1b 48 03 d6 }
      $op1 = { e9 48 ff ff ff 8b df 48 d1 eb 74 4c 49 8b 10 48 }
      $op2 = { 48 8b fe 0f b7 c0 48 8b ca 66 f3 ab 48 8d 34 56 }
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:f6ce8134-b9d4-404b-9fe0-73f2b1ef112c org: to_ids:True tags:[]
rule Phobos_dControl {
   meta:
      description = "dControl.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "6606d759667fbdfaa46241db7ffb4839d2c47b88a20120446f41e916cad77d0b"
   strings:
      $s1 = "/AutoIt3ExecuteScript" fullword wide
      $s2 = "/AutoIt3ExecuteLine" fullword wide
      $s3 = "WINGETPROCESS" fullword wide
      $s4 = "PROCESSGETSTATS" fullword wide
      $s5 = "SCRIPTNAME" fullword wide /* base64 encoded string 'H$H=3@0' */
      $s6 = "dControl.exe" fullword wide
      $s7 = "SHELLEXECUTEWAIT" fullword wide
      $s8 = "SHELLEXECUTE" fullword wide
      $s9 = "#NoAutoIt3Execute" fullword wide
      $s10 = "PROCESSWAITCLOSE" fullword wide
      $s11 = "PROCESSWAIT" fullword wide
      $s12 = "PROCESSSETPRIORITY" fullword wide
      $s13 = "PROCESSLIST" fullword wide
      $s14 = "PROCESSEXISTS" fullword wide
      $s15 = "PROCESSCLOSE" fullword wide
      $s16 = "HTTPSETUSERAGENT" fullword wide
      $s17 = "PROCESSORARCH" fullword wide
      $s18 = "LASTDLLERROR" fullword wide
      $s19 = "CMDLINERAW" fullword wide
      $s20 = "FTPSETPROXY" fullword wide

      $op0 = { e8 c5 ff ff ff 8d 8e bc }
      $op1 = { e8 34 13 01 00 8d 44 24 30 50 8d 8c 24 4c 01 00 }
      $op2 = { e9 25 ff ff ff 33 c0 89 06 eb a5 8b c1 33 c9 c7 }
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:de41dad1-992e-4e0b-b4b7-693430c69bb6 org: to_ids:True tags:[]
rule Phobos_SbieSupport {
   meta:
      description = "SbieSupport.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "57c56f7b312dc1f759e6ad039aac3f36ce5130d259eb9faad77239083398308b"
   strings:
      $x1 = "D:\\Projects\\processhacker2\\bin\\Release64\\plugins\\SbieSupport.pdb" fullword ascii
      $s2 = "C:\\Program Files\\Sandboxie\\SbieDll.dll" fullword wide
      $s3 = "SbieSupport.dll" fullword wide
      $s4 = "ProcessHacker.SbieSupport.SbieDllPath" fullword wide
      $s5 = "https://wj32.org/processhacker/forums/viewtopic.php?t=1115" fullword wide
      $s6 = "SbieDll.dll path:" fullword wide
      $s7 = "ProcessHacker.SbieSupport" fullword wide
      $s8 = "lall sandboxed processes" fullword wide
      $s9 = "PhFindProcessNode" fullword ascii
      $s10 = "PhOpenProcess" fullword ascii
      $s11 = "PhUpdateProcessNode" fullword ascii
      $s12 = "PhTerminateProcess" fullword ascii
      $s13 = "Provides functionality for sandboxed processes." fullword wide
      $s14 = "Terminate sandboxed processes" fullword wide
      $s15 = "Sandboxie Support for Process Hacker" fullword wide
      $s16 = "PhGetFileDialogFileName" fullword ascii
      $s17 = "PhGetWindowText" fullword ascii
      $s18 = "PhSetFileDialogFileName" fullword ascii
      $s19 = "PhFreeFileDialog" fullword ascii
      $s20 = "PhShowFileDialog" fullword ascii

      $op0 = { 4c 8d 05 be ff ff ff 48 8d 15 a7 ff ff ff 41 8d }
      $op1 = { f0 48 0f b1 3d 34 52 01 00 74 0d 48 8d 0d 2b 52 }
      $op2 = { 48 0f a3 c3 73 0b 41 83 c8 01 44 89 05 48 34 01 }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:f0a4797b-b8e0-4b4f-b43e-f3172ed9035b org: to_ids:True tags:[]
rule Phobos_NetworkTools {
   meta:
      description = "NetworkTools.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "476aa6af14dd0b268786e32543b9a6917a298d4d90e1015dac6fb2b522cf5d2e"
   strings:
      $x1 = "D:\\Projects\\processhacker2\\bin\\Release64\\plugins\\NetworkTools.pdb" fullword ascii
      $s2 = "%s\\system32\\tracert.exe -d %s" fullword wide
      $s3 = "%s\\system32\\pathping.exe -n %s" fullword wide
      $s4 = "NetworkTools.dll" fullword wide
      $s5 = "https://wj32.org/processhacker/forums/viewtopic.php?t=1117" fullword wide
      $s6 = "%s\\system32\\tracert.exe %s" fullword wide
      $s7 = "%s\\system32\\pathping.exe %s" fullword wide
      $s8 = "PhShellExecute" fullword ascii
      $s9 = "processhacker_%S_0x0D06F00D_x1" fullword ascii
      $s10 = "ProcessHacker.NetworkTools.WindowPosition" fullword wide
      $s11 = "ProcessHacker.NetworkTools.WindowSize" fullword wide
      $s12 = "ProcessHacker.NetworkTools.PingWindowPosition" fullword wide
      $s13 = "ProcessHacker.NetworkTools.PingWindowSize" fullword wide
      $s14 = "ProcessHacker.NetworkTools.PingMaxTimeout" fullword wide
      $s15 = "ProcessHacker.NetworkTools" fullword wide
      $s16 = "PhProcessesUpdatedEvent" fullword ascii
      $s17 = "PhCreateProcessWin32Ex" fullword ascii
      $s18 = "PhTerminateProcess" fullword ascii
      $s19 = "Process Hacker " fullword wide
      $s20 = "Network Tools plugin for Process Hacker" fullword wide

      $op0 = { ff 15 34 17 01 00 e9 b5 05 00 00 41 0f b7 c6 ff }
      $op1 = { ba 00 10 00 00 48 8d 4d c0 ff 15 34 17 01 00 45 }
      $op2 = { 48 8b c8 ff 15 d6 0f 01 00 b9 f1 ff ff ff 8b d0 }
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:4b23d057-0ff6-4fd6-b375-77701c5d0f4d org: to_ids:True tags:[]
rule Phobos_UserNotes {
   meta:
      description = "UserNotes.dll"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "fc9d0d0482c63ab7f238bc157c3c0fed97951ccf2d2e45be45c06c426c72cb52"
   strings:
      $x1 = "D:\\Projects\\processhacker2\\bin\\Release64\\plugins\\UserNotes.pdb" fullword ascii
      $x2 = "%APPDATA%\\Process Hacker 2\\usernotesdb.xml" fullword wide
      $s3 = "UserNotes.dll" fullword wide
      $s4 = "ProcessHacker.UserNotes.DatabasePath" fullword wide
      $s5 = "Only for processes with the same command line" fullword wide
      $s6 = "ProcessHacker.UserNotes.ColorCustomList" fullword wide
      $s7 = "ProcessHacker.UserNotes" fullword wide
      $s8 = "Allows the user to add comments for processes and services. Also allows the user to save process priority. Also allows the user " wide
      $s9 = "https://wj32.org/processhacker/forums/viewtopic.php?t=1120" fullword wide
      $s10 = "PhGetSelectedProcessItems" fullword ascii
      $s11 = "PhGetSelectedProcessItem" fullword ascii
      $s12 = "ProcessHacker.ToolStatus" fullword wide
      $s13 = "User Notes plugin for Process Hacker" fullword wide
      $s14 = "PhInvalidateAllProcessNodes" fullword ascii
      $s15 = "PhOpenProcess" fullword ascii
      $s16 = "PhProcessesUpdatedEvent" fullword ascii
      $s17 = "ProcessQueryAccess" fullword ascii
      $s18 = "PhAddProcessPropPage" fullword ascii
      $s19 = "PhCreateProcessPropPageContextEx" fullword ascii
      $s20 = "PhProcessModifiedEvent" fullword ascii

      $op0 = { 49 8b cd 0f 95 c0 88 46 34 ff 15 f2 d9 00 00 eb }
      $op1 = { e8 34 fa ff ff 48 8b c8 ff 15 6b cd 00 00 48 8b }
      $op2 = { e8 43 ec ff ff 48 85 c0 74 30 80 78 34 00 74 2a }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}

// MISP event:1317 uuid:3cb5cfad-1429-408a-a331-2168e39d6ec1 org: to_ids:True tags:[]
rule Phobos_pw_inspector {
   meta:
      description = "pw-inspector.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "8bae7326cb8456ce4c9409045264ca965e30f6381ddcaa6c87ba3ac5e7683555"
   strings:
      $s1 = "  -m MINLEN  minimum length of a valid password" fullword ascii
      $s2 = "cyggcj-16.dll" fullword ascii
      $s3 = "  -i FILE    file to read passwords from (default: stdin)" fullword ascii
      $s4 = "  -M MAXLEN  maximum length of a valid password" fullword ascii
      $s5 = "Error: -c MINSETS is larger than the sets defined" fullword ascii
      $s6 = "  -o FILE    file to write valid passwords to (default: stdout)" fullword ascii
      $s7 = "Syntax: %s [-i FILE] [-o FILE] [-m MINLEN] [-M MAXLEN] [-c MINSETS] -l -u -n -p -s" fullword ascii
      $s8 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii
      $s9 = "Error: -m MINLEN is greater than -M MAXLEN" fullword ascii
      $s10 = "%s reads passwords in and prints those which meet the requirements." fullword ascii
      $s11 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
      $s12 = "  -c MINSETS the minimum number of sets required (default: all given)" fullword ascii
      $s13 = "Use for security: check passwords, if 0 is returned, reject password choice." fullword ascii
      $s14 = "The return code is the number of valid passwords found, 0 if none was found." fullword ascii
      $s15 = "  -s         special characters - all others not withint the sets above" fullword ascii
      $s16 = "http://www.thc.org" fullword ascii
      $s17 = "%s %s (c) 2005 by van Hauser / THC %s [%s]" fullword ascii
      $s18 = "Usage only allowed for legal purposes." fullword ascii
      $s19 = "  </compatibility>" fullword ascii
      $s20 = "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" fullword ascii

      $op0 = { c7 04 24 04 34 40 00 e8 95 }
      $op1 = { c7 04 24 54 34 40 00 e8 89 }
      $op2 = { c7 04 24 a8 34 40 00 e8 7d }
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( 8 of them and all of ($op*) )
}

// MISP event:1317 uuid:b24fe70a-efe6-452d-8470-32da2cc8564b org: to_ids:True tags:[]
rule Phobos_hydra {
   meta:
      description = "hydra.exe"
      author = "Directoratul National de Securitate Cibernetica (DNSC)"
      date = "2024-02-15"
      hash1 = "85aba198a0ba204e8549ea0c8980447249d30dece0d430e3f517315ad10f32ce"
   strings:
      $x1 = "[ATTEMPT-ERROR] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu" fullword ascii
      $x2 = " \"/exchweb/bin/auth/owaauth.dll:destination=http%%3A%%2F%%2F<target>%%2Fexchange&flags=0&username=<domain>%%5C^USER^&password=^" ascii
      $x3 = "[%sATTEMPT] target %s - login \"%s\" - pass \"%s\" - %lu of %lu [child %d] (%d/%d)" fullword ascii
      $x4 = " \"/exchweb/bin/auth/owaauth.dll:destination=http%%3A%%2F%%2F<target>%%2Fexchange&flags=0&username=<domain>%%5C^USER^&password=^" ascii
      $x5 = "  hydra -l foo -m bar -P pass.txt target cisco-enable  (AAA Login foo, password bar)" fullword ascii
      $x6 = "[COMPLETED] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu" fullword ascii
      $x7 = "[DEBUG] Target %d - target %s  ip %s  login_no %lu  pass_no %lu  sent %lu  pass_state %d  redo_state %d (%d redos)  use_count %d" ascii
      $x8 = "Example%s:%s  hydra -l user -P passlist.txt ftp://192.168.0.1" fullword ascii
      $x9 = "  hydra -P pass.txt -m cisco target cisco-enable  (Logon password cisco)" fullword ascii
      $x10 = "[DEBUG] Target %d - target %s  ip %s  login_no %lu  pass_no %lu  sent %lu  pass_state %d  redo_state %d (%d redos)  use_count %d" ascii
      $x11 = "  hydra -L logins.txt -P pws.txt -M targets.txt ssh" fullword ascii
      $x12 = "(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=))(COMMAND=reload)(PASSWORD=%s)(SERVICE=)(VERSION=169869568)))" fullword ascii
      $x13 = "[ERROR] target ssh://%s:%d/ does not support password authentication." fullword ascii
      $x14 = "   hydra -L user.txt -P pass.txt -m 3:SHA:AES:READ target.com snmp" fullword ascii
      $x15 = "   hydra -L urllist.txt -s 3128 target.com http-proxy-urlenum user:pass" fullword ascii
      $x16 = "[DEBUG] TEMP head %d: pass == %s, login == %s" fullword ascii
      $x17 = "%d of %d target%s%scompleted, %lu valid password" fullword ascii
      $x18 = "[DEBUG] we will redo the following combination: target %s  child %d  login \"%s\"  pass \"%s\"" fullword ascii
      $x19 = "[DEBUG] send_next_pair_init target %d, head %d, redo %d, redo_state %d, pass_state %d. loop_mode %d, curlogin %s, curpass %s, tl" ascii
      $x20 = "[DEBUG] send_next_pair_init target %d, head %d, redo %d, redo_state %d, pass_state %d. loop_mode %d, curlogin %s, curpass %s, tl" ascii

      $op0 = { 89 4c 24 34 8b 4c 24 64 89 74 24 04 89 7c 24 10 }
      $op1 = { a1 50 f2 46 00 c7 05 28 e3 44 00 ff ff ff ff 8b }
      $op2 = { f3 a6 74 33 c7 04 24 ff ff ff ff e8 45 4b 04 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( 1 of ($x*) and all of ($op*) )
}

// MISP event:1320 uuid:3f56445e-022c-4280-9d04-667f1113b9ee org: to_ids:True tags:[]
rule apt_malware_py_upstyle : UTA0218
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-11"
        description = "Detect the UPSTYLE webshell."
        hash1 = "3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac"
        hash2 = "0d59d7bddac6c22230187ef6cf7fa22bca93759edc6f9127c41dc28a2cea19d8"
        hash3 = "4dd4bd027f060f325bf6a90d01bfcf4e7751a3775ad0246beacc6eb2bad5ec6f"
        os = "linux"
        os_arch = "all"
        report = "TIB-20240412"
        scan_context = "file,memory"
        last_modified = "2024-04-12T13:05Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10429
        version = 2

    strings:
        $stage1_str1 = "/opt/pancfg/mgmt/licenses/PA_VM"
        $stage1_str2 = "exec(base64."

        $stage2_str1 = "signal.signal(signal.SIGTERM,stop)"
        $stage2_str2 = "exec(base64."

        $stage3_str1 = "write(\"/*\"+output+\"*/\")"
        $stage3_str2 = "SHELL_PATTERN"

    condition:
        all of ($stage1*) or
        all of ($stage2*) or
        all of ($stage3*)
}

// MISP event:1320 uuid:5d13f09e-164e-47b8-b7b4-8af490fbf2a9 org: to_ids:True tags:[]
rule susp_any_gost_arguments
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-10"
        description = "Looks for common arguments passed to the hacktool GOST that are sometimes used by attackers in scripts (for example cronjobs etc)."
        os = "all"
        os_arch = "all"
        report = "TIB-20240412"
        scan_context = "file"
        last_modified = "2024-04-12T13:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10425
        version = 2

    strings:
        $s1 = "-L=socks5://" ascii
        $s2 = "-L rtcp://" ascii

    condition:
        filesize < 10KB and
        any of them
}

// MISP event:1320 uuid:71f30d18-92f2-4fed-88ee-9195ca4e83b1 org: to_ids:True tags:[]
rule susp_any_jarischf_user_path
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-10"
        description = "Detects paths embedded in samples in released projects written by Ferdinand Jarisch, a pentester in AISEC. These tools are sometimes used by attackers in real world intrusions."
        hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
        os = "all"
        os_arch = "all"
        report = "TIB-20240412"
        scan_context = "file,memory"
        last_modified = "2024-04-12T13:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10424
        version = 4

    strings:
        $proj_1 = "/home/jarischf/"

    condition:
        any of ($proj_*)
}

// MISP event:1320 uuid:61f4257b-e5c0-44f2-aa03-2c29692a31cb org: to_ids:True tags:[]
rule hacktool_golang_reversessh_fahrj
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-10"
        description = "Detects a reverse SSH utility available on GitHub. Attackers may use this tool or similar tools in post-exploitation activity."
        hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
        os = "all"
        os_arch = "all"
        reference = "https://github.com/Fahrj/reverse-ssh"
        report = "TIB-20240412"
        scan_context = "file,memory"
        last_modified = "2024-04-12T13:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10423
        version = 5

    strings:
        $fun_1 = "createLocalPortForwardingCallback"
        $fun_2 = "createReversePortForwardingCallback"
        $fun_3 = "createPasswordHandler"
        $fun_4 = "createPublicKeyHandler"
        $fun_5 = "createSFTPHandler"
        $fun_6 = "dialHomeAndListen"
        $fun_7 = "createExtraInfoHandler"
        $fun_8 = "createSSHSessionHandler"
        $fun_9 = "createReversePortForwardingCallback"

        $proj_1 = "github.com/Fahrj/reverse-ssh"

    condition:
        any of ($proj_*) or
        4 of ($fun_*)
}

// MISP event:1347 uuid:24f56a69-6897-46dd-8d1e-29a0492c5f8a org: to_ids:True tags:[]
rule Backdoor_GHOSTSPIDER_beacon_loader
{
    meta:
        author = "Trend Micro Research"

    strings:
        $clr = {
			C7 45 ?? 43 4C 52 43
			C7 45 ?? 72 65 61 74
			C7 45 ?? 65 49 6E 73
			C7 45 ?? 74 61 6E 63
		}

        $chunk1 = {
			C1 EA ??
			0F B6 D2
			8B 34 95 ?? ?? ?? ??
			8B 55 ??
			C1 EA ??
			8B 14 95 ?? ?? ?? ??
			C1 E9 ??
			0F B6 F9
			33 34 BD ?? ?? ?? ??
			8B 7D ??
			89 75 ??
			31 55 ??
			0F B6 55 ??
			8B 75 ??
			33 34 95 ?? ?? ?? ??
			8B D3
			33 B0 ?? ?? ?? ??
		}

        $chunk2 = {
            41 0F B6 1B
            41 8B C2
            99
            41 F7 F9
            48 63 C2
            0F B6 4C 05 ??
            44 03 C1
            44 03 C3
        }

    condition:
        uint16(0) == 0x5a4d and
		filesize < 300KB and
        (
            $clr and any of ($chunk*)
        )
}

// MISP event:1347 uuid:01291b43-0a48-4984-b61c-5533f2e49123 org: to_ids:True tags:[]
rule Backdoor_GHOSTSPIDER_stager
{
    meta:
        author = "Trend Micro Research"

    strings:
        $s1 = "new_comp" ascii wide
        $s2 = "del_comp" ascii wide
        $s3 = "new_client" ascii wide
        $s4 = "del_client" ascii wide
        $s5 = "new_base" ascii wide
        $s6 = "del_base" ascii wide
        $cookie = "phpsessid=%s; b=%d; path=/; expires=%s" ascii wide

    condition:
        uint16(0) == 0x5a4d and
        filesize < 300KB and
        (
            $cookie and 2 of ($s*)
        )
}

// MISP event:1355 uuid:51cf56e8-7f81-47c0-b992-2c67c9a53704 org: to_ids:True tags:[]
rule APT_serbia_novispy_android_accesibilityservice {
    meta:
        description = "Rule for Serbian NoviSpy Android spyware APK, com.accesibilityservice version"
        author = "Donncha O Cearbhaill, Amnesty International"
        sample = "99673ce7f10e938ed73ed4a99930fbd6499983caa7a2c1b9e3f0e0bb0a5df602"

    strings:
        $dex = { 64 65 78 0A 30 33 ?? 00 }

        // C2 communication
        $c2_1 = "195.178.51.251"
        $c2_2 = "79.101.110.108"
        $c2_3 = "188.93.127.34"

        // Unique Strings
        $u_1 = "kataklinger vibercajzna" ascii nocase
        $u_2 = "select action_command.* from action_command where action_id = ? and trigger_type = ?" ascii nocase
        $u_3 = "6FDF20EAFA2D58AF609C72AE7092BB45" ascii nocase
        $u_4 = "{\"cellChangeMonitoring\":true,\"signalStrengthMonitoring\":true,\"temperatureDelta\":1," ascii nocase
        $u_5 = "{\"fileUpload\":false,\"audioRecording\":false,\"cellChangeMonitoring\":true,"ascii nocase
        $u_6 = "\"serverIp\":\"188.93.127.34\"" ascii nocase
        $u_7 = "ucitavanjepodataka" ascii nocase

        // Other strings
        $s_1 = "test.dat" ascii
        $s_2 = "/active.config" ascii
        $s_3 = "message_map.ser" ascii
        $s_4 = "event type =" ascii
        $s_5 = "change type subtree" ascii
        $s_6 = "change type content description" ascii
        $s_7 = "change type pane title" ascii
        $s_8 = "content change type pane_appeared" ascii
        $s_9 = "window state changed" ascii
        $s_10 = "notification state changed" ascii
        $s_11 = "window content changed" ascii
        $s_12 = "view scrolled" ascii
        $s_13 = "type selection changed" ascii
        $s_14 = "type announcement" ascii
        $s_15 = "scroll position =" ascii
        $s_16 = "imei=%s;imsi=%s;phone=%s;sim_serial=%s;os=%s"
        $s_17 = "imei=%s;imsi=%s;phone=%s;sim_serial=%s;roaming=%s;os=%s"
        $s_18 = "last message = %s, level = %d, hash = %s, node count = %d"
        $s_19 = "MyAccessibilityService"

    condition:
        $dex at 0 and (
          any of ($u*) or
          any of ($c2*) or
          7 of ($s*)
        )
  }

// MISP event:1355 uuid:2367e2de-1cc4-49d4-be57-1fc4b45cc43b org: to_ids:True tags:[]
rule APT_serbia_novispy_android_serv_services  {
    meta:
        description = "Rule for Serbian NoviSpy Android spyware APK, com.serv.services version"
        author = "Donncha O Cearbhaill, Amnesty International"
        sample = "087fc1217c897033425fe7f1f12b913cd48918c875e99c25bdb9e1ffcf80f57e"

    strings:
        $dex = { 64 65 78 0A 30 33 ?? 00 }

        // C2 communication
        $c2_comm_1 = "178.220.122.57"

        // Unique Strings


        // C2 commands received via SMS
        $sms_c2_cmd_1 = "C_ARF" ascii
        $sms_c2_cmd_2 = "C_ARN" ascii
        $sms_c2_cmd_3 = "C_AWF" ascii
        $sms_c2_cmd_4 = "C_AWI" ascii
        $sms_c2_cmd_5 = "C_AWN" ascii
        $sms_c2_cmd_6 = "C_CRF" ascii
        $sms_c2_cmd_7 = "C_CRN" ascii
        $sms_c2_cmd_8 = "C_LCW" ascii
        $sms_c2_cmd_9 = "C_MNS" ascii
        $sms_c2_cmd_10 = "C_MXS" ascii
        $sms_c2_cmd_11 = "C_R_F" ascii
        $sms_c2_cmd_12 = "C_R_N" ascii
        $sms_c2_cmd_13 = "C_SMF" ascii
        $sms_c2_cmd_14 = "C_SMN" ascii
        $sms_c2_cmd_15 = "C_SWF" ascii
        $sms_c2_cmd_16 = "C_SWN" ascii
        $sms_c2_cmd_17 = "C_UIR" ascii
        $sms_c2_cmd_18 = "C_UMF" ascii
        $sms_c2_cmd_19 = "C_UMN" ascii
        $sms_c2_cmd_20 = "C_UWF" ascii
        $sms_c2_cmd_21 = "C_UWN" ascii
        $sms_c2_cmd_22 = "C_WLF" ascii
        $sms_c2_cmd_23 = "C_WLN" ascii

        // C2 commands received via FTP.
        // This is not a comprehensive list of commands, generic command names are excluded to prevent false positives.
        $ftp_c2_cmd_1 = "CALL_REC_OFF" ascii
        $ftp_c2_cmd_2 = "CALL_REC_ON" ascii
        $ftp_c2_cmd_3 = "CHARGING_REC_OFF" ascii
        $ftp_c2_cmd_4 = "CHARGING_REC_ON" ascii
        $ftp_c2_cmd_5 = "SECURE_REC_OFF" ascii
        $ftp_c2_cmd_6 = "SECURE_REC_ON" ascii
        $ftp_c2_cmd_7 = "SSD_MOBILE_OFF" ascii
        $ftp_c2_cmd_8 = "SSD_MOBILE_ON" ascii
        $ftp_c2_cmd_9 = "SSD_WIFI_OFF" ascii
        $ftp_c2_cmd_10 = "SSD_WIFI_ON" ascii
        $ftp_c2_cmd_11 = "UPLOAD_INTERVAL" ascii
        $ftp_c2_cmd_12 = "UPLOAD_MOBILE_OFF" ascii
        $ftp_c2_cmd_13 = "UPLOAD_MOBILE_ON" ascii
        $ftp_c2_cmd_14 = "UPLOAD_WIFI_OFF" ascii
        $ftp_c2_cmd_15 = "UPLOAD_WIFI_ON" ascii
        $ftp_c2_cmd_16 = "AUTO_WIFI_INTERVAL" ascii
        $ftp_c2_cmd_17 = "WIFI_LOCK_ON" ascii
        $ftp_c2_cmd_18 = "WIFI_LOCK_OFF" ascii
        $ftp_c2_cmd_19 = "AUTO_WIFI_ON" ascii
        $ftp_c2_cmd_20 = "AUTO_WIFI_OFF" ascii
        $ftp_c2_cmd_21 = "START_AUDIO" ascii

        // App local settings configured based on C2 commands.
        $setting_1 = "UIR" ascii
        $setting_2 = "ULW" ascii
        $setting_3 = "ULM" ascii
        $setting_4 = "SSW" ascii
        $setting_5 = "SSM" ascii
        $setting_6 = "CRN" ascii
        $setting_7 = "SRN" ascii
        $setting_8 = "CRC" ascii
        $setting_9 = "MXS" ascii
        $setting_10 = "MNS" ascii
        $setting_11 = "AWF" ascii
        $setting_12 = "AWI" ascii
        $setting_13 = "CHR" ascii
        $setting_14 = "WLS" ascii
        $setting_15 = "A_R_N" ascii
        $setting_16 = "A_R_F" ascii
        $setting_17 = "U_I" ascii
        $setting_18 = "U_W_N" ascii
        $setting_19 = "S_W_N" ascii
        $setting_20 = "U_M_F" ascii
        $setting_21 = "S_M_F" ascii
        $setting_22 = "A_W_F" ascii
        $setting_23 = "A_W_I" ascii
        $setting_24 = "W_L_N" ascii
        $setting_25 = "C_R_F" ascii
        $setting_26 = "CH_R_F" ascii
        $setting_27 = "S_R_N" ascii

    condition:
        $dex at 0 and (
          any of ($c2_comm*) or
          20 of ($sms_c2_cmd*) or
          20 of ($ftp_c2_cmd*) or
          20 of ($setting*)
        )
}

// MISP event:2175 uuid:5fd7bdce-2ea0-4f68-adaa-e42dc0a8ab16 org: to_ids:False tags:[]
// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/sunburst_countermeasures/blob/main/LICENSE.txt
import "pe"

rule APT_Backdoor_SUNBURST_1
{
    meta:
        author = "FireEye"
        description = "This rule is looking for portions of the SUNBURST backdoor that are vital to how it functions. The first signature fnv_xor matches a magic byte xor that the sample performs on process, service, and driver names/paths. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $cmd_regex_encoded = "U4qpjjbQtUzUTdONrTY2q42pVapRgooABYxQuIZmtUoA" wide
        $cmd_regex_plain = { 5C 7B 5B 30 2D 39 61 2D 66 2D 5D 7B 33 36 7D 5C 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 33 32 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 31 36 7D }
        $fake_orion_event_encoded = "U3ItS80rCaksSFWyUvIvyszPU9IBAA==" wide
        $fake_orion_event_plain = { 22 45 76 65 6E 74 54 79 70 65 22 3A 22 4F 72 69 6F 6E 22 2C }
        $fake_orion_eventmanager_encoded = "U3ItS80r8UvMTVWyUgKzfRPzEtNTi5R0AA==" wide
        $fake_orion_eventmanager_plain = { 22 45 76 65 6E 74 4E 61 6D 65 22 3A 22 45 76 65 6E 74 4D 61 6E 61 67 65 72 22 2C }
        $fake_orion_message_encoded = "U/JNLS5OTE9VslKqNqhVAgA=" wide
        $fake_orion_message_plain = { 22 4D 65 73 73 61 67 65 22 3A 22 7B 30 7D 22 }
        $fnv_xor = { 67 19 D8 A7 3B 90 AC 5B }
    condition:
        $fnv_xor and ($cmd_regex_encoded or $cmd_regex_plain) or ( ($fake_orion_event_encoded or $fake_orion_event_plain) and ($fake_orion_eventmanager_encoded or $fake_orion_eventmanager_plain) and ($fake_orion_message_encoded and $fake_orion_message_plain) )
}
rule APT_Backdoor_SUNBURST_2
{
    meta:
        author = "FireEye"
        description = "The SUNBURST backdoor uses a domain generation algorithm (DGA) as part of C2 communications. This rule is looking for each branch of the code that checks for which HTTP method is being used. This is in one large conjunction, and all branches are then tied together via disjunction. The grouping is intentionally designed so that if any part of the DGA is re-used in another sample, this signature should match that re-used portion. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $a = "0y3Kzy8BAA==" wide
        $aa = "S8vPKynWL89PS9OvNqjVrTYEYqNa3fLUpDSgTLVxrR5IzggA" wide
        $ab = "S8vPKynWL89PS9OvNqjVrTYEYqPaauNaPZCYEQA=" wide
        $ac = "C88sSs1JLS4GAA==" wide
        $ad = "C/UEAA==" wide
        $ae = "C89MSU8tKQYA" wide
        $af = "8wvwBQA=" wide
        $ag = "cyzIz8nJBwA=" wide
        $ah = "c87JL03xzc/LLMkvysxLBwA=" wide
        $ai = "88tPSS0GAA==" wide
        $aj = "C8vPKc1NLQYA" wide
        $ak = "88wrSS1KS0xOLQYA" wide
        $al = "c87PLcjPS80rKQYA" wide
        $am = "Ky7PLNAvLUjRBwA=" wide
        $an = "06vIzQEA" wide
        $b = "0y3NyyxLLSpOzIlPTgQA" wide
        $c = "001OBAA=" wide
        $d = "0y0oysxNLKqMT04EAA==" wide
        $e = "0y3JzE0tLknMLQAA" wide
        $f = "003PyU9KzAEA" wide
        $h = "0y1OTS4tSk1OBAA=" wide
        $i = "K8jO1E8uytGvNqitNqytNqrVA/IA" wide
        $j = "c8rPSQEA" wide
        $k = "c8rPSfEsSczJTAYA" wide
        $l = "c60oKUp0ys9JAQA=" wide
        $m = "c60oKUp0ys9J8SxJzMlMBgA=" wide
        $n = "8yxJzMlMBgA=" wide
        $o = "88lMzygBAA==" wide
        $p = "88lMzyjxLEnMyUwGAA==" wide
        $q = "C0pNL81JLAIA" wide
        $r = "C07NzXTKz0kBAA==" wide
        $s = "C07NzXTKz0nxLEnMyUwGAA==" wide
        $t = "yy9IzStOzCsGAA==" wide
        $u = "y8svyQcA" wide
        $v = "SytKTU3LzysBAA==" wide
        $w = "C84vLUpOdc5PSQ0oygcA" wide
        $x = "C84vLUpODU4tykwLKMoHAA==" wide
        $y = "C84vLUpO9UjMC07MKwYA" wide
        $z = "C84vLUpO9UjMC04tykwDAA==" wide
    condition:
        ($a and $b and $c and $d and $e and $f and $h and $i) or ($j and $k and $l and $m and $n and $o and $p and $q and $r and $s and ($aa or $ab)) or ($t and $u and $v and $w and $x and $y and $z and ($aa or $ab)) or ($ac and $ad and $ae and $af and $ag and $ah and ($am or $an)) or ($ai and $aj and $ak and $al and ($am or $an))
}
rule APT_Webshell_SUPERNOVA_1
{
    meta:
        author = "FireEye"
        description = "SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args). This rule is looking for specific strings and attributes related to SUPERNOVA."
    strings:
        $compile1 = "CompileAssemblyFromSource"
        $compile2 = "CreateCompiler"
        $context = "ProcessRequest"
        $httpmodule = "IHttpHandler" ascii
        $string1 = "clazz"
        $string2 = "//NetPerfMon//images//NoLogo.gif" wide
        $string3 = "SolarWinds" ascii nocase wide
    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10KB and pe.imports("mscoree.dll","_CorDllMain") and $httpmodule and $context and all of ($compile*) and all of ($string*)
}
rule APT_Webshell_SUPERNOVA_2
{
    meta:
        author = "FireEye"
        description = "This rule is looking for specific strings related to SUPERNOVA. SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args)."
    strings:
        $dynamic = "DynamicRun"
        $solar = "Solarwinds" nocase
        $string1 = "codes"
        $string2 = "clazz"
        $string3 = "method"
        $string4 = "args"
    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10KB and 3 of ($string*) and $dynamic and $solar
}
rule APT_HackTool_PS1_COSMICGALE_1
{
    meta:
        author = "FireEye"
        description = "This rule detects various unique strings related to COSMICGALE. COSMICGALE is a credential theft and reconnaissance PowerShell script that collects credentials using the publicly available Get-PassHashes routine. COSMICGALE clears log files, writes acquired data to a hard coded path, and encrypts the file with a password."
    strings:
        $sr1 = /\[byte\[\]\]@\([\x09\x20]{0,32}0xaa[\x09\x20]{0,32},[\x09\x20]{0,32}0xd3[\x09\x20]{0,32},[\x09\x20]{0,32}0xb4[\x09\x20]{0,32},[\x09\x20]{0,32}0x35[\x09\x20]{0,32},/ ascii nocase wide
        $sr2 = /\[bitconverter\]::toint32\(\$\w{1,64}\[0x0c..0x0f\][\x09\x20]{0,32},[\x09\x20]{0,32}0\)[\x09\x20]{0,32}\+[\x09\x20]{0,32}0xcc\x3b/ ascii nocase wide
        $sr3 = /\[byte\[\]\]\(\$\w{1,64}\.padright\(\d{1,2}\)\.substring\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}\d{1,2}\)\.tochararray\(\)\)/ ascii nocase wide
        $ss1 = "[text.encoding]::ascii.getbytes(\"ntpassword\x600\");" ascii nocase wide
        $ss2 = "system\\currentcontrolset\\control\\lsa\\$_" ascii nocase wide
        $ss3 = "[security.cryptography.md5]::create()" ascii nocase wide
        $ss4 = "[system.security.principal.windowsidentity]::getcurrent().name" ascii nocase wide
        $ss5 = "out-file" ascii nocase wide
        $ss6 = "convertto-securestring" ascii nocase wide
    condition:
        all of them
}
rule APT_Dropper_Raw64_TEARDROP_1
{
    meta:
        author = "FireEye"
        description = "This rule looks for portions of the TEARDROP backdoor that are vital to how it functions. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
    strings:
        $sb1 = { C7 44 24 ?? 80 00 00 00 [0-64] BA 00 00 00 80 [0-32] 48 8D 0D [4-32] FF 15 [4] 48 83 F8 FF [2-64] 41 B8 40 00 00 00 [0-64] FF 15 [4-5] 85 C0 7? ?? 80 3D [4] FF }
        $sb2 = { 80 3D [4] D8 [2-32] 41 B8 04 00 00 00 [0-32] C7 44 24 ?? 4A 46 49 46 [0-32] E8 [4-5] 85 C0 [2-32] C6 05 [4] 6A C6 05 [4] 70 C6 05 [4] 65 C6 05 [4] 67 }
        $sb3 = { BA [4] 48 89 ?? E8 [4] 41 B8 [4] 48 89 ?? 48 89 ?? E8 [4] 85 C0 7? [1-32] 8B 44 24 ?? 48 8B ?? 24 [1-16] 48 01 C8 [0-32] FF D0 }
    condition:
        all of them
}
rule APT_Dropper_Win64_TEARDROP_1
{
    meta:
        author = "FireEye"
        description = "This rule is intended match specific sequences of opcode found within TEARDROP, including those that decode the embedded payload. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
    strings:
        $loc_4218FE24A5 = { 48 89 C8 45 0F B6 4C 0A 30 }
        $loc_4218FE36CA = { 48 C1 E0 04 83 C3 01 48 01 E8 8B 48 28 8B 50 30 44 8B 40 2C 48 01 F1 4C 01 FA }
        $loc_4218FE2747 = { C6 05 ?? ?? ?? ?? 6A C6 05 ?? ?? ?? ?? 70 C6 05 ?? ?? ?? ?? 65 C6 05 ?? ?? ?? ?? 67 }
        $loc_5551D725A0 = { 48 89 C8 45 0F B6 4C 0A 30 48 89 CE 44 89 CF 48 F7 E3 48 C1 EA 05 48 8D 04 92 48 8D 04 42 48 C1 E0 04 48 29 C6 }
        $loc_5551D726F6 = { 53 4F 46 54 57 41 52 45 ?? ?? ?? ?? 66 74 5C 43 ?? ?? ?? ?? 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

// MISP event:2183 uuid:7caa1494-bcdf-45bf-9757-ddce6dd834c9 org: to_ids:False tags:[]
rule webshell_aspx_sportsball : Webshell Unclassified
{
    meta:
        author = â€œthreatintel@volexity.comâ€
        date = â€œ2021-03-01â€
        description = â€œThe SPORTSBALL webshell allows attackers to upload files or execute commands on the system.â€
        hash = â€œ2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0aâ€
 
    strings:
        $uniq1 = â€œHttpCookie newcook = new HttpCookie(\â€fqrspt\â€, HttpContext.Current.Request.Formâ€
        $uniq2 = â€œZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE=â€
 
        $var1 = â€œResult.InnerText = string.Empty;â€
        $var2 = â€œnewcook.Expires = DateTime.Now.AddDays(â€
        $var3 = â€œSystem.Diagnostics.Process process = new System.Diagnostics.Process();â€
        $var4 = â€œprocess.StandardInput.WriteLine(HttpContext.Current.Request.Form[\â€â€
        $var5 = â€œelse if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\â€â€
        $var6 = â€œ<input type=\â€submit\â€ value=\â€Upload\â€ />â€
 
    condition:
        any of ($uniq*) or
        all of ($var*)
}

// MISP event:2183 uuid:db746cd7-c4e1-4c13-8025-c66dcb75461e org: to_ids:False tags:[]
rule webshell_aspx_reGeorgTunnel : Webshell Commodity
{
    meta:
        author = â€œthreatintel@volexity.comâ€
        date = â€œ2021-03-01â€
        description = â€œA variation on the reGeorg tunnel webshellâ€
        hash = â€œ406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928â€
        reference = â€œhttps://github.com/sensepost/reGeorg/blob/master/tunnel.aspxâ€
 
    strings:
        $s1 = â€œSystem.Net.Socketsâ€
        $s2 = â€œSystem.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Getâ€
        // a bit more experimental
        $t1 = â€œ.Split(â€˜|â€™)â€
        $t2 = â€œRequest.Headers.Getâ€
        $t3 = â€œ.Substring(â€œ
        $t4 = â€œnew Socket(â€œ
        $t5 = â€œIPAddress ip;â€
 
    condition:
        all of ($s*) or
        all of ($t*)
}

// MISP event:2183 uuid:761b7175-fdab-45b0-a6a0-b1a3fa5f94e6 org: to_ids:False tags:[]
rule webshell_aspx_simpleseesharp : Webshell Unclassified
{
    meta:
        author = â€œthreatintel@volexity.comâ€
        date = â€œ2021-03-01â€
        description = â€œA simple ASPX Webshell that allows an attacker to write further files to disk.â€
        hash = â€œ893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2â€
 
    strings:
        $header = â€œ<%@ Page Language=\â€C#\â€ %>â€
        $body = â€œ<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combineâ€
 
    condition:
        $header at 0 and
        $body and
        filesize < 1KB
}

// MISP event:2185 uuid:f4c67e85-6e71-408a-8d9d-f1d5edddab40 org: to_ids:False tags:[]
rule Backdoor_Win_C3_1
{
    meta:
        author = â€œFireEyeâ€
        date_created = "2021-05-11"
        description = "Detection to identify the Custom Command and Control (C3) binaries."
        md5 = "7cdac4b82a7573ae825e5edb48f80be5"
    strings:
        $dropboxAPI = "Dropbox-API-Arg"
        $knownDLLs1 = "WINHTTP.dll" fullword
        $knownDLLs2 = "SHLWAPI.dll" fullword
        $knownDLLs3 = "NETAPI32.dll" fullword
        $knownDLLs4 = "ODBC32.dll" fullword
        $tokenString1 = { 5B 78 5D 20 65 72 72 6F 72 20 73 65 74 74 69 6E 67 20 74 6F 6B 65 6E }
        $tokenString2 = { 5B 78 5D 20 65 72 72 6F 72 20 63 72 65 61 74 69 6E 67 20 54 6F 6B 65 6E }
        $tokenString3 = { 5B 78 5D 20 65 72 72 6F 72 20 64 75 70 6C 69 63 61 74 69 6E 67 20 74 6F 6B 65 6E }
    condition:
        filesize < 5MB and uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and (((all of ($knownDLLs*)) and ($dropboxAPI or (1 of ($tokenString*)))) or (all of ($tokenString*)))

// MISP event:2185 uuid:e9e8c009-3b79-4af3-91a1-784d5a5397aa org: to_ids:False tags:[]
rule Dropper_Win_Darkside_1
{
    meta:
        author = "FireEye"
        date_created = "2021-05-11"
        description = "Detection for on the binary that was used as the dropper leading to DARKSIDE."
    strings:
        $CommonDLLs1 = "KERNEL32.dll" fullword
        $CommonDLLs2 = "USER32.dll" fullword
        $CommonDLLs3 = "ADVAPI32.dll" fullword
        $CommonDLLs4 = "ole32.dll" fullword
        $KeyString1 = { 74 79 70 65 3D 22 77 69 6E 33 32 22 20 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E 57 69 6E 64 6F 77 73 2E 43 6F 6D 6D 6F 6E 2D 43 6F 6E 74 72 6F 6C 73 22 20 76 65 72 73 69 6F 6E 3D 22 36 2E 30 2E 30 2E 30 22 20 70 72 6F 63 65 73 73 6F 72 41 72 63 68 69 74 65 63 74 75 72 65 3D 22 78 38 36 22 20 70 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 22 36 35 39 35 62 36 34 31 34 34 63 63 66 31 64 66 22 }
        $KeyString2 = { 74 79 70 65 3D 22 77 69 6E 33 32 22 20 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E 56 43 39 30 2E 4D 46 43 22 20 76 65 72 73 69 6F 6E 3D 22 39 2E 30 2E 32 31 30 32 32 2E 38 22 20 70 72 6F 63 65 73 73 6F 72 41 72 63 68 69 74 65 63 74 75 72 65 3D 22 78 38 36 22 20 70 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 22 31 66 63 38 62 33 62 39 61 31 65 31 38 65 33 62 22 }
        $Slashes = { 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C }
    condition:
        filesize < 2MB and filesize > 500KB and uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and (all of ($CommonDLLs*)) and (all of ($KeyString*)) and $Slashes

// MISP event:2185 uuid:99f25851-feb2-492f-b932-cb989ba3bc64 org: to_ids:False tags:[]
rule Ransomware_Win_DARKSIDE_v1__1
{
    meta:
        author = â€œFireEyeâ€
        date_created = â€œ2021-03-22â€
        description = â€œDetection for early versions of DARKSIDE ransomware samples based on the encryption mode configuration values.â€
        md5 = â€œ1a700f845849e573ab3148daef1a3b0bâ€   
    strings:
        $consts = { 80 3D [4] 01 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] 00 00 04 00 [1-10] 00 00 00 00 [1-30] 80 3D [4] 02 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] FF FF FF FF [1-10] FF FF FF FF [1-30] 03 00 00 00 [1-10] 03 00 00 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $consts
}

// MISP event:2186 uuid:8a30fd31-438b-4232-81a3-0d6d55e018da org: to_ids:False tags:[]
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-05-09
Identifier: 3584
Reference: https://thedfirreport.com
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule icedid_rate_x32 {
meta:
description = "files - file rate_x32.dat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "eb79168391e64160883b1b3839ed4045b4fd40da14d6eec5a93cfa9365503586"
strings:
$s1 = "UAWAVAUATVWSH" fullword ascii
$s2 = "UAWAVVWSPH" fullword ascii
$s3 = "AWAVAUATVWUSH" fullword ascii
$s4 = "update" fullword ascii /* Goodware String - occured 207 times */
$s5 = "?klopW@@YAHXZ" fullword ascii
$s6 = "?jutre@@YAHXZ" fullword ascii
$s7 = "PluginInit" fullword ascii
$s8 = "[]_^A\\A]A^A_" fullword ascii
$s9 = "e8[_^A\\A]A^A_]" fullword ascii
$s10 = "[_^A\\A]A^A_]" fullword ascii
$s11 = "Kts=R,4iu" fullword ascii
$s12 = "mqr55c" fullword ascii
$s13 = "R,4i=Bj" fullword ascii
$s14 = "Ktw=R,4iu" fullword ascii
$s15 = "Ktu=R,4iu" fullword ascii
$s16 = "Kt{=R,4iu" fullword ascii
$s17 = "KVL.Mp" fullword ascii
$s18 = "Kt|=R,4iu" fullword ascii
$s19 = "=8c[Vt8=" fullword ascii
$s20 = "Ktx=R,4iu" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 700KB and
( pe.imphash() == "15787e97e92f1f138de37f6f972eb43c" and ( pe.exports("?jutre@@YAHXZ") and pe.exports("?klopW@@YAHXZ") and pe.exports("PluginInit") and pe.exports("update") ) or 8 of them )
}

rule conti_cobaltstrike_192145 {
meta:
description = "files - file 192145.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "29bc338e63a62c24c301c04961084013816733dad446a29c20d4413c5c818af9"
strings:
$x1 = "cmd.exe /c echo NGAtoDgLpvgJwPLEPFdj>\"%s\"&exit" fullword ascii
$s2 = "veniamatquiest90.dll" fullword ascii
$s3 = "Quaerat magni assumenda nihil architecto labore ullam autem unde temporibus mollitia illum" fullword ascii
$s4 = "Quaerat tempora culpa provident" fullword ascii
$s5 = "Velit consequuntur quisquam tempora error" fullword ascii
$s6 = "Quo omnis repellat ut expedita temporibus eius fuga error" fullword ascii
$s7 = "Dolores ullam tempora error distinctio ut natus facere quibusdam" fullword ascii
$s8 = "Corporis minima omnis qui est temporibus sint quo error magnam" fullword ascii
$s9 = "Officia sit maiores deserunt nobis tempora deleniti aut et quidem fugit" fullword ascii
$s10 = "Rerum tenetur sapiente est tempora qui deserunt" fullword ascii
$s11 = "Sed nulla quaerat porro error excepturi" fullword ascii
$s12 = "Aut tempore quo cumque dicta ut quia in" fullword ascii
$s13 = "Doloribus commodi repudiandae voluptates consequuntur neque tempora ut neque nemo ad ut" fullword ascii
$s14 = "Tempore possimus aperiam nam mollitia illum hic at ut doloremque" fullword ascii
$s15 = "Dolorum eum ipsum tempora non et" fullword ascii
$s16 = "Quas alias illum laborum tempora sit est rerum temporibus dicta et" fullword ascii
$s17 = "Et quia aut temporibus enim repellat dolores totam recusandae repudiandae" fullword ascii
$s18 = "Sed velit ipsa et dolor tempore sunt nostrum" fullword ascii
$s19 = "Veniam voluptatem aliquam et eaque tempore tenetur possimus" fullword ascii
$s20 = "Possimus suscipit placeat dolor quia tempora voluptas qui fugiat et accusantium" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "5cf3cdfe8585c01d2673249153057181" and pe.exports("StartW") or ( 1 of ($x*) or 4 of them ) )
}

rule conti_cobaltstrike_icju1 {
meta:
description = "files - file icju1.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "e54f38d06a4f11e1b92bb7454e70c949d3e1a4db83894db1ab76e9d64146ee06"
strings:
$x1 = "cmd.exe /c echo NGAtoDgLpvgJwPLEPFdj>\"%s\"&exit" fullword ascii
$s2 = "veniamatquiest90.dll" fullword ascii
$s3 = "Quaerat magni assumenda nihil architecto labore ullam autem unde temporibus mollitia illum" fullword ascii
$s4 = "Quaerat tempora culpa provident" fullword ascii
$s5 = "Velit consequuntur quisquam tempora error" fullword ascii
$s6 = "Quo omnis repellat ut expedita temporibus eius fuga error" fullword ascii
$s7 = "Dolores ullam tempora error distinctio ut natus facere quibusdam" fullword ascii
$s8 = "Corporis minima omnis qui est temporibus sint quo error magnam" fullword ascii
$s9 = "Officia sit maiores deserunt nobis tempora deleniti aut et quidem fugit" fullword ascii
$s10 = "Rerum tenetur sapiente est tempora qui deserunt" fullword ascii
$s11 = "Sed nulla quaerat porro error excepturi" fullword ascii
$s12 = "Aut tempore quo cumque dicta ut quia in" fullword ascii
$s13 = "Doloribus commodi repudiandae voluptates consequuntur neque tempora ut neque nemo ad ut" fullword ascii
$s14 = "Tempore possimus aperiam nam mollitia illum hic at ut doloremque" fullword ascii
$s15 = "Dolorum eum ipsum tempora non et" fullword ascii
$s16 = "Quas alias illum laborum tempora sit est rerum temporibus dicta et" fullword ascii
$s17 = "Et quia aut temporibus enim repellat dolores totam recusandae repudiandae" fullword ascii
$s18 = "Sed velit ipsa et dolor tempore sunt nostrum" fullword ascii
$s19 = "Veniam voluptatem aliquam et eaque tempore tenetur possimus" fullword ascii
$s20 = "Possimus suscipit placeat dolor quia tempora voluptas qui fugiat et accusantium" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "a6d9b7f182ef1cfe180f692d89ecc759" or ( 1 of ($x*) or 4 of them ) )
}

rule conti_v3 {

meta:
description = "conti_yara - file conti_v3.dll" 
author = "pigerlin" 
reference = "https://thedfirreport.com" 
date = "2021-05-09" 
hash1 = "8391dc3e087a5cecba74a638d50b771915831340ae3e027f0bb8217ad7ba4682"

strings: 
$s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
$s2 = "conti_v3.dll" fullword ascii 
$s3 = " <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii 
$s4 = " Type Descriptor'" fullword ascii 
$s5 = "operator co_await" fullword ascii 
$s6 = " <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii 
$s7 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide 
$s8 = " Base Class Descriptor at (" fullword ascii 
$s9 = " Class Hierarchy Descriptor'" fullword ascii 
$s10 = " Complete Object Locator'" fullword ascii 
$s11 = " delete[]" fullword ascii 
$s12 = " </trustInfo>" fullword ascii 
$s13 = "__swift_1" fullword ascii 
$s15 = "__swift_2" fullword ascii 
$s19 = " delete" fullword ascii

condition:
uint16(0) == 0x5a4d and filesize < 700KB and
all of them

}


rule conti_cobaltstrike_192145_icju1_0 {
meta:
description = "files - from files 192145.dll, icju1.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "29bc338e63a62c24c301c04961084013816733dad446a29c20d4413c5c818af9"
hash2 = "e54f38d06a4f11e1b92bb7454e70c949d3e1a4db83894db1ab76e9d64146ee06"
strings:
$x1 = "cmd.exe /c echo NGAtoDgLpvgJwPLEPFdj>\"%s\"&exit" fullword ascii
$s2 = "veniamatquiest90.dll" fullword ascii
$s3 = "Quaerat magni assumenda nihil architecto labore ullam autem unde temporibus mollitia illum" fullword ascii
$s4 = "Quaerat tempora culpa provident" fullword ascii
$s5 = "Dolores ullam tempora error distinctio ut natus facere quibusdam" fullword ascii
$s6 = "Velit consequuntur quisquam tempora error" fullword ascii
$s7 = "Corporis minima omnis qui est temporibus sint quo error magnam" fullword ascii
$s8 = "Quo omnis repellat ut expedita temporibus eius fuga error" fullword ascii
$s9 = "Officia sit maiores deserunt nobis tempora deleniti aut et quidem fugit" fullword ascii
$s10 = "Rerum tenetur sapiente est tempora qui deserunt" fullword ascii
$s11 = "Sed nulla quaerat porro error excepturi" fullword ascii
$s12 = "Aut tempore quo cumque dicta ut quia in" fullword ascii
$s13 = "Doloribus commodi repudiandae voluptates consequuntur neque tempora ut neque nemo ad ut" fullword ascii
$s14 = "Tempore possimus aperiam nam mollitia illum hic at ut doloremque" fullword ascii
$s15 = "Et quia aut temporibus enim repellat dolores totam recusandae repudiandae" fullword ascii
$s16 = "Dolorum eum ipsum tempora non et" fullword ascii
$s17 = "Quas alias illum laborum tempora sit est rerum temporibus dicta et" fullword ascii
$s18 = "Sed velit ipsa et dolor tempore sunt nostrum" fullword ascii
$s19 = "Veniam voluptatem aliquam et eaque tempore tenetur possimus" fullword ascii
$s20 = "Possimus suscipit placeat dolor quia tempora voluptas qui fugiat et accusantium" fullword ascii
condition:
( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
) or ( all of them )
}

// MISP event:2202 uuid:ebf3bbba-7671-420c-844c-a81ca0aeb7fe org: to_ids:False tags:[]
rule JsOutProx_v2 { 


meta: 
      description = "Yara Rule for JsOutProx_v2" 
      author = "Yoroi Malware Zlab" 
      last_updated = "2021_07_29" 
      tlp = "white" 
      category = "informational" 
 

strings: 
    $s1= /uA\[[a-zA-Z]/ ascii wide
    $s2= /u[A-Z]\(/ ascii wide


condition: 
    #s1>800 and #s2>4000 and (filesize > 1500KB)
    
}

// MISP event:2204 uuid:820e79e9-0a6e-4f1b-8f28-8ebb9c09850e org: to_ids:False tags:[]
import "pe"

rule apt_ZZ_MeteorExpress_wiper_broad 
{
	meta:
		desc = "Meteor wiper - broad hunting rule"
		author = "JAG-S @ SentinelLabs"
		version = "1.0"
		last_modified = "07.23.2021"
		hash = "2aa6e42cb33ec3c132ffce425a92dfdb5e29d8ac112631aec068c8a78314d49b"
	strings:
		$meteor1 = "Meteor is still alive." ascii wide
		$meteor2 = "Meteor has finished. This shouldn't be possible because of the is-alive loop." ascii wide
		$meteor3 = "Meteor has started." ascii wide

		$rtti1 = ".?AVBlackHoleException@@" ascii wide
		$rtti2 = ".?AVWiperException@@" ascii wide
		$rtti3 = ".?AVMiddleWiperException@@" ascii wide
		$rtti4 = ".?AVCMDException@@" ascii wide
		$rtti5 = ".?AVCouldNotFindNewWinlogonException@@" ascii wide
		$rtti6 = ".?AVLockScreenException@@" ascii wide
		$rtti7 = ".?AVScreenSaverException@@" ascii wide
		$rtti8 = ".?AVFailedToIsolateFromDomainWinapiException@@" ascii wide
		$rtti9 = ".?AVFailedToIsolateFromDomainWmiException@@" ascii wide
		$rtti10 = ".?AVSettingPasswordException@@" ascii wide
		$rtti11 = ".?AVPasswordChangerException@@" ascii wide
		$rtti12 = ".?AVEnumeratingUsersException@@" ascii wide
		$rtti13 = ".?AVProcessTerminationFailedException@@" ascii wide
		$rtti14 = ".?AVProcessNotTerminatedException@@" ascii wide
		$rtti15 = ".?AVFirstProcessWasNotFoundException@@" ascii wide
		$rtti16 = ".?AVProcessSnapshotCreationFailedException@@" ascii wide
		$rtti17 = ".?AVProcessTerminatorException@@" ascii wide
		$rtti18 = ".?AVOpenProcessFailedException@@" ascii wide
		$rtti19 = ".?AVFailedToLockException@@" ascii wide
		$rtti20 = ".?AVLockerException@@" ascii wide
		$rtti21 = ".?AVBCDException@@" ascii wide
		$rtti22 = ".?AVCouldNotCreateProcessException@@" ascii wide
		$rtti23 = ".?AVPipeNotCreatedCMDException@@" ascii wide

		$config_keys1 = "state_path" ascii wide fullword
		$config_keys2 = "log_encryption_key" ascii wide fullword
		$config_keys3 = "processes_to_kill" ascii wide fullword
		$config_keys4 = "process_termination_timeout" ascii wide fullword
		$config_keys5 = "log_server_port" ascii wide fullword
		$config_keys6 = "locker_background_image_jpg_path" ascii wide fullword
		$config_keys7 = "auto_logon_path" ascii wide fullword
		$config_keys8 = "locker_background_image_bmp_path" ascii wide fullword
		$config_keys9 = "state_encryption_key" ascii wide fullword
		$config_keys10 = "log_server_ip" ascii wide fullword
		$config_keys11 = "log_file_path" ascii wide fullword
		$config_keys12 = "paths_to_wipe" ascii wide fullword
		$config_keys13 = "wiping_stage_logger_interval" ascii wide fullword
		$config_keys14 = "locker_installer_path" ascii wide fullword
		$config_keys15 = "locker_exe_path" ascii wide fullword
		$config_keys16 = "locker_registry_settings_files" ascii wide fullword
		$config_keys17 = "locker_password_hash" ascii wide fullword
		$config_keys18 = "users_password" ascii wide fullword
		$config_keys19 = "cleanup_scheduled_task_name" ascii wide fullword
		$config_keys20 = "self_scheduled_task_name" ascii wide fullword
		$config_keys21 = "cleanup_script_path" ascii wide fullword
		$config_keys22 = "is_alive_loop_interval" ascii wide fullword		

		$failure1 = "failed to initialize configuration from file %s" ascii wide
		$failure2 = "Failed to find base-64 data size. Error code: %s." ascii wide
		$failure3 = "Failed to encode wide-character string as Base64. Error code: %s." ascii wide
		$failure4 = "Failed to generate password of length %s. Generating a default one." ascii wide
		$failure5 = "Failed creating scheduled task for system with name %s." ascii wide
		$failure6 = "Failed to add a new administrator: %s." ascii wide
		$failure7 = "Failed logging off session: %s" ascii wide
		$failure8 = "Failed creating scheduled task with name %s for user %s." ascii wide
		$failure9 = "Failed to wipe file %s" ascii wide
		$failure10 = "Failed to create thread. Error message: %s" ascii wide
		$failure11 = "failed to get configuration value with key %s" ascii wide
		$failure12 = "failed to parse the configuration from file %s" ascii wide
		$failure13 = "Failed to create handle. Error code %s" ascii wide
		$failure14 = "failed to write message to log file %s" ascii wide
		$failure15 = "Getting new winlogon session failed. Attempts: %s/%s" ascii wide
		$failure16 = "Failed creating processes snapshot, process name: %s, error code %s." ascii wide
		$failure17 = "Failed to query process info from snapshot. Process name: %s, error code: %s." ascii wide
		$failure18 = "Failed to add new user %s. Error code %s." ascii wide
		$failure19 = "Failed opening process, process name: %s, error code %s." ascii wide
		$failure20 = "Failed to open the access token of a process. Error code: %s" ascii wide
		$failure21 = "Failed to enumerate local WTS. The error code: %s" ascii wide
		$failure22 = "Failed to duplicate the access token of a process. Error code: %s" ascii wide
		$failure23 = "Failed to query the session id of a given token. Error code: %s." ascii wide
		$failure24 = "Failed to add user %s to group %s. Error code %s" ascii wide
		$failure25 = "Failed to set value for key %s. Error code: %s." ascii wide
		$failure26 = "Failed to retrieve subkey of HKEY_USER. index is %s. error code %s." ascii wide
		$failure27 = "Failed to disable rotating lock screen for user %s." ascii wide
		$failure28 = "Failed to isolate from domain using wmi. Error code: %s." ascii wide
		$failure29 = "Failed to isolate from domain using winapi. Error code %s" ascii wide
		$failure30 = "Failed while trying to wipe files: %s" ascii wide
		$failure31 = "Failed to change password for user %s. Error code %s." ascii wide
		$failure32 = "Failed to get network info. Error code %s" ascii wide
		$failure33 = "Failed to open process. Pid: %s, error code: %s" ascii wide
		$failure34 = "Failed to terminate process. Pid: %s, error code: %s" ascii wide
		$failure35 = "Failed to create a snapshot of the running processes. Error code: %s." ascii wide
		$failure36 = "Failed to delete locker lock screen, path %s" ascii wide
		$failure37 = "Failed to delete locker uninstaller from path %s" ascii wide
		$failure38 = "Failed to flush key %s: %s." ascii wide
		$failure39 = "Gfailed to parse json from file %s" ascii wide
		$failure40 = "failed to read from json file %s" ascii wide
		$failure41 = "Failed to wait for a mutex. the return value was: %s." ascii wide
		$failure42 = "Waiting for process failed. Error: %s" ascii wide
		$failure43 = "Failed to open key %s, with error %s." ascii wide
		$failure44 = "Failed to query information of hkey %s." ascii wide
		$failure45 = "Failed to get value for key %s. Failed with error code %s" ascii wide
		$failure46 = "Failed disabling wow 64 redirection mechanism. Error code %s" ascii wide
		$failure47 = "Failed getting  %s module. Error code %s" ascii wide
		$failure48 = "Failed retrieving method address, method name: %s. Error code %s" ascii wide
		$failure49 = "Failed to adjust access token privileges." ascii wide
		$failure50 = "Failed to retrieve LUID for a privilege name in local system." ascii wide
		$failure51 = "Failed to initiate reboot." ascii wide
		$failure52 = "Failed to retrieve process token." ascii wide
		$failure53 = "Failed to change lock screen in Windows XP." ascii wide
		$failure54 = "Failed to register auto logon" ascii wide
		$failure55 = "Failed to change lock screen in Windows 7." ascii wide
		$failure56 = "Failed to change lock screen in Windows 10." ascii wide
		$failure57 = "PLocker failed" ascii wide
		$failure58 = "Failed to isolate from domain using wmi because command couldn't run" ascii wide
		$failure59 = "Failed to parse domain and username data." ascii wide
		$failure60 = "Failed to run the locker" ascii wide
		$failure61 = "Failed to find default browser" ascii wide
		$failure62 = "Failed to install locker" ascii wide
		$failure63 = "Failed to terminate the locker process." ascii wide
		$failure64 = "Failed to import locker settings" ascii wide
		$failure65 = "Failed to set locker settings." ascii wide
		$failure66 = "Failed to lock" ascii wide
		$failure67 = "Failed to create mutex." ascii wide
		$failure68 = "Supplier failed while iterating filter functions that check if a file is valid." ascii wide
		$failure69 = "Supplier failed while filtering an existing target." ascii wide
		$failure70 = "Supplier failed while filtering a potential target." ascii wide
		$failure72 = "Wiper operation failed." ascii wide
		$failure73 = "Screen saver disable failed." ascii wide
		$failure74 = "Failed to delete boot configuration" ascii wide
		$failure75 = "Failed to change lock screen" ascii wide
		$failure76 = "Failed to kill all winlogon processes" ascii wide
		$failure77 = "Process terminator failed" ascii wide
		$failure78 = "Failed to change the passwords of all users" ascii wide
		$failure79 = "Failed to run the locker thread" ascii wide
		$failure80 = "Generating random password failed" ascii wide
		$failure81 = "Locker installation failed" ascii wide
		$failure82 = "Failed to set auto logon." ascii wide
		$failure83 = "Failed to initialize interval logger. Using a dummy logger instead." ascii wide
		$failure84 = "Failed disabling the first logon privacy settings user approval." ascii wide
		$failure85 = "Failed disabling the first logon animation." ascii wide
		$failure86 = "Failed to isolate from domain" ascii wide
		$failure87 = "Failed to get the new token of winlogon." ascii wide
		$failure88 = "Failed adding new admin user." ascii wide
		$failure89 = "Failed changing settings for the created new user." ascii wide
		$failure90 = "Failed disabling recovery mode." ascii wide
		$failure91 = "Failed to log off all sessions" ascii wide
		$failure92 = "Failed to delete shadowcopies." ascii wide
		$failure93 = "Failed setting boot policy to ignore all errors." ascii wide
		$failure94 = "Failed logging off all local sessions, except winlogon." ascii wide

		$log1 = "Succeeded loggingoff session: %s" ascii wide fullword
		$log2 = "Logging off all local sessions, except winlogon." ascii wide fullword
		$log3 = "Logging off all sessions." ascii wide fullword
		$log4 = "Logging off users on Windows version 8 or above" ascii wide fullword
		$log5 = "Logging off users in Windows 7" ascii wide fullword
		$log6 = "Logging off users in Windows XP" ascii wide fullword
		$log7 = "End interval logger. Resuming writing every log." ascii wide fullword
		$log8 = "Exiting main function because of some error" ascii wide fullword

		$lockMyPC1 = "C:\\Program Files\\Lock My PC 4\\unins000.exe" ascii wide fullword
		$lockMyPC2 = "SOFTWARE\\FSPro Labs\\Lock My PC 4" ascii wide fullword
		$lockMyPC3 = "C:\\Program Files\\Lock My PC 4\\LockScreens\\lockscreen2.jpg" ascii wide fullword
		$lockMyPC4 = "C:\\Program Files\\Lock My PC 4\\LockScreens\\lockscreen1.jpg" ascii wide fullword
		$lockMyPC5 = "C:\\Program Files\\Lock My PC 4\\LockScreens\\lockscreen4.jpg" ascii wide fullword
		$lockMyPC6 = "C:\\Program Files\\Lock My PC 4\\LockScreens\\lockscreen3.jpg" ascii wide fullword
		$lockMyPC7 = "C:\\Program Files\\Lock My PC 4\\LockScreens\\lockscreen6_r.gif" ascii wide fullword
		$lockMyPC8 = "C:\\Program Files\\Lock My PC 4\\LockScreens\\lockscreen5_b.gif" ascii wide fullword

		$bcd1 = "bcdedit.exe /set {default} recoveryenabled no" ascii wide fullword
		$bcd2 = "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" ascii wide fullword
		$bcd3 = "sCould not delete BCD entry. Identifier: %s" ascii wide fullword
		$bcd4 = "Could not delete all BCD entries." ascii wide fullword
		$bcd5 = "Finished deleting BCD entries." ascii wide fullword
		$bcd6 = "Reached maximum number of BCD entry deletion attempts." ascii wide fullword
		$bcd7 = "Could not get BCD entries." ascii wide fullword
		$bcd8 = "bcd00000000\\objects" ascii wide fullword

		$password1 = "Changing passwords of all users to %s" ascii wide fullword
		$password2 = "Succeeded adding new user %s with password %s." ascii wide fullword
		$password3 = "Changed the password of local user %s to %s." ascii wide fullword
		$password4 = "The password's length is smaller than the complex prefix. Returning a fixed prefix." ascii wide fullword

		$boot1 = "default=multi(0)disk(10000000)rdisk(0)partition(1000000)\\WINDOWS" ascii wide
		$boot2 = "multi(0)disk(10000000)rdisk(0)partition(1000000)\\WINDOWS=\"Microsoft Windows XP Professional\" /noexecute=optin /fastdetect" ascii wide

		$success1 = "Succeeded setting auto logon for %s." ascii wide fullword
		$success2 = "Succeeded creating scheduled task for system with name %s." ascii wide fullword
		$success3 = "Succeeded creating scheduled task with name %s for user %s." ascii wide fullword
		$success4 = "Unsuccessful exit code returned from cmd: %s. Exit code: %s." ascii wide fullword
		$success5 = "Succeeded adding new user %s to group %s." ascii wide fullword
		$success6 = "Successfully disabled rotating lock screen saver of user %s." ascii wide fullword
		$success7 = "Successfully removed %s from lock screen directory." ascii wide fullword
		$success8 = "Terminated process successfully. process name: %s, pid: %s" ascii wide fullword
		$success9 = "Process created successfully. Executed command: %s." ascii wide fullword
		$success10 = "Success restarting machine using cmd." ascii wide fullword
		$success11 = "Successfully changed lock screen image in Windows 7" ascii wide fullword
		$success12 = "Successfully changed lock screen image in Windows 10" ascii wide fullword
		$success13 = "Successfully changed lock screen image in Windows XP" ascii wide fullword
		$success14 = "Unjoining domain using WMIC finished successfully" ascii wide fullword
		$success15 = "Unjoining domain using WINAPI finished successfully" ascii wide fullword
		$success16 = "Succeeded disabling the first logon animation." ascii wide fullword
		$success17 = "Succeeded disabling the first logon privacy settings user approval." ascii wide fullword
		$success18 = "Boot configuration deleted successfully" ascii wide fullword
		$success19 = "Screen saver disabled successfully." ascii wide fullword
		$success20 = "Succeeded setting boot policy to ignore all errors." ascii wide fullword
		$success21 = "Succeeded disabling recovery mode." ascii wide fullword
		$success22 = "Successfully logged off all local sessions, except winlogon." ascii wide fullword
		$success23 = "Succeeded deleting shadowcopies." ascii wide fullword

		$locker1 = "Installing the locker from path %s" ascii wide fullword
		$locker2 = "Removing locker uninstaller from path %s" ascii wide fullword
		$locker3 = "Started changing lock screen image in Windows 7." ascii wide fullword
		$locker4 = "Started changing lock screen image in Windows XP." ascii wide fullword
		$locker5 = "Could not remove lock screen cache directory _P." ascii wide fullword
		$locker6 = "Started changing lock screen image in Windows 10." ascii wide fullword
		$locker7 = "Could not remove lock screen cache directory _Z." ascii wide fullword
		$locker8 = "eUpdating locker settings" ascii wide fullword
		$locker9 = "The locker is not installed" ascii wide fullword
		$locker10 = "Running locker thread" ascii wide fullword

		$attempt1 = "attempted to access encrypted file in offset %s, but it only supports offset 0" ascii wide
		$attempt2 = "Attempting to restart machine using cmd in %s seconds" ascii wide
		$attempt3 = "Attempting to restart machine using winapi in %s seconds" ascii wide
		$attempt4 = "Attempted to restart asynchronously using cmd." ascii wide
		$attempt5 = "Attempted to restart asynchronously using WINAPI." ascii wide
		$attempt6 = "Restart attempted using cmd, while another restart is already initiated." ascii wide
		$attempt7 = "Reached maximal attempts of getting a new winlogon token" ascii wide

		$process1 = "Process %s was not found." ascii wide fullword
		$process2 = "Could not find snapshot's first process. Error code: %s" ascii wide fullword
		$process3 = "Process %s with pid %s was not terminated." ascii wide fullword
		$process4 = "Process termination wait timed out. Error code: %s" ascii wide fullword
		$process5 = "Could not get process exit code. Error code: %s." ascii wide fullword
		$process6 = "Process exit code is %s." ascii wide fullword
		$process7 = "Could not create process. Command: %s, error code: %s." ascii wide fullword
		$process8 = "Could not create impersonated process. Command: %s, error code: %s." ascii wide fullword
		$process9 = "Encountered an error while terminating process with fatal priority. continuing" ascii wide fullword
		$process10 = "Process has finished." ascii wide fullword
		$process11 = "Waiting for new winlogon process" ascii wide fullword
		$process12 = "Killing all winlogon processes" ascii wide fullword
		
		$command1 = "icacls.exe \"C:\\Windows\\Web\\Screen\" /grant System:(OI)(CI)F /T" ascii wide
		$command2 = "takeown.exe /F \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\" /R /A /D Y" ascii wide
		$command3 = "icacls.exe \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\" /grant Administrators:(OI)(CI)F /T" ascii wide
		$command4 = "icacls.exe \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\" /grant System:(OI)(CI)F /T" ascii wide
		$command5 = "icacls.exe \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\\S-1-5-18\\ReadOnly\" /reset /T" ascii wide
		$command6 = "icacls.exe \"C:\\Windows\\Web\\Screen\" /grant Administrators:(OI)(CI)F /T" ascii wide
		$command7 = "icacls.exe \"C:\\Windows\\Web\\Screen\" /reset /T" ascii wide
		$command8 = "wmic computersystem where name=\"%computername%\" call unjoindomainorworkgroup" ascii wide
		$command9 = "vssadmin.exe delete shadows /all /quiet" ascii wide
		$command10 = "shutdown.exe /r /f /t " ascii wide
		$command11 = "wbem\\wmic.exe shadowcopy delete" ascii wide
		$command12 = "takeown.exe /F \"C:\\Windows\\Web\\Screen\" /R /A /D Y" ascii wide

		$formatStr1 = "File %s is not readable." ascii wide fullword
		$formatStr2 = "File %s is not writable." ascii wide fullword
		$formatStr3 = "Could not open file %s. error message: %s" ascii wide fullword
		$formatStr4 = "Could not write to file %s. error message: %s" ascii wide fullword
		$formatStr5 = "tCould not tell file pointer location on file %s." ascii wide fullword
		$formatStr6 = "Could not set file pointer location on file %s to offset %s." ascii wide fullword
		$formatStr7 = "Could not read from file %s. error message: %s" ascii wide fullword
		$formatStr8 = "File %s does not exist" ascii wide fullword
		$formatStr9 = "Skipping %s logs. Writing log number %s: " ascii wide fullword
		$formatStr10 = "Start interval logger. Writing logs with an interval of %s logs." ascii wide fullword
		$formatStr11 = "The log message is too big: %s/%s characters." ascii wide fullword
		$formatStr13 = "Found local user: %s." ascii wide fullword
		$formatStr14 = "Filesystem failure: %s" ascii wide fullword
		$formatStr15 = "Couldn't wipe file %s." ascii wide fullword
		$formatStr16 = "Finished wiping file %s with %s." ascii wide fullword
		$formatStr17 = "Started wiping file %s with %s." ascii wide fullword
		$formatStr18 = "Failure while enumerating local users. Error code: %s." ascii wide fullword
		$formatStr19 = "The browser %s is not supported" ascii wide fullword
		$formatStr20 = ".json array size is %s, but should have been %s" ascii wide fullword
		$formatStr21 = "ejson uint value is not in range %s to %s." ascii wide fullword
		$formatStr22 = "The path %s does not exist." ascii wide fullword
		$formatStr23 = "A path in %s could not be accessed. Continuing..." ascii wide fullword
		$formatStr24 = "The directory path %s could not be iterated." ascii wide fullword
		$formatStr25 = "Caught std::filesystem::filesystem_error: %s" ascii wide fullword
		$formatStr26 = "Line %d, Column %d" ascii wide fullword
		$formatStr27 = "Error from reader: %s" ascii wide fullword
		$formatStr28 = "%s %s HTTP/1.1" ascii wide fullword

		$settings1 = "unknown_hostname" ascii wide fullword
		$settings2 = "unknown_mac" ascii wide fullword
		$settings3 = "copy_file" ascii wide fullword
		$settings4 = "create_directories" ascii wide fullword

		$couldnt1 = "Could not change background image." ascii wide fullword
		$couldnt2 = "Could not create stdout pipe." ascii wide fullword
		$couldnt3 = "Could not set handle information for pipe." ascii wide fullword
		$couldnt4 = "Could not hide current console." ascii wide fullword
		$couldnt5 = "Could not get the window handle used by the console." ascii wide fullword

		$random1 = "C:\\Windows\\Sysnative\\" ascii wide fullword
		$random2 = "C:\\Windows\\system32\\" ascii wide fullword
		$random3 = "MESSAGE_IN_QUEUE" ascii wide fullword
		$random4 = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.93 Safari/537.36" ascii wide fullword
		$random5 = "cpp-httplib/0.2" ascii wide fullword
	
	condition:
		uint16(0) == 0x5a4d
		and
		(
			any of ($meteor*)
			or
			5 of ($rtti*)
			or
			5 of ($config_keys*)
			or
			10 of ($failure*)
			or
			2 of ($log*)
			or
			all of ($lockMyPC*)
			or
			4 of ($bcd*)
			or
			2 of ($password*)
			or
			any of ($boot*)
			or
			3 of ($success*)
			or
			3 of ($locker*)
			or
			2 of ($attempt*)
			or
			3 of ($process*)
			or
			3 of ($command*)
			or
			10 of ($formatStr*)
			or
			all of ($settings*)
			or
			all of ($couldnt*)
			or
			all of ($random*)
		)
}

rule apt_ZZ_MeteorExpress_locker
{
	meta:
		desc = "MeteorExpress ScreenLocker"
		author = "JAG-S @ SentinelLabs"
		version = "1.0"
		last_modified = "07.21.2021"
		hash = "074bcc51b77d8e35b96ed444dc479b2878bf61bf7b07e4d7bd4cf136cc3c0dce"
	strings:
		$a1 = "WindowClass" ascii wide fullword
		$a2 = "C:\\temp\\mscap.bmp" ascii wide
		$a3 = ".?AVCreateWindowFailed@exceptions@@" ascii wide
		$a4 = ".00cfg" ascii wide fullword
	condition:
		uint16(0) == 0x5a4d
		and
		all of them
}

// MISP event:2216 uuid:8036e611-07ca-4308-86aa-2266ea4850a6 org: to_ids:False tags:[misp-galaxy:malpedia="Conti Ransomware", misp-galaxy:mitre-malware="Conti - S0575"]
rule win_conti_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.conti."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.conti"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 85c0 750f c705????????0b000000 e9???????? }
            // n = 4, score = 700
            //   85c0                 | test                eax, eax
            //   750f                 | jne                 0x11
            //   c705????????0b000000     |     
            //   e9????????           |                     

        $sequence_1 = { 8975fc 803e00 7542 53 bb0e000000 }
            // n = 5, score = 600
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   803e00               | cmp                 byte ptr [esi], 0
            //   7542                 | jne                 0x44
            //   53                   | push                ebx
            //   bb0e000000           | mov                 ebx, 0xe

        $sequence_2 = { 8d7f01 0fb6c0 b95d000000 2bc8 }
            // n = 4, score = 600
            //   8d7f01               | lea                 edi, dword ptr [edi + 1]
            //   0fb6c0               | movzx               eax, al
            //   b95d000000           | mov                 ecx, 0x5d
            //   2bc8                 | sub                 ecx, eax

        $sequence_3 = { 8a07 8d7f01 0fb6c0 b948000000 }
            // n = 4, score = 600
            //   8a07                 | mov                 al, byte ptr [edi]
            //   8d7f01               | lea                 edi, dword ptr [edi + 1]
            //   0fb6c0               | movzx               eax, al
            //   b948000000           | mov                 ecx, 0x48

        $sequence_4 = { a1???????? 83f80a 7409 83f80c }
            // n = 4, score = 600
            //   a1????????           |                     
            //   83f80a               | cmp                 eax, 0xa
            //   7409                 | je                  0xb
            //   83f80c               | cmp                 eax, 0xc

        $sequence_5 = { 99 f7fe 8d427f 99 f7fe 8857ff 83eb01 }
            // n = 7, score = 600
            //   99                   | cdq                 
            //   f7fe                 | idiv                esi
            //   8d427f               | lea                 eax, dword ptr [edx + 0x7f]
            //   99                   | cdq                 
            //   f7fe                 | idiv                esi
            //   8857ff               | mov                 byte ptr [edi - 1], dl
            //   83eb01               | sub                 ebx, 1

        $sequence_6 = { 8d7601 884431ff 83ea01 75f2 }
            // n = 4, score = 600
            //   8d7601               | lea                 esi, dword ptr [esi + 1]
            //   884431ff             | mov                 byte ptr [ecx + esi - 1], al
            //   83ea01               | sub                 edx, 1
            //   75f2                 | jne                 0xfffffff4

        $sequence_7 = { 8d7f01 0fb6c0 b957000000 2bc8 }
            // n = 4, score = 600
            //   8d7f01               | lea                 edi, dword ptr [edi + 1]
            //   0fb6c0               | movzx               eax, al
            //   b957000000           | mov                 ecx, 0x57
            //   2bc8                 | sub                 ecx, eax

        $sequence_8 = { 85c0 750f c705????????0a000000 e9???????? }
            // n = 4, score = 500
            //   85c0                 | test                eax, eax
            //   750f                 | jne                 0x11
            //   c705????????0a000000     |     
            //   e9????????           |                     

        $sequence_9 = { 6a01 ff15???????? 6aff 8d45fc 50 }
            // n = 5, score = 400
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   6aff                 | push                -1
            //   8d45fc               | lea                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax

        $sequence_10 = { 6a01 6810660000 ff7508 ff15???????? 85c0 }
            // n = 5, score = 400
            //   6a01                 | push                1
            //   6810660000           | push                0x6610
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_11 = { ffd0 85c0 750f c705????????0c000000 e9???????? }
            // n = 5, score = 400
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax
            //   750f                 | jne                 0x11
            //   c705????????0c000000     |     
            //   e9????????           |                     

        $sequence_12 = { b800005000 6a00 8d4c2418 51 }
            // n = 4, score = 400
            //   b800005000           | mov                 eax, 0x500000
            //   6a00                 | push                0
            //   8d4c2418             | lea                 ecx, dword ptr [esp + 0x18]
            //   51                   | push                ecx

        $sequence_13 = { 56 8bf1 57 ff7608 ff15???????? }
            // n = 5, score = 400
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   57                   | push                edi
            //   ff7608               | push                dword ptr [esi + 8]
            //   ff15????????         |                     

        $sequence_14 = { 8b0d???????? 85c0 ba0d000000 0f44ca }
            // n = 4, score = 400
            //   8b0d????????         |                     
            //   85c0                 | test                eax, eax
            //   ba0d000000           | mov                 edx, 0xd
            //   0f44ca               | cmove               ecx, edx

        $sequence_15 = { 83c10b f7e9 c1fa02 8bc2 }
            // n = 4, score = 400
            //   83c10b               | add                 ecx, 0xb
            //   f7e9                 | imul                ecx
            //   c1fa02               | sar                 edx, 2
            //   8bc2                 | mov                 eax, edx

        $sequence_16 = { 741d 6aff ff75f0 ff15???????? ff75f4 ff15???????? }
            // n = 6, score = 400
            //   741d                 | je                  0x1f
            //   6aff                 | push                -1
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff15????????         |                     
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   ff15????????         |                     

        $sequence_17 = { e8???????? 8bb6007d0000 85f6 75ef 6aff }
            // n = 5, score = 400
            //   e8????????           |                     
            //   8bb6007d0000         | mov                 esi, dword ptr [esi + 0x7d00]
            //   85f6                 | test                esi, esi
            //   75ef                 | jne                 0xfffffff1
            //   6aff                 | push                -1

        $sequence_18 = { 8b0d???????? 83c00b 99 83c117 }
            // n = 4, score = 400
            //   8b0d????????         |                     
            //   83c00b               | add                 eax, 0xb
            //   99                   | cdq                 
            //   83c117               | add                 ecx, 0x17

        $sequence_19 = { 83c10b f7e9 03d1 c1fa04 8bc2 }
            // n = 5, score = 400
            //   83c10b               | add                 ecx, 0xb
            //   f7e9                 | imul                ecx
            //   03d1                 | add                 edx, ecx
            //   c1fa04               | sar                 edx, 4
            //   8bc2                 | mov                 eax, edx

        $sequence_20 = { 6800100000 68???????? ff75f8 ff15???????? 85c0 }
            // n = 5, score = 400
            //   6800100000           | push                0x1000
            //   68????????           |                     
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_21 = { 8b4df0 8bc1 8b55f4 0bc2 }
            // n = 4, score = 400
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   8bc1                 | mov                 eax, ecx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   0bc2                 | or                  eax, edx

        $sequence_22 = { ba0b010000 0fb74118 663bc2 740a }
            // n = 4, score = 300
            //   ba0b010000           | mov                 edx, 0x10b
            //   0fb74118             | movzx               eax, word ptr [ecx + 0x18]
            //   663bc2               | cmp                 ax, dx
            //   740a                 | je                  0xc

    condition:
        7 of them and filesize < 520192
}

// MISP event:2221 uuid:6e9165ac-e29b-4437-b982-8ca0899b57d1 org: to_ids:False tags:[]
rule APT_UA_Hermetic_Wiper_Feb22_1 {
   meta:
      description = "Detects Hermetic Wiper malware"
      author = "Florian Roth"
      reference = "https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/"
      date = "2022-02-24"
      score = 75
      hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
      hash2 = "3c557727953a8f6b4788984464fb77741b821991acbf5e746aebdd02615b1767"
      hash3 = "2c10b2ec0b995b88c27d141d6f7b14d6b8177c52818687e4ff8e6ecf53adf5bf"
      hash4 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
   strings:
      $xc1 = { 00 5C 00 5C 00 2E 00 5C 00 50 00 68 00 79 00 73
               00 69 00 63 00 61 00 6C 00 44 00 72 00 69 00 76
               00 65 00 25 00 75 00 00 00 5C 00 5C 00 2E 00 5C
               00 45 00 50 00 4D 00 4E 00 54 00 44 00 52 00 56
               00 5C 00 25 00 75 00 00 00 5C 00 5C 00 2E 00 5C
               00 00 00 00 00 25 00 73 00 25 00 2E 00 32 00 73
               00 00 00 00 00 24 00 42 00 69 00 74 00 6D 00 61
               00 70 00 00 00 24 00 4C 00 6F 00 67 00 46 00 69
               00 6C 00 65 }
      $sc1 = { 00 44 00 72 00 69 00 76 00 65 00 72 00 73 00 00
               00 64 00 72 00 76 00 00 00 53 00 79 00 73 00 74
               00 65 00 6D 00 33 00 32 }

      $s1 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" wide fullword
      $s2 = "\\\\.\\EPMNTDRV\\%u" wide fullword
      $s3 = "DRV_XP_X64" wide fullword
      $s4 = "%ws%.2ws" wide fullword

      $op1 = { 8b 7e 08 0f 57 c0 8b 46 0c 83 ef 01 66 0f 13 44 24 20 83 d8 00 89 44 24 18 0f 88 3b 01 00 00 }
      $op2 = { 13 fa 8b 55 f4 4e 3b f3 7f e6 8a 45 0f 01 4d f0 0f 57 c0 }
   condition:
      ( uint16(0) == 0x5a53 or uint16(0) == 0x5a4d ) and
      filesize < 400KB and ( 1 of ($x*) or 3 of them )
}

// MISP event:2221 uuid:a03b29ef-4085-4f2b-b2cf-83f2953042eb org: to_ids:False tags:[]
rule APT_UA_Hermetic_Wiper_Artefacts_Feb22_1 {
   meta:
      description = "Detects artefacts found in Hermetic Wiper malware related intrusions"
      author = "Florian Roth"
      reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ukraine-wiper-malware-russia"
      date = "2022-02-25"
      score = 75
   strings:
      $sx1 = "/c powershell -c \"rundll32 C:\\windows\\system32\\comsvcs.dll MiniDump" ascii wide
      $sx2 = "appdata\\local\\microsoft\\windows\\winupd.log" ascii wide
      $sx3 = "AppData\\Local\\Microsoft\\Windows\\Winupd.log" ascii wide
      $sx4 = "CSIDL_SYSTEM_DRIVE\\temp\\sys.tmp1" ascii wide
      $sx5 = "\\policydefinitions\\postgresql.exe" ascii wide

      $sx6 = "powershell -v 2 -exec bypass -File text.ps1" ascii wide
      $sx7 = "powershell -exec bypass gp.ps1" ascii wide
      $sx8 = "powershell -exec bypass -File link.ps1" ascii wide

      /* 16 is the prefix of an epoch timestamp that shouldn't change until the 14th of November 2023 */
      $sx9 = " 1> \\\\127.0.0.1\\ADMIN$\\__16" ascii wide
      
      $sa1 = "(New-Object System.Net.WebClient).DownloadFile(" ascii wide
      $sa2 = "CSIDL_SYSTEM_DRIVE\\temp\\" ascii wide
      $sa3 = "1> \\\\127.0.0.1\\ADMIN$" ascii wide
   condition:
      1 of ($sx*) or all of ($sa*)
}

// MISP event:2221 uuid:f6cc4d97-8ebb-4823-8cac-ed4064ccd5da org: to_ids:False tags:[]
rule APT_UA_Hermetic_Wiper_Scheduled_Task_Feb22_1 {
   meta:
      description = "Detects scheduled task pattern found in Hermetic Wiper malware related intrusions"
      author = "Florian Roth"
      reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ukraine-wiper-malware-russia"
      date = "2022-02-25"
      score = 85
   strings:
      $a0 = "<Task version=" ascii wide

      $sa1 = "CSIDL_SYSTEM_DRIVE\\temp" ascii wide
      $sa2 = "postgresql.exe 1> \\\\127.0.0.1\\ADMIN$" ascii wide
      $sa3 = "cmd.exe /Q /c move CSIDL_SYSTEM_DRIVE" ascii wide
   condition:
      $a0 and 1 of ($s*)
}

// MISP event:2224 uuid:0bd0b3e3-32e6-4568-9d99-502d90857b15 org: to_ids:True tags:[]
rule infostealer_win_mars_stealer_early_version {
    meta:
        description = "Identifies samples of Mars Stealer early version based on opcodes of the function loading obfuscated strings."
        source = "SEKOIA.IO"
        reference = "https://blog.sekoia.io/mars-a-red-hot-information-stealer/"
        classification = "TLP:WHITE"
        hash = "7da3029263bfbb0699119a715ce22a3941cf8100428fd43c9e1e46bf436ca687"

    strings:
        $dec = {a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 ??}

        $api00 = "LoadLibrary" ascii
        $api01 = "GetProcAddress" ascii
        $api02 = "ExitProcess" ascii
        $api03 = "advapi32.dll" ascii
        $api04 = "crypt32.dll" ascii
        $api05 = "GetTickCount" ascii
        $api06 = "Sleep" ascii
        $api07 = "GetUserDefaultLangID" ascii
        $api08 = "CreateMutex" ascii
        $api09 = "GetLastError" ascii
        $api10 = "HeapAlloc" ascii
        $api11 = "GetProcessHeap" ascii
        $api12 = "GetComputerName" ascii
        $api13 = "VirtualProtect" ascii
        $api14 = "GetUserName" ascii
        $api15 = "CryptStringToBinary" ascii

        $str0 = "JohnDoe" ascii

    condition:
        uint16(0)==0x5A4D and
        #dec > 400 and 12 of ($api*) and $str0
}

// MISP event:2224 uuid:f46ff8e6-5b3e-4c0d-8ed1-6649aced557b org: to_ids:True tags:[]
import "pe"

rule infostealer_win_mars_stealer_llcppc {
    meta:
        description = "Identifies samples of Mars Stealer based on the PE section name LLCPPC."
        source = "SEKOIA.IO"
        reference = "https://blog.sekoia.io/mars-a-red-hot-information-stealer/"
        classification = "TLP:WHITE"
        hash = "fd92fe8a4534bc6e14e177fee38a13f771a091fa6c7171fcee2791c58fbecf40"

    condition:
        uint16(0)==0x5A4D and
        for any i in ( 0..pe.number_of_sections-1 ): (
                pe.sections[i].name == "LLCPPC" and pe.sections[i].raw_data_size < 5000 )
}

// MISP event:2224 uuid:8d4a5f7c-b080-455b-8138-91ecaaf07141 org: to_ids:True tags:[]
rule infostealer_win_mars_stealer_xor_routine {
    meta:
        description = "Identifies samples of Mars Stealer based on the XOR deobfuscation routine."
        source = "SEKOIA.IO"
        reference = "https://blog.sekoia.io/mars-a-red-hot-information-stealer/"
        classification = "TLP:WHITE"
        hash = "4bcff4386ce8fadce358ef0dbe90f8d5aa7b4c7aec93fca2e605ca2cbc52218b"

    strings:
        $xor = {8b 4d ?? 03 4d ?? 0f be 19 8b 55 ?? 52 e8 ?? ?? ?? ?? 83 c4 ?? 8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 0f be 0c 10 33 d9 8b 55 ?? 03 55 ?? 88 1a eb be}

    condition:
        uint16(0)==0x5A4D and $xor
}

// MISP event:2227 uuid:426d1c1d-4177-4c8b-a17d-59b39be02847 org: to_ids:True tags:[]
import "pe"

rule SparrowDoor_apipatch {
    meta:
        author = "NCSC"
        description = "Identifies code segments in SparrowDoor responsible for patching APIs. No MZ/PE match as the backdoor has no header. Targeting in memory."
        date = "2022-02-28"
        hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

    strings:
	$save = {8B 06 89 07 8A 4E 04} // save off first 5 bytes of function
	$vp_1 = {89 10 8A 4E 04 8B D6 2B D0 88 48 04 83 EA 05 C6 40 05 E9 89 50 06} // calculate long jump 
	$vp_2 = {50 8B D6 6A 40 2B D7 88 4F 04 83 EA 05 6A 05 C6 47 05 E9 89 57 06 56} // calculate long jump 2
	$vp_3 = {51 52 2B DE 6A 05 83 EB 05 56 C6 06 E9 89 5E 01} // restore memory protections
	$va = {6A 40 68 00 10 00 00 68 00 10 00 00 6A 00} // virtually alloc set size, allocation and protection
	$s_patch = {50 68 7F FF FF FF 68 FF FF 00 00 56} // socket patch SO_DONTLINGER

    condition:
	    3 of them
}

rule SparrowDoor_clipshot {
    meta:
        author = "NCSC"
        description = "The SparrowDoor loader contains a feature it calls clipshot, which logs clipboard data to a file."
        date = "2022-02-28"
        hash1 = "989b3798841d06e286eb083132242749c80fdd4d"

    strings:
	    $exsting_cmp = {8B 1E 3B 19 75 ?? 83 E8 04 83 C1 04 83 C6 04 83 F8 04} // comparison routine for previous clipboard data
	    $time_format_string = "%d/%d/%d %d:%d" ascii
	    $cre_fil_args = {6A 00 68 80 00 00 00 6A 04 6A 00 6A 02 68 00 00 00 40 52}	

    condition:
	    (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and all of them and (pe.imports("User32.dll","OpenClipboard") and pe.imports("User32.dll","GetClipboardData") and pe.imports("Kernel32.dll","GetLocalTime") and pe.imports("Kernel32.dll","GlobalSize"))

}

rule SparrowDoor_config {
    meta:
        author = "NCSC"
        description = "Targets the XOR encoded loader config and shellcode in the file libhost.dll using the known position of the XOR key."
        date = "2022-02-28"
        hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

    condition:
	    (uint16(0) != 0x5A4D) and
            (uint16(0) != 0x8b55) and
	    (uint32(0) ^ uint32(0x4c) ==  0x00) and
	    (uint32(0) ^ uint32(0x34) ==  0x00) and
	    (uint16(0) ^ uint16(0x50) ==  0x8b55)
}

rule SparrowDoor_loader {
    meta:
        author = "NCSC"
        description = "Targets code features of the SparrowDoor loader. This rule detects the previous variant and this new variant."
        date = "2022-02-28"
        hash1 = "989b3798841d06e286eb083132242749c80fdd4d"

    strings:
        $xor_algo = {8B D0 83 E2 03 8A 54 14 10 30 14 30 40 3B C1}
	$rva = {8D B0 [4] 8D 44 24 ?? 50 6A 40 6A 05 56} // load RVA of process exe
        $lj = {2B CE 83 E9 05 8D [3] 52 C6 06 E9 89 4E 01 8B [3] 50 6A 05 56} // calculate long jump

    condition:
        (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and all of them

}


rule SparrowDoor_shellcode {
    meta:
        author = "NCSC"
        description = "Targets code features of the reflective loader for SparrowDoor. Targeting in memory."
        date = "2022-02-28"
        hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

    strings:
        $peb = {8B 48 08 89 4D FC 8B 51 3C 8B 54 0A 78 8B 74 0A 20 03 D1 03 F1 B3 64}
	$getp_match = {8B 06 03 C1 80 38 47 75 34 80 78 01 65 75 2E 80 78 02 74 75 28 80 78 03 50 75 22 80 78 04 72 75 1C 80 78 06 63 75 16 80 78 05 6F 75 10 80 78 07 41 75 0A}
        $k_check = {8B 48 20 8A 09 80 F9 6B 74 05 80 F9 4B 75 05}
        $resolve_load_lib = {C7 45 C4 4C 6F 61 64 C7 45 C8 4C 69 62 72 C7 45 CC 61 72 79 41 C7 45 D0 00 00 00 00 FF 75 FC FF 55 E4}		

    condition:
        3 of them
}


rule SparrowDoor_sleep_routine {
    meta:
        author = "NCSC"
        description = "SparrowDoor implements a Sleep routine with value seeded on GetTickCount. This signature detects the previous and this variant of SparrowDoor. No MZ/PE match as the backdoor has no header. Targeting in memory."
        date = "2022-02-28"
        hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

    strings:
        $sleep = {FF D7 33 D2 B9 [4] F7 F1 81 C2 [4] 8B C2 C1 E0 04 2B C2 03 C0 03 C0 03 C0 50}

    condition:
	  all of them
}

rule SparrowDoor_xor {
    meta:
        author = "NCSC"
        description = "Highlights XOR routines in SparrowDoor. No MZ/PE match as the backdoor has no header. Targeting in memory."
        date = "2022-02-28"
        hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

    strings:
        $xor_routine_outbound = {B8 39 8E E3 38 F7 E1 D1 EA 8D 14 D2 8B C1 2B C2 8A [4] 00 30 14 39 41 3B CE}
	$xor_routine_inbound = {B8 25 49 92 24 F7 E1 8B C1 2B C2 D1 E8 03 C2 C1 E8 02 8D 14 C5 [4] 2B D0 8B C1 2B C2}
        $xor_routine_config = {8B D9 83 E3 07 0F [6] 30 18 8D 1C 07 83 E3 07 0F [6] 30 58 01 8D 1C 28 83 E3 07 0F [6] 30 58 02 8D 1C 02 83 E3 07 0F [6] 30 58 03 8B DE 83 E3 07 0F [6] 30 58 04 83 C6 05 83 C1 05}

    condition:
	    2 of them
}

rule SparrowDoor_strings {
    meta:
        author = "NCSC"
        description = "Strings that appear in SparrowDoor's backdoor. Targeting in memory."
        date = "2022-02-28"
        hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

    strings:
        $reg = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
	$http_headers = {55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 35 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 35 2E 30 29 0D 0A 41 63 63 65 70 74 2D 4C 61 6E 67 75 61 67 65 3A 20 65 6E 2D 55 53 0D 0A 41 63 63 65 70 74 3A 20 2A 2F 2A 0D 0A}
	$http_proxy = "HTTPS=HTTPS://%s:%d" ascii
	$debug = "SeDebugPrivilege" ascii
	$av1 = "avp.exe" ascii // Kaspersky
	$av2 = "ZhuDongFangYu.exe" ascii // Qihoo360
	$av3 = "egui.exe" ascii // ESET
	$av4 = "TMBMSRV.exe" ascii // Trend Micro
	$av5 = "ccSetMgr.exe" ascii // Norton
	$clipshot = "clipshot" ascii
	$ComSpec =  "ComSpec" ascii
	$export = "curl_easy_init" ascii

    condition:
        10 of them
}

// MISP event:2229 uuid:c8a2108d-5ec7-423a-8fb3-1fc03d1440e7 org: to_ids:True tags:[]
rule QUIETEXIT_strings

{

    meta:

        author = "Mandiant"

        date_created = "2022-01-13"

        date_modified = "2022-01-13"

        rev = 1

    strings:

        $s1 = "auth-agent@openssh.com"

        $s2 = "auth-%.8x-%d"

        $s3 = "Child connection from %s:%s"

        $s4 = "Compiled without normal mode, can't run without -i"

        $s5 = "cancel-tcpip-forward"

        $s6 = "dropbear_prng"

        $s7 = "cron"

    condition:

        uint32be(0) == 0x7F454C46 and filesize < 2MB and all of them

}

// MISP event:2229 uuid:d56f1861-a8e2-42ca-a98c-462064327412 org: to_ids:True tags:[]
rule REGEORG_Tuneller_generic

{

    meta:

        author = "Mandiant"

        date_created = "2021-12-20"

        date_modified = "2021-12-20"

        md5 = "ba22992ce835dadcd06bff4ab7b162f9"

    strings:

        $s1 = "System.Net.IPEndPoint"

        $s2 = "Response.AddHeader"

        $s3 = "Request.InputStream.Read"

        $s4 = "Request.Headers.Get"

        $s5 = "Response.Write"

        $s6 = "System.Buffer.BlockCopy"

        $s7 = "Response.BinaryWrite"

        $s8 = "SocketException soex"

    condition:

        filesize < 1MB and 7 of them

}

// MISP event:2229 uuid:b84fac0c-679b-4384-85b1-018f3985b684 org: to_ids:True tags:[]
rule UNC3524_sha1

{

    meta:

        author = "Mandiant"

        date_created = "2022-01-19"

        date_modified = "2022-01-19"

   strings:

        $h1 = { DD E5 D5 97 20 53 27 BF F0 A2 BA CD 96 35 9A AD 1C 75 EB 47 }

    condition:

        uint32be(0) == 0x7F454C46 and filesize < 10MB and all of them

}

// MISP event:2238 uuid:e1a0a631-54f1-4677-98c6-99ead3078225 org: to_ids:True tags:[]
rule CISA_10382580_02 : rat
{
	meta:
		Author = "CISA Code & Media Analysis"
		Incident = "10382580"
		Date = "2022-06-02"
		Last_Modified = "20220602_1200"
		Actor = "n/a"
		Category = "RAT"
		Family = "n/a"
		Description = "Detects unidentified Remote Access Tool samples"
		MD5_1 = "7b1ce3fe542c6ae2919aa94e20dc860e"
		SHA256_1 = "d071c4959d00a1ef9cce535056c6b01574d8a8104a7c3b00a237031ef930b10f"
	strings:
		$s0 = { 48 8B 06 0F B6 04 01 32 C2 F6 C1 01 75 02 34 E7 }
		$s1 = { 88 04 0F 48 FF C1 48 8B 46 08 48 3B }
		$s2 = { 0F BE CA C1 CF 0D 8D 41 E0 80 FA 61 0F 4C C1 03 }
		$s3 = { F8 4D 8D 40 01 41 0F B6 10 84 D2 }
	condition:
		all of them
}

// MISP event:2245 uuid:4a8fcbc0-e720-4eec-8d11-54713f3258b8 org: to_ids:False tags:[]
rule monti_ransom {
      meta:
            description = "Detects ChaCha8 encrypted 'MONTI Strain' text (using all-zero key and nonce) embedded in ransomware payload"
            author = "BlackBerry Threat Research Team"
            date = "August 15, 2021"
            license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

      strings:
            $s = {20 19 57 65 03 62 D0 AE F4 D1 68}

      condition:
            uint16be(0) == 0x4d5a and filesize < 2MB
            and $s
}

// MISP event:2245 uuid:c154b708-1b6e-4fb9-9673-56555fbf6895 org: to_ids:False tags:[]
rule veeam_dumper {
      meta:
            description = "Detects Veeam credential Dumper"
            author = "BlackBerry Threat Research Team"
            date = "August 15, 2021"
            license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"
      strings:
            $s1 = "SqlCommand" fullword ascii wide
            $s2 = "SqlConnection" fullword ascii wide
            $s3 = "SqlDataReader" fullword ascii wide
            $s4 = "veeamp.exe" fullword ascii wide
            $s5 = "veeamp.pdb" fullword ascii wide

      condition:
            uint16be(0) == 0x4d5a and filesize < 60KB
            and 4 of them
}

// MISP event:2265 uuid:efecc807-4099-491a-a0ef-17fabb9eaf1a org: to_ids:False tags:[]
rule M_Hunting_Launcher_BLUEHAZE_1 { 

    meta: 

        author = "Mandiant" 

    strings: 

        $s1 = "Libraries\\CNNUDTV" ascii 

        $s2 = "closed.theworkpc.com" ascii 

        $s3 = "cmd.exe /C wuwebv.exe -t -e" ascii 

    condition: 

        uint16(0) == 0x5a4d and 

        filesize < 500KB and 

        (2 of ($s*)) 

}

// MISP event:2265 uuid:ded991fd-475e-4481-9d6d-91530586fc7a org: to_ids:False tags:[]
rule M_Hunting_Dropper_DARKDEW_1 { 

    meta: 

        author = "Mandiant" 

    strings: 

        $s1 = "do inroot" ascii 

        $s2 = "disk_watch" ascii 

        $s5 = "G:\\project\\APT\\" ascii 

        $s3 = "c:\\programdata\\udisk" ascii 

        $s4 = "new\\shellcode\\Release\\shellcode.pdb" ascii 

    condition: 

        filesize < 500KB and 

        (2 of ($s*)) 

}

// MISP event:2265 uuid:b2cda36a-82eb-4ea0-99f6-c6d399ac64e7 org: to_ids:False tags:[]
rule M_Hunting_Launcher_MISTCLOAK_1 { 

    meta: 

        author = "Mandiant" 

    strings: 

        $s1 = "CheckUsbService" ascii 

        $s2 = "new\\u2ec\\Release\\u2ec.pdb" ascii 

        $s3 = "autorun.inf\\Protection for Autorun" ascii 

    condition: 

        uint16(0) == 0x5a4d and 

        filesize < 200KB and 

        (2 of ($s*)) 

}

// MISP event:2268 uuid:fe6d2186-8a43-4079-854f-7fb7ad525f1c org: to_ids:False tags:[]
rule M_APT_Kopiluwak_Recon_1

{

    meta:

        author = "Mandiant"

    strings:

        $rc4_1 = ".charCodeAt(i %"

        $rc4_2 = ".length)) % 256"

        $b64_1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

        $b64_3 = ".charAt(parseInt("

        $recon_1 = "WScript.CreateObject"

        $recon_2 = ".Run("

        $Arguments = "WScript.Arguments"

    condition:

        ($rc4_1 and $rc4_2 and $b64_1) and ($Arguments or ($b64_3 and $recon_1 and $recon_2))

}

// MISP event:2268 uuid:bac7cdd5-7b90-46b2-ae22-93dec027f5b0 org: to_ids:False tags:[]
rule M_HUNTING_QUIETCANARY_STRINGS {

  meta:

        author="Mandiant"

  strings:

    $pdb1 = "c:\\Users\\Scott\\source\\repos\\Kapushka.Client\\BrowserTelemetry\\obj\\Release\\CmService.pdb" ascii wide nocase

    $pdb2 = "c:\\Users\\Scott\\source\\repos\\Kapushka.Client\\BrowserTelemetry\\obj\\Release\\BrowserTelemetry.pdb" ascii wide nocase

    $pdb3 = "c:\\Users\\Scott\\source\\repos\\BrowserTelemetry\\BrowserTelemetry\\obj\\Release\\BrowserTelemetry.pdb" ascii wide nocase

    $orb1 = {  68 00 74 00 74 00 70 00 73 00 3A 00 2F 00 2F }

    $orb2 = {  68 00 74 00 74 00 70 00 3A 00 2F 00 2F }

    $command1 = "get_Command" ascii wide nocase

    $command2 = "set_Command" ascii wide nocase

    $command3 = "DownloadCommand" ascii wide nocase

    $command4 = "UploadCommand"  ascii wide nocase

    $command5 = "AddCommand" ascii wide nocase

    $command6 = "ExeCommand" ascii wide nocase

    $command7 = "KillCommand" ascii wide nocase

    $command8 = "ClearCommand"  ascii wide nocase

      $rc4 = {21 00 62 00 76 00 7A 00 65 00 26 00 78 00 61 00 62 00 72 00 39 00 7C 00 38 00 5B 00 3F 00 78 00 77 00 7C 00 7C 00 79 00 26 00 7A 00 6C 00 23 00 74 00 70 00

6B 00 7A 00 6A 00 5E 00 62 00 39 00 61 00 38 00 6A 00 5D 00 40 00 6D 00 39 00 6E 00 28 00 67 00 67 00 24 00 40 00 74 00 74 00 65 00 33 00 33 00 6E 00 28 00 32 00 72 00 7A

00 62 00 7A 00 69 00 74 00 75 00 31 00 2A 00 66 00 61 00 00 80 E9 4D 00 6F 00 7A 00 69 00 6C 00 6C 00 61 }

  condition:

    (1 of ($pdb*)) and (1 of ($orb*)) and (all of ($command*)) or ($rc4)

}

// MISP event:2272 uuid:505e6aa2-add9-4042-a533-57855e6e4576 org: to_ids:False tags:[]
rule lazarus_dtrack_unpacked
{
meta:
author="Withsecure Threat Intelligence"
description="Detects unpacked dtrack variant with smb data staging"
date="2023-01-01"
strings:
$str_mutex = "MTX_Global"
$str_cmd_1 = "/c net use \\\\" wide
$str_cmd_2 = "/c ping -n 3 127.0.01 > NUL % echo EEE > \"%s\"" wide
$str_cmd_3 = "/c move /y %s \\\\" wide
$str_cmd_4 = "/c systeminfo > \"%s\" & tasklist > \"%s\" & netstat -naop tcp > \"%s\"" wide
condition:
uint16(0) == 0x5A4D and
all of them
}

// MISP event:2272 uuid:feb09fa0-a495-4270-adac-a0a8c5b3db07 org: to_ids:False tags:[]
rule lazarus_dtrack_unpacked
{
meta:
author=" Withsecure Threat Intelligence "
description="Detects lazarus acres.exe 64bit rat written with QT framework"
date="2023-01-01"
strings:
$str_nopineapple = "< No Pineapple! >"
$str_qt_library = "Qt 5.12.10"
$str_xor = {8B 10 83 F6 ?? 83 FA 01 77}
condition:
uint16(0) == 0x5A4D and
all of them
}

// MISP event:2272 uuid:25aa3252-61d5-46ab-b358-1bf46601bd4e org: to_ids:False tags:[]
rule lazarus_grease2
{
meta:
author=" Withsecure Threat Intelligence "
description="Detects GREASE2 malware"
date="2023-01-01"
strings:
$str_rdpconf = "c: \\windows\\temp\\RDPConf.exe" fullword nocase
$str_rdpwinst = "c: \\windows\\temp\\RDPWInst.exe" fullword nocase
$str_net_user = "net user”
$str_admins_add = "net localgroup administrators"
condition:
uint16(0) == 0x5A4D and
all of them
}

// MISP event:2272 uuid:a8af9677-abbf-4934-a635-7060f145246f org: to_ids:False tags:[]
rule lazarus_bindshell
{
meta:
author=" Withsecure Threat Intelligence "
description="Detects bind shell from Lazarus group"
date="2023-01-01"
strings:
$str_comspec = "COMSPEC"
$str_consolewindow = "GetConsoleWindow"
$str_ShowWindow = "ShowWindow"
$str_WSASocketA = "WSASocketA"
$str_CreateProcessA = "CreateProcessA"
$str_port = {B9 4D 05 00 00 89}
condition:
uint16(0) == 0x5A4D and
all of them
}

// MISP event:2276 uuid:95dee575-2a55-4056-a7a3-7effdffb4034 org: to_ids:False tags:[]
rule Powerpoint_Code_Execution_87211_00007 {
meta:
author = "Cluster25"
description ="Detects Code execution technique in Powerpoint (Hyperlink and Action)"
hash1 = "d1bceccf5d2b900a6b601c612346fdb3fa5bb0e2faeefcac3f9c29dc1d74838d"
strings:
$magic = {D0 CF 11 E0 A1 B1 1A E1}
$s1 = "local.lnk" fullword wide
$s2 = "lmapi2.dll" fullword wide
$s3 = "rundll32.exe" fullword wide
$s4 = "InProcServer32" fullword wide
$s5 = "DownloadData" fullword wide
$s6 = "SyncAppvPublishingServer" fullword wide
condition: ($magic at 0) and (all of ($s*)) and filesize < 10MB 
}

// MISP event:2276 uuid:26e1c876-4aee-4458-9398-9816ffd298e0 org: to_ids:False tags:[]
rule APT28_Graphite_62333_00028 : RUSSIAN THREAT GROUP {
meta:
description = "Detects Fancy Bear Graphite variant through internal strings"
author = "Cluster25"
tlp = "white"
hash1 = "34aca02d3a4665f63fddb354551b5eff5a7e8877032ddda6db4f5c42452885ad"
strings:
$ = "_LL_x64.dll" fullword ascii
$ = "qqhqx!iwwU1ptzd1WngCv9BCmVtxgFTJBPR1bJ2Ze17e0N6W3VHZC2FQOOUhu4nQ2Wrj0qLEBowQ$$" ascii
$ = "62272a08-fe9d-4825-bc65-203842ff92bc" fullword ascii
$ = "%s %04d sp%1d.%1d %s" fullword ascii
condition:
uint16(0) == 0x5a4d and
filesize < 100KB and
all of them
}

// MISP event:2293 uuid:400d0786-da9e-4ace-bff3-517bb0b2319d org: to_ids:False tags:[]
ule NOBELIUM_SpyDLL_March2023
{
                meta:
                                copyright = "BlackBerry"
                                description = "Yara rule based on code NOBELIUM_SpyDLL_March2023"
                                author = "BlackBerry Threat Intelligence Team"
                                date = "2023-03-07"
                                sha256 =  "e957326b2167fa7ccd508cbf531779a28bfce75eb2635ab81826a522979aeb98"
                                sha256 =  "4d92a4cecb62d237647a20d2cdfd944d5a29c1a14b274d729e9c8ccca1f0b68b"     
                                sha256 =  "3a489ef91058620951cb185ec548b67f2b8d047e6fdb7638645ec092fc89a835"
                strings:                                

                                $1807379073_247 = { 8B ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? ?? ?? F7 ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 0F 10 ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 8B ?? ?? ?? 89 ?? 49 ?? ?? 89 ?? 49 ?? ?? 49 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? 4C ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 0F 11 ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9? 0F 10 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 5? 5? 5? 5? 41 ?? 41 ?? 41 ?? C3 }
                                $1807233630_154 = { 48 ?? ?? ?? ?? ?? ?? 49 ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? 49 ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 49 ?? ?? 41 ?? ?? 4C ?? ?? 4D ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 4D ?? ?? 45 ?? ?? 4C ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? 45 ?? ?? 45 ?? ?? BA ?? ?? ?? ?? 31 ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 88 }
                                $1807250632_125 = { 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? 4D ?? ?? 48 ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 45 ?? ?? 4D ?? ?? 4C ?? ?? 4C ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 84 ?? 0F 85 }
                                $1807244815_125 = { 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? 49 ?? ?? 4C ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 45 ?? ?? 4D ?? ?? 4C ?? ?? 4C ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 84 ?? 0F 85 }
                                $1807376832_81 = { 41 ?? 41 ?? 41 ?? 41 ?? 5? 5? 5? 5? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? 0F 10 ?? 48 ?? ?? ?? ?? ?? ?? ?? 0F 10 ?? 49 ?? ?? 48 ?? ?? 4C ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? 0F 11 ?? ?? ?? 83 ?? ?? ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? 7D }
                                $1807378924_80 = { 48 ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? E8 ?? ?? ?? ?? 0F 10 ?? ?? ?? ?? ?? ?? 0F 10 ?? ?? ?? ?? ?? ?? 0F 10 ?? ?? ?? ?? ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? 39 ?? ?? ?? ?? ?? ?? 74 }
                                $1807227484_78 = { 31 ?? 31 ?? 4C ?? ?? FF D? 49 ?? ?? ?? 31 ?? 4D ?? ?? 4C ?? ?? F2 ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 4C ?? ?? F2 ?? 89 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 4C ?? ?? 48 ?? ?? 44 ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
                                $1807233543_78 = { 4C ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? ?? 49 ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? 49 ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? 41 ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 45 ?? ?? 0F 85 }
                                $1807231440_74 = { 4C ?? ?? 31 ?? 48 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 8A ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 42 ?? ?? ?? 0F BE ?? FF 1? ?? ?? ?? ?? 48 ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? 75 }
                                $1807236234_71 = { 41 ?? 41 ?? 41 ?? 41 ?? 5? 5? 5? 5? 48 ?? ?? ?? 45 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? C6 ?? ?? 49 ?? ?? 44 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 45 ?? ?? 48 ?? ?? 4C ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 0F 85 }
                                $1807238694_70 = { 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 0F 84 }
                                $1807227341_69 = { 31 ?? 31 ?? FF D? 4C ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? 45 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 4C ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 49 ?? ?? 48 ?? ?? 0F 84 }
                                $1807227414_66 = { 4D ?? ?? 45 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 49 ?? ?? 48 ?? ?? 0F 84 }
                                $1807378203_62 = { 41 ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 31 ?? 41 ?? ?? 41 ?? ?? ?? ?? ?? ?? 99 41 ?? ?? 45 ?? ?? 41 ?? ?? ?? ?? ?? 0F 9F ?? 01 ?? 8D ?? ?? ?? ?? ?? 99 41 ?? ?? 48 ?? ?? 81 F? ?? ?? ?? ?? 7D }
                                $1807378800_62 = { 41 ?? 41 ?? 41 ?? 5? 5? 5? 5? 48 ?? ?? ?? ?? ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? F2 ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? 49 ?? ?? 49 ?? ?? 4C ?? ?? 0F 54 ?? ?? ?? ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? 73 }
                                $1807239523_59 = { 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 49 ?? ?? 4C ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 84 ?? 0F 84 }
                                $1807234558_49 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 45 ?? ?? 45 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? FF D? 83 ?? ?? 0F 85 }
                                $1807229643_48 = { 48 ?? ?? ?? ?? ?? 0F B7 ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 8A ?? ?? ?? ?? ?? 84 ?? 75 }
                                $1807251921_46 = { 44 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? 41 ?? ?? 89 ?? 0F B7 ?? 8B ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 89 ?? ?? 41 ?? ?? ?? ?? ?? ?? 74 }
                                $1807234510_44 = { 48 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 45 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? FF D? 85 ?? 0F 85 }
                                $1807248778_42 = { 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C ?? ?? 4C ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 ?? 0F 84 }
                                $1807227300_37 = { C7 ?? ?? ?? ?? ?? ?? ?? 45 ?? ?? 45 ?? ?? 31 ?? 48 ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 49 ?? ?? 48 ?? ?? 0F 84 }
                                $1807409201_33 = { 48 ?? ?? BD ?? ?? ?? ?? 49 ?? ?? 48 ?? ?? ?? 31 ?? 48 ?? ?? 0F 92 ?? 48 ?? ?? 4D ?? ?? 48 ?? ?? 75 }
                                $1807348925_27 = { 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 42 ?? ?? ?? ?? 88 ?? ?? ?? 0F B6 ?? ?? 45 ?? ?? 74 }
                                $1807351416_16 = { 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 4C ?? ?? 0F 86 }

                condition:
                                uint16(0) == 0x5a4d and filesize < 1MB and 18 of them
}

// MISP event:2294 uuid:b662d726-bce2-44df-a2a0-724120ad298b org: to_ids:False tags:[]
rule targeted_BlindEagle_Loader : Fsociety
{
    meta:
        description = "Rule to detect BlindEagle malicious Loader"
        author = "The BlackBerry Research & Intelligence team"
        date = "2023-02-07"
        last_modified = "2023-02-22"
        distribution = "TLP:White"
        version = "1.0"    

    strings:        

                        $h0 = {6449640053697A655F00526573657276656431004465736B746F70005469746C65006477580064775900647758536
97A650064775953697A6500647758436F756E74436861727300647759436F756E74436861727300647746696C6C41747472}
                        $h1 = {000004200101022901002434353136453045312D354330452D344234452D394133322D39453337453233453734323600000C01000731
2E302E302E3000004901001A2E4E45544672616D65776F726B2C5665}         

      condition:
        uint16(0) == 0x5A4D and filesize < 100KB and 1 of ($h*)

}

// MISP event:2295 uuid:b6a68969-da2a-4ec4-bf36-0ed76948bb2b org: to_ids:False tags:[]
rule Darkbit_Ransomware {
meta:
        description = "Yara rule based of the DarkBit Ransomware code"
        author = "The BlackBerry Research & Intelligence team"
        date = "2023-02-14"
        last_modified = "2023-02-15"
        distribution = "TLP:White"
        version = "1.0"
        sha256 = "9107be160f7b639d68fe3670de58ed254d81de6aec9a41ad58d91aa814a247ff"
        md5 = "9880fae6551d1e9ee921f39751a6f3c0"

strings:
        $4538285_63 = { 9? 9? 9? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? C6 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 66 ?? E8 ?? ?? ?? ?? 48 ?? ?? 84 ?? 0F 85 }
        $5891110_63 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 4C ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 0F 1F ?? ?? ?? 48 ?? ?? 0F 8E }
        $7545077_63 = { 48 ?? ?? ?? ?? ?? ?? 0F 1F ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 0F 84 }
        $5903045_63 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? 0F 1F ?? ?? ?? 48 ?? ?? 73 }
        $5127463_63 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? 4C ?? ?? 0F 9E ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 }
        $6072198_63 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 9? 48 ?? ?? 0F 84 }
        $4935722_63 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 ?? 0F 85 }
        $4976425_63 = { 41 ?? ?? ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? 4F ?? ?? ?? 4D ?? ?? ?? 41 ?? ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? 4F ?? ?? ?? 4D ?? ?? ?? 41 ?? ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? 74 }
        $4527589_63 = { 48 ?? ?? ?? ?? 48 ?? ?? 0F B7 ?? ?? ?? 0F B7 ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? ?? 9? 48 ?? ?? 7D }
        $4716056_63 = { 0F B6 ?? ?? ?? 0F B6 ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 66 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? C3 }
        $5798030_63 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 0F 1F ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 9? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 75 }
        $6047533_63 = { 0F B6 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? ?? ?? 48 ?? ?? 48 }
        $7558727_62 = { 31 ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 1F ?? 48 ?? ?? 0F 84 }
        $4266979_62 = { 48 ?? ?? ?? 48 ?? ?? 8B ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF D? 48 ?? ?? ?? ?? 0F B6 ?? ?? 83 ?? ?? 88 ?? ?? 0F B6 ?? ?? BE ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 66 ?? 74 }
        $5892010_62 = { 4B ?? ?? ?? 49 ?? ?? ?? 49 ?? ?? ?? ?? 49 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 4C ?? ?? ?? ?? ?? ?? ?? 49 ?? ?? 0F 8F }
        $5132165_62 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 9? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? 4C ?? ?? 0F 9E ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? EB }
        $6850214_62 = { 44 ?? ?? ?? ?? ?? 8B ?? 89 ?? ?? ?? 8B ?? ?? 89 ?? ?? ?? 8B ?? ?? 89 ?? ?? ?? 8B ?? ?? 89 ?? ?? ?? 0F 10 ?? ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? C3 }
        $4976188_62 = { 41 ?? ?? ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? 4B ?? ?? ?? 48 ?? ?? ?? 0F 10 ?? 0F 11 ?? ?? ?? ?? ?? ?? 4B ?? ?? ?? 48 ?? ?? ?? 0F 10 ?? 0F 11 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? 0F 85 }
        $4610524_62 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 84 ?? 0F 85 }
        $6072616_61 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 0F 1F ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 0F 84 }
        $4442442_61 = { 4C ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? ?? ?? ?? ?? 45 ?? ?? ?? 41 ?? ?? ?? 41 ?? ?? ?? 47 ?? ?? ?? 45 ?? ?? ?? 41 ?? ?? ?? 44 ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 45 ?? ?? 0F 8E }
        $4448822_61 = { 48 ?? ?? ?? ?? 0F 1F ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 8B ?? 89 ?? C1 ?? ?? C1 ?? ?? 01 ?? C1 ?? ?? 41 ?? ?? C1 ?? ?? 29 ?? 85 ?? 0F 8C }
        $4726213_61 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 40 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 4C ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 0F B6 ?? ?? ?? 4C ?? ?? ?? ?? 48 }
        $5127401_61 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? 4C ?? ?? 0F 9E ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? EB }
        $4357770_61 = { 48 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 0F 10 ?? ?? ?? ?? ?? 0F 11 ?? ?? ?? 0F 10 ?? ?? ?? ?? ?? 0F 11 ?? ?? ?? 31 ?? EB }
        $5046026_60 = { 48 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? FF D? 66 ?? 48 ?? ?? ?? 0F 85 }
        $6918301_60 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 0F 10 ?? ?? ?? ?? ?? ?? 0F 11 ?? ?? 0F 10 ?? ?? ?? ?? ?? ?? 0F 11 ?? ?? 0F 10 ?? ?? ?? ?? ?? ?? 0F 11 ?? ?? 0F 10 ?? ?? ?? ?? ?? ?? 0F 11 ?? ?? EB }
        $5651196_60 = { 0F 1F ?? ?? E8 ?? ?? ?? ?? 9? 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? ?? 31 ?? EB }
        $5735857_60 = { E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 0F 1F ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 75 }
        $5058799_60 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 0F BA ?? ?? 73 }
        $4987306_60 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? 81 E? ?? ?? ?? ?? 44 ?? ?? ?? ?? 41 ?? ?? ?? 4C ?? ?? 9? 0F B6 ?? 40 ?? ?? ?? 75 }
        $4491881_60 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 0F 82 }
        $5384124_60 = { 0F 1F ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 75 }
        $6212553_60 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 9? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 0F 1F ?? ?? 48 ?? ?? 0F 84 }
        $5991938_60 = { 4C ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 0F 94 ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? ?? 89 ?? 48 }
        $4975050_60 = { 48 ?? ?? ?? ?? ?? ?? ?? 0F 10 ?? 0F 11 ?? ?? ?? ?? ?? ?? 0F 10 ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? 0F 10 ?? ?? 0F 11 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 0F 1F ?? 48 ?? ?? ?? 0F 8F }
        $7558357_59 = { 31 ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 0F 84 }
        $5152831_59 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 1F ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 }
        $4347563_59 = { 48 ?? ?? ?? ?? 66 ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? 9? 9? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 0F 83 }
        $6022661_59 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 0F 1F ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 89 ?? 48 }
        $6139378_59 = { 88 ?? ?? ?? 44 ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? FF D? 48 ?? ?? ?? ?? 0F B6 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? C3 }

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and all of them
}

// MISP event:2298 uuid:24a978bd-f6e0-477d-b921-d5987ca1db7f org: to_ids:False tags:[]
rule Malware_dprk_3cx
{
    meta:
        author = "HuntressLabs"
        created = "2023/03/30"
    strings:
        
        $ffmpeg = {41 f7 da 44 01 d2 ff c2 4c 63 ca 46 8a 94 0c 50 03 00 00 45 00 d0 45 0f b6 d8 42 8a ac 1c 50 03 00 00 46 88 94 1c 50 03 00 00 42 88 ac 0c 50 03 00 00 42 02 ac 1c 50 03 00 00 44 0f b6 cd 46 8a 8c 0c 50 03 00 00}
        $s1 = "D3dcompiler_47.dll" ascii
        $s2 = "3jB(2bsG#@c7" ascii
        
        $ror = {41 c1 cb 0d 0f be 03 48 ff c3 44 03 d8 80 7b ff 00}
        $header = {31 32 30 30 20 32 34 30 30 20 22 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 31 30 2e 30 3b 20 57 69 6e 36 34 3b 20 78 36 34 29 20 41 70 70 6c 65 57 65 62 4b 69 74 2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20 6c 69 6b 65 20 47 65 63 6b 6f 29 20 33 43 58 44 65 73 6b 74 6f 70 41 70 70 2f 31 38 2e 31 31 2e 31 31 39 37 20 43 68 72 6f 6d 65 2f 31 30 32 2e 30 2e 35 30 30 35 2e 31 36 37 20 45 6c 65 63 74 72 6f 6e}
        
        
        $downloader1 = {33 c1 41 69 d0 7d 50 bf 12 45 8b d1 83 c3 10 4c 0f af d7 49 c1 e9 20 81 c2 87 d6 12 00 4d 03 d1 44 69 ca 7d 50 bf 12}
        
        $github = "https://raw.githubusercontent.com/IconStorages/" wide nocase
        
    condition:
        $ffmpeg or ($s1 and $s2) or ($ror and $header) or $downloader1 or $github
}

// MISP event:2298 uuid:9408d857-20e4-42fd-ace4-c6a8a50dffdc org: to_ids:False tags:[]
import "pe"

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_1 {
   meta:
      description = "Detects malicious DLLs related to 3CX compromise"
      author = "X__Junior, Florian Roth (Nextron Systems)"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      date = "2023-03-29"
      score = 85
      hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
      hash2 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
    strings:
      $op1 = { 4C 89 F1 4C 89 EA 41 B8 40 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 4C 89 F0 FF 15 ?? ?? ?? ?? 4C 8D 4C 24 ?? 45 8B 01 4C 89 F1 4C 89 EA FF 15 } /* VirtualProtect and execute payload*/
      $op2 = { 48 C7 44 24 ?? 00 00 00 00 4C 8D 7C 24 ?? 48 89 F9 48 89 C2 41 89 E8 4D 89 F9 FF 15 ?? ?? ?? ?? 41 83 3F 00 0F 84 ?? ?? ?? ?? 0F B7 03 3D 4D 5A 00 00} /* ReadFile and MZ compare*/
      $op3 = { 41 80 7C 00 ?? FE 75 ?? 41 80 7C 00 ?? ED 75 ?? 41 80 7C 00 ?? FA 75 ?? 41 80 3C 00 CE} /* marker */
      $op4 = { 44 0F B6 CD 46 8A 8C 0C ?? ?? ?? ?? 45 30 0C 0E 48 FF C1} /* xor part in RC4 decryption*/
    condition:
      uint16(0) == 0x5a4d
      and filesize < 3MB 
      and pe.characteristics & pe.DLL
      and 2 of them
}

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_2 {
   meta:
      description = "Detects malicious DLLs related to 3CX compromise (decrypted payload)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/dan__mayer/status/1641170769194672128?s=20"
      date = "2023-03-29"
      score = 80
      hash1 = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
   strings:
      $s1 = "raw.githubusercontent.com/IconStorages/images/main/icon%d.ico" wide fullword
      $s2 = "https://raw.githubusercontent.com/IconStorages" wide fullword
      $s3 = "icon%d.ico" wide fullword
      $s4 = "__tutmc" ascii fullword
      $op1 = { 2d ee a1 00 00 c5 fa e6 f5 e9 40 fe ff ff 0f 1f 44 00 00 75 2e c5 fb 10 0d 46 a0 00 00 44 8b 05 7f a2 00 00 e8 0a 0e 00 00 }
      $op4 = { 4c 8d 5c 24 71 0f 57 c0 48 89 44 24 60 89 44 24 68 41 b9 15 cd 5b 07 0f 11 44 24 70 b8 b1 68 de 3a 41 ba a4 7b 93 02 }
      $op5 = { f7 f3 03 d5 69 ca e8 03 00 00 ff 15 c9 0a 02 00 48 8d 44 24 30 45 33 c0 4c 8d 4c 24 38 48 89 44 24 20 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 900KB and 3 of them
      or 5 of them
}

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_3 {
   meta:
      description = "Detects malicious DLLs related to 3CX compromise (decrypted payload)"
      author = "Florian Roth , X__Junior"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      date = "2023-03-29"
      score = 80
      hash1 = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
    strings:
      $opa1 = { 41 81 C0 ?? ?? ?? ?? 02 C8 49 C1 E9 ?? 41 88 4B ?? 4D 03 D1 8B C8 45 8B CA C1 E1 ?? 33 C1 41 69 D0 ?? ?? ?? ?? 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 81 C2 ?? ?? ?? ?? 33 C1 43 8D 0C 02 02 C8 49 C1 EA ?? 41 88 0B 8B C8 C1 E1 ?? 33 C1 44 69 C2 ?? ?? ?? ?? 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 41 81 C0 } /*lcg chunk */
      $opa2 = { 8B C8 41 69 D1 ?? ?? ?? ?? C1 E1 ?? 33 C1 45 8B CA 8B C8 C1 E9 ?? 33 C1 81 C2 ?? ?? ?? ?? 8B C8 C1 E1 ?? 33 C1 41 8B C8 4C 0F AF CF 44 69 C2 ?? ?? ?? ?? 4C 03 C9 45 8B D1 4C 0F AF D7} /*lcg chunk */
      $opb1 = { 45 33 C9 48 89 6C 24 ?? 48 8D 44 24 ?? 48 89 6C 24 ?? 8B D3 48 89 B4 24 ?? ?? ?? ?? 48 89 44 24 ?? 45 8D 41 ?? FF 15 } /* base64 decode */
      $opb2 = { 44 8B 0F 45 8B C6 48 8B 4D ?? 49 8B D7 44 89 64 24 ?? 48 89 7C 24 ?? 44 89 4C 24 ?? 4C 8D 4D ?? 48 89 44 24 ?? 44 89 64 24 ?? 4C 89 64 24 ?? FF 15} /* AES decryption */
      $opb3 = { 48 FF C2 66 44 39 2C 56 75 ?? 4C 8D 4C 24 ?? 45 33 C0 48 8B CE FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 44 0F B7 44 24 ?? 33 F6 48 8B 54 24 ?? 45 33 C9 48 8B 0B 48 89 74 24 ?? 89 74 24 ?? C7 44 24 ?? ?? ?? ?? ?? 48 89 74 24 ?? FF 15 } /* internet connection */
      $opb4 = { 33 C0 48 8D 6B ?? 4C 8D 4C 24 ?? 89 44 24 ?? BA ?? ?? ?? ?? 48 89 44 24 ?? 48 8B CD 89 44 24 ?? 44 8D 40 ?? 8B F8 FF 15} /* VirtualProtect */
    condition:
      ( all of ($opa*) )
      or
      ( 1 of ($opa*) and 1 of ($opb*) )
      or
      ( 3 of ($opb*) )
}

rule SUSP_APT_MAL_NK_3CX_Malicious_Samples_Mar23_1 {
   meta:
      description = "Detects marker found in malicious DLLs related to 3CX compromise"
      author = "X__Junior, Florian Roth (Nextron Systems)"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      date = "2023-03-29"
      score = 75
      hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
      hash2 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
   strings:
      $opx1 = { 41 80 7C 00 FD FE 75 ?? 41 80 7C 00 FE ED 75 ?? 41 80 7C 00 FF FA 75 ?? 41 80 3C 00 CE } 
   condition:
      $opx1
}

rule APT_SUSP_NK_3CX_RC4_Key_Mar23_1 {
   meta:
      description = "Detects RC4 key used in 3CX binaries known to be malicious"
      author = "Florian Roth (Nextron Systems)"
      date = "2023-03-29"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      score = 70
      hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
      hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
      hash3 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
      hash4 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
   strings:
      $x1 = "3jB(2bsG#@c7"
   condition:
      ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d )
      and $x1
}

rule SUSP_3CX_App_Signed_Binary_Mar23_1 {
   meta:
      description = "Detects 3CX application binaries signed with a certificate and created in a time frame in which other known malicious binaries have been created"
      author = "Florian Roth (Nextron Systems)"
      date = "2023-03-29"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      score = 65
      hash1 = "fad482ded2e25ce9e1dd3d3ecc3227af714bdfbbde04347dbc1b21d6a3670405"
      hash2 = "dde03348075512796241389dfea5560c20a3d2a2eac95c894e7bbed5e85a0acc"
   strings:
      $sa1 = "3CX Ltd1"
      $sa2 = "3CX Desktop App" wide
      $sc1 = { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 } // Known compromised cert
   condition:
      uint16(0) == 0x5a4d
      and pe.timestamp > 1669680000 // 29.11.2022 earliest known malicious sample 
      and pe.timestamp < 1680108505 // 29.03.2023 date of the report
      and all of ($sa*)
      and $sc1 // serial number of known compromised certificate
}

rule SUSP_3CX_MSI_Signed_Binary_Mar23_1 {
   meta:
      description = "Detects 3CX MSI installers signed with a known compromised certificate and signed in a time frame in which other known malicious binaries have been signed"
      author = "Florian Roth (Nextron Systems)"
      date = "2023-03-29"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      score = 60
      hash1 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
      hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
   strings:
      $a1 = { 84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46 } // MSI marker
      $sc1 = { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 } // Known compromised cert
      $s1 = "3CX Ltd1"
      $s2 = "202303" // in 
   condition:
      uint16(0) == 0xcfd0
      and $a1 
      and $sc1 
      and (
         $s1 in (filesize-20000..filesize)
         and $s2 in (filesize-20000..filesize)
      )
}

rule APT_MAL_macOS_NK_3CX_Malicious_Samples_Mar23_1 {
   meta:
      description = "Detects malicious macOS application related to 3CX compromise (decrypted payload)"
      author = "Florian Roth"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      date = "2023-03-30"
      score = 80
      hash1 = "b86c695822013483fa4e2dfdf712c5ee777d7b99cbad8c2fa2274b133481eadb"
      hash2 = "ac99602999bf9823f221372378f95baa4fc68929bac3a10e8d9a107ec8074eca"
      hash3 = "51079c7e549cbad25429ff98b6d6ca02dc9234e466dd9b75a5e05b9d7b95af72"
    strings:
      $s1 = "20230313064152Z0"
      $s2 = "Developer ID Application: 3CX (33CF4654HL)"
    condition:
      uint16(0) == 0xfeca and all of them
}

// MISP event:2300 uuid:00f38400-e8af-4e48-8a15-6aac57f8aa7c org: to_ids:False tags:[]
rule M_Hunting_TAXHAUL_Hash_1

{

meta:

author = "Mandiant"

disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

description = "Rule looks for hardcoded value used in string hashing algorithm observed in instances of TAXHAUL."

md5 = "e424f4e52d21c3da1b08394b42bc0829"

strings:

$c_x64 = { 25 A3 87 DE [4-20] 25 A3 87 DE [4-20] 25 A3 87 DE }

condition:

filesize < 15MB and uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and any of them

}

// MISP event:2309 uuid:1aefea1b-0067-4bad-beec-0f225b8e8b7a org: to_ids:False tags:[]
rule apt_win_powerstar_persistence_batch : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects the batch script used to persist PowerStar via Startup."
        hash1 = "9777f106ac62829cd3cfdbc156100fe892cfc4038f4c29a076e623dc40a60872"
        memory_suitable = 1
        license = "Please see the license at the head of this rules file for acceptable use."

    strings:
        $s_1 = "e^c^h^o o^f^f"
        $s_2 = "powershertxdll.ertxdxe"
        $s_3 = "Get-Conrtxdtent -Prtxdath"
        $s_4 = "%appdata%\\Microsrtxdoft\\Windortxdws\\"
        $s_5 = "&(gcm i*x)$"
    condition:
        3 of them
}

// MISP event:2309 uuid:7ac00490-69dd-4b3a-a7fb-bf4a32b74594 org: to_ids:False tags:[]
rule apt_win_powerstar_memonly : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects the initial stage of the memory only variant of PowerStar."
        hash1 = "977cf5cc1d0c61b7364edcf397e5c67d910fac628c6c9a41cf9c73b3720ce67f"
        memory_suitable = 1
        license = "Please see the license at the head of this rules file for acceptable use."

    strings:
        $s_1 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($in.substring(3)))"
        $s_2 = "[Convert]::ToByte(([Convert]::ToString(-bnot ($text_bytes[$i])"
        $s_3 = "$Exec=[System.Text.Encoding]::UTF8.GetString($text_bytes)"
        $s_4 = "((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})"
        $f_1 = "function Gorjol{"
        $f_2 = "Borjol \"$"
        $f_3 = "Gorjol -text"
        $f_4 = "function Borjoly{"
        $f_6 = "$filename = $env:APPDATA+\"\\Microsoft\\Windows\\DocumentPreview.pdf\";"
        $f_7 = "$env:APPDATA+\"\\Microsoft\\Windows\\npv.txt\""
        $f_8 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\brt8ts74e.bat"
        $f_9 = "\\Microsoft\\Windows\\s7qe52.txt"
        $f_10 = "$yeolsoe2 = $yeolsoe"
        $f_11 = "setRequestHeader(\"Content-DPR\""
        $f_12 = "getResponseHeader(\"Content-DPR\")"
        $f_13 = {24 43 6f 6d 6d 61 6e 64 50 61 72 74 73 20 3d 24 53 65 73 73 69 6f 6e 52 65 73 70 6f 6e 73 65 2e 53 70 6c 69 74 28 22 b6 22 29}
        $f_14 = "$language -like \"*shar*\""
        $f_15 = "$language -like \"*owers*\""
        $alias_1 = "(gcm *v????E?P?e*)"
        $alias_2 = "&(gcm *ke-e*) $Command"
        $key = "T2r0y1M1e1n1o0w1"
        $args_1 = "$sem.Close()"
        $args_2 = "$cem.Close()"
        $args_3 = "$mem.Close()"
        $command_1 = "_____numone_____"
        $command_2 = "_____mac2_____"
        $command_3 = "_____yeolsoe_____"
    condition:
        2 of ($s_*) or
        any of ($f_*) or
        2 of ($alias_*) or
        $key or
        all of ($args_*) or
        any of ($command_*)
}

// MISP event:2309 uuid:735addec-6df5-4061-9de2-c439c941111d org: to_ids:False tags:[]
rule apt_win_powerstar_logmessage : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects interesting log message embedded in memory only version of PowerStar."
        memory_suitable = 1
        license = "Please see the license at the head of this rules file for acceptable use."

    strings:
        $s_1 = "wau, ije ulineun mueos-eul halkkayo?"
    condition:
        all of them
}

// MISP event:2309 uuid:a08288ec-f7be-4ed8-9575-cbeb63b3597b org: to_ids:False tags:[]
rule apt_win_powerstar_lnk : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects LNK command line used to install PowerStar."
        memory_suitable = 1
        license = "Please see the license at the head of this rules file for acceptable use."

    strings:
        $p_1 = "-UseBasicParsing).Content; &(gcm i*x)$"

        $c_1 = "powershecde43ell.ecde43exe"
        $c_2 = "wgcde43eet -Ucde43eri"
        $c_3 = "-UseBasicde43ecParsing).Contcde43eent; &(gcm i*x)$"
    condition:
        any of them
}

// MISP event:2309 uuid:c064e437-b042-492a-bff7-971cbbc6ec2a org: to_ids:False tags:[]
rule apt_win_powerstar_decrypt_function : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects PowerStar decrypt function, potentially downloaded standalone and then injected."
        hash1 = "b79d28fe5e3c988bb5aadb12ce442d53291dbb9ede0c7d9d64eec078beba5585"
        memory_suitable = 1
        license = "Please see the license at the head of this rules file for acceptable use."

    strings:
        $f_1 = "function Borjol{"

        $s_1 = "$global:Domain = \""
        $s_2 = "$global:IP = \""
        $s_3 = "$global:yeolsoe"
        $s_4 = "$semii.Close()"
        $s_5 = "$cemii.Close()"
        $s_6 = "$memii.Close()"
    condition:
        any of ($f_*) or
        2 of ($s_*)

}

// MISP event:2309 uuid:6e9ed04b-7d9e-4454-80fe-6155a229b2a1 org: to_ids:False tags:[]
rule apt_win_powerstar : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        description = "Custom PowerShell backdoor used by Charming Kitten."
        date = "2021-10-13"
        hash1 = "de99c4fa14d99af791826a170b57a70b8265fee61c6b6278d3fe0aad98e85460"
        memory_suitable = 1
        license = "Please see the license at the head of this rules file for acceptable use."

    strings:
        $appname = "[AppProject.Program]::Main()" ascii wide // caller for C# code

        $langfilters1 = "*shar*" ascii wide
        $langfilters2 = "*owers*" ascii wide

        $definitions1 = "[string]$language" ascii wide
        $definitions2 = "[string]$Command" ascii wide
        $definitions3 = "[string]$ThreadName" ascii wide
        $definitions4 = "[string]$StartStop" ascii wide

        $sess = "$session = $v + \";;\" + $env:COMPUTERNAME + $mac;" ascii wide

    condition:
        $appname or
        all of ($langfilters*) or
        all of ($definitions*) or
        $sess
}

// MISP event:2313 uuid:82b4afd9-6e7b-424a-9a0c-6e0b13e17fee org: to_ids:False tags:[]
rule APT29_Duke_Malware_Jul17
{
    meta: 
        description = "Detects APT29 Duke malware variant "  
        Author = "EclecticIQ Threat Research Team"   
        creation_date = "2023-07-30"  
        classification = "TLP:WHITE"
        hash1 = "0be11b4f34ede748892ea49e473d82db"
        hash2 = "5e1389b494edc86e17ff1783ed6b9d37"
    strings:
        $x1 = {48 89 4C 24 08 48 89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 64 48 C7 C1}
            /*
0x2ac406170 80790F00                   cmp byte ptr [rcx + 0xf], 0
0x2ac406174 4889C8                      mov rax, rcx
0x2ac406177 751C                          jne 0x2ac406195
0x2ac406179 4889CA                     mov rdx, rcx
0x2ac40617c 488D490F                  lea rcx, [rcx + 0xf]
0x2ac406180 440FB64010              movzx r8d, byte ptr [rax + 0x10]
0x2ac406185 443002                       xor byte ptr [rdx], r8b
0x2ac406188 4883C201                  add rdx, 1
0x2ac40618c 4839CA                      cmp rdx, rcx
0x2ac40618f 75EF                           jne 0x2ac406180
0x2ac406191 C6400F01                  mov byte ptr [rax + 0xf], 1
0x2ac406195 C3                              ret 
 */
  $decryption_routine = {
80 79 ?? 00
48 89 C8
75 ??
48 89 CA
48 8D 49 ??
44 0F B6 40 ??
44 30 02
48 83 C2 01
48 39 CA
75 ??
C6 40 ?? 01
C3
}
    condition:
        uint16(0) == 0x5A4D and
        $x1 or $decryption_routine and 
        filesize <= 2MB
}

// MISP event:2313 uuid:b45cb583-c491-43cd-ad0c-192013a09d7d org: to_ids:False tags:[]
rule APT29_Embassy_Invitation_Lure
{
    meta: 
        description = "Detects APT29 Embassy Invitation Lure"  
        Author = "EclecticIQ Threat Research Team"   
        creation_date = "2023-07-30"  
        classification = "TLP:WHITE"
        hash1 = "fc53c75289309ffb7f65a3513e7519eb"
    strings:
        $pdf_meta1 = {2f 54 79 70 65 20 2f 45 6d 62 65 64 64 65 64 46 69 6c 65}
        $pdf_meta2 = "q='+btoa(p)" fullword ascii wide nocase 
        $x1 = {2F 50 72 6F 64 75 63 65 72 20 28 50 79 50 44 46 32 29}  
        $x2 = "Invitation"  fullword ascii wide nocase 
        $x3 = "embassy"  fullword ascii wide nocase 
        $x4 = "reception"  fullword ascii wide nocase 
    condition:
         ( uint32(0) == 0x46445025 or uint32(0) == 0x4450250a ) and
         all of ($pdf_meta*) and any of ($x*) and
         filesize <= 1MB
}

