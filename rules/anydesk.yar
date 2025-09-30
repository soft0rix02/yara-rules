rule INDICATOR_RMM_AnyDesk {
   meta:
      description = "_subset_batch - file AnyDesk.exe"
      author = "Metin Yigit"
      reference = "internal"
      date = "2025-09-28"
      hash1 = "ac7f226bdf1c6750afa6a03da2b483eee2ef02cd9c2d6af71ea7c6a9a4eace2f"
   strings:
      $x1 = "C:\\Users\\worker\\workspace\\AD_windows32\\release\\win_9.6.1\\4004\\anydesk\\release\\app-32\\win_loader\\AnyDesk.pdb" fullword ascii /* score: '42.00'*/
      $x2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii /* score: '32.00'*/
      $s3 = "<assemblyIdentity version=\"9.6.1.0\" processorArchitecture=\"x86\" name=\"AnyDesk.AnyDesk.AnyDesk\" type=\"win32\" />" fullword ascii /* score: '19.00'*/
      $s4 = "http://www.digicert.com/CPS0" fullword ascii /* score: '17.00'*/
      $s5 = "<description>AnyDesk screen sharing and remote control software.</description>" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 23000KB and
      1 of ($x*) and 2 of them
}
