/*

   Generic Anomalies

   Florian Roth
   BSK Consulting GmbH

	License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
	Copyright and related rights waived via https://creativecommons.org/licenses/by-nc-sa/4.0/

*/
/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-12-21
    Identifier: Uncommon File Sizes
*/

rule Suspicious_Size_explorer_exe {
    meta:
        description = "Detects uncommon file size of explorer.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "explorer.exe"
        and not filepath contains "teamviewer"
        and ( filesize < 800KB or filesize > 5000KB )
}

rule Suspicious_Size_chrome_exe {
    meta:
        description = "Detects uncommon file size of chrome.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "chrome.exe"
        and ( filesize < 500KB or filesize > 2000KB )
}

rule Suspicious_Size_csrss_exe {
    meta:
        description = "Detects uncommon file size of csrss.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "csrss.exe"
        and ( filesize > 18KB )
}

rule Suspicious_Size_iexplore_exe {
    meta:
        description = "Detects uncommon file size of iexplore.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "iexplore.exe"
        and not filepath contains "teamviewer"
        and ( filesize < 75KB or filesize > 910KB )
}

rule Suspicious_Size_firefox_exe {
    meta:
        description = "Detects uncommon file size of firefox.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "firefox.exe"
        and ( filesize < 265KB or filesize > 910KB )
}

rule Suspicious_Size_java_exe {
    meta:
        description = "Detects uncommon file size of java.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "java.exe"
        and ( filesize < 42KB or filesize > 900KB )
}

rule Suspicious_Size_lsass_exe {
    meta:
        description = "Detects uncommon file size of lsass.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "lsass.exe"
        and ( filesize < 10KB or filesize > 58KB )
}

rule Suspicious_Size_svchost_exe {
    meta:
        description = "Detects uncommon file size of svchost.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "svchost.exe"
        and ( filesize < 14KB or filesize > 60KB )
}

rule Suspicious_Size_winlogon_exe {
    meta:
        description = "Detects uncommon file size of winlogon.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "winlogon.exe"
        and ( filesize < 279KB or filesize > 970KB )
}

rule Suspicious_Size_igfxhk_exe {
    meta:
        description = "Detects uncommon file size of igfxhk.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "igfxhk.exe"
        and ( filesize < 200KB or filesize > 265KB )
}

rule Suspicious_Size_servicehost_dll {
    meta:
        description = "Detects uncommon file size of servicehost.dll"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
    condition:
        uint16(0) == 0x5a4d
        and filename == "servicehost.dll"
        and filesize > 150KB
}

rule Suspicious_Size_rundll32_exe {
    meta:
        description = "Detects uncommon file size of rundll32.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
    condition:
        uint16(0) == 0x5a4d
        and filename == "rundll32.exe"
        and ( filesize < 30KB or filesize > 80KB )
}

rule Suspicious_Size_taskhost_exe {
    meta:
        description = "Detects uncommon file size of taskhost.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
    condition:
        uint16(0) == 0x5a4d
        and filename == "taskhost.exe"
        and ( filesize < 45KB or filesize > 120KB )
}

rule Suspicious_Size_spoolsv_exe {
    meta:
        description = "Detects uncommon file size of spoolsv.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
    condition:
        uint16(0) == 0x5a4d
        and filename == "spoolsv.exe"
        and ( filesize < 50KB or filesize > 930KB )
}

rule Suspicious_Size_smss_exe {
    meta:
        description = "Detects uncommon file size of smss.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
    condition:
        uint16(0) == 0x5a4d
        and filename == "smss.exe"
        and ( filesize < 40KB or filesize > 320KB )
}

rule Suspicious_Size_wininit_exe {
    meta:
        description = "Detects uncommon file size of wininit.exe"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
    condition:
        uint16(0) == 0x5a4d
        and filename == "wininit.exe"
        and ( filesize < 90KB or filesize > 400KB )
}

rule Suspicious_AutoIt_by_Microsoft {
   meta:
      description = "Detects a AutoIt script with Microsoft identification"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research - VT"
      date = "2017-12-14"
      score = 60
      hash1 = "c0cbcc598d4e8b501aa0bd92115b4c68ccda0993ca0c6ce19edd2e04416b6213"
   strings:
      $s1 = "Microsoft Corporation. All rights reserved" fullword wide
      $s2 = "AutoIt" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule SUSP_Size_of_ASUS_TuningTool {
   meta:
      description = "Detects an ASUS tuning tool with a suspicious size"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17"
      score = 60
      hash1 = "d4e97a18be820a1a3af639c9bca21c5f85a3f49a37275b37fd012faeffcb7c4a"
   strings:
      $s1 = "\\Release\\ASGT.pdb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and filesize > 70KB and all of them
}
