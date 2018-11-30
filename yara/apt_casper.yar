
/* State-sponsored Casper Malware Rules by @4nc4p - attribution and analysis by @pinkflawd @r00tbsd @circl_lu */

rule Casper_EXE_Dropper {
	meta:
		description = "Casper French Espionage Malware - Win32/ProxyBot.B - Dropper http://goo.gl/VRJNLo"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/05"
		hash = "e4cc35792a48123e71a2c7b6aa904006343a157a"
		score = 80
	strings:
		$s0 = "<Command>" fullword ascii
		$s1 = "</Command>" fullword ascii
		$s2 = "\" /d \"" fullword ascii
		$s4 = "'%s' %s" fullword ascii
		$s5 = "nKERNEL32.DLL" fullword wide
		$s6 = "@ReturnValue" fullword wide
		$s7 = "ID: 0x%x" fullword ascii
		$s8 = "Name: %S" fullword ascii
	condition:
		7 of them
}

rule Casper_Included_Strings {
	meta:
		description = "Casper French Espionage Malware - String Match in File - http://goo.gl/VRJNLo"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/06"
		score = 50
	strings:
		$a0 = "cmd.exe /C FOR /L %%i IN (1,1,%d) DO IF EXIST"
		$a1 = "& SYSTEMINFO) ELSE EXIT"
		
		$mz = { 4d 5a }
		$c1 = "domcommon.exe" wide fullword							// File Name
		$c2 = "jpic.gov.sy" fullword 								// C2 Server
		$c3 = "aiomgr.exe" wide fullword							// File Name
		$c4 = "perfaudio.dat" fullword								// Temp File Name
		$c5 = "Casper_DLL.dll" fullword								// Name 
		$c6 = { 7B 4B 59 DE 37 4A 42 26 59 98 63 C6 2D 0F 57 40 } 	// Decryption Key
		$c7 = "{4216567A-4512-9825-7745F856}" fullword 				// Mutex
	condition:
		all of ($a*) or
		( $mz at 0 ) and ( 1 of ($c*) )
}

rule Casper_SystemInformation_Output {
	meta:
		description = "Casper French Espionage Malware - System Info Output - http://goo.gl/VRJNLo"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/06"
		score = 70	
	strings:
		$a0 = "***** SYSTEM INFORMATION ******"
		$a1 = "***** SECURITY INFORMATION ******"
		$a2 = "Antivirus: "
		$a3 = "Firewall: "
		$a4 = "***** EXECUTION CONTEXT ******"
		$a5 = "Identity: "
		$a6 = "<CONFIG TIMESTAMP="
	condition:
		all of them
}
