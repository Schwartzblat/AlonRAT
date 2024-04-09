#pragma once
#include <string>
#include <WS2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include "obfuscate.h"
#include "windows_structs.h"
#include "winapi_types.h"

#define WINAPI_OBFUSCATE(type, name, dll) reinterpret_cast<type>(resolve_winapi(OBFUSCATE(dll), OBFUSCATE(name)))

void initilize_winapi();

FARPROC resolve_winapi(const char* dll_name, const char* func_name);