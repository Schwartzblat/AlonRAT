#pragma once
#include "Windows.h"
#include <cstdint>



typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
} UNICODE_STRING;

// Define the PEB structure
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    struct _PEB_LDR_DATA* Ldr; // Corrected declaration
} PEB, * PPEB;

// Define the PEB_LDR_DATA structure
typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// Define the LDR_DATA_TABLE_ENTRY structure
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    PVOID Reserved5[2];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;