#pragma once
#include <ntifs.h>

#define ObjectTypesInformation 3
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x40
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x4
#define PROCESS_DEBUG_INHERIT 0x00000001 // default for a non-debugged process
#define PROCESS_NO_DEBUG_INHERIT 0x00000002 // default for a debugged process
#define PROCESS_QUERY_INFORMATION   0x0400
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

#define BACKUP_RETURNLENGTH() \
    ULONG TempReturnLength = 0; \
    if(ARGUMENT_PRESENT(ReturnLength)) \
        TempReturnLength = *ReturnLength

#define RESTORE_RETURNLENGTH() \
    if(ARGUMENT_PRESENT(ReturnLength)) \
        (*ReturnLength) = TempReturnLength

BOOLEAN HookSyscalls();