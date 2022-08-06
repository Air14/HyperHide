#pragma once
#include <ntifs.h>

VOID ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);

VOID ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);