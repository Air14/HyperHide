#pragma once
#include <ntifs.h>
#include <array>
#include <string>

struct SyscallInfo
{
	SHORT SyscallNumber;
	std::string_view SyscallName;
	PVOID HookFunctionAddress;
	PVOID* OriginalFunctionAddress;
};

BOOLEAN GetNtSyscallNumbers(std::array<SyscallInfo, 22>& SyscallsToFind);

BOOLEAN GetWin32kSyscallNumbers(std::array<SyscallInfo, 5>& SyscallsToFind);

BOOLEAN IsWindowBad(HANDLE hWnd);

VOID FilterProcesses(PSYSTEM_PROCESS_INFO ProcessInfo);