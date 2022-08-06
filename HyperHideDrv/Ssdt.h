#pragma once
#include <ntifs.h>

namespace SSDT 
{
	BOOLEAN FindCodeCaves();

	BOOLEAN HookWin32kSyscall(CHAR* SyscallName, SHORT SyscallIndex, PVOID NewFunctionAddress, PVOID* OriginFunction);

	BOOLEAN HookNtSyscall(ULONG SyscallIndex, PVOID NewFunctionAddress, PVOID* OriginFunction);

	BOOLEAN GetSsdt();

	PVOID GetWin32KFunctionAddress(CONST CHAR* SyscallName, SHORT SyscallIndex);
}