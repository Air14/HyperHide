#pragma warning( disable : 4201)
#include <ntddk.h>
#include <ntifs.h>
#include "Ntapi.h"
#include "Log.h"
#include "Peb.h"

BOOLEAN SetPebDeuggerFlag(PEPROCESS TargetProcess, BOOLEAN Value)
{
	PPEB Peb = PsGetProcessPeb(TargetProcess);
	PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(TargetProcess);
	if (Peb32 != NULL)
	{
		KAPC_STATE State;
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);
		__try
		{
			Peb32->BeingDebugged = Value;

			Peb->BeingDebugged = Value;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LogError("Access Violation");
			KeUnstackDetachProcess(&State);
			return FALSE;
		}

		KeUnstackDetachProcess(&State);
	}
	else if (Peb != NULL)
	{
		KAPC_STATE State;
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);
		__try
		{
			Peb->BeingDebugged = Value;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LogError("Access Violation");
			KeUnstackDetachProcess(&State);
			return FALSE;
		}
		KeUnstackDetachProcess(&State);
	}
	else
	{
		LogError("Both pebs doesn't exist");
		return FALSE;
	}

	return TRUE;
}

BOOLEAN ClearPebNtGlobalFlag(PEPROCESS TargetProcess)
{
	PPEB Peb = PsGetProcessPeb(TargetProcess);
	PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(TargetProcess);
	if (Peb32 != NULL)
	{
		KAPC_STATE State;
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);
		__try
		{
			Peb32->NtGlobalFlag &= ~0x70;

			Peb->NtGlobalFlag &= ~0x70;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LogError("Access Violation");
			KeUnstackDetachProcess(&State);
			return FALSE;
		}

		KeUnstackDetachProcess(&State);
	}
	else if (Peb != NULL)
	{
		KAPC_STATE State;
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);
		__try
		{
			Peb->NtGlobalFlag &= ~0x70;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LogError("Access Violation");
			KeUnstackDetachProcess(&State);
			return FALSE;
		}
		KeUnstackDetachProcess(&State);
	}
	else
	{
		LogError("Both pebs doesn't exist");
		return FALSE;
	}

	return TRUE;
}