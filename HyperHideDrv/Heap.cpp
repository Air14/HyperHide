#pragma warning( disable : 4201 4100 4101 4244 4333 4245 4366)
#include <ntifs.h>
#include "Ntapi.h"
#include "Log.h"
#include "Heap.h"
#include "Peb.h"

#define HEAP_SKIP_VALIDATION_CHECKS 0x10000000  
#define HEAP_VALIDATE_PARAMETERS_ENABLED  0x40000000

BOOLEAN ClearHeapFlags(PEPROCESS TargetProcess)
{
	PPEB Peb = (PPEB)PsGetProcessPeb(TargetProcess);
	PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(TargetProcess);

	// https://ctf-wiki.github.io/ctf-wiki/reverse/windows/anti-debug/heap-flags/
	// In all versions of Windows, the value of the Flags 
	// field is normally set to HEAP_GROWABLE(2), 
	// and the ForceFlags field is normally set to 0

	// 32-bit process.Both of these default values depend on the[subsystem] of its host process
	if (Peb32 != NULL)
	{
		KAPC_STATE State;
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

		__try
		{
			for (size_t i = 0; i < Peb32->NumberOfHeaps; i++)
			{
				ULONG Heap = *(ULONG*)(Peb32->ProcessHeaps + 4 * i);

				// Heap Flags
				*(ULONG*)(Heap + 0x40) &= ~(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_SKIP_VALIDATION_CHECKS | HEAP_VALIDATE_PARAMETERS_ENABLED);

				// Heap Force Flags
				*(ULONG*)(Heap + 0x44) &= ~(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_VALIDATE_PARAMETERS_ENABLED);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) 
		{
			LogError("Access violation");
			KeUnstackDetachProcess(&State);
			return FALSE;
		}

		KeUnstackDetachProcess(&State);
	}

	if (Peb != NULL)
	{
		KAPC_STATE State;
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

		__try 
		{
			for (size_t i = 0; i < Peb->NumberOfHeaps; i++)
			{
				PHEAP Heap = (PHEAP)Peb->ProcessHeaps[i];
				Heap->Flags &= ~(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_SKIP_VALIDATION_CHECKS | HEAP_VALIDATE_PARAMETERS_ENABLED);
				Heap->ForceFlags &= ~(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_VALIDATE_PARAMETERS_ENABLED);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LogError("Access violation");
			KeUnstackDetachProcess(&State);
			return FALSE;
		}

		KeUnstackDetachProcess(&State);
	}
	else
	{
		LogError("Both Peb and Peb32 doesn't exist");
		return FALSE;
	}

	return TRUE;
}