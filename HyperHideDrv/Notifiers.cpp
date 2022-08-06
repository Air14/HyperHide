#pragma warning( disable : 4201)
#include <ntifs.h>
#include "Hider.h"
#include "Utils.h"
#include "Ntapi.h"
#include "Log.h"
#include <intrin.h>

VOID ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
	if (Create == FALSE)
	{
		PETHREAD CurrentThread;
		if (NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &CurrentThread)) == TRUE)
			Hider::TruncateThreadList(PidToProcess(ProcessId), CurrentThread);
	}
}

VOID ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	UNREFERENCED_PARAMETER(ParentId);

	if (Create == FALSE)
		Hider::RemoveEntry(PidToProcess(ProcessId));
}