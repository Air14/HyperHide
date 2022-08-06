#pragma warning( disable : 4201)
#include <ntddk.h>
#include "Utils.h"
#include "Hider.h"
#include "GlobalData.h"
#include "Log.h"
#include "Ntapi.h"
#include "KuserSharedData.h"
#include "Peb.h"

namespace Hider
{
	KGUARDED_MUTEX HiderMutex;
	LIST_ENTRY HiddenProcessesHead;
	BOOLEAN StopCounterThread = FALSE;
	HANDLE CounterThreadHandle = NULL;

	CONST WCHAR* HiddenDeviceNames[] =
	{
		L"\\??\\HyperHideDrv",
		L"\\??\\airhv",
		L"\\??\\ProcmonDebugLogger",
	};
	
	CONST WCHAR* HiddenWindowNames[] =
	{
		L"x64dbg",
		L"x32dbg",
		L"Process Hacker",
		L"Import reconstructor",
		L"[CPU",
		L"Debug",
		L"scylla",
		L"HyperHide",
		L"disassembly",
		L"ida"
		L"HyperHide"
		L"Sysinternals"
	};

	CONST WCHAR* HiddenApplicationNames[] =
	{
		L"ollydbg.exe",
		L"ida.exe",
		L"ida64.exe",
		L"idag.exe",
		L"idag64.exe",
		L"idaw.exe",
		L"idaw64.exe",
		L"idaq.exe",
		L"idaq64.exe",
		L"idau.exe",
		L"idau64.exe",
		L"scylla.exe",
		L"scylla_x64.exe",
		L"scylla_x86.exe",
		L"protection_id.exe",
		L"x64dbg.exe",
		L"x32dbg.exe",
		L"reshacker.exe",
		L"ImportREC.exe",
		L"devenv.exe",
		L"ProcessHacker.exe",
		L"tcpview.exe",
		L"autoruns.exe",
		L"autorunsc.exe",
		L"filemon.exe",
		L"procmon.exe",
		L"regmon.exe",
		L"wireshark.exe",
		L"dumpcap.exe",
		L"HookExplorer.exe",
		L"ImportRCE.exe",
		L"PETools.exe",
		L"LordPE.exe",
		L"SysInspector.exe",
		L"proc_analyzer.exe",
		L"sysAnalyzer.exe",
		L"sniff_hit.exe",
		L"joeboxcontrol.exe",
		L"joeboxserver.exe",
		L"ResourceHacker.exe",
		L"fiddler.exe",
		L"httpdebugger.exe",
		L"procexp64.exe",
		L"procexp.exe",
		L"Dbgview.exe",
		L"procmon64.exe"
	};

	CONST WCHAR* HiddenWindowClassNames[] =
	{
		L"Qt5QWindowIcon" // Ida and x64dbg ClassNames
		L"ObsidianGUI",
		L"idawindow",
		L"tnavbox",
		L"idaview",
		L"tgrzoom"
	};

	VOID DeleteThreadList(PHIDDEN_PROCESS HiddenProcess)
	{
		PLIST_ENTRY CurrentThread = HiddenProcess->HiddenThreads.HiddenThreadList.Flink;
		while (CurrentThread != &HiddenProcess->HiddenThreads.HiddenThreadList)
		{
			PHIDDEN_THREAD HiddenThread = (PHIDDEN_THREAD)CONTAINING_RECORD(CurrentThread, HIDDEN_THREAD, HiddenThreadList);
			RemoveEntryList(CurrentThread);
			CurrentThread = CurrentThread->Flink;
			ExFreePoolWithTag(HiddenThread, DRIVER_TAG);
		}
	}

	//
	// Append and return.If thread struct already exist return it
	//
	PHIDDEN_THREAD AppendThreadList(PEPROCESS TargetProcess, PETHREAD ThreadObject)
	{
		PHIDDEN_THREAD HiddenThread = NULL;
		BOOLEAN Acquired = KeTryToAcquireGuardedMutex(&HiderMutex);
		
		PLIST_ENTRY Current = HiddenProcessesHead.Flink;
		while (Current != &HiddenProcessesHead)
		{
			PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
			Current = Current->Flink;

			if (HiddenProcess->DebuggedProcess == TargetProcess)
			{
				PLIST_ENTRY CurrentThread = HiddenProcess->HiddenThreads.HiddenThreadList.Flink;

				while (CurrentThread != &HiddenProcess->HiddenThreads.HiddenThreadList)
				{
					HiddenThread = (PHIDDEN_THREAD)CONTAINING_RECORD(CurrentThread, HIDDEN_THREAD, HiddenThreadList);
					CurrentThread = CurrentThread->Flink;
	
					if (HiddenThread->ThreadObject == ThreadObject)
						goto End;
				}

				HiddenThread = (PHIDDEN_THREAD)ExAllocatePoolWithTag(NonPagedPool, sizeof(HIDDEN_THREAD), DRIVER_TAG);
				if (HiddenThread == NULL)
					return NULL;

				RtlSecureZeroMemory(HiddenThread, sizeof(HIDDEN_THREAD));
				HiddenThread->ThreadObject = ThreadObject;

				InsertTailList(&HiddenProcess->HiddenThreads.HiddenThreadList, &HiddenThread->HiddenThreadList);
				break;
			}
		}

	End:
		if(Acquired == TRUE)
			KeReleaseGuardedMutex(&HiderMutex);

		return HiddenThread;
	}

	VOID TruncateThreadList(PEPROCESS TargetProcess, PETHREAD ThreadObject)
	{
		KeAcquireGuardedMutex(&HiderMutex);
		
		PLIST_ENTRY Current = HiddenProcessesHead.Flink;
		while (Current != &HiddenProcessesHead)
		{
			PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
			Current = Current->Flink;

			if (HiddenProcess->DebuggedProcess == TargetProcess)
			{
				PLIST_ENTRY CurrentThread = HiddenProcess->HiddenThreads.HiddenThreadList.Flink;
				while (CurrentThread != &HiddenProcess->HiddenThreads.HiddenThreadList)
				{
					PHIDDEN_THREAD HiddenThread = (PHIDDEN_THREAD)CONTAINING_RECORD(CurrentThread, HIDDEN_THREAD, HiddenThreadList);
					CurrentThread = CurrentThread->Flink;

					if (HiddenThread->ThreadObject == ThreadObject)
					{
						RemoveEntryList(&HiddenThread->HiddenThreadList);
						ExFreePoolWithTag(HiddenThread, DRIVER_TAG);

						goto End;
					}
				}
			}
		}

	End:
		KeReleaseGuardedMutex(&HiderMutex);
	}

	PHIDDEN_PROCESS QueryHiddenProcess(PEPROCESS TargetProcess)
	{
		KeAcquireGuardedMutex(&HiderMutex);

		PLIST_ENTRY Current = HiddenProcessesHead.Flink;
		while (Current != &HiddenProcessesHead)
		{
			PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
			Current = Current->Flink;

			if (HiddenProcess->DebuggedProcess == TargetProcess)
			{
				KeReleaseGuardedMutex(&HiderMutex);
				return HiddenProcess;
			}
		}

		KeReleaseGuardedMutex(&HiderMutex);
		return NULL;
	}

	BOOLEAN StopCounterForProcess(PEPROCESS TargetProcess)
	{
		BOOLEAN Status = FALSE;

		if (TargetProcess == NULL)
		{
			LogError("Debugger process equal null");
			return Status;
		}

		KeAcquireGuardedMutex(&HiderMutex);
		PLIST_ENTRY Current = HiddenProcessesHead.Flink;
		while (Current != &HiddenProcessesHead)
		{
			PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
			Current = Current->Flink;

			if (TargetProcess == HiddenProcess->DebuggedProcess)
			{
				Status = HiddenProcess->ProcessPaused = TRUE;
				break;
			}
		}

		KeReleaseGuardedMutex(&HiderMutex);
		return Status;
	}

	BOOLEAN ResumeCounterForProcess(PEPROCESS TargetProcess)
	{
		BOOLEAN Status = FALSE;
		if (TargetProcess == NULL)
		{
			LogError("Debugger process equal null");
			return Status;
		}

		KeAcquireGuardedMutex(&HiderMutex);
		PLIST_ENTRY Current = HiddenProcessesHead.Flink;
		while (Current != &HiddenProcessesHead)
		{
			PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
			Current = Current->Flink;

			if (TargetProcess == HiddenProcess->DebuggedProcess)
			{
				HiddenProcess->ProcessPaused = FALSE;
				Status = TRUE;
				break;
			}
		}

		KeReleaseGuardedMutex(&HiderMutex);
		return Status;
	}

	BOOLEAN Initialize()
	{
		InitializeListHead(&HiddenProcessesHead);
		KeInitializeGuardedMutex(&HiderMutex);

		if (GetPfnDatabase() == FALSE)
		{
			LogError("Couldn't get pfn database");
			return FALSE;
		}

		if (NT_SUCCESS(PsCreateSystemThread(&CounterThreadHandle, 0, 0, 0, 0, CounterUpdater, NULL)) == FALSE)
		{
			LogError("Couldn't create system thread");
			return FALSE;
		}

		return TRUE;
	}

	VOID Uninitialize()
	{
		PETHREAD CounterThread;
		ObReferenceObjectByHandle(CounterThreadHandle, NULL, *PsThreadType, KernelMode, (PVOID*)&CounterThread, NULL);
		StopCounterThread = TRUE;
		KeWaitForSingleObject(CounterThread, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(CounterThread);
		ZwClose(CounterThreadHandle);

		PLIST_ENTRY Current = HiddenProcessesHead.Flink;
		while (Current != &HiddenProcessesHead)
		{
			PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
			Current = Current->Flink;

			if (HiddenProcess->HiddenThreads.HiddenThreadList.Flink != NULL)
			{
				if (HiddenProcess->HideTypes[HIDE_KUSER_SHARED_DATA] == TRUE)
				{
					HiddenProcess->Kusd.PteKuserSharedData->Fields.PhysicalAddress = HiddenProcess->Kusd.OriginalKuserSharedDataPfn;
					MmFreeContiguousMemory(HiddenProcess->Kusd.KuserSharedData);
				}

				PLIST_ENTRY CurrentThread = HiddenProcess->HiddenThreads.HiddenThreadList.Flink;
				while (CurrentThread != &HiddenProcess->HiddenThreads.HiddenThreadList)
				{
					PHIDDEN_THREAD HiddenThread = (PHIDDEN_THREAD)CONTAINING_RECORD(CurrentThread, HIDDEN_THREAD, HiddenThreadList);
					CurrentThread = CurrentThread->Flink;
					ExFreePoolWithTag(HiddenThread, DRIVER_TAG);
				}
			}

			ExFreePoolWithTag(HiddenProcess, DRIVER_TAG);
		}

	}

	BOOLEAN CreateEntry(PEPROCESS DebuggerProcess, PEPROCESS DebuggedProcess)
	{
		PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)ExAllocatePoolWithTag(NonPagedPool, sizeof(HIDDEN_PROCESS), DRIVER_TAG);
		if (HiddenProcess == NULL)
		{
			LogError("Allocation failed");
			return FALSE;
		}
		RtlSecureZeroMemory(HiddenProcess, sizeof(HIDDEN_PROCESS));

		HiddenProcess->DebuggedProcess = DebuggedProcess;
		HiddenProcess->DebuggerProcess = DebuggerProcess;

		KeAcquireGuardedMutex(&HiderMutex);
		InsertTailList(&HiddenProcessesHead, &HiddenProcess->HiddenProcessesList);
		InitializeListHead(&HiddenProcess->HiddenThreads.HiddenThreadList);
		KeReleaseGuardedMutex(&HiderMutex);

		return TRUE;
	}

	BOOLEAN RemoveEntry(PEPROCESS TargetProcess)
	{
		if (TargetProcess == NULL)
		{
			LogError("Target process equal null");
			return FALSE;
		}

		KeAcquireGuardedMutex(&HiderMutex);

		PLIST_ENTRY Current = HiddenProcessesHead.Flink;
		while (Current != &HiddenProcessesHead)
		{
			PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
			Current = Current->Flink;

			if (HiddenProcess->DebuggedProcess == TargetProcess || HiddenProcess->DebuggerProcess == TargetProcess)
			{
				DeleteThreadList(HiddenProcess);

				RemoveEntryList(Current->Blink);

				if (HiddenProcess->Kusd.KuserSharedData != NULL)
				{
					UnHookKuserSharedData(HiddenProcess);
				}

				ExFreePoolWithTag(HiddenProcess, DRIVER_TAG);
			}
		}

		KeReleaseGuardedMutex(&HiderMutex);
		return TRUE;
	}

	BOOLEAN IsDebuggerProcess(PEPROCESS TargetProcess)
	{
		BOOLEAN Status = FALSE;
		if (TargetProcess == NULL)
		{
			LogError("Target process equal null");
			return Status;
		}

		KeAcquireGuardedMutex(&HiderMutex);

		PLIST_ENTRY Current = HiddenProcessesHead.Flink;
		while (Current != &HiddenProcessesHead)
		{
			PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
			Current = Current->Flink;

			if (HiddenProcess->DebuggerProcess == TargetProcess)
			{
				Status = TRUE;
				break;
			}
		}

		KeReleaseGuardedMutex(&HiderMutex);
		return Status;
	}

	BOOLEAN IsHidden(PEPROCESS TargetProcess, HIDE_TYPE HideType)
	{
		BOOLEAN Status = FALSE;
		if (HideType >= HIDE_LAST)
		{
			LogError("Wrong hide type");
			return Status;
		}

		KeAcquireGuardedMutex(&HiderMutex);

		PLIST_ENTRY Current = HiddenProcessesHead.Flink;
		while (Current != &HiddenProcessesHead)
		{
			PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
			Current = Current->Flink;

			if (HiddenProcess->DebuggedProcess == TargetProcess)
			{
				Status = HiddenProcess->HideTypes[HideType];
				break;
			}
		}

		KeReleaseGuardedMutex(&HiderMutex);
		return Status;
	}

	BOOLEAN Hide(PHIDE_INFO HideInfo)
	{
		PEPROCESS TargetProcess = PidToProcess(HideInfo->Pid);

		if (TargetProcess == NULL)
		{
			LogError("Process with pid: %d doesn't exist", HideInfo->Pid);
			return FALSE;
		}

		KeAcquireGuardedMutex(&HiderMutex);

		PLIST_ENTRY Current = HiddenProcessesHead.Flink;
		while (Current != &HiddenProcessesHead)
		{
			PHIDDEN_PROCESS HiddenProcess = (PHIDDEN_PROCESS)CONTAINING_RECORD(Current, HIDDEN_PROCESS, HiddenProcessesList);
			Current = Current->Flink;

			if (HiddenProcess->DebuggedProcess == TargetProcess)
			{
				if (HideInfo->HookKuserSharedData == TRUE && HiddenProcess->HideTypes[HIDE_KUSER_SHARED_DATA] == FALSE)
					HookKuserSharedData(HiddenProcess);

				else if (HideInfo->HookKuserSharedData == FALSE && HiddenProcess->HideTypes[HIDE_KUSER_SHARED_DATA] == TRUE)
					UnHookKuserSharedData(HiddenProcess);

				if (HideInfo->HookNtSetInformationThread == TRUE && HiddenProcess->HideTypes[HIDE_NT_SET_INFORMATION_THREAD] == FALSE)
					InitializeListHead(&HiddenProcess->HiddenThreads.HiddenThreadList);

				if (HideInfo->ClearHideFromDebuggerFlag == TRUE && HiddenProcess->HideFromDebuggerFlagCleared == FALSE) 
				{
					ClearThreadHideFromDebuggerFlag(HiddenProcess->DebuggedProcess);
					HiddenProcess->HideFromDebuggerFlagCleared = TRUE;
				}

				if (HideInfo->ClearBypassProcessFreeze == TRUE && HiddenProcess->BypassProcessFreezeFlagCleared == FALSE) 
				{
					ClearBypassProcessFreezeFlag(HiddenProcess->DebuggedProcess);
					HiddenProcess->BypassProcessFreezeFlagCleared = TRUE;
				}

				if (HideInfo->ClearPebBeingDebugged == TRUE && HiddenProcess->PebBeingDebuggedCleared == FALSE)
				{
					SetPebDeuggerFlag(HiddenProcess->DebuggedProcess, FALSE);
					HiddenProcess->PebBeingDebuggedCleared = TRUE;
				}

				if (HideInfo->ClearPebNtGlobalFlag == TRUE && HiddenProcess->PebNtGlobalFlagCleared == FALSE)
				{
					ClearPebNtGlobalFlag(HiddenProcess->DebuggedProcess);
					HiddenProcess->PebNtGlobalFlagCleared = TRUE;
				}

				if (HideInfo->ClearHeapFlags == TRUE && HiddenProcess->HeapFlagsCleared == FALSE)
				{
					ClearHeapFlags(HiddenProcess->DebuggedProcess);
					HiddenProcess->HeapFlagsCleared = TRUE;
				}

				if (HideInfo->ClearKuserSharedData == TRUE && HiddenProcess->KUserSharedDataCleared == FALSE)
				{
					if (HiddenProcess->Kusd.KuserSharedData != NULL)
					{
						HiddenProcess->Kusd.KuserSharedData->KdDebuggerEnabled = 0;
						HiddenProcess->KUserSharedDataCleared = TRUE;
					}
				}

				if (HideInfo->ClearProcessBreakOnTerminationFlag == TRUE && HiddenProcess->ProcessBreakOnTerminationCleared == FALSE)
				{
					ClearProcessBreakOnTerminationFlag(HiddenProcess);
					HiddenProcess->ProcessBreakOnTerminationCleared = TRUE;
				}

				if (HideInfo->ClearThreadBreakOnTerminationFlag == TRUE && HiddenProcess->ThreadBreakOnTerminationCleared == FALSE)
				{
					ClearThreadBreakOnTerminationFlags(HiddenProcess->DebuggedProcess);
					HiddenProcess->ThreadBreakOnTerminationCleared = TRUE;
				}

				if (HideInfo->SaveProcessDebugFlags == TRUE && HiddenProcess->ProcessDebugFlagsSaved == FALSE)
				{
					SaveProcessDebugFlags(HiddenProcess);
					HiddenProcess->ProcessDebugFlagsSaved = TRUE;
				}

				if (HideInfo->SaveProcessHandleTracing == TRUE && HiddenProcess->ProcessHandleTracingSaved == FALSE)
				{
					SaveProcessHandleTracing(HiddenProcess);
					HiddenProcess->ProcessHandleTracingSaved = TRUE;
				}

				RtlCopyBytes(&HiddenProcess->HideTypes[0], &HideInfo->HookNtQueryInformationProcess, HIDE_LAST);

				KeReleaseGuardedMutex(&HiderMutex);
				return TRUE;
			}
		}

		LogError("Process with pid %d isn't in list", HideInfo->Pid);
		KeReleaseGuardedMutex(&HiderMutex);
		return FALSE;
	}

	BOOLEAN IsDriverHandleHidden(PUNICODE_STRING SymLink)
	{
		if (SymLink->Buffer == NULL || SymLink->Length == NULL)
			return FALSE;

		UNICODE_STRING ForbiddenSymLink;

		for (ULONG64 i = 0; i < sizeof(HiddenDeviceNames) / sizeof(HiddenDeviceNames[0]); i++)
		{
			RtlInitUnicodeString(&ForbiddenSymLink, HiddenDeviceNames[i]);
			if (RtlCompareUnicodeString(&ForbiddenSymLink, SymLink, TRUE) == 0)
			{
				return TRUE;
			}
		}

		return FALSE;
	}

	BOOLEAN IsProcessNameBad(PUNICODE_STRING ProcessName)
	{
		if (ProcessName->Buffer == NULL || ProcessName->Length == NULL)
			return FALSE;

		UNICODE_STRING CurrentProcessName = PsQueryFullProcessImageName(IoGetCurrentProcess());
		if (RtlCompareUnicodeString(ProcessName, &CurrentProcessName, FALSE) == 0)
			return FALSE;

		UNICODE_STRING ForbiddenProcessName;
		for (ULONG64 i = 0; i < sizeof(HiddenApplicationNames) / sizeof(HiddenApplicationNames[0]); i++)
		{
			RtlInitUnicodeString(&ForbiddenProcessName, HiddenApplicationNames[i]);
			if (RtlCompareUnicodeString(&ForbiddenProcessName, ProcessName, TRUE) == 0)
			{
				return TRUE;
			}
		}

		return FALSE;
	}

	BOOLEAN IsProcessWindowBad(PUNICODE_STRING WindowName)
	{
		if (WindowName->Buffer == NULL || WindowName->Length == NULL)
			return FALSE;

		UNICODE_STRING ForbiddenWindowName;
		for (ULONG64 i = 0; i < sizeof(HiddenWindowNames) / sizeof(HiddenWindowNames[0]); i++)
		{
			RtlInitUnicodeString(&ForbiddenWindowName, HiddenWindowNames[i]);
			if (RtlUnicodeStringContains(WindowName, &ForbiddenWindowName, TRUE) == 0)
				return TRUE;
		}

		return FALSE;
	}

	BOOLEAN IsProcessWindowClassBad(PUNICODE_STRING WindowClassName)
	{
		if (WindowClassName->Buffer == NULL || WindowClassName->Length == NULL)
			return FALSE;

		UNICODE_STRING ForbbidenWindowClassName;

		for (ULONG64 i = 0; i < sizeof(HiddenWindowClassNames) / sizeof(HiddenWindowClassNames[0]); i++)
		{
			RtlInitUnicodeString(&ForbbidenWindowClassName, HiddenWindowClassNames[i]);
			if (RtlCompareUnicodeString(WindowClassName, &ForbbidenWindowClassName, FALSE) == 0)
				return TRUE;
		}

		return FALSE;
	}
}