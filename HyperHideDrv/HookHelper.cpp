#pragma warning(disable : 4267 4201)

#include <ntddk.h>
#include <ntifs.h>
#include "Utils.h"
#include "HookHelper.h"
#include "GlobalData.h"
#include "HypervisorGateway.h"
#include "Log.h"
#include <intrin.h>

extern HYPER_HIDE_GLOBAL_DATA g_HyperHide;

extern HANDLE(NTAPI* OriginalNtUserQueryWindow)(HANDLE hWnd, WINDOWINFOCLASS WindowInfo);

VOID FilterProcesses(PSYSTEM_PROCESS_INFO ProcessInfo)
{
	//
	// First process is always system so there won't be a case when forbidden process is first
	//
	PSYSTEM_PROCESS_INFO PrevProcessInfo = NULL;

	while (PrevProcessInfo != ProcessInfo)
	{
		ULONG Offset = ProcessInfo->NextEntryOffset;

		if (Hider::IsProcessNameBad(&ProcessInfo->ImageName) == TRUE)
		{
			if (ProcessInfo->NextEntryOffset == NULL)
				PrevProcessInfo->NextEntryOffset = NULL;

			else
				PrevProcessInfo->NextEntryOffset += ProcessInfo->NextEntryOffset;
				
			RtlSecureZeroMemory(ProcessInfo, sizeof(SYSTEM_PROCESS_INFO) + ProcessInfo->NumberOfThreads * sizeof(SYSTEM_THREAD_INFORMATION) - sizeof(SYSTEM_THREAD_INFORMATION));
		}

		else
		{
			PrevProcessInfo = ProcessInfo;
		}

		ProcessInfo = (PSYSTEM_PROCESS_INFO)((UCHAR*)ProcessInfo + Offset);
	}
}

VOID FilterHandlesEx(PSYSTEM_HANDLE_INFORMATION_EX HandleInfoEx)
{
	ULONG TotalDeletedHandles = 0;
	BOOLEAN Found;

	do
	{
		ULONG FirstHandlePosition = 0;
		Found = FALSE;

		for (ULONG i = 0; i < HandleInfoEx->NumberOfHandles; i++)
		{
			PEPROCESS OriginalProcess = PidToProcess(HandleInfoEx->Handles[i].UniqueProcessId);
			if (OriginalProcess != NULL)
			{
				UNICODE_STRING ProcessName = PsQueryFullProcessImageName(OriginalProcess);

				if (Found == FALSE && Hider::IsProcessNameBad(&ProcessName) == TRUE)
				{
					FirstHandlePosition = i;
					Found = TRUE;
				}

				else if (Found == TRUE && Hider::IsProcessNameBad(&ProcessName) == FALSE)
				{
					RtlCopyBytes(&HandleInfoEx->Handles[FirstHandlePosition], &HandleInfoEx->Handles[i], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * (HandleInfoEx->NumberOfHandles - i));
					HandleInfoEx->NumberOfHandles = HandleInfoEx->NumberOfHandles - (i - FirstHandlePosition);
					TotalDeletedHandles += (i - FirstHandlePosition);
					break;
				}

				if (i + 1 == HandleInfoEx->NumberOfHandles && Found == TRUE)
				{
					RtlSecureZeroMemory(&HandleInfoEx->Handles[FirstHandlePosition], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * (i - FirstHandlePosition));
					HandleInfoEx->NumberOfHandles = HandleInfoEx->NumberOfHandles - (i - FirstHandlePosition);
					TotalDeletedHandles += (i - FirstHandlePosition);
				}
			}
		}
	} while (Found == TRUE);

	
	RtlSecureZeroMemory(&HandleInfoEx->Handles[HandleInfoEx->NumberOfHandles], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * TotalDeletedHandles);
}

VOID FilterHandles(PSYSTEM_HANDLE_INFORMATION HandleInfo)
{
	ULONG TotalDeletedHandles = 0;
	BOOLEAN Found;

	do
	{
		ULONG FirstHandlePosition = 0;
		Found = FALSE;

		for (ULONG i = 0; i < HandleInfo->NumberOfHandles; i++)
		{
			PEPROCESS OriginalProcess = PidToProcess(HandleInfo->Handles[i].UniqueProcessId);
			if (OriginalProcess != NULL)
			{
				UNICODE_STRING ProcessName = PsQueryFullProcessImageName(OriginalProcess);

				if (Found == FALSE && Hider::IsProcessNameBad(&ProcessName) == TRUE)
				{
					FirstHandlePosition = i;
					Found = TRUE;
				}

				else if (Found == TRUE && Hider::IsProcessNameBad(&ProcessName) == FALSE)
				{
					RtlCopyBytes(&HandleInfo->Handles[FirstHandlePosition], &HandleInfo->Handles[i], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * (HandleInfo->NumberOfHandles - i));
					HandleInfo->NumberOfHandles = HandleInfo->NumberOfHandles - (i - FirstHandlePosition);
					TotalDeletedHandles += (i - FirstHandlePosition);
					break;
				}

				if (i + 1 == HandleInfo->NumberOfHandles && Found == TRUE)
				{
					RtlSecureZeroMemory(&HandleInfo->Handles[FirstHandlePosition], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * (i - FirstHandlePosition));
					HandleInfo->NumberOfHandles = HandleInfo->NumberOfHandles - (i - FirstHandlePosition);
					TotalDeletedHandles += (i - FirstHandlePosition);
				}
			}
		}
	} while (Found == TRUE);


	RtlSecureZeroMemory(&HandleInfo->Handles[HandleInfo->NumberOfHandles], sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * TotalDeletedHandles);
}

BOOLEAN IsWindowBad(HANDLE hWnd)
{
	PEPROCESS WindProcess = PidToProcess(OriginalNtUserQueryWindow(hWnd, WindowProcess));
	if (WindProcess == IoGetCurrentProcess())
		return FALSE;

	UNICODE_STRING WindowProcessName = PsQueryFullProcessImageName(WindProcess);

	return Hider::IsProcessNameBad(&WindowProcessName);
}

BOOLEAN HookKiDispatchException(PVOID HookedKiDispatchException, PVOID* OriginalKiDispatchException)
{
	PVOID KernelSectionBase = 0;
	ULONG64 KernelSectionSize = 0;
	CHAR* Pattern = g_HyperHide.CurrentWindowsBuildNumber >= WINDOWS_11 ? "\x24\x00\x00\x41\xB1\x01\x48\x8D\x4C\x24\x00\xE8" : "\x8B\x00\x50\x00\x8B\x00\x58\x48\x8D\x4D\x00\xE8\x00\x00\x00\xFF\x8B\x55";
	CHAR* Mask = g_HyperHide.CurrentWindowsBuildNumber >= WINDOWS_11 ? "x??xxxxxxx?x" : "x?x?x?xxxx?x???xxx";
	CHAR* Section = g_HyperHide.CurrentWindowsBuildNumber >= WINDOWS_11 ? "PAGE" : ".text";

	if (GetSectionData("ntoskrnl.exe", Section, KernelSectionSize, KernelSectionBase) == FALSE)
		return FALSE;

	PVOID KiDispatchExceptionAddress = FindSignature(KernelSectionBase, KernelSectionSize, Pattern, Mask);
	if ((ULONG64)KiDispatchExceptionAddress >= (ULONG64)KernelSectionBase && (ULONG64)KiDispatchExceptionAddress <= (ULONG64)KernelSectionBase + KernelSectionSize)
	{
		KiDispatchExceptionAddress = (PVOID)(*(LONG*)((ULONG64)KiDispatchExceptionAddress + 12) + (LONGLONG)((ULONG64)KiDispatchExceptionAddress + 16));

		LogInfo("KiDispatchException address: 0x%llx", KiDispatchExceptionAddress);

		return hv::hook_function(KiDispatchExceptionAddress, HookedKiDispatchException, OriginalKiDispatchException);
	}

	return FALSE;
}

VOID GetNtSyscallNumbers(NT_SYSCALL_NUMBERS &SyscallNumbers)
{
	if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_11)
	{
		SyscallNumbers.NtSetInformationThread = 0xd;
		SyscallNumbers.NtQueryInformationProcess = 0x19;
		SyscallNumbers.NtQueryObject = 0x10;
		SyscallNumbers.NtSystemDebugControl = 0x1c8;
		SyscallNumbers.NtSetContextThread = 0x194;
		SyscallNumbers.NtQuerySystemInformation = 0x36;
		SyscallNumbers.NtGetContextThread = 0xf7;
		SyscallNumbers.NtClose = 0xf;
		SyscallNumbers.NtQueryInformationThread = 0x25;
		SyscallNumbers.NtCreateThreadEx = 0xC5;
		SyscallNumbers.NtCreateFile = 0x55;
		SyscallNumbers.NtCreateProcessEx = 0x4d;
		SyscallNumbers.NtYieldExecution = 0x46;
		SyscallNumbers.NtQuerySystemTime = 0x5a;
		SyscallNumbers.NtQueryPerformanceCounter = 0x31;
		SyscallNumbers.NtContinue = 0xa3;
		SyscallNumbers.NtQueryInformationJobObject = 0x150;
		SyscallNumbers.NtCreateUserProcess = 0xcd;
		SyscallNumbers.NtGetNextProcess = 0xfc;
		SyscallNumbers.NtOpenProcess = 0x26;
		SyscallNumbers.NtOpenThread = 0x134;
		SyscallNumbers.NtSetInformationProcess = 0x1c;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_20H2 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_20H1 || 
		g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_21H1 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_21H2)
	{
		SyscallNumbers.NtSetInformationThread = 0xd;
		SyscallNumbers.NtQueryInformationProcess = 0x19;
		SyscallNumbers.NtQueryObject = 0x10;
		SyscallNumbers.NtSystemDebugControl = 0x1bd;
		SyscallNumbers.NtSetContextThread = 0x18b;
		SyscallNumbers.NtQuerySystemInformation = 0x36;
		SyscallNumbers.NtGetContextThread = 0xf2;
		SyscallNumbers.NtClose = 0xf;
		SyscallNumbers.NtQueryInformationThread = 0x25;
		SyscallNumbers.NtCreateThreadEx = 0xc1;
		SyscallNumbers.NtCreateFile = 0x55;
		SyscallNumbers.NtCreateProcessEx = 0x4d;
		SyscallNumbers.NtYieldExecution = 0x46;
		SyscallNumbers.NtQuerySystemTime = 0x5a;
		SyscallNumbers.NtQueryPerformanceCounter = 0x31;
		SyscallNumbers.NtContinue = 0xa1;
		SyscallNumbers.NtQueryInformationJobObject = 0x14a;
		SyscallNumbers.NtCreateUserProcess = 0xc8;
		SyscallNumbers.NtGetNextProcess = 0xf7;
		SyscallNumbers.NtOpenProcess = 0x26;
		SyscallNumbers.NtOpenThread = 0x12e;
		SyscallNumbers.NtSetInformationProcess = 0x1c;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_19H2 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_19H1)
	{
		SyscallNumbers.NtSetInformationThread = 0xd;
		SyscallNumbers.NtQueryInformationProcess = 0x19;
		SyscallNumbers.NtQueryObject = 0x10;
		SyscallNumbers.NtSystemDebugControl = 0x1b7;
		SyscallNumbers.NtSetContextThread = 0x185;
		SyscallNumbers.NtQuerySystemInformation = 0x36; 
		SyscallNumbers.NtGetContextThread = 0xed;
		SyscallNumbers.NtClose = 0xf;
		SyscallNumbers.NtQueryInformationThread = 0x25;
		SyscallNumbers.NtCreateThreadEx = 0xbd;
		SyscallNumbers.NtCreateFile = 0x55;
		SyscallNumbers.NtCreateProcessEx = 0x4d;
		SyscallNumbers.NtYieldExecution = 0x46;
		SyscallNumbers.NtQuerySystemTime = 0x5a;
		SyscallNumbers.NtQueryPerformanceCounter = 0x31;
		SyscallNumbers.NtContinue = 0x43;
		SyscallNumbers.NtQueryInformationJobObject = 0x144;
		SyscallNumbers.NtCreateUserProcess = 0xc4;
		SyscallNumbers.NtGetNextProcess = 0xf2;
		SyscallNumbers.NtOpenProcess = 0x26;
		SyscallNumbers.NtOpenThread = 0x129;
		SyscallNumbers.NtSetInformationProcess = 0x1c;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE5)
	{
		SyscallNumbers.NtSetInformationThread = 0xd;
		SyscallNumbers.NtQueryInformationProcess = 0x19;
		SyscallNumbers.NtQueryObject = 0x10;
		SyscallNumbers.NtSystemDebugControl = 0x1b6;
		SyscallNumbers.NtSetContextThread = 0x184;
		SyscallNumbers.NtQuerySystemInformation = 0x36;
		SyscallNumbers.NtGetContextThread = 0xec;
		SyscallNumbers.NtClose = 0xf;
		SyscallNumbers.NtQueryInformationThread = 0x25;
		SyscallNumbers.NtCreateThreadEx = 0xbc;
		SyscallNumbers.NtCreateFile = 0x55;
		SyscallNumbers.NtCreateProcessEx = 0x4d;
		SyscallNumbers.NtYieldExecution = 0x46;
		SyscallNumbers.NtQuerySystemTime = 0x5a;
		SyscallNumbers.NtQueryPerformanceCounter = 0x31;
		SyscallNumbers.NtContinue = 0x43;
		SyscallNumbers.NtQueryInformationJobObject = 0x143;
		SyscallNumbers.NtCreateUserProcess = 0xc3;
		SyscallNumbers.NtGetNextProcess = 0xf1;
		SyscallNumbers.NtOpenProcess = 0x26;
		SyscallNumbers.NtOpenThread = 0x128;
		SyscallNumbers.NtSetInformationProcess = 0x1c;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE4)
	{
		SyscallNumbers.NtSetInformationThread = 0xd;
		SyscallNumbers.NtQueryInformationProcess = 0x19;
		SyscallNumbers.NtQueryObject = 0x10;
		SyscallNumbers.NtSystemDebugControl = 0x1b5;
		SyscallNumbers.NtSetContextThread = 0x183;
		SyscallNumbers.NtQuerySystemInformation = 0x36;
		SyscallNumbers.NtGetContextThread = 0xeb;
		SyscallNumbers.NtClose = 0xf;
		SyscallNumbers.NtQueryInformationThread = 0x25;
		SyscallNumbers.NtCreateThreadEx = 0xbb;
		SyscallNumbers.NtCreateFile = 0x55;
		SyscallNumbers.NtCreateProcessEx = 0x4d;
		SyscallNumbers.NtYieldExecution = 0x46;
		SyscallNumbers.NtQuerySystemTime = 0x5a;
		SyscallNumbers.NtQueryPerformanceCounter = 0x31;
		SyscallNumbers.NtContinue = 0x43;
		SyscallNumbers.NtQueryInformationJobObject = 0x142;
		SyscallNumbers.NtCreateUserProcess = 0xc2;
		SyscallNumbers.NtGetNextProcess = 0xf0;
		SyscallNumbers.NtOpenProcess = 0x26;
		SyscallNumbers.NtOpenThread = 0x127;
		SyscallNumbers.NtSetInformationProcess = 0x1c;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE3)
	{
		// Native
		SyscallNumbers.NtSetInformationThread = 0xd;
		SyscallNumbers.NtQueryInformationProcess = 0x19;
		SyscallNumbers.NtQueryObject = 0x10;
		SyscallNumbers.NtSystemDebugControl = 0x1b3;
		SyscallNumbers.NtSetContextThread = 0x181;
		SyscallNumbers.NtQuerySystemInformation = 0x36;
		SyscallNumbers.NtGetContextThread = 0xea;
		SyscallNumbers.NtClose = 0xf;
		SyscallNumbers.NtQueryInformationThread = 0x25;
		SyscallNumbers.NtCreateThreadEx = 0xba;
		SyscallNumbers.NtCreateFile = 0x55;
		SyscallNumbers.NtCreateProcessEx = 0x4d;
		SyscallNumbers.NtYieldExecution = 0x46;
		SyscallNumbers.NtQuerySystemTime = 0x5a;
		SyscallNumbers.NtQueryPerformanceCounter = 0x31;
		SyscallNumbers.NtContinue = 0x43;
		SyscallNumbers.NtQueryInformationJobObject = 0x140;
		SyscallNumbers.NtCreateUserProcess = 0xc1;
		SyscallNumbers.NtGetNextProcess = 0xef;
		SyscallNumbers.NtOpenProcess = 0x26;
		SyscallNumbers.NtOpenThread = 0x125;
		SyscallNumbers.NtSetInformationProcess = 0x1c;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE2)
	{
		SyscallNumbers.NtSetInformationThread = 0xd;
		SyscallNumbers.NtQueryInformationProcess = 0x19;
		SyscallNumbers.NtQueryObject = 0x10;
		SyscallNumbers.NtSystemDebugControl = 0x1b0;
		SyscallNumbers.NtSetContextThread = 0x17e;
		SyscallNumbers.NtQuerySystemInformation = 0x36;
		SyscallNumbers.NtGetContextThread = 0xe9;
		SyscallNumbers.NtClose = 0xf;
		SyscallNumbers.NtQueryInformationThread = 0x25;
		SyscallNumbers.NtCreateThreadEx = 0xb9;
		SyscallNumbers.NtCreateFile = 0x55;
		SyscallNumbers.NtCreateProcessEx = 0x4d;
		SyscallNumbers.NtYieldExecution = 0x46;
		SyscallNumbers.NtQuerySystemTime = 0x5a;
		SyscallNumbers.NtQueryPerformanceCounter = 0x31;
		SyscallNumbers.NtContinue = 0x43;
		SyscallNumbers.NtQueryInformationJobObject = 0x13d;
		SyscallNumbers.NtCreateUserProcess = 0xc0;
		SyscallNumbers.NtGetNextProcess = 0xee;
		SyscallNumbers.NtOpenProcess = 0x26;
		SyscallNumbers.NtOpenThread = 0x123;
		SyscallNumbers.NtSetInformationProcess = 0x1c;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE1)
	{
		SyscallNumbers.NtSetInformationThread = 0xd;
		SyscallNumbers.NtQueryInformationProcess = 0x19;
		SyscallNumbers.NtQueryObject = 0x10;
		SyscallNumbers.NtSystemDebugControl = 0x1aa;
		SyscallNumbers.NtSetContextThread = 0x178;
		SyscallNumbers.NtQuerySystemInformation = 0x36;
		SyscallNumbers.NtGetContextThread = 0xe6;
		SyscallNumbers.NtClose = 0xf;
		SyscallNumbers.NtQueryInformationThread = 0x25;
		SyscallNumbers.NtCreateThreadEx = 0xb6;
		SyscallNumbers.NtCreateFile = 0x55;
		SyscallNumbers.NtCreateProcessEx = 0x4d;
		SyscallNumbers.NtYieldExecution = 0x46;
		SyscallNumbers.NtQuerySystemTime = 0x5a;
		SyscallNumbers.NtQueryPerformanceCounter = 0x31;
		SyscallNumbers.NtContinue = 0x43;
		SyscallNumbers.NtQueryInformationJobObject = 0x137;
		SyscallNumbers.NtCreateUserProcess = 0xbd;
		SyscallNumbers.NtGetNextProcess = 0xeb;
		SyscallNumbers.NtOpenProcess = 0x26;
		SyscallNumbers.NtOpenThread = 0x11f;
		SyscallNumbers.NtSetInformationProcess = 0x1c;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_THRESHOLD2)
	{
		SyscallNumbers.NtSetInformationThread = 0xd;
		SyscallNumbers.NtQueryInformationProcess = 0x19;
		SyscallNumbers.NtQueryObject = 0x10;
		SyscallNumbers.NtSystemDebugControl = 0x1a4;
		SyscallNumbers.NtSetContextThread = 0x172;
		SyscallNumbers.NtQuerySystemInformation = 0x36;
		SyscallNumbers.NtGetContextThread = 0xe4;
		SyscallNumbers.NtClose = 0xf;
		SyscallNumbers.NtQueryInformationThread = 0x25;
		SyscallNumbers.NtCreateThreadEx = 0xb4;
		SyscallNumbers.NtCreateFile = 0x55;
		SyscallNumbers.NtCreateProcessEx = 0x4d;
		SyscallNumbers.NtYieldExecution = 0x46;
		SyscallNumbers.NtQuerySystemTime = 0x5a;
		SyscallNumbers.NtQueryPerformanceCounter = 0x31;
		SyscallNumbers.NtContinue = 0x43;
		SyscallNumbers.NtQueryInformationJobObject = 0x134;
		SyscallNumbers.NtCreateUserProcess = 0xbb;
		SyscallNumbers.NtGetNextProcess = 0xe9;
		SyscallNumbers.NtOpenProcess = 0x26;
		SyscallNumbers.NtOpenThread = 0x11c;
		SyscallNumbers.NtSetInformationProcess = 0x1c;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_THRESHOLD1)
	{
		SyscallNumbers.NtSetInformationThread = 0xd;
		SyscallNumbers.NtQueryInformationProcess = 0x19;
		SyscallNumbers.NtQueryObject = 0x10;
		SyscallNumbers.NtSystemDebugControl = 0x1a1;
		SyscallNumbers.NtSetContextThread = 0x16f;
		SyscallNumbers.NtQuerySystemInformation = 0x36;
		SyscallNumbers.NtGetContextThread = 0xe3;
		SyscallNumbers.NtClose = 0xf;
		SyscallNumbers.NtQueryInformationThread = 0x25;
		SyscallNumbers.NtCreateThreadEx = 0xb3;
		SyscallNumbers.NtCreateFile = 0x55;
		SyscallNumbers.NtCreateProcessEx = 0x4d;
		SyscallNumbers.NtYieldExecution = 0x46;
		SyscallNumbers.NtQuerySystemTime = 0x5a;
		SyscallNumbers.NtQueryPerformanceCounter = 0x31;
		SyscallNumbers.NtContinue = 0x43;
		SyscallNumbers.NtQueryInformationJobObject = 0x131;
		SyscallNumbers.NtCreateUserProcess = 0xba;
		SyscallNumbers.NtGetNextProcess = 0xe8;
		SyscallNumbers.NtOpenProcess = 0x26;
		SyscallNumbers.NtOpenThread = 0x119;
		SyscallNumbers.NtSetInformationProcess = 0x1c;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_8_1)
	{
		SyscallNumbers.NtSetInformationThread = 0xc;
		SyscallNumbers.NtQueryInformationProcess = 0x18;
		SyscallNumbers.NtQueryObject = 0xf;
		SyscallNumbers.NtSystemDebugControl = 0x199;
		SyscallNumbers.NtSetContextThread = 0x168;
		SyscallNumbers.NtQuerySystemInformation = 0x35;
		SyscallNumbers.NtGetContextThread = 0xe0;
		SyscallNumbers.NtClose = 0xe;
		SyscallNumbers.NtQueryInformationThread = 0x24;
		SyscallNumbers.NtCreateThreadEx = 0xb0;
		SyscallNumbers.NtCreateFile = 0x54;
		SyscallNumbers.NtCreateProcessEx = 0x4c;
		SyscallNumbers.NtYieldExecution = 0x45;
		SyscallNumbers.NtQuerySystemTime = 0x59;
		SyscallNumbers.NtQuerySystemTime = 0x5a;
		SyscallNumbers.NtQueryPerformanceCounter = 0x30;
		SyscallNumbers.NtContinue = 0x42;
		SyscallNumbers.NtQueryInformationJobObject = 0x12b;
		SyscallNumbers.NtCreateUserProcess = 0xb7;
		SyscallNumbers.NtGetNextProcess = 0xe4;
		SyscallNumbers.NtOpenProcess = 0x25;
		SyscallNumbers.NtOpenThread = 0x113;
		SyscallNumbers.NtSetInformationProcess = 0x1b;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_8)
	{
		SyscallNumbers.NtSetInformationThread = 0xb;
		SyscallNumbers.NtQueryInformationProcess = 0x17;
		SyscallNumbers.NtQueryObject = 0xe;
		SyscallNumbers.NtSystemDebugControl = 0x194;
		SyscallNumbers.NtSetContextThread = 0x165;
		SyscallNumbers.NtQuerySystemInformation = 0x34;
		SyscallNumbers.NtGetContextThread = 0xdd;
		SyscallNumbers.NtClose = 0xd;
		SyscallNumbers.NtQueryInformationThread = 0x23;
		SyscallNumbers.NtCreateThreadEx = 0xaf;
		SyscallNumbers.NtCreateFile = 0x53;
		SyscallNumbers.NtCreateProcessEx = 0x4b;
		SyscallNumbers.NtYieldExecution = 0x44;
		SyscallNumbers.NtQuerySystemTime = 0x58;
		SyscallNumbers.NtQueryPerformanceCounter = 0x2f;
		SyscallNumbers.NtContinue = 0x41;
		SyscallNumbers.NtQueryInformationJobObject = 0x128;
		SyscallNumbers.NtCreateUserProcess = 0xb5;
		SyscallNumbers.NtGetNextProcess = 0xe1;
		SyscallNumbers.NtOpenProcess = 0x24;
		SyscallNumbers.NtOpenThread = 0x110;
		SyscallNumbers.NtSetInformationProcess = 0x1a;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_7_SP1 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_7)
	{
		SyscallNumbers.NtSetInformationThread = 0xa;
		SyscallNumbers.NtQueryInformationProcess = 0x16;
		SyscallNumbers.NtQueryObject = 0xd;
		SyscallNumbers.NtSystemDebugControl = 0x17c;
		SyscallNumbers.NtSetContextThread = 0x150;
		SyscallNumbers.NtQuerySystemInformation = 0x33;
		SyscallNumbers.NtGetContextThread = 0xca;
		SyscallNumbers.NtClose = 0xc;
		SyscallNumbers.NtQueryInformationThread = 0x22;
		SyscallNumbers.NtCreateThreadEx = 0xa5;
		SyscallNumbers.NtCreateFile = 0x52;
		SyscallNumbers.NtCreateProcessEx = 0x4a;
		SyscallNumbers.NtYieldExecution = 0x43;
		SyscallNumbers.NtQuerySystemTime = 0x57;
		SyscallNumbers.NtQueryPerformanceCounter = 0x2e;
		SyscallNumbers.NtContinue = 0x40;
		SyscallNumbers.NtQueryInformationJobObject = 0x116;
		SyscallNumbers.NtCreateUserProcess = 0xaa;
		SyscallNumbers.NtGetNextProcess = 0xce;
		SyscallNumbers.NtOpenProcess = 0x23;
		SyscallNumbers.NtOpenThread = 0xfe;
		SyscallNumbers.NtSetInformationProcess = 0x19;
	}
}

VOID GetWin32kSyscallNumbers(WIN32K_SYSCALL_NUMBERS& SyscallNumbers)
{
	if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_11)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x67;
		SyscallNumbers.NtUserBuildHwndList = 0x1a;
		SyscallNumbers.NtUserQueryWindow = 0xe;
		SyscallNumbers.NtUserGetForegroundWindow = 0x37;
		SyscallNumbers.NtUserGetThreadState = 0x0;
		SyscallNumbers.NtUserInternalGetWindowText = 0x5D;
		SyscallNumbers.NtUserGetClassName = 0x74;
	}

	if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_20H2 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_20H1 || 
		g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_21H1 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_21H2)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x6c;
		SyscallNumbers.NtUserBuildHwndList = 0x1c;
		SyscallNumbers.NtUserQueryWindow = 0x10;
		SyscallNumbers.NtUserGetForegroundWindow = 0x3c;
		SyscallNumbers.NtUserGetThreadState = 0x0;
		SyscallNumbers.NtUserInternalGetWindowText = 0x62;
		SyscallNumbers.NtUserGetClassName = 0x79;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_19H2 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_19H1)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x6f;
		SyscallNumbers.NtUserBuildHwndList = 0x1f;
		SyscallNumbers.NtUserQueryWindow = 0x13;
		SyscallNumbers.NtUserGetForegroundWindow = 0x3f;
		SyscallNumbers.NtUserGetThreadState = 0x3;
		SyscallNumbers.NtUserInternalGetWindowText = 0x65;
		SyscallNumbers.NtUserGetClassName = 0x7c;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE5)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x6f;
		SyscallNumbers.NtUserBuildHwndList = 0x1f;
		SyscallNumbers.NtUserQueryWindow = 0x13;
		SyscallNumbers.NtUserGetForegroundWindow = 0x3f;
		SyscallNumbers.NtUserGetThreadState = 0x3;
		SyscallNumbers.NtUserInternalGetWindowText = 0x65;
		SyscallNumbers.NtUserGetClassName = 0x7c;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE4)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x6f;
		SyscallNumbers.NtUserBuildHwndList = 0x1f;
		SyscallNumbers.NtUserQueryWindow = 0x13;
		SyscallNumbers.NtUserGetForegroundWindow = 0x3f;
		SyscallNumbers.NtUserGetThreadState = 0x3;
		SyscallNumbers.NtUserInternalGetWindowText = 0x65;
		SyscallNumbers.NtUserGetClassName = 0x7c;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE3)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x6f;
		SyscallNumbers.NtUserBuildHwndList = 0x1f;
		SyscallNumbers.NtUserQueryWindow = 0x13;
		SyscallNumbers.NtUserGetForegroundWindow = 0x3f;
		SyscallNumbers.NtUserGetThreadState = 0x3;
		SyscallNumbers.NtUserInternalGetWindowText = 0x65;
		SyscallNumbers.NtUserGetClassName = 0x7c;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE2)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x6f;
		SyscallNumbers.NtUserBuildHwndList = 0x1f;
		SyscallNumbers.NtUserQueryWindow = 0x13;
		SyscallNumbers.NtUserGetForegroundWindow = 0x3f;
		SyscallNumbers.NtUserGetThreadState = 0x3;
		SyscallNumbers.NtUserInternalGetWindowText = 0x65;
		SyscallNumbers.NtUserGetClassName = 0x7c;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE1)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x70;
		SyscallNumbers.NtUserBuildHwndList = 0x1f;
		SyscallNumbers.NtUserQueryWindow = 0x13;
		SyscallNumbers.NtUserGetForegroundWindow = 0x3f;
		SyscallNumbers.NtUserGetThreadState = 0x3;
		SyscallNumbers.NtUserInternalGetWindowText = 0x65;
		SyscallNumbers.NtUserGetClassName = 0x7d;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_THRESHOLD2)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x70;
		SyscallNumbers.NtUserBuildHwndList = 0x1f;
		SyscallNumbers.NtUserQueryWindow = 0x13;
		SyscallNumbers.NtUserGetForegroundWindow = 0x3f;
		SyscallNumbers.NtUserGetThreadState = 0x3;
		SyscallNumbers.NtUserInternalGetWindowText = 0x65;
		SyscallNumbers.NtUserGetClassName = 0x7d;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_THRESHOLD1)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x70;
		SyscallNumbers.NtUserBuildHwndList = 0x1f;
		SyscallNumbers.NtUserQueryWindow = 0x13;
		SyscallNumbers.NtUserGetForegroundWindow = 0x3f;
		SyscallNumbers.NtUserGetThreadState = 0x3;
		SyscallNumbers.NtUserInternalGetWindowText = 0x65;
		SyscallNumbers.NtUserGetClassName = 0x7d;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_8_1)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x6f;
		SyscallNumbers.NtUserBuildHwndList = 0x1e;
		SyscallNumbers.NtUserQueryWindow = 0x12;
		SyscallNumbers.NtUserGetForegroundWindow = 0x3e;
		SyscallNumbers.NtUserGetThreadState = 0x2;
		SyscallNumbers.NtUserInternalGetWindowText = 0x64;
		SyscallNumbers.NtUserGetClassName = 0x7c;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_8)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x6e;
		SyscallNumbers.NtUserBuildHwndList = 0x1d;
		SyscallNumbers.NtUserQueryWindow = 0x11;
		SyscallNumbers.NtUserGetForegroundWindow = 0x3d;
		SyscallNumbers.NtUserGetThreadState = 0x1;
		SyscallNumbers.NtUserInternalGetWindowText = 0x63;
		SyscallNumbers.NtUserGetClassName = 0x7b;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_7_SP1 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_7)
	{
		SyscallNumbers.NtUserFindWindowEx = 0x6e;
		SyscallNumbers.NtUserBuildHwndList = 0x1c;
		SyscallNumbers.NtUserQueryWindow = 0x10;
		SyscallNumbers.NtUserGetForegroundWindow = 0x3c;
		SyscallNumbers.NtUserGetThreadState = 0x0;
		SyscallNumbers.NtUserInternalGetWindowText = 0x63;
		SyscallNumbers.NtUserGetClassName = 0x7b;
	}
}