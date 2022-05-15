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

SHORT GetSyscallNumber(PVOID FunctionAddress)
{
	return *(SHORT*)((ULONG64)FunctionAddress + 4);
}

BOOLEAN GetNtSyscallNumbers(std::array<SyscallInfo, 22>& SyscallsToFind)
{
	UNICODE_STRING knownDlls{};
	RtlInitUnicodeString(&knownDlls, LR"(\KnownDlls\ntdll.dll)");

	OBJECT_ATTRIBUTES objAttributes{};
	InitializeObjectAttributes(&objAttributes, &knownDlls, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	HANDLE section{};
	if (!NT_SUCCESS(ZwOpenSection(&section, SECTION_MAP_READ, &objAttributes)))
		return false;

	PVOID ntdllBase{};
	size_t ntdllSize{};
	LARGE_INTEGER sectionOffset{};
	if (!NT_SUCCESS(ZwMapViewOfSection(section, ZwCurrentProcess(), &ntdllBase, 0, 0, &sectionOffset, &ntdllSize, ViewShare, 0, PAGE_READONLY)))
	{
		ZwClose(section);
		return false;
	}

	auto status = true;
	for (auto& syscallInfo : SyscallsToFind)
	{
		if (syscallInfo.SyscallName == "NtQuerySystemTime")
		{
			const auto functionAddress = GetExportedFunctionAddress(0, ntdllBase, "NtAccessCheckByTypeAndAuditAlarm");
			if (!functionAddress)
			{
				status = false;
				break;
			}

			syscallInfo.SyscallNumber = GetSyscallNumber(functionAddress) + 1;
		}
		else
		{
			const auto functionAddress = GetExportedFunctionAddress(0, ntdllBase, syscallInfo.SyscallName.data());
			if (!functionAddress)
			{
				status = false;
				break;
			}

			syscallInfo.SyscallNumber = GetSyscallNumber(functionAddress);
		}

		LogDebug("Syscall %s is equal: 0x%X", syscallInfo.SyscallName.data(), syscallInfo.SyscallNumber);
	}

	ZwClose(section);
	ZwUnmapViewOfSection(ZwCurrentProcess(), ntdllBase);

	return status;
}

VOID GetWin32kSyscallNumbersPreRedstone(std::array<SyscallInfo, 5>& SyscallsToFind)
{
	SyscallsToFind[0].SyscallName = "NtUserBuildHwndList";
	SyscallsToFind[1].SyscallName = "NtUserFindWindowEx";
	SyscallsToFind[2].SyscallName = "NtUserQueryWindow";
	SyscallsToFind[3].SyscallName = "NtUserGetForegroundWindow";
	SyscallsToFind[4].SyscallName = "NtUserGetThreadState";

	if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_THRESHOLD2 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_THRESHOLD1)
	{
		SyscallsToFind[0].SyscallNumber = 0x70;
		SyscallsToFind[1].SyscallNumber = 0x1f;
		SyscallsToFind[2].SyscallNumber = 0x13;
		SyscallsToFind[3].SyscallNumber = 0x3f;
		SyscallsToFind[4].SyscallNumber = 0x3;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_8_1)
	{
		SyscallsToFind[0].SyscallNumber = 0x6f;
		SyscallsToFind[1].SyscallNumber = 0x1e;
		SyscallsToFind[2].SyscallNumber = 0x12;
		SyscallsToFind[3].SyscallNumber = 0x3e;
		SyscallsToFind[4].SyscallNumber = 0x2;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_8)
	{
		SyscallsToFind[0].SyscallNumber = 0x6e;
		SyscallsToFind[1].SyscallNumber = 0x1d;
		SyscallsToFind[2].SyscallNumber = 0x11;
		SyscallsToFind[3].SyscallNumber = 0x3d;
		SyscallsToFind[4].SyscallNumber = 0x1;
	}
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_7_SP1 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_7)
	{
		SyscallsToFind[0].SyscallNumber = 0x6e;
		SyscallsToFind[1].SyscallNumber = 0x1c;
		SyscallsToFind[2].SyscallNumber = 0x10;
		SyscallsToFind[3].SyscallNumber = 0x3c;
		SyscallsToFind[4].SyscallNumber = 0x0;
	}
}

BOOLEAN GetWin32kSyscallNumbers(std::array<SyscallInfo, 5>& SyscallsToFind)
{
	if (g_HyperHide.CurrentWindowsBuildNumber >= WINDOWS_10_VERSION_REDSTONE1)
	{
		UNICODE_STRING knownDlls{};
		RtlInitUnicodeString(&knownDlls, LR"(\KnownDlls\win32u.dll)");

		OBJECT_ATTRIBUTES objAttributes{};
		InitializeObjectAttributes(&objAttributes, &knownDlls, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

		HANDLE section{};
		if (!NT_SUCCESS(ZwOpenSection(&section, SECTION_MAP_READ, &objAttributes)))
			return false;

		PVOID win32uBase{};
		size_t win32uSize{};
		LARGE_INTEGER sectionOffset{};
		if (!NT_SUCCESS(ZwMapViewOfSection(section, ZwCurrentProcess(), &win32uBase, 0, 0, &sectionOffset, &win32uSize, ViewShare, 0, PAGE_READONLY)))
		{
			ZwClose(section);
			return false;
		}

		auto status = true;
		for (auto& syscallInfo : SyscallsToFind)
		{
			const auto functionAddress = GetExportedFunctionAddress(0, win32uBase, syscallInfo.SyscallName.data());
			if (!functionAddress)
			{
				status = false;
				break;
			}

			syscallInfo.SyscallNumber = GetSyscallNumber(functionAddress) - 0x1000;
			LogDebug("Syscall %s is equal: 0x%X", syscallInfo.SyscallName, syscallInfo.SyscallNumber);
		}

		ZwClose(section);
		ZwUnmapViewOfSection(ZwCurrentProcess(), win32uBase);

		return status;
	}
	else
	{
		GetWin32kSyscallNumbersPreRedstone(SyscallsToFind);
		return true;
	}
}