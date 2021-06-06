#pragma once
#include <ntddk.h>

typedef struct _NT_SYSCALL_NUMBERS
{
	SHORT NtSetInformationThread;
	SHORT NtQueryInformationProcess;
	SHORT NtQueryObject;
	SHORT NtSystemDebugControl;
	SHORT NtSetContextThread;
	SHORT NtQuerySystemInformation;
	SHORT NtGetContextThread;
	SHORT NtClose;
	SHORT NtQueryInformationThread;
	SHORT NtCreateThreadEx;
	SHORT NtCreateFile;
	SHORT NtCreateProcessEx;
	SHORT NtYieldExecution;
	SHORT NtQuerySystemTime;
	SHORT NtQueryPerformanceCounter;
	SHORT NtContinue;
	SHORT NtQueryInformationJobObject;
	SHORT NtCreateUserProcess;
	SHORT NtGetNextProcess;
	SHORT NtOpenProcess;
	SHORT NtOpenThread;
	SHORT NtSetInformationProcess;
}NT_SYSCALL_NUMBERS;

typedef struct _WIN32K_SYSCALL_NUMBERS
{
	SHORT NtUserFindWindowEx;
	SHORT NtUserBuildHwndList;
	SHORT NtUserQueryWindow;
	SHORT NtUserGetForegroundWindow;
	SHORT NtUserGetThreadState;
	SHORT NtUserGetClassName;
	SHORT NtUserInternalGetWindowText;
}WIN32K_SYSCALL_NUMBERS;

VOID GetNtSyscallNumbers(NT_SYSCALL_NUMBERS& SyscallNumbers);

VOID GetWin32kSyscallNumbers(WIN32K_SYSCALL_NUMBERS& SyscallNumbers);

BOOLEAN IsWindowBad(HANDLE hWnd);

VOID FilterProcesses(PSYSTEM_PROCESS_INFO ProcessInfo);

VOID FilterHandlesEx(PSYSTEM_HANDLE_INFORMATION_EX HandleInfoEx);

VOID FilterHandles(PSYSTEM_HANDLE_INFORMATION HandleInfo);

BOOLEAN HookKiDispatchException(PVOID HookedKiDispatchException, PVOID* OriginalKiDispatchException);;