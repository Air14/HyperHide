#pragma once
#include "Pte.h"

enum HIDE_TYPE
{
	HIDE_NT_QUERY_INFORMATION_PROCESS,		
	HIDE_NT_QUERY_SYSTEM_INFORMATION,
	HIDE_NT_QUERY_INFORMATION_THREAD,
	HIDE_NT_QUERY_INFORMATION_JOB_OBJECT,
	HIDE_NT_QUERY_OBJECT,
	HIDE_NT_QUERY_SYSTEM_TIME,
	HIDE_NT_QUERY_PERFORMANCE_COUNTER,
	HIDE_NT_CREATE_USER_PROCESS,
	HIDE_NT_CREATE_PROCESS_EX,
	HIDE_NT_CREATE_THREAD_EX,
	HIDE_NT_SET_CONTEXT_THREAD,
	HIDE_NT_GET_CONTEXT_THREAD,
	HIDE_NT_OPEN_PROCESS,
	HIDE_NT_OPEN_THREAD,
	HIDE_NT_SET_INFORMATION_THREAD,
	HIDE_NT_SYSTEM_DEBUG_CONTROL,	
	HIDE_NT_GET_NEXT_PROCESS,
	HIDE_NT_YIELD_EXECUTION,
	HIDE_NT_CREATE_FILE,
	HIDE_NT_CONTINUE,
	HIDE_NT_CLOSE,
	HIDE_NT_USER_BUILD_HWND_LIST,							  
	HIDE_NT_USER_FIND_WINDOW_EX,							  
	HIDE_NT_USER_QUERY_WINDOW,		
	HIDE_NT_USER_GET_FOREGROUND_WINDOW,
    HIDE_KUSER_SHARED_DATA,
	HIDE_KI_EXCEPTION_DISPATCH,
	HIDE_NT_SET_INFORMATION_PROCESS,
	HIDE_LAST
};

typedef struct _HIDE_INFO
{
	ULONG Pid;
	BOOLEAN HookNtQueryInformationProcess;
	BOOLEAN HookNtQuerySystemInformation;
	BOOLEAN HookNtQueryInformationThread;
	BOOLEAN HookNtQueryInformationJobObject;
	BOOLEAN HookNtQueryObject;
	BOOLEAN HookNtQuerySystemTime;
	BOOLEAN HookNtQueryPerformanceCounter;
	BOOLEAN HookNtCreateUserProcess;
	BOOLEAN HookNtCreateProcessEx;
	BOOLEAN HookNtCreateThreadEx;
	BOOLEAN HookNtSetContextThread;
	BOOLEAN HookNtGetContextThread;
	BOOLEAN HookNtOpenProcess;
	BOOLEAN HookNtOpenThread;
	BOOLEAN HookNtSetInformationThread;
	BOOLEAN HookNtSystemDebugControl;
	BOOLEAN HookNtGetNextProcess;
	BOOLEAN HookNtYieldExecution;
	BOOLEAN HookNtCreateFile;
	BOOLEAN HookNtContinue;
	BOOLEAN HookNtClose;
	BOOLEAN HookNtUserBuildHwndList;
	BOOLEAN HookNtUserFindWindowEx;
	BOOLEAN HookNtUserQueryWindow;
	BOOLEAN HookNtUserGetForegroundWindow;
	BOOLEAN HookKuserSharedData;
	BOOLEAN HookNtSetInformationProcess;
	BOOLEAN ClearPebBeingDebugged;
	BOOLEAN ClearPebNtGlobalFlag;
	BOOLEAN ClearHeapFlags;
	BOOLEAN ClearKuserSharedData;
	BOOLEAN ClearHideFromDebuggerFlag;
	BOOLEAN ClearBypassProcessFreeze;
	BOOLEAN ClearProcessBreakOnTerminationFlag;
	BOOLEAN ClearThreadBreakOnTerminationFlag;
	BOOLEAN SaveProcessDebugFlags;
	BOOLEAN SaveProcessHandleTracing;
}HIDE_INFO, * PHIDE_INFO;

namespace Hider
{
	extern BOOLEAN StopCounterThread;
	extern LIST_ENTRY HiddenProcessesHead;
	extern KGUARDED_MUTEX HiderMutex;

	typedef struct _DEBUG_CONTEXT 
	{
		ULONG64 DR0;
		ULONG64 DR1;
		ULONG64 DR2;
		ULONG64 DR3;
		ULONG64 DR6;
		ULONG64 DR7;

		ULONG64 DebugControl;
		ULONG64 LastBranchFromRip;
		ULONG64 LastBranchToRip;
		ULONG64 LastExceptionFromRip;
		ULONG64 LastExceptionToRip;
	}DEBUG_CONTEXT,* PDEBUG_CONTEXT;

	typedef struct _WOW64_DEBUG_CONTEXT
	{
		ULONG DR0;
		ULONG DR1;
		ULONG DR2;
		ULONG DR3;
		ULONG DR6;
		ULONG DR7;
	}WOW64_DEBUG_CONTEXT,*PWOW64_DEBUG_CONTEXT;

	typedef struct _KUSD
	{
		// Pointer to new KuserSharedData
		PKUSER_SHARED_DATA KuserSharedData;

		// Pte of virtual page number 7FFE0
		PTE* PteKuserSharedData;

		// Page frame number of original KuserSharedData
		ULONG OriginalKuserSharedDataPfn;

		// Begin
		ULONG64 BeginInterruptTime;
		ULONG64 BeginSystemTime;
		ULONG BeginLastSystemRITEventTickCount;
		ULONG64 BeginTickCount;
		ULONG64 BeginTimeUpdateLock;
		ULONG64 BeginBaselineSystemQpc;

		// Delta
		ULONG64 DeltaInterruptTime;
		ULONG64 DeltaSystemTime;
		ULONG DeltaLastSystemRITEventTickCount;
		ULONG64 DeltaTickCount;
		ULONG64 DeltaTimeUpdateLock;
		ULONG64 DeltaBaselineSystemQpc;
	}KUSD, * PKUSD;

	typedef struct _HIDDEN_THREAD
	{
		LIST_ENTRY HiddenThreadList;
		PETHREAD ThreadObject;
		WOW64_DEBUG_CONTEXT FakeWow64DebugContext;
		DEBUG_CONTEXT FakeDebugContext;
		BOOLEAN IsThreadHidden;
		BOOLEAN BreakOnTermination;
	}HIDDEN_THREAD, * PHIDDEN_THREAD;

	typedef struct _HIDDEN_PROCESS
	{
		LIST_ENTRY HiddenProcessesList;
		
		HIDDEN_THREAD HiddenThreads;

		PEPROCESS DebuggerProcess;
		PEPROCESS DebuggedProcess;

		LARGE_INTEGER FakePerformanceCounter;
		LARGE_INTEGER FakeSystemTime;

		BOOLEAN HideTypes[HIDE_LAST];

		BOOLEAN ProcessPaused;

		BOOLEAN PebBeingDebuggedCleared;
		BOOLEAN HeapFlagsCleared;
		BOOLEAN PebNtGlobalFlagCleared;
		BOOLEAN KUserSharedDataCleared;
		BOOLEAN HideFromDebuggerFlagCleared;
		BOOLEAN BypassProcessFreezeFlagCleared;
		BOOLEAN ProcessHandleTracingEnabled;
		BOOLEAN ProcessBreakOnTerminationCleared;
		BOOLEAN ThreadBreakOnTerminationCleared;

		BOOLEAN ProcessDebugFlagsSaved;
		BOOLEAN ProcessHandleTracingSaved;

		BOOLEAN ValueProcessBreakOnTermination;
		BOOLEAN ValueProcessDebugFlags;

		KUSD Kusd;
	}HIDDEN_PROCESS, * PHIDDEN_PROCESS;

	PHIDDEN_PROCESS QueryHiddenProcess(PEPROCESS DebuggedProcess);

	PHIDDEN_THREAD AppendThreadList(PEPROCESS InterceptedProcess, PETHREAD ThreadObject);

	BOOLEAN CreateEntry(PEPROCESS DebuggerProcess, PEPROCESS DebuggedProcess);

	BOOLEAN RemoveEntry(PEPROCESS DebuggerProcess);

	BOOLEAN IsHidden(PEPROCESS Process, HIDE_TYPE HideType);

	BOOLEAN Hide(PHIDE_INFO HideInfo);

	BOOLEAN IsDriverHandleHidden(PUNICODE_STRING SymLink);

	BOOLEAN Initialize();

	BOOLEAN StopCounterForProcess(PEPROCESS DebuggedProcess);

	BOOLEAN ResumeCounterForProcess(PEPROCESS DebuggedProcess);

	BOOLEAN IsDebuggerProcess(PEPROCESS DebuggerProcess);

	BOOLEAN IsProcessNameBad(PUNICODE_STRING ProcessName);

	BOOLEAN IsProcessWindowBad(PUNICODE_STRING WindowName);

	BOOLEAN IsProcessWindowClassBad(PUNICODE_STRING WindowClassName);

	VOID DeleteThreadList(PHIDDEN_PROCESS HiddenProcess);

	VOID TruncateThreadList(PEPROCESS InterceptedProcess, PETHREAD ThreadObject);

	VOID Uninitialize();
}