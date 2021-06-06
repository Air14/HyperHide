#pragma once
#include <iostream>
#include <Windows.h>

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
    BOOLEAN HookKiExceptionDispatch;
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

class HyperHideDrv 
{
public:
	HyperHideDrv();
	~HyperHideDrv();
	BOOLEAN CreateHandleToDriver();
	BOOLEAN CallDriver(size_t Ioctl);
    BOOLEAN Hide(HIDE_INFO& HideInfo);
	void SetTargetPid(UINT32 Pid);
	HANDLE GetDriverHandleValue();

private:
	const std::string HyperHideDrvLink = "\\\\.\\HyperHideDrv";
	HANDLE DriverHandle = 0;
	UINT32 Pid = 0;
};