#pragma once
#include <ntifs.h>
#include "Ntstructs.h"
#include "Hider.h"

typedef struct _NTAPI_OFFSETS
{
	ULONG SeAuditProcessCreationInfoOffset;
	ULONG BypassProcessFreezeFlagOffset;
	ULONG ThreadHideFromDebuggerFlagOffset;
	ULONG ThreadBreakOnTerminationFlagOffset;
	ULONG PicoContextOffset;
	ULONG RestrictSetThreadContextOffset;
}NTAPI_OFFSETS;

template <typename T>
PEPROCESS PidToProcess(T Pid)
{
	PEPROCESS Process;
	PsLookupProcessByProcessId((HANDLE)Pid, &Process);
	return Process;
}

PEPROCESS GetCsrssProcess();

ULONG64 GetPteAddress(ULONG64 Address);

PVOID FindSignature(PVOID Memory, ULONG64 Size, PCSZ Pattern, PCSZ Mask);

BOOLEAN GetProcessInfo(CONST CHAR* Name, _Out_ ULONG64& ImageSize, _Out_ PVOID& ImageBase);

PEPROCESS GetProcessByName(CONST WCHAR* ProcessName);

BOOLEAN RtlUnicodeStringContains(PUNICODE_STRING Str, PUNICODE_STRING SubStr, BOOLEAN CaseInsensitive);

BOOLEAN GetSectionData(CONST CHAR* ModuleName, CONST CHAR* SectionName, ULONG64& SectionSize, PVOID& SectionBaseAddress);

BOOLEAN ClearBypassProcessFreezeFlag(PEPROCESS Process);

BOOLEAN ClearThreadHideFromDebuggerFlag(PEPROCESS Process);

PVOID GetExportedFunctionAddress(PEPROCESS Process, PVOID ModuleBase, CONST CHAR* ExportedFunctionName);

BOOLEAN ClearProcessBreakOnTerminationFlag(Hider::PHIDDEN_PROCESS HiddenProcess);

BOOLEAN ClearThreadBreakOnTerminationFlags(PEPROCESS TargetProcess);

VOID SaveProcessDebugFlags(Hider::PHIDDEN_PROCESS HiddenProcess);

VOID SaveProcessHandleTracing(Hider::PHIDDEN_PROCESS HiddenProcess);

BOOLEAN IsPicoContextNull(PETHREAD TargetThread);

BOOLEAN IsSetThreadContextRestricted(PEPROCESS TargetProcess);

BOOLEAN GetOffsets();

PVOID GetUserModeModule(PEPROCESS Process, CONST WCHAR* ModuleName, BOOLEAN IsWow64);

UNICODE_STRING PsQueryFullProcessImageName(PEPROCESS TargetProcess);