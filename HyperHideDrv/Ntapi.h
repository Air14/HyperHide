#pragma once
#include <ntddk.h>
#include <ntifs.h>
#include "Ntstructs.h"

extern "C"
{
    NTSTATUS NTAPI KeRaiseUserException(NTSTATUS Status);

    VOID NTAPI KeGenericCallDpc
    (
        _In_ PKDEFERRED_ROUTINE Routine,
        _In_ PVOID Context
    );

    VOID NTAPI KeSignalCallDpcDone
    (
        _In_ PVOID SystemArgument1
    );

    BOOLEAN NTAPI KeSignalCallDpcSynchronize
    (
        _In_ PVOID SystemArgument2
    );

    NTKERNELAPI VOID KeStackAttachProcess
    (
        _Inout_ PRKPROCESS PROCESS, 
        _Out_ PRKAPC_STATE ApcState
    );

    NTKERNELAPI VOID KeUnstackDetachProcess
    (
        _In_ PRKAPC_STATE ApcState
    );

    NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation
    (
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass, 
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength, 
        OUT PULONG ReturnLength OPTIONAL
    );

    NTSTATUS NTAPI MmCopyVirtualMemory
    (
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    );

    NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process
    (
        IN PEPROCESS Process
    );

    NTKERNELAPI PPEB NTAPI PsGetProcessPeb
    (
        IN PEPROCESS Process
    );

    NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName
    (
        PUNICODE_STRING ObjectName,
        ULONG Attributes,
        PACCESS_STATE AccessState,
        ACCESS_MASK DesiredAccess,
        POBJECT_TYPE ObjectType,
        KPROCESSOR_MODE AccessMode,
        PVOID ParseContext OPTIONAL,
        PVOID* Object
    );

    NTSYSAPI WCHAR* NTAPI PsGetProcessImageFileName(PEPROCESS Process);

    NTSYSAPI NTSTATUS NTAPI ZwQueryInformationJobObject(
        HANDLE JobHandle,
        JOBOBJECTINFOCLASS JobInformationClass,
        PVOID JobInformation,
        ULONG JobInformationLength,
        PULONG ReturnLength
    );

    NTSTATUS NTAPI ZwQueryInformationProcess(
        HANDLE           ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID            ProcessInformation,
        ULONG            ProcessInformationLength,
        PULONG           ReturnLength
    );

    BOOLEAN NTAPI ObFindHandleForObject(
            __in PEPROCESS Process,
            __in_opt PVOID Object OPTIONAL,
            __in_opt POBJECT_TYPE ObjectType OPTIONAL,
            __in_opt POBJECT_HANDLE_INFORMATION HandleInformation,
            __out PHANDLE Handle
        );

    NTSTATUS NTAPI ZwSetInformationProcess(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength
    );

    BOOLEAN NTAPI PsIsProcessBeingDebugged(PEPROCESS Process);

    HANDLE NTAPI
        PsGetProcessInheritedFromUniqueProcessId(
            __in PEPROCESS Process
        );

    PVOID NTAPI PsGetCurrentProcessWow64Process();

    NTSTATUS
        PsGetContextThread(
            __in PETHREAD Thread,
            __inout PCONTEXT ThreadContext,
            __in KPROCESSOR_MODE Mode
        );
}