#pragma warning( disable : 4201)
#include <ntddk.h>
#include <intrin.h>
#include <span>
#include "Ntstructs.h"
#include "GlobalData.h"
#include "Log.h"
#include "Utils.h"
#include "Hider.h"
#include "Ntapi.h"
#include "HookHelper.h"
#include "Ssdt.h"
#include "HookedFunctions.h"
#include "HypervisorGateway.h"

CONST PKUSER_SHARED_DATA KuserSharedData = (PKUSER_SHARED_DATA)KUSER_SHARED_DATA_USERMODE;

KMUTEX NtCloseMutex;

HANDLE (NTAPI * NtUserGetThreadState)(ULONG Routine);
ULONG64 KiUserExceptionDispatcherAddress = 0;

extern HYPER_HIDE_GLOBAL_DATA g_HyperHide;

NTSTATUS(NTAPI* OriginalNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI HookedNtQueryInformationProcess(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
)
{
	if (ExGetPreviousMode() == UserMode &&
		Hider::IsHidden(IoGetCurrentProcess(),HIDE_NT_QUERY_INFORMATION_PROCESS) == TRUE &&
		(ProcessInformationClass == ProcessDebugObjectHandle || ProcessInformationClass == ProcessDebugPort ||
		 ProcessInformationClass == ProcessDebugFlags || ProcessInformationClass == ProcessBreakOnTermination ||
		 ProcessInformationClass == ProcessBasicInformation || ProcessInformationClass == ProcessIoCounters ||
		 ProcessInformationClass == ProcessHandleTracing)
		)
	{
		if (ProcessInformationLength != 0)
		{
			__try
			{
				ProbeForRead(ProcessInformation, ProcessInformationLength, 4);
				if (ReturnLength != 0)
					ProbeForWrite(ReturnLength, 4, 1);
			}

			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}

		if (ProcessInformationClass == ProcessDebugObjectHandle)
		{
			if(ProcessInformationLength != sizeof(ULONG64))
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (Hider::IsHidden(TargetProcess, HIDE_NT_QUERY_INFORMATION_PROCESS) == TRUE)
				{
					__try
					{
						*(ULONG64*)ProcessInformation = NULL;
						if (ReturnLength != NULL) *ReturnLength = sizeof(ULONG64);

						Status = STATUS_PORT_NOT_SET;
					}

					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
			}

			return Status;
		}

		else if (ProcessInformationClass == ProcessDebugPort)
		{
			if (ProcessInformationLength != sizeof(ULONG64))
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (Hider::IsHidden(TargetProcess, HIDE_NT_QUERY_INFORMATION_PROCESS) == TRUE)
				{
					__try
					{
						*(ULONG64*)ProcessInformation = 0;
						if (ReturnLength != 0)
							*ReturnLength = sizeof(ULONG64);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}
					
					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
			}

			return Status;
		}

		else if (ProcessInformationClass == ProcessDebugFlags)
		{
			if (ProcessInformationLength != 4)
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (Hider::IsHidden(TargetProcess, HIDE_NT_QUERY_INFORMATION_PROCESS) == TRUE)
				{
					__try
					{
						*(ULONG*)ProcessInformation = (Hider::QueryHiddenProcess(TargetProcess)->ValueProcessDebugFlags == 0) ? PROCESS_DEBUG_INHERIT : 0;
						if (ReturnLength != 0)
							*ReturnLength = sizeof(ULONG);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
			}

			return Status;
		}

		else if (ProcessInformationClass == ProcessBreakOnTermination)
		{
			if (ProcessInformationLength != 4)
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0x1000, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (Hider::IsHidden(TargetProcess, HIDE_NT_QUERY_INFORMATION_PROCESS) == TRUE)
				{
					__try
					{
						*(ULONG*)ProcessInformation = Hider::QueryHiddenProcess(TargetProcess)->ValueProcessBreakOnTermination;
						if (ReturnLength != 0)
							*ReturnLength = sizeof(ULONG);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
			}

			return Status;
		}

		NTSTATUS Status = OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
		if (NT_SUCCESS(Status) == TRUE) 
		{
			PEPROCESS TargetProcess;
			NTSTATUS ObStatus = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, (PVOID*)&TargetProcess, NULL);

			if (NT_SUCCESS(ObStatus) == TRUE)
			{
				ObDereferenceObject(TargetProcess);

				if (Hider::IsHidden(TargetProcess, HIDE_NT_QUERY_INFORMATION_PROCESS) == TRUE)
				{
					Hider::PHIDDEN_PROCESS HiddenProcess = Hider::QueryHiddenProcess(TargetProcess);

					if (HiddenProcess != NULL)
					{
						if (ProcessInformationClass == ProcessBasicInformation)
						{
							BACKUP_RETURNLENGTH();
							PEPROCESS ExplorerProcess = GetProcessByName(L"explorer.exe");
							if(ExplorerProcess != NULL)
								((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId = PsGetProcessId(ExplorerProcess);
							RESTORE_RETURNLENGTH();
							return Status;
						}

						else if (ProcessInformationClass == ProcessIoCounters)
						{
							BACKUP_RETURNLENGTH();
							((PIO_COUNTERS)ProcessInformation)->OtherOperationCount = 1;
							RESTORE_RETURNLENGTH();
							return Status;
						}

						else if (ProcessInformationClass == ProcessHandleTracing)
						{
							return HiddenProcess->ProcessHandleTracingEnabled ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
						}
					}
				}
			}
		}

		return Status;
	}

	return OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS(NTAPI* OriginalNtSetInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
NTSTATUS NTAPI HookedNtSetInformationThread(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength
)
{
	PEPROCESS CurrentProcess = IoGetCurrentProcess();
	if (Hider::IsHidden(CurrentProcess,HIDE_NT_SET_INFORMATION_THREAD) == TRUE &&
		ExGetPreviousMode() == UserMode &&
		(ThreadInformationClass == ThreadHideFromDebugger || ThreadInformationClass == ThreadWow64Context ||
		 ThreadInformationClass == ThreadBreakOnTermination))
	{
		if (ThreadInformationLength != 0)
		{
			__try
			{
				ProbeForRead(ThreadInformation, ThreadInformationLength, sizeof(ULONG));
			}

			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}

		if (ThreadInformationClass == ThreadHideFromDebugger)
		{
			if (ThreadInformationLength != 0)
				return STATUS_INFO_LENGTH_MISMATCH;

			PETHREAD Thread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_INFORMATION, *PsThreadType, UserMode, (PVOID*)&Thread, NULL);

			if (NT_SUCCESS(Status) == TRUE)
			{
				PEPROCESS TargetThreadProcess = IoThreadToProcess(Thread);
				if (Hider::IsHidden(TargetThreadProcess, HIDE_NT_SET_INFORMATION_THREAD) == TRUE)
				{
					Hider::PHIDDEN_THREAD HiddenThread = Hider::AppendThreadList(TargetThreadProcess, Thread);

					HiddenThread->IsThreadHidden = TRUE;

					ObDereferenceObject(Thread);
					return Status;
				}

				ObDereferenceObject(Thread);
				return OriginalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
			}

			return Status;
		}

		else if (ThreadInformationClass == ThreadWow64Context)
		{
			PETHREAD TargetThread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_CONTEXT, *PsThreadType, UserMode, (PVOID*)&TargetThread, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				PEPROCESS TargetProcess = IoThreadToProcess(TargetThread);
				if (Hider::IsHidden(TargetProcess, HIDE_NT_SET_INFORMATION_THREAD) == TRUE)
				{
					if (ThreadInformationLength != sizeof(WOW64_CONTEXT))
					{
						ObDereferenceObject(TargetThread);
						return STATUS_INFO_LENGTH_MISMATCH;
					}

					PVOID WoW64Process = PsGetCurrentProcessWow64Process();
					if (WoW64Process == 0)
					{
						ObDereferenceObject(TargetThread);
						return STATUS_INVALID_PARAMETER;
					}

					__try
					{
						PWOW64_CONTEXT Wow64Context = (PWOW64_CONTEXT)ThreadInformation;
						ULONG OriginalFlags = Wow64Context->ContextFlags;

						Wow64Context->ContextFlags &= ~0x10;

						Status = OriginalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);

						if (OriginalFlags & 0x10)
						{
							Wow64Context->ContextFlags |= 0x10;
							Hider::PHIDDEN_THREAD HiddenThread = Hider::AppendThreadList(IoThreadToProcess(TargetThread), TargetThread);
							if (HiddenThread != NULL)
								RtlCopyBytes(&HiddenThread->FakeWow64DebugContext, &Wow64Context->Dr0, sizeof(ULONG) * 6);
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetThread);
					return Status;
				}

				ObDereferenceObject(TargetThread);
				return OriginalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
			}

			return Status;
		}

		else if (ThreadInformationClass == ThreadBreakOnTermination) 
		{
			if (ThreadInformationLength != sizeof(ULONG))
				return STATUS_INFO_LENGTH_MISMATCH;

			__try
			{
				volatile ULONG Touch = *(ULONG*)ThreadInformation;
				UNREFERENCED_PARAMETER(Touch);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}

			LUID PrivilageValue;
			PrivilageValue.LowPart = SE_DEBUG_PRIVILEGE;
			if (SeSinglePrivilegeCheck(PrivilageValue, UserMode) == FALSE)
				return STATUS_PRIVILEGE_NOT_HELD;

			PETHREAD ThreadObject;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_INFORMATION, *PsThreadType, ExGetPreviousMode(), (PVOID*)&ThreadObject, NULL);

			if (NT_SUCCESS(Status) == TRUE)
			{
				PEPROCESS TargetProcess = IoThreadToProcess(ThreadObject);
				if (Hider::IsHidden(TargetProcess, HIDE_NT_SET_INFORMATION_THREAD) == TRUE)
				{
					Hider::PHIDDEN_THREAD HiddenThread = Hider::AppendThreadList(TargetProcess, ThreadObject);
					if (HiddenThread != NULL)
						HiddenThread->BreakOnTermination = *(ULONG*)ThreadInformation ? TRUE : FALSE;

					ObDereferenceObject(ThreadHandle);
					return Status;
				}

				ObDereferenceObject(ThreadHandle);
				return OriginalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
			}

			return Status;
		}
	}

	return OriginalNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS(NTAPI* OriginalNtSetInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
NTSTATUS NTAPI HookedNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
	if (ExGetPreviousMode() == UserMode &&
		Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_SET_INFORMATION_PROCESS) == TRUE  &&
		(ProcessInformationClass == ProcessBreakOnTermination || ProcessInformationClass == ProcessDebugFlags||
		ProcessInformationClass == ProcessHandleTracing))
	{
		if (ProcessInformationLength != 0)
		{
			__try
			{
				ProbeForRead(ProcessInformation, ProcessInformationLength, 4);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}

		if (ProcessInformationClass == ProcessBreakOnTermination) 
		{
			if (ProcessInformationLength != sizeof(ULONG))
				return STATUS_INFO_LENGTH_MISMATCH;

			__try
			{
				volatile ULONG Touch = *(ULONG*)ProcessInformation;
				UNREFERENCED_PARAMETER(Touch);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}

			LUID PrivilageValue;
			PrivilageValue.LowPart = SE_DEBUG_PRIVILEGE;
			if (SeSinglePrivilegeCheck(PrivilageValue,UserMode) == FALSE)
				return STATUS_PRIVILEGE_NOT_HELD;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0x200, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (Hider::IsHidden(TargetProcess, HIDE_NT_SET_INFORMATION_PROCESS) == TRUE)
				{
					Hider::PHIDDEN_PROCESS HiddenProcess = Hider::QueryHiddenProcess(TargetProcess);
					if (HiddenProcess != NULL)
						HiddenProcess->ValueProcessBreakOnTermination = *(ULONG*)ProcessInformation & 1;

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
			}
			return Status;
		}

		else if (ProcessInformationClass == ProcessDebugFlags) 
		{
			if (ProcessInformationLength != sizeof(ULONG))
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0x200, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (Hider::IsHidden(TargetProcess, HIDE_NT_SET_INFORMATION_PROCESS) == TRUE)
				{
					__try
					{
						ULONG Flags = *(ULONG*)ProcessInformation;
						if ((Flags & ~PROCESS_DEBUG_INHERIT) != 0)
						{
							ObDereferenceObject(TargetProcess);
							return STATUS_INVALID_PARAMETER;
						}

						Hider::PHIDDEN_PROCESS HiddenProcess = Hider::QueryHiddenProcess(TargetProcess);

						if ((Flags & PROCESS_DEBUG_INHERIT) != 0)
							HiddenProcess->ValueProcessDebugFlags = 0;

						else
							HiddenProcess->ValueProcessDebugFlags = TRUE;

						Status = STATUS_SUCCESS;
					}

					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
			}

			return Status;
		}

		else if (ProcessInformationClass == ProcessHandleTracing)
		{
			BOOLEAN Enable = ProcessInformationLength != 0;
			if (Enable == TRUE)
			{
				if (ProcessInformationLength != sizeof(ULONG) && ProcessInformationLength != sizeof(ULONG64))
					return STATUS_INFO_LENGTH_MISMATCH;
				
				__try 
				{
					PPROCESS_HANDLE_TRACING_ENABLE_EX ProcessHandleTracing = (PPROCESS_HANDLE_TRACING_ENABLE_EX)ProcessInformation;
					if (ProcessHandleTracing->Flags != 0)
						return STATUS_INVALID_PARAMETER;
				}

				__except (EXCEPTION_EXECUTE_HANDLER) 
				{
					return GetExceptionCode();
				}
			}

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0x200, *PsProcessType, UserMode, (PVOID*)&TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (Hider::IsHidden(TargetProcess, HIDE_NT_SET_INFORMATION_PROCESS) == TRUE)
				{
					Hider::PHIDDEN_PROCESS HiddenProcess = Hider::QueryHiddenProcess(TargetProcess);
					if (HiddenProcess != NULL)
						HiddenProcess->ProcessHandleTracingEnabled = Enable;

					ObDereferenceObject(TargetProcess);
					return Status;
				}

				ObDereferenceObject(TargetProcess);
				return OriginalNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
			}

			return Status;
		}
	}
	return OriginalNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

NTSTATUS (NTAPI* OriginalNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI HookedNtQueryObject(
	HANDLE                   Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID                    ObjectInformation,
	ULONG                    ObjectInformationLength,
	PULONG                   ReturnLength
)
{
	NTSTATUS Status = OriginalNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_QUERY_OBJECT) == TRUE &&
		NT_SUCCESS(Status) == TRUE &&
		ExGetPreviousMode() == UserMode &&
		ObjectInformation != NULL)
	{

		if (ObjectInformationClass == ObjectTypeInformation)
		{
			UNICODE_STRING DebugObject;
			RtlInitUnicodeString(&DebugObject, L"DebugObject");
			POBJECT_TYPE_INFORMATION Type = (POBJECT_TYPE_INFORMATION)ObjectInformation;

			if (RtlEqualUnicodeString(&Type->TypeName, &DebugObject, FALSE) == TRUE)
			{
				BACKUP_RETURNLENGTH();
				Type->TotalNumberOfObjects -= g_HyperHide.NumberOfActiveDebuggers;
				Type->TotalNumberOfHandles -= g_HyperHide.NumberOfActiveDebuggers;
				RESTORE_RETURNLENGTH();
			}

			return Status;
		}

		else if (ObjectInformationClass == ObjectTypesInformation)
		{
			UNICODE_STRING DebugObject;
			RtlInitUnicodeString(&DebugObject, L"DebugObject");
			POBJECT_ALL_INFORMATION ObjectAllInfo = (POBJECT_ALL_INFORMATION)ObjectInformation;
			UCHAR* ObjInfoLocation = (UCHAR*)ObjectAllInfo->ObjectTypeInformation;
			ULONG TotalObjects = ObjectAllInfo->NumberOfObjectsTypes;

			BACKUP_RETURNLENGTH();
			for (ULONG i = 0; i < TotalObjects; i++)
			{
				POBJECT_TYPE_INFORMATION ObjectTypeInfo = (POBJECT_TYPE_INFORMATION)ObjInfoLocation;
				if (RtlEqualUnicodeString(&ObjectTypeInfo->TypeName, &DebugObject, FALSE) == TRUE)
				{
					ObjectTypeInfo->TotalNumberOfObjects -= g_HyperHide.NumberOfActiveDebuggers;
					ObjectTypeInfo->TotalNumberOfHandles -= g_HyperHide.NumberOfActiveDebuggers;
				}
				ObjInfoLocation = (UCHAR*)ObjectTypeInfo->TypeName.Buffer;
				ObjInfoLocation += ObjectTypeInfo->TypeName.MaximumLength;
				ULONG64 Tmp = ((ULONG64)ObjInfoLocation) & -(LONG64)sizeof(PVOID);
				if ((ULONG64)Tmp != (ULONG64)ObjInfoLocation)
					Tmp += sizeof(PVOID);
				ObjInfoLocation = ((UCHAR*)Tmp);
			}
			RESTORE_RETURNLENGTH();
			return Status;
		}
	}

	return Status;
}

NTSTATUS (NTAPI* OriginalNtSystemDebugControl)(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
NTSTATUS NTAPI HookedNtSystemDebugControl(
	 SYSDBG_COMMAND       Command,
	 PVOID                InputBuffer ,
	 ULONG                InputBufferLength,
	 PVOID               OutputBuffer ,
	 ULONG                OutputBufferLength,
	 PULONG              ReturnLength )
{
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_SYSTEM_DEBUG_CONTROL) == TRUE &&
		Command != SysDbgGetTriageDump && 
		Command != SysDbgGetLiveKernelDump)
	{
		return STATUS_DEBUGGER_INACTIVE;
	}

	return OriginalNtSystemDebugControl(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
}

NTSTATUS (NTAPI* OriginalNtClose)(HANDLE Handle);
NTSTATUS NTAPI HookedNtClose(HANDLE Handle)
{
	const auto targetProcess = IoGetCurrentProcess();
	if(Hider::IsHidden(targetProcess, HIDE_NT_CLOSE) == TRUE)
	{
		KeWaitForSingleObject(&NtCloseMutex, Executive, KernelMode, FALSE, NULL);
		
		OBJECT_HANDLE_ATTRIBUTE_INFORMATION ObjAttributeInfo;

		NTSTATUS Status = ZwQueryObject(Handle,(OBJECT_INFORMATION_CLASS)4 /*ObjectDataInformation*/, &ObjAttributeInfo, sizeof(OBJECT_HANDLE_ATTRIBUTE_INFORMATION), NULL);

		if (Status == STATUS_INVALID_HANDLE)
		{
			KeReleaseMutex(&NtCloseMutex, FALSE);

			if (const auto HiddenProcess = Hider::QueryHiddenProcess(targetProcess); HiddenProcess && HiddenProcess->ProcessHandleTracingEnabled)
				return KeRaiseUserException(STATUS_INVALID_HANDLE);

			return STATUS_INVALID_HANDLE;
		}

		if (NT_SUCCESS(Status) == TRUE) 
		{
			if (ObjAttributeInfo.ProtectFromClose == TRUE)
			{
				KeReleaseMutex(&NtCloseMutex, FALSE);

				if (const auto HiddenProcess = Hider::QueryHiddenProcess(targetProcess); HiddenProcess && HiddenProcess->ProcessHandleTracingEnabled)
					return KeRaiseUserException(STATUS_HANDLE_NOT_CLOSABLE);

				return STATUS_HANDLE_NOT_CLOSABLE;
			}
		}

		KeReleaseMutex(&NtCloseMutex, FALSE);
	}

	return OriginalNtClose(Handle);
}

NTSTATUS(NTAPI* OriginalNtGetNextProcess)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle);
NTSTATUS NTAPI HookedNtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle) 
{
	NTSTATUS Status = OriginalNtGetNextProcess(ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_GET_NEXT_PROCESS) == TRUE &&
		ExGetPreviousMode() == UserMode &&
		NT_SUCCESS(Status) == TRUE)
	{
		PEPROCESS NewProcess;
		NTSTATUS ObStatus = ObReferenceObjectByHandle(*NewProcessHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&NewProcess, NULL);
		if (NT_SUCCESS(ObStatus) == TRUE)
		{
			UNICODE_STRING ProcessImageName = PsQueryFullProcessImageName(NewProcess);
			if (Hider::IsProcessNameBad(&ProcessImageName) == TRUE)
			{
				HANDLE OldHandleValue = *NewProcessHandle;

				Status = HookedNtGetNextProcess(*NewProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
				ObCloseHandle(OldHandleValue, UserMode);
			}

			ObDereferenceObject(NewProcess);
			return Status;
		}

		return Status;
	}

	return OriginalNtGetNextProcess(ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
}

NTSTATUS (NTAPI* OriginalNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS Status = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	PEPROCESS CurrentProcess = IoGetCurrentProcess();

	if (ExGetPreviousMode() == UserMode &&
		Hider::IsHidden(CurrentProcess, HIDE_NT_QUERY_SYSTEM_INFORMATION) == TRUE &&
		NT_SUCCESS(Status) == TRUE
		)
	{
		if (SystemInformationClass == SystemKernelDebuggerInformation)
		{
			PSYSTEM_KERNEL_DEBUGGER_INFORMATION DebuggerInfo = (PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation;

			BACKUP_RETURNLENGTH();
			DebuggerInfo->DebuggerEnabled = 0;
			DebuggerInfo->DebuggerNotPresent = 1;
			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemProcessInformation ||
			SystemInformationClass == SystemSessionProcessInformation ||
			SystemInformationClass == SystemExtendedProcessInformation ||
			SystemInformationClass == SystemFullProcessInformation)
		{
			PSYSTEM_PROCESS_INFO ProcessInfo = (PSYSTEM_PROCESS_INFO)SystemInformation;
			if (SystemInformationClass == SystemSessionProcessInformation)
				ProcessInfo = (PSYSTEM_PROCESS_INFO)((PSYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation)->Buffer;

			BACKUP_RETURNLENGTH();

			FilterProcesses(ProcessInfo);

			for (PSYSTEM_PROCESS_INFO Entry = ProcessInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
			{
				if (Hider::IsHidden(PidToProcess(Entry->ProcessId), HIDE_NT_QUERY_SYSTEM_INFORMATION) == TRUE)
				{
					PEPROCESS ExplorerProcess = GetProcessByName(L"explorer.exe");
					if (ExplorerProcess != NULL)
						Entry->InheritedFromProcessId = PsGetProcessId(ExplorerProcess);

					Entry->OtherOperationCount.QuadPart = 1;
				}
			}
			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemCodeIntegrityInformation)
		{
			BACKUP_RETURNLENGTH();
			((PSYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation)->CodeIntegrityOptions = 0x1; // CODEINTEGRITY_OPTION_ENABLED
			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemKernelDebuggerInformationEx)
		{
			BACKUP_RETURNLENGTH();
			((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerAllowed = FALSE;
			((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerEnabled = FALSE;
			((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerPresent = FALSE;
			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemKernelDebuggerFlags)
		{
			BACKUP_RETURNLENGTH();
			*(UCHAR*)SystemInformation = NULL;
			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemExtendedHandleInformation)
		{
			const auto systemHandleInfoEx = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(SystemInformation);
			BACKUP_RETURNLENGTH();

			std::span systemHandleTableEntryInfo{ systemHandleInfoEx->Handles, systemHandleInfoEx->NumberOfHandles };
			auto newEnd = std::remove_if(systemHandleTableEntryInfo.begin(), systemHandleTableEntryInfo.end(), [](auto& HandleEntryInfo)
				{
					const auto originalProcess = PidToProcess(HandleEntryInfo.UniqueProcessId);
					if (!originalProcess)
						return false;

					auto processName = PsQueryFullProcessImageName(originalProcess);
					return static_cast<bool>(Hider::IsProcessNameBad(&processName));
				});

			if (newEnd != systemHandleTableEntryInfo.end())
			{
				const auto numberOfHandleInfos = std::distance(newEnd, systemHandleTableEntryInfo.end());
				RtlSecureZeroMemory(&*newEnd, sizeof(decltype(systemHandleTableEntryInfo)::element_type) * numberOfHandleInfos);
				systemHandleInfoEx->NumberOfHandles -= numberOfHandleInfos;
			}

			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemHandleInformation)
		{
			const auto systemHandleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(SystemInformation);
			BACKUP_RETURNLENGTH();

			std::span systemHandleTableEntryInfo{ systemHandleInfo->Handles, systemHandleInfo->NumberOfHandles };
			auto newEnd = std::remove_if(systemHandleTableEntryInfo.begin(), systemHandleTableEntryInfo.end(), [](auto& HandleEntryInfo)
				{
					const auto originalProcess = PidToProcess(HandleEntryInfo.UniqueProcessId);
					if (!originalProcess)
						return false;

					auto processName = PsQueryFullProcessImageName(originalProcess);
					return static_cast<bool>(Hider::IsProcessNameBad(&processName));
				});

			if (newEnd != systemHandleTableEntryInfo.end())
			{
				const auto numberOfHandleInfos = std::distance(newEnd, systemHandleTableEntryInfo.end());
				RtlSecureZeroMemory(&*newEnd, sizeof(decltype(systemHandleTableEntryInfo)::element_type) * numberOfHandleInfos);
				systemHandleInfo->NumberOfHandles -= static_cast<ULONG>(numberOfHandleInfos);
			}

			RESTORE_RETURNLENGTH();
		}

		else if (SystemInformationClass == SystemPoolTagInformation)
		{
			const auto systemPooltagInfo = reinterpret_cast<PSYSTEM_POOLTAG_INFORMATION>(SystemInformation);
			BACKUP_RETURNLENGTH();

			std::span poolTags{ systemPooltagInfo->TagInfo, systemPooltagInfo->Count };
			auto newEnd = std::remove_if(poolTags.begin(), poolTags.end(), [](auto& PoolTag) 
				{return PoolTag.TagUlong == DRIVER_TAG || PoolTag.TagUlong == 'vhra' ? true : false;});

			if (newEnd != poolTags.end())
			{
				const auto numberOfPools = std::distance(newEnd, poolTags.end());
				RtlSecureZeroMemory(&*newEnd, sizeof(decltype(poolTags)::element_type) * numberOfPools);
				systemPooltagInfo->Count -= static_cast<ULONG>(numberOfPools);
			}

			RESTORE_RETURNLENGTH();
		}
	}

	return Status;
}

NTSTATUS(NTAPI* OriginalNtSetContextThread)(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NTAPI HookedNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context)
{
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_SET_CONTEXT_THREAD) == TRUE &&
		ExGetPreviousMode() == UserMode)
	{
		PETHREAD TargethThread;
		NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_CONTEXT, *PsThreadType, UserMode, (PVOID*)&TargethThread, 0);
		if (NT_SUCCESS(Status) == TRUE)
		{
			PEPROCESS TargetProcess = IoThreadToProcess(TargethThread);
			if (Hider::IsHidden(TargetProcess, HIDE_NT_SET_CONTEXT_THREAD) == TRUE)
			{
				if (IsSetThreadContextRestricted(TargetProcess) == TRUE && IoThreadToProcess(PsGetCurrentThread()) == TargetProcess)
				{
					ObDereferenceObject(TargethThread);
					return STATUS_SET_CONTEXT_DENIED;
				}

				// If it is a system thread or pico process thread return STATUS_INVALID_HANDLE
				if (IoIsSystemThread(TargethThread) == TRUE || IsPicoContextNull(TargethThread) == FALSE)
				{
					ObDereferenceObject(TargethThread);
					return STATUS_INVALID_HANDLE;
				}

				__try
				{
					ProbeForWrite(reinterpret_cast<char*>(Context) + 48, 4, 1);

					ULONG OriginalFlags = Context->ContextFlags;

					Context->ContextFlags &= ~0x10;

					Status = OriginalNtSetContextThread(ThreadHandle, Context);

					if (OriginalFlags & 0x10)
					{
						Context->ContextFlags |= 0x10;

						Hider::PHIDDEN_THREAD HiddenThread = Hider::AppendThreadList(TargetProcess, TargethThread);
						if (HiddenThread != 0)
						{
							RtlCopyBytes(&HiddenThread->FakeDebugContext.DR0, &Context->Dr0, sizeof(ULONG64) * 6);
							RtlCopyBytes(&HiddenThread->FakeDebugContext.DebugControl, &Context->DebugControl, sizeof(ULONG64) * 5);
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
				}

				ObDereferenceObject(TargethThread);
				return Status;
			}

			ObDereferenceObject(TargethThread);
			return OriginalNtSetContextThread(ThreadHandle, Context);
		}

		return Status;
	}

	return OriginalNtSetContextThread(ThreadHandle, Context);
}

NTSTATUS (NTAPI* OriginalNtGetContextThread)(IN HANDLE ThreadHandle, IN OUT PCONTEXT Context);
NTSTATUS NTAPI HookedNtGetContextThread(IN HANDLE ThreadHandle, IN OUT PCONTEXT Context)
{
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_GET_CONTEXT_THREAD) == TRUE &&
		ExGetPreviousMode() == UserMode
		)
	{
		PETHREAD ThreadObject;
		NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_CONTEXT, *PsThreadType, UserMode, (PVOID*)&ThreadObject, 0);
		if (NT_SUCCESS(Status) == TRUE)
		{
			// If it is a system thread return STATUS_INVALID_HANDLE
			if (IoIsSystemThread(ThreadObject) == TRUE)
			{
				ObDereferenceObject(ThreadObject);
				return STATUS_INVALID_HANDLE;
			}

			__try
			{
				ProbeForWrite(reinterpret_cast<char*>(Context) + 48, 4, 1);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				ObDereferenceObject(ThreadObject);
				return GetExceptionCode();
			}

			// Check if thread object belongs to any hidden process
			if (Hider::IsHidden(IoThreadToProcess(ThreadObject), HIDE_NT_SET_CONTEXT_THREAD) == TRUE)
			{
				__try
				{
					ULONG OriginalFlags = Context->ContextFlags;

					Context->ContextFlags &= ~0x10;

					Status = OriginalNtGetContextThread(ThreadHandle, Context);

					if (OriginalFlags & 0x10)
					{
						Context->ContextFlags |= 0x10;

						Hider::PHIDDEN_THREAD HiddenThread = Hider::AppendThreadList(IoThreadToProcess(ThreadObject), ThreadObject);
						if (HiddenThread != NULL)
						{
							RtlCopyBytes(&Context->Dr0, &HiddenThread->FakeDebugContext.DR0, sizeof(ULONG64) * 6);
							RtlCopyBytes(&Context->DebugControl, &HiddenThread->FakeDebugContext.DebugControl, sizeof(ULONG64) * 5);
						}
						else 
						{
							RtlSecureZeroMemory(&Context->Dr0, sizeof(ULONG64) * 6);
							RtlSecureZeroMemory(&Context->DebugControl, sizeof(ULONG64) * 5);
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
				}

				ObDereferenceObject(ThreadObject);
				return Status;
			}

			ObDereferenceObject(ThreadObject);
			return OriginalNtGetContextThread(ThreadHandle, Context);
		}

		return Status;
	}

	return OriginalNtGetContextThread(ThreadHandle, Context);
}

NTSTATUS (NTAPI* OriginalNtQueryInformationThread)(HANDLE ThreadHandle,THREADINFOCLASS ThreadInformationClass,PVOID ThreadInformation,ULONG ThreadInformationLength,PULONG ReturnLength);
NTSTATUS NTAPI HookedNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength) 
{
	PEPROCESS CurrentProcess = IoGetCurrentProcess();
	if (Hider::IsHidden(CurrentProcess, HIDE_NT_QUERY_INFORMATION_THREAD) == TRUE &&
		ExGetPreviousMode() == UserMode && (ThreadInformationClass == ThreadHideFromDebugger ||
			ThreadInformationClass == ThreadBreakOnTermination || ThreadInformationClass == ThreadWow64Context))
	{
		if (ThreadInformationLength != 0)
		{
			const auto alignment = ThreadInformationLength < 4 ? 1 : 4;

			__try
			{
				ProbeForRead(ThreadInformation, ThreadInformationLength, alignment);
				if(ReturnLength != 0)
					ProbeForWrite(ReturnLength, 4, 1);

			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}

		if (ThreadInformationClass == ThreadHideFromDebugger)
		{
			if (ThreadInformationLength != 1)
				return STATUS_INFO_LENGTH_MISMATCH;

			PETHREAD TargetThread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, 0x40, *PsThreadType, UserMode, (PVOID*)&TargetThread, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (Hider::IsHidden(IoThreadToProcess(TargetThread), HIDE_NT_QUERY_INFORMATION_THREAD) == TRUE) 
				{
					__try 
					{
						*(BOOLEAN*)ThreadInformation = Hider::AppendThreadList(IoThreadToProcess(TargetThread), TargetThread)->IsThreadHidden;

						if(ReturnLength != 0) *ReturnLength = 1;
					}
					__except (EXCEPTION_EXECUTE_HANDLER) 
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetThread);
					return Status;
				}

				ObDereferenceObject(TargetThread);
				return OriginalNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
			}

			return Status;
		}

		if (ThreadInformationClass == ThreadBreakOnTermination)
		{
			if (ThreadInformationLength != 4)
				return STATUS_INFO_LENGTH_MISMATCH;

			PETHREAD TargetThread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, 0x40, *PsThreadType, UserMode, (PVOID*)&TargetThread, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (Hider::IsHidden(IoThreadToProcess(TargetThread), HIDE_NT_QUERY_INFORMATION_THREAD) == TRUE)
				{
					__try
					{
						*(ULONG*)ThreadInformation = Hider::AppendThreadList(IoThreadToProcess(TargetThread), TargetThread)->BreakOnTermination;

						if (ReturnLength != NULL) *ReturnLength = 4;
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetThread);
					return Status;
				}

				ObDereferenceObject(TargetThread);
				return OriginalNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
			}

			return Status;
		}

		if (ThreadInformationClass == ThreadWow64Context) 
		{
			PETHREAD TargetThread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_GET_CONTEXT, *PsThreadType, UserMode, (PVOID*)&TargetThread, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (Hider::IsHidden(IoThreadToProcess(TargetThread), HIDE_NT_QUERY_INFORMATION_THREAD) == TRUE)
				{
					if (ThreadInformationLength != sizeof(WOW64_CONTEXT))
					{
						ObDereferenceObject(TargetThread);
						return STATUS_INFO_LENGTH_MISMATCH;
					}

					PVOID WoW64Process = PsGetCurrentProcessWow64Process();
					if (WoW64Process == 0)
					{
						ObDereferenceObject(TargetThread);
						return STATUS_INVALID_PARAMETER;
					}

					__try
					{
						PWOW64_CONTEXT Context = (PWOW64_CONTEXT)ThreadInformation;
						ULONG OriginalFlags = Context->ContextFlags;

						Context->ContextFlags &= ~0x10;

						Status = OriginalNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

						if (OriginalFlags & 0x10)
						{
							Context->ContextFlags |= 0x10;

							Hider::PHIDDEN_THREAD HiddenThread = Hider::AppendThreadList(IoThreadToProcess(TargetThread), TargetThread);

							if (HiddenThread != NULL)
								RtlCopyBytes(&Context->Dr0, &HiddenThread->FakeWow64DebugContext, sizeof(ULONG) * 6);

							else 
								RtlSecureZeroMemory(&Context->Dr0, sizeof(ULONG) * 6);
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Status = GetExceptionCode();
					}

					ObDereferenceObject(TargetThread);
					return Status;
				}

				ObDereferenceObject(TargetThread);
				return OriginalNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
			}

			return Status;
		}
	}

	return OriginalNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}

NTSTATUS(NTAPI* OriginalNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS NTAPI HookedNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_OPEN_PROCESS) == TRUE && 
		ExGetPreviousMode() == UserMode) 
	{
		__try
		{
			ProbeForWrite(ProcessHandle, 4, 1);
			ProbeForWrite(ObjectAttributes, 28, 4);
		}

		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}

		if (ClientId != NULL) 
		{
			__try
			{
				ProbeForRead(ClientId, 1, 4);
				volatile ULONG64 Touch = (ULONG64)ClientId->UniqueProcess;
				Touch = (ULONG64)ClientId->UniqueThread;
			}

			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}

			if(ClientId->UniqueProcess == NULL)
				return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

			PEPROCESS TargetProcess = PidToProcess(ClientId->UniqueProcess);
			UNICODE_STRING ProcessImageName = PsQueryFullProcessImageName(TargetProcess);

			if (Hider::IsProcessNameBad(&ProcessImageName) == TRUE)
			{
				HANDLE OldPid = ClientId->UniqueProcess;

				ClientId->UniqueProcess = UlongToHandle(0xFFFFFFFC);

				NTSTATUS Status = OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

				ClientId->UniqueProcess = OldPid;

				return Status;
			}
		}
	}
	return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS(NTAPI* OriginalNtOpenThread)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS NTAPI HookedNtOpenThread(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) 
{
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_OPEN_THREAD) == TRUE &&
		ExGetPreviousMode() == UserMode)
	{
		__try
		{
			ProbeForWrite(ProcessHandle, 4, 1);
			ProbeForWrite(ObjectAttributes, 28, 4);
		}

		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}

		if (ClientId != NULL)
		{
			__try
			{
				ProbeForRead(ClientId, 1, 4);
				volatile ULONG64 Touch = (ULONG64)ClientId->UniqueProcess;
				Touch = (ULONG64)ClientId->UniqueThread;
			}

			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}

			if (ClientId->UniqueThread == NULL)
				return OriginalNtOpenThread(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

			PETHREAD TargetThread;
			PsLookupThreadByThreadId(ClientId->UniqueThread, &TargetThread);
			if (TargetThread != NULL)
			{
				PEPROCESS TargetProcess = IoThreadToProcess(TargetThread);
				UNICODE_STRING ProcessImageName = PsQueryFullProcessImageName(TargetProcess);

				if (Hider::IsProcessNameBad(&ProcessImageName) == TRUE)
				{
					HANDLE OriginalTID = ClientId->UniqueThread;
					ClientId->UniqueThread = UlongToHandle(0xFFFFFFFC);

					NTSTATUS Status = OriginalNtOpenThread(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

					ClientId->UniqueThread = OriginalTID;

					return Status;
				}
			}
		}
	}
	return OriginalNtOpenThread(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS(NTAPI* OriginalNtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
NTSTATUS NTAPI HookedNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_CREATE_FILE) == TRUE &&
		ExGetPreviousMode() == UserMode
		)
	{
		NTSTATUS Status = OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
		
		if (NT_SUCCESS(Status) == TRUE) 
		{
			__try 
			{
				UNICODE_STRING SymLink;
				RtlInitUnicodeString(&SymLink, ObjectAttributes->ObjectName->Buffer);

				if (Hider::IsDriverHandleHidden(&SymLink) == TRUE)
				{
					ObCloseHandle(*FileHandle, UserMode);
					*FileHandle = INVALID_HANDLE_VALUE;
					Status = STATUS_OBJECT_NAME_NOT_FOUND;
				}
			}

			__except (EXCEPTION_EXECUTE_HANDLER) 
			{
			}
		}

		return Status;
	}

	return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS (NTAPI* OriginalNtCreateThreadEx)
(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PVOID AttributeList
);
NTSTATUS NTAPI HookedNtCreateThreadEx
(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PVOID AttributeList
) 
{
	if (Hider::IsHidden(IoGetCurrentProcess(),HIDE_NT_CREATE_THREAD_EX) == TRUE &&
		(CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER ||
		 CreateFlags & THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE))
	{
		NTSTATUS Status;
		ULONG OriginalFlags = CreateFlags;
		
		if(g_HyperHide.CurrentWindowsBuildNumber >= WINDOWS_10_VERSION_19H1)
			Status = OriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags & ~(THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE), ZeroBits, StackSize, MaximumStackSize, AttributeList);

		else 
			Status = OriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags & ~(THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER), ZeroBits, StackSize, MaximumStackSize, AttributeList);

		if (NT_SUCCESS(Status) == TRUE) 
		{
			PETHREAD NewThread;
			NTSTATUS ObStatus = ObReferenceObjectByHandle(*ThreadHandle, NULL, *PsThreadType, KernelMode, (PVOID*)&NewThread, NULL);

			if (NT_SUCCESS(ObStatus) == TRUE) 
			{
				PEPROCESS TargetProcess;
				ObStatus = ObReferenceObjectByHandle(ProcessHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&TargetProcess, NULL);

				if (NT_SUCCESS(ObStatus) == TRUE)
				{
					if (Hider::IsHidden(TargetProcess, HIDE_NT_CREATE_THREAD_EX) == TRUE)
					{
						Hider::PHIDDEN_THREAD HiddenThread =  Hider::AppendThreadList(TargetProcess, NewThread);
						if (HiddenThread != NULL) 
							HiddenThread->IsThreadHidden = OriginalFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
					}
					ObDereferenceObject(TargetProcess);
				}
				ObDereferenceObject(NewThread);
			}
		}

		return Status;
	}

	return OriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS (NTAPI* OriginalNtCreateProcessEx)
(
	OUT PHANDLE     ProcessHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
	IN HANDLE   ParentProcess,
	IN ULONG    Flags,
	IN HANDLE SectionHandle     OPTIONAL,
	IN HANDLE DebugPort     OPTIONAL,
	IN HANDLE ExceptionPort     OPTIONAL,
	IN ULONG  JobMemberLevel
);
NTSTATUS NTAPI HookedNtCreateProcessEx
(
	OUT PHANDLE     ProcessHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
	IN HANDLE   ParentProcess,
	IN ULONG    Flags,
	IN HANDLE SectionHandle     OPTIONAL,
	IN HANDLE DebugPort     OPTIONAL,
	IN HANDLE ExceptionPort     OPTIONAL,
	IN ULONG  JobMemberLevel
) 
{
	NTSTATUS Status = OriginalNtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, JobMemberLevel);
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_CREATE_PROCESS_EX) == TRUE &&
		NT_SUCCESS(Status) == TRUE) 
	{
		PEPROCESS NewProcess;
		NTSTATUS ObStatus = ObReferenceObjectByHandle(*ProcessHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&NewProcess, NULL);
		if (NT_SUCCESS(ObStatus) == TRUE) 
		{
			Hider::PHIDDEN_PROCESS HiddenProcess = Hider::QueryHiddenProcess(IoGetCurrentProcess());
			Hider::CreateEntry(HiddenProcess->DebuggerProcess, NewProcess);

			HIDE_INFO HideInfo = { 0 };

			RtlFillBytes(&HideInfo.HookNtQueryInformationProcess, 1, sizeof(HideInfo) - 4);
			HideInfo.Pid = HandleToUlong(PsGetProcessId(NewProcess));

			Hider::Hide(&HideInfo);
			ObDereferenceObject(NewProcess);
		}
	}
	return Status;
}

NTSTATUS(NTAPI* OriginalNtCreateUserProcess)
(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	POBJECT_ATTRIBUTES ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	PVOID CreateInfo, // PPS_CREATE_INFO
	PVOID AttributeList // PPS_ATTRIBUTE_LIST
);

NTSTATUS NTAPI HookedNtCreateUserProcess
(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	POBJECT_ATTRIBUTES ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	PVOID CreateInfo, // PPS_CREATE_INFO
	PVOID AttributeList // PPS_ATTRIBUTE_LIST
) 
{
	NTSTATUS Status = OriginalNtCreateUserProcess
	(
		ProcessHandle, ThreadHandle,
		ProcessDesiredAccess, ThreadDesiredAccess,
		ProcessObjectAttributes, ThreadObjectAttributes,
		ProcessFlags, ThreadFlags,
		ProcessParameters, CreateInfo, AttributeList
	);

	PEPROCESS CurrentProcess = IoGetCurrentProcess();
	if (Hider::IsHidden(CurrentProcess, HIDE_NT_CREATE_PROCESS_EX) == TRUE &&
		ExGetPreviousMode() == UserMode &&
		NT_SUCCESS(Status) == TRUE)
	{
		PEPROCESS NewProcess;
		NTSTATUS ObStatus = ObReferenceObjectByHandle(*ProcessHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&NewProcess, NULL);
		if (NT_SUCCESS(ObStatus) == TRUE) 
		{
			Hider::PHIDDEN_PROCESS HiddenProcess = Hider::QueryHiddenProcess(CurrentProcess);
			if(HiddenProcess != NULL)
			{
				HIDE_INFO HideInfo = { 0 };

				Hider::CreateEntry(HiddenProcess->DebuggerProcess, NewProcess);

				RtlFillBytes(&HideInfo.HookNtQueryInformationProcess, 1, sizeof(HideInfo) - 4);
				HideInfo.Pid = HandleToUlong(PsGetProcessId(NewProcess));

				Hider::Hide(&HideInfo);
			}

			ObDereferenceObject(NewProcess);
		}
	}


	return Status;
}

NTSTATUS(NTAPI* OriginalNtYieldExecution)();
NTSTATUS NTAPI HookedNtYieldExecution() 
{
	if(Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_YIELD_EXECUTION) == TRUE)
	{
		OriginalNtYieldExecution();
		return STATUS_SUCCESS;
	}

	return OriginalNtYieldExecution();
}

NTSTATUS(NTAPI* OriginalNtQuerySystemTime)(PLARGE_INTEGER SystemTime);
NTSTATUS NTAPI HookedNtQuerySystemTime(PLARGE_INTEGER SystemTime) 
{
	PEPROCESS Current = IoGetCurrentProcess();

	if(Hider::IsHidden(Current,HIDE_NT_QUERY_SYSTEM_TIME) == TRUE &&
		ExGetPreviousMode() == UserMode)
	{
		__try
		{
			ProbeForWrite(SystemTime, sizeof(ULONG64), 4);

			Hider::PHIDDEN_PROCESS HiddenProcess = Hider::QueryHiddenProcess(Current);
			if (HiddenProcess != NULL)
			{
				if (Hider::IsHidden(Current, HIDE_KUSER_SHARED_DATA) == TRUE)
					SystemTime->QuadPart = *(ULONG64*)&HiddenProcess->Kusd.KuserSharedData->SystemTime;

				else
				{
					if (HiddenProcess->FakeSystemTime.QuadPart == NULL)
						KeQuerySystemTime(&HiddenProcess->FakeSystemTime);

					SystemTime->QuadPart = HiddenProcess->FakeSystemTime.QuadPart;
					HiddenProcess->FakeSystemTime.QuadPart += 1;
				}

				return STATUS_SUCCESS;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) 
		{
			return GetExceptionCode();
		}
	}

	return OriginalNtQuerySystemTime(SystemTime);
}

NTSTATUS(NTAPI* OriginalNtQueryPerformanceCounter)(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);
NTSTATUS NTAPI HookedNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency) 
{
	PEPROCESS Current = IoGetCurrentProcess();

	if (Hider::IsHidden(Current, HIDE_NT_QUERY_SYSTEM_TIME) == TRUE &&
		ExGetPreviousMode() == UserMode
		)
	{
		__try
		{
			ProbeForWrite(PerformanceCounter, sizeof(ULONG64), 4);
			if (PerformanceFrequency != NULL)
			{
				ProbeForWrite(PerformanceFrequency, sizeof(ULONG64), 4);
			}

			Hider::PHIDDEN_PROCESS HiddenProcess = Hider::QueryHiddenProcess(Current);
			if (HiddenProcess != NULL)
			{
				if (Hider::IsHidden(Current, HIDE_KUSER_SHARED_DATA) == TRUE)
					PerformanceCounter->QuadPart = HiddenProcess->Kusd.KuserSharedData->BaselineSystemTimeQpc;

				else
				{
					if (HiddenProcess->FakePerformanceCounter.QuadPart == NULL)
						HiddenProcess->FakePerformanceCounter = KeQueryPerformanceCounter(NULL);

					PerformanceCounter->QuadPart = HiddenProcess->FakePerformanceCounter.QuadPart;
					HiddenProcess->FakePerformanceCounter.QuadPart += 1;
				}

				if (PerformanceFrequency != NULL)
					PerformanceFrequency->QuadPart = KuserSharedData->QpcFrequency;

				return STATUS_SUCCESS;
			}
		}

		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}

	return OriginalNtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);
}

NTSTATUS(NTAPI* OriginalNtContinue)(PCONTEXT Context, ULONG64 TestAlert);
NTSTATUS NTAPI HookedNtContinue(PCONTEXT Context, ULONG64 TestAlert)
{
	PEPROCESS CurrentProcess = IoGetCurrentProcess();
	if (Hider::IsHidden(CurrentProcess, HIDE_NT_CONTINUE) == TRUE &&
		ExGetPreviousMode() == UserMode)
	{
		__try
		{
			ProbeForRead(Context, 1, 16);

			Hider::PHIDDEN_THREAD HiddenThread = Hider::AppendThreadList(CurrentProcess, (PETHREAD)KeGetCurrentThread());

			if ((Context->Dr0 != __readdr(0) && Context->Dr1 != __readdr(1) &&
				Context->Dr2 != __readdr(2) && Context->Dr3 != __readdr(3) &&
				Context->ContextFlags & 0x10 && HiddenThread != NULL) == TRUE)
			{
				RtlCopyBytes(&HiddenThread->FakeDebugContext.DR0, &Context->Dr0, sizeof(ULONG64) * 6);
				RtlCopyBytes(&HiddenThread->FakeDebugContext.DebugControl, &Context->DebugControl, sizeof(ULONG64) * 5);
			}

			Context->ContextFlags &= ~0x10;

			return OriginalNtContinue(Context, TestAlert);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}

	return OriginalNtContinue(Context, TestAlert);
}

NTSTATUS(NTAPI* OriginalNtQueryInformationJobObject)(HANDLE JobHandle, JOBOBJECTINFOCLASS JobInformationClass, PVOID JobInformation, ULONG JobInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI HookedNtQueryInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobInformationClass, PVOID JobInformation, ULONG JobInformationLength, PULONG ReturnLength) 
{
	NTSTATUS Status = OriginalNtQueryInformationJobObject(JobHandle, JobInformationClass, JobInformation, JobInformationLength, ReturnLength);
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_QUERY_INFORMATION_JOB_OBJECT) == TRUE &&
		JobInformationClass == JobObjectBasicProcessIdList &&
		NT_SUCCESS(Status) == TRUE)
	{
		BACKUP_RETURNLENGTH();

		PJOBOBJECT_BASIC_PROCESS_ID_LIST JobProcessIdList = (PJOBOBJECT_BASIC_PROCESS_ID_LIST)JobInformation;
		for (size_t i = 0; i < JobProcessIdList->NumberOfAssignedProcesses; i++)
		{
			if (Hider::IsDebuggerProcess(PidToProcess(JobProcessIdList->ProcessIdList[i])) == TRUE) 
			{
				if (i == JobProcessIdList->NumberOfAssignedProcesses - 1) 
					JobProcessIdList->ProcessIdList[i] = NULL;

				else
				{
					for (size_t j = i + 1; j < JobProcessIdList->NumberOfAssignedProcesses; j++)
					{
						JobProcessIdList->ProcessIdList[j - 1] = JobProcessIdList->ProcessIdList[j];
						JobProcessIdList->ProcessIdList[j] = 0;
					}
				}

				JobProcessIdList->NumberOfAssignedProcesses--;
				JobProcessIdList->NumberOfProcessIdsInList--;
			}
		}

		RESTORE_RETURNLENGTH();
	}
	return Status;
}

// Win32k Syscalls

HANDLE (NTAPI* OriginalNtUserQueryWindow)(HANDLE hWnd, WINDOWINFOCLASS WindowInfo);
HANDLE NTAPI HookedNtUserQueryWindow(HANDLE hWnd, WINDOWINFOCLASS WindowInfo)
{
	if (Hider::IsHidden(IoGetCurrentProcess(),HIDE_NT_USER_QUERY_WINDOW) == TRUE &&
		(WindowInfo == WindowProcess || WindowInfo == WindowThread)&&
		IsWindowBad(hWnd))
	{
		if (WindowInfo == WindowProcess)
			return PsGetCurrentProcessId();
		
		if (WindowInfo == WindowThread)
			return PsGetCurrentProcessId();
	}
	return OriginalNtUserQueryWindow(hWnd, WindowInfo);
}

NTSTATUS(NTAPI* OriginalNtUserBuildHwndList)(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize);
NTSTATUS NTAPI HookedNtUserBuildHwndList(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize)
{
	NTSTATUS Status = OriginalNtUserBuildHwndList(hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_USER_BUILD_HWND_LIST) == TRUE &&
		NT_SUCCESS(Status) == TRUE &&
		pWnd != NULL &&
		pBufSize != NULL)
	{
		for (size_t i = 0; i < *pBufSize; i++)
		{
			if (pWnd[i] != NULL && IsWindowBad(pWnd[i]) == TRUE)
			{
				if (i == *pBufSize - 1)
				{
					pWnd[i] = NULL;
					*pBufSize -= 1;
					continue;
				}

				for (size_t j = i + 1; j < *pBufSize; j++)
				{
					pWnd[i] = pWnd[j];
				}

				pWnd[*pBufSize - 1] = NULL;
				*pBufSize -= 1;
				continue;
			}
		}
	}

	return Status;
}

NTSTATUS(NTAPI* OriginalNtUserBuildHwndListSeven)(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize);
NTSTATUS NTAPI HookedNtUserBuildHwndListSeven(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize)
{
	NTSTATUS Status = OriginalNtUserBuildHwndListSeven(hDesktop, hwndParent, bChildren, dwThreadId, lParam, pWnd, pBufSize);

	PEPROCESS Current = IoGetCurrentProcess();
	if (Hider::IsHidden(Current, HIDE_NT_USER_BUILD_HWND_LIST) == TRUE &&
		NT_SUCCESS(Status) == TRUE &&
		pWnd != NULL &&
		pBufSize != NULL)
	{
		for (size_t i = 0; i < *pBufSize; i++)
		{
			if (pWnd[i] != NULL && IsWindowBad(pWnd[i]) == TRUE)
			{
				if (i == *pBufSize - 1)
				{
					pWnd[i] = NULL;
					*pBufSize -= 1;
					break;
				}

				for (size_t j = i + 1; j < *pBufSize; j++)
				{
					pWnd[i] = pWnd[j];
				}

				pWnd[*pBufSize - 1] = NULL;
				*pBufSize -= 1;
				break;
			}
		}
	}

	return Status;
}

HANDLE(NTAPI* OriginalNtUserFindWindowEx)(PVOID hwndParent, PVOID hwndChild, PUNICODE_STRING ClassName, PUNICODE_STRING WindowName, ULONG Type);
HANDLE NTAPI HookedNtUserFindWindowEx(PVOID hwndParent, PVOID hwndChild, PUNICODE_STRING ClassName, PUNICODE_STRING WindowName, ULONG Type)
{
	HANDLE hWnd = OriginalNtUserFindWindowEx(hwndParent, hwndChild, ClassName, WindowName, Type);
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_USER_FIND_WINDOW_EX) == TRUE &&
		hWnd != NULL)
	{
		if (Hider::IsProcessWindowBad(WindowName) == TRUE || Hider::IsProcessWindowClassBad(ClassName) == TRUE)
			return 0;
	}

	return hWnd;
}

HANDLE(NTAPI* OriginalNtUserGetForegroundWindow)();
HANDLE NTAPI HookedNtUserGetForegroundWindow() 
{
	HANDLE hWnd = OriginalNtUserGetForegroundWindow();
	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_USER_GET_FOREGROUND_WINDOW) == TRUE &&
		hWnd != NULL && IsWindowBad(hWnd) == TRUE)
	{
		hWnd = NtUserGetThreadState(THREADSTATE_ACTIVEWINDOW);
	}
	
	return hWnd;
}

VOID(NTAPI* OriginalKiDispatchException)(PEXCEPTION_RECORD ExceptionRecord, PKEXCEPTION_FRAME ExceptionFrame, PKTRAP_FRAME TrapFrame, KPROCESSOR_MODE PreviousMode, BOOLEAN FirstChance);
VOID NTAPI HookedKiDispatchException(PEXCEPTION_RECORD ExceptionRecord, PKEXCEPTION_FRAME ExceptionFrame, PKTRAP_FRAME TrapFrame, KPROCESSOR_MODE PreviousMode, BOOLEAN FirstChance)
{
	OriginalKiDispatchException(ExceptionRecord, ExceptionFrame, TrapFrame, PreviousMode, FirstChance);

	PEPROCESS CurrentProcess = IoGetCurrentProcess();
	if (PreviousMode == UserMode && TrapFrame->Rip == KiUserExceptionDispatcherAddress && Hider::IsHidden(CurrentProcess, HIDE_KI_EXCEPTION_DISPATCH) == TRUE)
	{
		PETHREAD CurentThread = (PETHREAD)KeGetCurrentThread();
		Hider::PHIDDEN_THREAD HiddenThread = Hider::AppendThreadList(CurrentProcess, CurentThread);

		PCONTEXT UserModeContext = (PCONTEXT)TrapFrame->Rsp;

		if (HiddenThread != NULL)
		{
			if (PsGetProcessWow64Process(CurrentProcess) == NULL)
			{
				RtlCopyBytes(&UserModeContext->Dr0, &HiddenThread->FakeDebugContext.DR0, sizeof(ULONG64) * 6);
				RtlCopyBytes(&UserModeContext->DebugControl, &HiddenThread->FakeDebugContext.DebugControl, sizeof(ULONG64) * 5);
			}

			else
			{
				UserModeContext->Dr0 = HiddenThread->FakeWow64DebugContext.DR0;
				UserModeContext->Dr1 = HiddenThread->FakeWow64DebugContext.DR1;
				UserModeContext->Dr2 = HiddenThread->FakeWow64DebugContext.DR2;
				UserModeContext->Dr3 = HiddenThread->FakeWow64DebugContext.DR3;
				UserModeContext->Dr6 = HiddenThread->FakeWow64DebugContext.DR6;
				UserModeContext->Dr7 = HiddenThread->FakeWow64DebugContext.DR7;

				RtlSecureZeroMemory(&TrapFrame->DebugControl, sizeof(ULONG64) * 5);
			}
		}
	}
}

BOOLEAN HookNtSyscalls()
{
	KeInitializeMutex(&NtCloseMutex, 0);

	std::array NtSyscallsToHook
	{
		SyscallInfo{0, "NtSetInformationThread", HookedNtSetInformationThread, (void**)&OriginalNtSetInformationThread},
		SyscallInfo{0, "NtQueryInformationProcess", HookedNtQueryInformationProcess, (void**)&OriginalNtQueryInformationProcess},
		SyscallInfo{0, "NtQueryObject", HookedNtQueryObject, (void**)&OriginalNtQueryObject},
		SyscallInfo{0, "NtSystemDebugControl", HookedNtSystemDebugControl, (void**)&OriginalNtSystemDebugControl},
		SyscallInfo{0, "NtSetContextThread", HookedNtSetContextThread, (void**)&OriginalNtSetContextThread},
		SyscallInfo{0, "NtQuerySystemInformation", HookedNtQuerySystemInformation, (void**)&OriginalNtQuerySystemInformation},
		SyscallInfo{0, "NtGetContextThread", HookedNtGetContextThread, (void**)&OriginalNtGetContextThread},
		SyscallInfo{0, "NtClose", HookedNtClose, (void**)&OriginalNtClose},
		SyscallInfo{0, "NtQueryInformationThread", HookedNtQueryInformationThread, (void**)&OriginalNtQueryInformationThread},
		SyscallInfo{0, "NtCreateThreadEx", HookedNtCreateThreadEx, (void**)&OriginalNtCreateThreadEx},
		SyscallInfo{0, "NtCreateFile", HookedNtCreateFile, (void**)&OriginalNtCreateFile},
		SyscallInfo{0, "NtCreateProcessEx", HookedNtCreateProcessEx, (void**)&OriginalNtCreateProcessEx},
		SyscallInfo{0, "NtYieldExecution", HookedNtYieldExecution, (void**)&OriginalNtYieldExecution},
		SyscallInfo{0, "NtQuerySystemTime", HookedNtQuerySystemTime, (void**)&OriginalNtQuerySystemTime},
		SyscallInfo{0, "NtQueryPerformanceCounter", HookedNtQueryPerformanceCounter, (void**)&OriginalNtQueryPerformanceCounter},
		SyscallInfo{0, "NtContinueEx", HookedNtContinue, (void**)&OriginalNtContinue},
		SyscallInfo{0, "NtQueryInformationJobObject", HookedNtQueryInformationJobObject, (void**)&OriginalNtQueryInformationJobObject},
		SyscallInfo{0, "NtCreateUserProcess", HookedNtCreateUserProcess, (void**)&OriginalNtCreateUserProcess},
		SyscallInfo{0, "NtGetNextProcess", HookedNtGetNextProcess,(void**)&OriginalNtGetNextProcess},
		SyscallInfo{0, "NtOpenProcess", HookedNtOpenProcess, (void**)&OriginalNtOpenProcess},
		SyscallInfo{0, "NtOpenThread", HookedNtOpenThread, (void**)&OriginalNtOpenThread},
		SyscallInfo{0, "NtSetInformationProcess", HookedNtSetInformationProcess, (void**)&OriginalNtSetInformationProcess}
	};
	if (g_HyperHide.CurrentWindowsBuildNumber < WINDOWS_10_VERSION_20H1) NtSyscallsToHook[15].SyscallName = "NtContinue";

	if (!GetNtSyscallNumbers(NtSyscallsToHook))
	{
		LogError("Couldn't find all nt syscalls");
		return FALSE;
	}

	for (auto& syscallToHook : NtSyscallsToHook)
	{
		if (!SSDT::HookNtSyscall(syscallToHook.SyscallNumber, syscallToHook.HookFunctionAddress, syscallToHook.OriginalFunctionAddress))
		{
			LogError("%s hook failed", syscallToHook.SyscallName.data());
			return FALSE;
		}
	}

	return TRUE;
}

BOOLEAN HookWin32kSyscalls()
{
	std::array Win32kSyscallsToHook
	{
		SyscallInfo{0UL, "NtUserBuildHwndList", HookedNtUserBuildHwndList, (void**)&OriginalNtUserBuildHwndList},
		SyscallInfo{0UL, "NtUserFindWindowEx", HookedNtUserFindWindowEx, (void**)&OriginalNtUserFindWindowEx},
		SyscallInfo{0UL, "NtUserQueryWindow", HookedNtUserQueryWindow, (void**)&OriginalNtUserQueryWindow},
		SyscallInfo{0UL, "NtUserGetForegroundWindow", HookedNtUserGetForegroundWindow, (void**)&OriginalNtUserGetForegroundWindow},
		SyscallInfo{0UL, "NtUserGetThreadState", nullptr, nullptr},
	};
	if (g_HyperHide.CurrentWindowsBuildNumber <= WINDOWS_7_SP1)
	{
		Win32kSyscallsToHook[0].HookFunctionAddress = HookedNtUserBuildHwndListSeven;
		Win32kSyscallsToHook[0].OriginalFunctionAddress = (void**)&OriginalNtUserBuildHwndListSeven;
	}

	if (!GetWin32kSyscallNumbers(Win32kSyscallsToHook))
	{
		LogError("Couldn't find all win32k syscalls");
		return FALSE;
	}

	NtUserGetThreadState = (decltype(NtUserGetThreadState))SSDT::GetWin32KFunctionAddress("NtUserGetThreadState", Win32kSyscallsToHook[4].SyscallNumber);
	if (!NtUserGetThreadState)
	{
		LogError("Couldn't get NtUserGetThreadState address");
		return FALSE;
	}

	for (auto& syscallToHook : Win32kSyscallsToHook)
	{
		if (!syscallToHook.HookFunctionAddress)
			continue;

		if (!SSDT::HookWin32kSyscall((char*)syscallToHook.SyscallName.data(), syscallToHook.SyscallNumber, syscallToHook.HookFunctionAddress, syscallToHook.OriginalFunctionAddress))
		{
			LogError("%s hook failed", syscallToHook.SyscallName.data());
			return FALSE;
		}
	}

	return TRUE;
}

BOOLEAN GetKiUserExceptionDispatcherAddress()
{
	KiUserExceptionDispatcherAddress = reinterpret_cast<ULONG64>(GetExportedFunctionAddress(GetCsrssProcess(),
		GetUserModeModule(GetCsrssProcess(), L"ntdll.dll", FALSE), "KiUserExceptionDispatcher"));

	if (!KiUserExceptionDispatcherAddress)
	{
		LogError("Couldn't get KiUserExceptionDispatcher address");
		return FALSE;
	}
	LogInfo("KiUserExceptionDispatcher address: 0x%llx", KiUserExceptionDispatcherAddress);

	return TRUE;
}

BOOLEAN HookKiDispatchException()
{
	if (!GetKiUserExceptionDispatcherAddress())
		return FALSE;

	PVOID KernelSectionBase = 0;
	ULONG64 KernelSectionSize = 0;
	const auto Pattern = g_HyperHide.CurrentWindowsBuildNumber >= WINDOWS_11 ? "\x24\x00\x00\x41\xB1\x01\x48\x8D\x4C\x24\x00\xE8" : "\x8B\x00\x50\x00\x8B\x00\x58\x48\x8D\x4D\x00\xE8\x00\x00\x00\xFF\x8B\x55";
	const auto Mask = g_HyperHide.CurrentWindowsBuildNumber >= WINDOWS_11 ? "x??xxxxxxx?x" : "x?x?x?xxxx?x???xxx";
	const auto Section = g_HyperHide.CurrentWindowsBuildNumber >= WINDOWS_11 ? "PAGE" : ".text";

	if (GetSectionData("ntoskrnl.exe", Section, KernelSectionSize, KernelSectionBase) == FALSE)
	{
		LogError("KiDispatchException hook failed");
		return FALSE;
	}

	PVOID KiDispatchExceptionAddress = FindSignature(KernelSectionBase, KernelSectionSize, Pattern, Mask);
	if ((ULONG64)KiDispatchExceptionAddress >= (ULONG64)KernelSectionBase && (ULONG64)KiDispatchExceptionAddress <= (ULONG64)KernelSectionBase + KernelSectionSize)
	{
		KiDispatchExceptionAddress = (PVOID)(*(LONG*)((ULONG64)KiDispatchExceptionAddress + 12) + (LONGLONG)((ULONG64)KiDispatchExceptionAddress + 16));

		LogInfo("KiDispatchException address: 0x%llx", KiDispatchExceptionAddress);

		return hv::hook_function(KiDispatchExceptionAddress, HookedKiDispatchException, (PVOID*)&OriginalKiDispatchException);
	}

	LogError("KiDispatchException hook failed");
	return FALSE;
}

BOOLEAN HookSyscalls()
{
	return HookNtSyscalls() && HookWin32kSyscalls() && HookKiDispatchException();
}