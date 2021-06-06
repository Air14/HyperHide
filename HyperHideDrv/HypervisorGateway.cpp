#pragma warning( disable : 4201)
#include <ntddk.h>
#include "vmintrin.h"
#include "Ntapi.h"
#include "Log.h"

#define IOCTL_POOL_MANAGER_ALLOCATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

enum __vmcall_reason
{
	VMCALL_TEST,
	VMCALL_VMXOFF,
	VMCALL_EPT_HOOK_FUNCTION,
	VMCALL_EPT_UNHOOK_FUNCTION,
	VMCALL_UNHOOK_ALL_PAGES,
	VMCALL_INVEPT_CONTEXT,
};

enum invept_type
{
	INVEPT_SINGLE_CONTEXT = 1,
	INVEPT_ALL_CONTEXTS = 2
};

namespace hv
{
	PDEVICE_OBJECT AirHvDeviceObject = NULL;

	void broadcast_vmoff(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
	{
		UNREFERENCED_PARAMETER(DeferredContext);
		UNREFERENCED_PARAMETER(Dpc);

		__vm_call(VMCALL_VMXOFF, 0, 0, 0);
		KeSignalCallDpcSynchronize(SystemArgument2);
		KeSignalCallDpcDone(SystemArgument1);
	}

	void broadcast_invept_all_contexts(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
	{
		UNREFERENCED_PARAMETER(DeferredContext);
		UNREFERENCED_PARAMETER(Dpc); 
		
		__vm_call(VMCALL_INVEPT_CONTEXT, true, 0, 0);
		KeSignalCallDpcSynchronize(SystemArgument2);
		KeSignalCallDpcDone(SystemArgument1);
	}

	void broadcast_invept_single_context(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
	{
		UNREFERENCED_PARAMETER(DeferredContext);
		UNREFERENCED_PARAMETER(Dpc); 
		
		__vm_call(VMCALL_INVEPT_CONTEXT, false, 0, 0);
		KeSignalCallDpcSynchronize(SystemArgument2);
		KeSignalCallDpcDone(SystemArgument1);
	}

	/// <summary>
	/// Turn off virtual machine
	/// </summary>
	void vmoff()
	{
		KeGenericCallDpc(broadcast_vmoff, NULL);
	}

	/// <summary>
	/// Unhook all pages
	/// </summary>
	/// <returns> status </returns>
	bool unhook_all_functions()
	{
		return __vm_call(VMCALL_EPT_UNHOOK_FUNCTION, true, 0, 0);
	}

	/// <summary>
	/// Unhook single page
	/// </summary>
	/// <param name="page_physcial_address"></param>
	/// <returns> status </returns>
	bool unhook_function(unsigned __int64 function_address)
	{
		return __vm_call(VMCALL_EPT_UNHOOK_FUNCTION, false, function_address, 0);
	}

	/// <summary>
	/// invalidate ept entries in tlb
	/// </summary>
	/// <param name="invept_all"> If true invalidates all contexts otherway invalidate only single context (currently hv doesn't use more than 1 context)</param>
	void invept(bool invept_all)
	{
		if (invept_all == true) KeGenericCallDpc(broadcast_invept_all_contexts, NULL);
		else KeGenericCallDpc(broadcast_invept_single_context, NULL);
	}

	/// <summary>
	/// Hook function via ept and invalidate ept entries in tlb
	/// </summary>
	/// <param name="target_address">Address of function which we want to hook</param>
	/// <param name="hook_function">Address of function which is used to call original function</param>
	/// <param name="trampoline_address">Address of some memory which isn't used with size at least 13 and withing 2GB range of target function
	/// Use only if you can function you want to hook use relative offeset in first 13 bytes of it. For example if you want hook NtYieldExecution which
	/// size is 15 bytes you have to find a codecave witihn ntoskrnl.exe image with size atleast 13 bytes and pass it there</param>
	/// <param name="origin_function">Address of function which is used to call original function</param>
	/// <returns> status </returns>
	bool hook_function(void* target_address, void* hook_function, void* trampoline_address, void** origin_function)
	{
		bool status = __vm_call_ex(VMCALL_EPT_HOOK_FUNCTION, (unsigned __int64)target_address, (unsigned __int64)hook_function, (unsigned __int64)trampoline_address, (unsigned __int64)origin_function, 0, 0, 0, 0, 0);
		invept(false);

		return status;
	}


	/// <summary>
	/// Hook function via ept and invalidate ept entries in tlb
	/// </summary>
	/// <param name="target_address">Address of function which we want to hook</param>
	/// <param name="hook_function">Address of function which is used to call original function</param>
	/// <param name="origin_function">Address of function which is used to call original function</param>
	/// <returns> status </returns>
	bool hook_function(void* target_address, void* hook_function, void** origin_function)
	{
		bool status = __vm_call_ex(VMCALL_EPT_HOOK_FUNCTION, (unsigned __int64)target_address, (unsigned __int64)hook_function, 0, (unsigned __int64)origin_function, 0, 0, 0, 0, 0);
		invept(false);

		return status;
	}

	/// <summary>
	/// Check if we can communicate with hypervisor
	/// </summary>
	/// <returns> status </returns>
	bool test_vmcall()
	{
		return __vm_call(VMCALL_TEST, 0, 0, 0);
	}

	BOOLEAN PerformAllocation() 
	{
		NTSTATUS Status;
		KEVENT Event;
		PIRP Irp;
		IO_STATUS_BLOCK ioStatus = { 0 };

		if (AirHvDeviceObject == NULL) 
		{
			UNICODE_STRING AirHvName;
			PFILE_OBJECT FileObject;
			RtlInitUnicodeString(&AirHvName, L"\\Device\\airhv");

			Status = IoGetDeviceObjectPointer(&AirHvName, NULL, &FileObject, &AirHvDeviceObject);

			if (NT_SUCCESS(Status) == FALSE) 
			{
				LogError("Couldn't get hypervisor device object pointer");
				return FALSE;
			}
		}

		KeInitializeEvent(&Event, NotificationEvent, FALSE);
		__try
		{
			Irp = IoBuildDeviceIoControlRequest(IOCTL_POOL_MANAGER_ALLOCATE, AirHvDeviceObject, NULL, NULL, NULL, NULL, FALSE, &Event, &ioStatus);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) 
		{
			ASSERT(FALSE);
			return FALSE;
		}


		if (Irp == NULL)
		{
			LogError("Couldn't create Irp");
			return FALSE;
		}

		else
		{
			Status = IofCallDriver(AirHvDeviceObject, Irp);

			if (Status == STATUS_PENDING)
			{
				KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
				Status = ioStatus.Status;
			}

			return TRUE;
		}
	}

	VOID CloseHandle() 
	{
		ObDereferenceObject(AirHvDeviceObject);
	}
}