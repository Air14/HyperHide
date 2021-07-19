#pragma warning( disable : 4201)
#include <ntddk.h>
#include "vmintrin.h"
#include "Ntapi.h"
#include "Log.h"

#define IOCTL_POOL_MANAGER_ALLOCATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

enum vm_call_reasons
{
	VMCALL_TEST,
	VMCALL_VMXOFF,
	VMCALL_EPT_HOOK_FUNCTION,
	VMCALL_EPT_UNHOOK_FUNCTION,
	VMCALL_INVEPT_CONTEXT,
	VMCALL_DUMP_POOL_MANAGER,
	VMCALL_DUMP_VMCS_STATE,
	VMCALL_HIDE_HV_PRESENCE,
	VMCALL_UNHIDE_HV_PRESENCE
};

enum invept_type
{
	INVEPT_SINGLE_CONTEXT = 1,
	INVEPT_ALL_CONTEXTS = 2
};

namespace hv
{
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
	/// Set/Unset presence of hypervisor
	/// </summary>
	/// <param name="value"> If false, hypervisor is not visible via cpuid interface, If true, it become visible</param>
	void hypervisor_visible(bool value)
	{
		if (value == true)
			__vm_call(VMCALL_UNHIDE_HV_PRESENCE, 0, 0, 0);
		else
			__vm_call(VMCALL_HIDE_HV_PRESENCE, 0, 0, 0);
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

	bool send_irp_perform_allocation()
	{
		PDEVICE_OBJECT airhv_device_object;
		NTSTATUS status;
		KEVENT event;
		PIRP irp;
		IO_STATUS_BLOCK io_status = { 0 };
		UNICODE_STRING airhv_name;
		PFILE_OBJECT file_object;

		RtlInitUnicodeString(&airhv_name, L"\\Device\\airhv");

		status = IoGetDeviceObjectPointer(&airhv_name, 0, &file_object, &airhv_device_object);

		ObReferenceObjectByPointer(airhv_device_object, FILE_ALL_ACCESS, 0, KernelMode);

		// We don't need this so we instantly dereference file object
		ObDereferenceObject(file_object);

		if (NT_SUCCESS(status) == false)
		{
			LogError("Couldn't get hypervisor device object pointer");
			return false;
		}

		KeInitializeEvent(&event, NotificationEvent, 0);
		irp = IoBuildDeviceIoControlRequest(IOCTL_POOL_MANAGER_ALLOCATE, airhv_device_object, 0, 0, 0, 0, 0, &event, &io_status);

		if (irp == NULL)
		{
			LogError("Couldn't create Irp");
			ObDereferenceObject(airhv_device_object);
			return false;
		}

		else
		{
			status = IofCallDriver(airhv_device_object, irp);

			if (status == STATUS_PENDING)
				KeWaitForSingleObject(&event, Executive, KernelMode, 0, 0);

			ObDereferenceObject(airhv_device_object);
			return true;
		}
	}
}