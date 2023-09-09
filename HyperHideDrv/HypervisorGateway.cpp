#pragma warning( disable : 4201)
#include <ntifs.h>
#include <intrin.h>
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
	void broadcast_vmoff(KDPC*, PVOID, PVOID SystemArgument1, PVOID SystemArgument2)
	{
		__vm_call(VMCALL_VMXOFF, 0, 0, 0);
		KeSignalCallDpcSynchronize(SystemArgument2);
		KeSignalCallDpcDone(SystemArgument1);
	}

	struct HookFunctionArgs
	{
		void* target_address;
		void* hook_function;
		void** origin_function;
		unsigned __int64 current_cr3;
		volatile SHORT statuses;
	};
	void broadcast_hook_function(KDPC*, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
	{
		const auto args = reinterpret_cast<HookFunctionArgs*>(DeferredContext);

		if (__vm_call_ex(VMCALL_EPT_HOOK_FUNCTION, (unsigned __int64)args->target_address,
			(unsigned __int64)args->hook_function, (unsigned __int64)args->origin_function, args->current_cr3, 0, 0, 0, 0, 0))
		{
			InterlockedIncrement16(&args->statuses);
		}

		KeSignalCallDpcSynchronize(SystemArgument2);
		KeSignalCallDpcDone(SystemArgument1);
	}

	struct UnHookFunctionArgs
	{
		bool unhook_all_functions;
		void* function_to_unhook;
		unsigned __int64 current_cr3;
		volatile SHORT statuses;
	};
	void broadcast_unhook_function(KDPC*, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
	{
		const auto args = reinterpret_cast<UnHookFunctionArgs*>(DeferredContext);

		if (__vm_call(VMCALL_EPT_UNHOOK_FUNCTION, args->unhook_all_functions,
			(unsigned __int64)args->function_to_unhook, args->current_cr3))
		{
			InterlockedIncrement16(&args->statuses);
		}

		KeSignalCallDpcSynchronize(SystemArgument2);
		KeSignalCallDpcDone(SystemArgument1);
	}

	void broadcast_test_vmcall(KDPC*, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
	{
		const auto statuses = reinterpret_cast<volatile SHORT*>(DeferredContext);

		if (__vm_call(VMCALL_TEST, 0, 0, 0))
		{
			InterlockedIncrement16(statuses);
		}

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
	/// Unhook all functions and invalidate tlb
	/// </summary>
	/// <returns> status </returns>
	bool unhook_all_functions()
	{
		UnHookFunctionArgs args{ true, nullptr, __readcr3(), 0 };
		KeGenericCallDpc(broadcast_unhook_function, &args);

		return static_cast<ULONG>(args.statuses) == KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	}

	/// <summary>
	/// Unhook single function and invalidate tlb
	/// </summary>
	/// <param name="function_address"></param>
	/// <returns> status </returns>
	bool unhook_function(void* function_address)
	{
		UnHookFunctionArgs args{ false, function_address, __readcr3(), 0 };
		KeGenericCallDpc(broadcast_unhook_function, &args);

		return static_cast<ULONG>(args.statuses) == KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	}

	/// <summary>
	/// Hook function via ept and invalidates mappings
	/// </summary>
	/// <param name="target_address">Address of function which we want to hook</param>
	/// <param name="hook_function">Address of function which is used to call original function</param>
	/// <param name="origin_function">Address of function which is used to call original function</param>
	/// <returns> status </returns>
	bool hook_function(void* target_address, void* hook_function, void** origin_function)
	{
		HookFunctionArgs args{ target_address, hook_function, origin_function, __readcr3(), 0 };
		KeGenericCallDpc(broadcast_hook_function, &args);

		return static_cast<ULONG>(args.statuses) == KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	}

	/// <summary>
	/// Dump info about allocated pools (Use Dbgview to see information)
	/// </summary>
	void dump_pool_manager()
	{
		__vm_call(VMCALL_DUMP_POOL_MANAGER, 0, 0, 0);
	}

	/// <summary>
	/// Check if we can communicate with hypervisor
	/// </summary>
	/// <returns> status </returns>
	bool test_vmcall()
	{
		volatile SHORT statuses{};
		KeGenericCallDpc(broadcast_test_vmcall, (PVOID)&statuses);

		return static_cast<ULONG>(statuses) == KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	}

	/// <summary>
	/// Send irp with information to allocate memory
	/// </summary>
	/// <returns> status </returns>
	bool send_irp_perform_allocation()
	{
		PDEVICE_OBJECT airhv_device_object;
		KEVENT event;
		PIRP irp;
		IO_STATUS_BLOCK io_status = { 0 };
		UNICODE_STRING airhv_name;
		PFILE_OBJECT file_object;

		RtlInitUnicodeString(&airhv_name, L"\\Device\\airhv");

		NTSTATUS status = IoGetDeviceObjectPointer(&airhv_name, 0, &file_object, &airhv_device_object);

		ObReferenceObjectByPointer(airhv_device_object, FILE_ALL_ACCESS, NULL, KernelMode);

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