#pragma once
#include <ntddk.h>
namespace hv
{
	extern PDEVICE_OBJECT AirHvDeviceObject;

	bool hook_function(void* target_address, void* hook_function, void* trampoline, void** origin_function);

	bool hook_function(void* target_address, void* hook_function, void** origin_function);

	bool test_vmcall();

	bool unhook_all_functions();

	bool unhook_function(unsigned __int64 function_address);

	BOOLEAN PerformAllocation();
}