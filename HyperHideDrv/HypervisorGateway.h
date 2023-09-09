#pragma once
namespace hv
{
	bool hook_function(void* target_address, void* hook_function, void** origin_function);

	void hypervisor_visible(bool value);

	bool test_vmcall();

	bool unhook_all_functions();

	bool unhook_function(unsigned __int64 function_address);

	bool send_irp_perform_allocation();
}