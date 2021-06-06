#pragma once
extern "C"
{
	bool __vm_call(unsigned __int64 vmcall_reason, unsigned __int64 rdx, unsigned __int64 r8, unsigned __int64 r9);
	bool __vm_call_ex(unsigned __int64 vmcall_reason, unsigned __int64 rdx, unsigned __int64 r8, unsigned __int64 r9, unsigned __int64 r10, unsigned __int64 r11, unsigned __int64 r12, unsigned __int64 r13, unsigned __int64 r14, unsigned __int64 r15);
	BOOLEAN __invept(unsigned __int32 Type, void* Descriptors);
}