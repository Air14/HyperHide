#pragma warning( disable : 4201)
#include <ntddk.h>
#include <ntifs.h>
#include "Log.h"
#include "Utils.h"
#include "HookedFunctions.h"
#include "GlobalData.h"
#include "HypervisorGateway.h"
#include "Dispatcher.h"
#include "Notifiers.h"
#include "Ssdt.h"
#include "Ntapi.h"
#include <intrin.h>

HYPER_HIDE_GLOBAL_DATA g_HyperHide = { 0 };

VOID DrvUnload(PDRIVER_OBJECT  DriverObject)
{
	Hider::Uninitialize();

	LARGE_INTEGER WaitTime;
	WaitTime.QuadPart = -1000000LL; // 100ms
	KeDelayExecutionThread(KernelMode, FALSE, &WaitTime);

	PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
	PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);

	hv::unhook_all_functions();

	KeDelayExecutionThread(KernelMode, FALSE, &WaitTime);

	UNICODE_STRING DosDeviceName;
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\HyperHideDrv");
	IoDeleteSymbolicLink(&DosDeviceName);

	IoDeleteDevice(DriverObject->DeviceObject);

	LogInfo("Driver Unloaded");
}

NTSTATUS DrvClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;

	if (Hider::RemoveEntry(IoGetCurrentProcess()) == FALSE) 
		Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;

	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return STATUS_SUCCESS;
}

NTSTATUS DrvCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PCUNICODE_STRING Reg)
{
	UNREFERENCED_PARAMETER(Reg);

	PDEVICE_OBJECT DeviceObject;
	UNICODE_STRING DriverName, DosDeviceName;
	OSVERSIONINFOW OsVersion;

	RtlGetVersion(&OsVersion);
	g_HyperHide.CurrentWindowsBuildNumber = OsVersion.dwBuildNumber;

	__try
	{
		if (hv::test_vmcall() == FALSE)
			return STATUS_UNSUCCESSFUL;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) 
	{
		return STATUS_UNSUCCESSFUL;
	}
	 
	LogInfo("HyperVisor On");

	if (GetOffsets() == FALSE)
		return STATUS_UNSUCCESSFUL;

	LogInfo("Got offsets");

	if (SSDT::FindCodeCaves() == FALSE) 
		return STATUS_UNSUCCESSFUL;

	LogInfo("Got code caves");

	if (SSDT::GetSsdt() == FALSE)
		return STATUS_UNSUCCESSFUL;

	LogInfo("Got Ssdt");

	if (Hider::Initialize() == FALSE) 
		return STATUS_UNSUCCESSFUL;

	LogInfo("Hider Initialized");

	if(NT_SUCCESS(PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine)) == FALSE)
	{
		Hider::Uninitialize();
		return STATUS_UNSUCCESSFUL;
	}

	LogInfo("PsSetCreateThreadNotifyRoutine succeded");

	if (NT_SUCCESS(PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, FALSE)) == FALSE)
	{
		Hider::Uninitialize();
		PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
		return STATUS_UNSUCCESSFUL;
	}

	LogInfo("PsSetCreateProcessNotifyRoutine succeded");

	if(HookSyscalls() == FALSE)
	{
		hv::unhook_all_functions();
		PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
		PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);
		Hider::Uninitialize();
		return STATUS_UNSUCCESSFUL;
	}

	LogInfo("Syscalls Hooked");

	RtlInitUnicodeString(&DriverName, L"\\Device\\HyperHideDrv");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\HyperHideDrv");
	
	IoCreateDevice(Driver, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

	Driver->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
	Driver->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
	Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIOCTLDispatcher;

	Driver->DriverUnload = DrvUnload;
	Driver->Flags |= DO_BUFFERED_IO;

	IoCreateSymbolicLink(&DosDeviceName, &DriverName);
	
	LogInfo("Driver initialized");
	
	return STATUS_SUCCESS;
}