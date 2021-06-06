#pragma once
#include <ntddk.h>
NTSTATUS DrvIOCTLDispatcher(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);