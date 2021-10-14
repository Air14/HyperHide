#pragma warning( disable : 4201)
#include <ntddk.h>
#include <ntifs.h>
#include "Utils.h"
#include "Hider.h"
#include "GlobalData.h"
#include "Log.h"
#include "KuserSharedData.h"

PKUSER_SHARED_DATA KernelKuserSharedData = (PKUSER_SHARED_DATA)(KUSER_SHARED_DATA_KERNELMODE);

PMMPFN MmPfnDatabase = 0;

BOOLEAN GetPfnDatabase() 
{
	ULONG64 TextSize;
	PVOID TextBase;	

	if (GetSectionData("ntoskrnl.exe", ".text", TextSize, TextBase) == FALSE)
		return FALSE;

	CONST CHAR* Pattern = "\x48\x8B\x05\x00\x00\x00\x00\x48\x89\x43\x18\x48\x8D\x05";
	CONST CHAR* Mask = "xxx????xxxxxxx";

	ULONG64 MmPfnDatabaseOffsetAddress = (ULONG64)FindSignature(TextBase, TextSize, Pattern, Mask);
	if (MmPfnDatabaseOffsetAddress >= (ULONG64)TextBase && MmPfnDatabaseOffsetAddress <= (ULONG64)TextBase + TextSize)
	{
		MmPfnDatabase = (PMMPFN)*(ULONG64*)((MmPfnDatabaseOffsetAddress + 7) + *(LONG*)(MmPfnDatabaseOffsetAddress + 3));
		LogInfo("MmPfnDataBase address 0x%llx", MmPfnDatabase);
		return TRUE;
	}

	LogError("Couldn't get PfnDatabase address");
	return FALSE;
}
VOID HookKuserSharedData(Hider::PHIDDEN_PROCESS HiddenProcess)
{
	KAPC_STATE State;
	PHYSICAL_ADDRESS PhysicalMax;
	PhysicalMax.QuadPart = ~0ULL;

	PVOID NewKuserSharedData = MmAllocateContiguousMemory(PAGE_SIZE, PhysicalMax);

	ULONG64 PfnNewKuserSharedData = MmGetPhysicalAddress(NewKuserSharedData).QuadPart >> PAGE_SHIFT;

	KeStackAttachProcess((PRKPROCESS)HiddenProcess->DebuggedProcess, &State);

	PMMPFN FakeKUSDMmpfn = (PMMPFN)(MmPfnDatabase + PfnNewKuserSharedData);

	FakeKUSDMmpfn->u4.EntireField |= 0x200000000000000;

	RtlCopyMemory(NewKuserSharedData, (PVOID)KUSER_SHARED_DATA_USERMODE, PAGE_SIZE);

	HiddenProcess->Kusd.PteKuserSharedData = (PTE*)GetPteAddress(KUSER_SHARED_DATA_USERMODE);

	HiddenProcess->Kusd.OriginalKuserSharedDataPfn = HiddenProcess->Kusd.PteKuserSharedData->Fields.PhysicalAddress;
	HiddenProcess->Kusd.PteKuserSharedData->Fields.PhysicalAddress = PfnNewKuserSharedData;
	HiddenProcess->Kusd.KuserSharedData = (PKUSER_SHARED_DATA)NewKuserSharedData;

	KeUnstackDetachProcess(&State);
}

VOID UnHookKuserSharedData(Hider::PHIDDEN_PROCESS HiddenProcess)
{
	KAPC_STATE State;
	HiddenProcess->HideTypes[HIDE_KUSER_SHARED_DATA] = FALSE;

	KeStackAttachProcess((PRKPROCESS)HiddenProcess->DebuggedProcess, &State);

	PMMPFN FakeKUSDMmpfn = (PMMPFN)(MmPfnDatabase + HiddenProcess->Kusd.PteKuserSharedData->Fields.PhysicalAddress);
	FakeKUSDMmpfn->u4.EntireField &= ~0x200000000000000;

	MmFreeContiguousMemory(HiddenProcess->Kusd.KuserSharedData);

	HiddenProcess->Kusd.KuserSharedData = NULL;
	HiddenProcess->Kusd.PteKuserSharedData->Fields.PhysicalAddress = HiddenProcess->Kusd.OriginalKuserSharedDataPfn;
	KeUnstackDetachProcess(&State);
}

VOID CounterUpdater(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);

	LARGE_INTEGER TimeToWait = { 0 };
	TimeToWait.QuadPart = -10000LL; // relative 1ms

	while (Hider::StopCounterThread == FALSE)
	{
		KeDelayExecutionThread(KernelMode, FALSE, &TimeToWait);

		KeAcquireGuardedMutex(&Hider::HiderMutex);
		PLIST_ENTRY current = Hider::HiddenProcessesHead.Flink;
		while (current != &Hider::HiddenProcessesHead)
		{
			Hider::PHIDDEN_PROCESS HiddenProcess = (Hider::PHIDDEN_PROCESS)CONTAINING_RECORD(current, Hider::HIDDEN_PROCESS, HiddenProcessesList);
			current = current->Flink;

			if (HiddenProcess->DebuggedProcess != NULL &&
				HiddenProcess->ProcessPaused == FALSE &&
				HiddenProcess->Kusd.KuserSharedData != NULL &&
				HiddenProcess->HideTypes[HIDE_KUSER_SHARED_DATA] == TRUE)
			{

				*(ULONG64*)&HiddenProcess->Kusd.KuserSharedData->InterruptTime = *(ULONG64*)&KernelKuserSharedData->InterruptTime.LowPart - HiddenProcess->Kusd.DeltaInterruptTime;
				HiddenProcess->Kusd.KuserSharedData->InterruptTime.High2Time = HiddenProcess->Kusd.KuserSharedData->InterruptTime.High1Time;

				*(ULONG64*)&HiddenProcess->Kusd.KuserSharedData->SystemTime = *(ULONG64*)&KernelKuserSharedData->SystemTime.LowPart - HiddenProcess->Kusd.DeltaSystemTime;
				HiddenProcess->Kusd.KuserSharedData->SystemTime.High2Time = HiddenProcess->Kusd.KuserSharedData->SystemTime.High1Time;

				HiddenProcess->Kusd.KuserSharedData->LastSystemRITEventTickCount = KernelKuserSharedData->LastSystemRITEventTickCount - HiddenProcess->Kusd.DeltaLastSystemRITEventTickCount;

				*(ULONG64*)&HiddenProcess->Kusd.KuserSharedData->TickCount = *(ULONG64*)&KernelKuserSharedData->TickCount.LowPart - HiddenProcess->Kusd.DeltaTickCount;
				HiddenProcess->Kusd.KuserSharedData->TickCount.High2Time = HiddenProcess->Kusd.KuserSharedData->TickCount.High1Time;

				HiddenProcess->Kusd.KuserSharedData->TimeUpdateLock = KernelKuserSharedData->TimeUpdateLock - HiddenProcess->Kusd.DeltaTimeUpdateLock;

				HiddenProcess->Kusd.KuserSharedData->BaselineSystemTimeQpc = KernelKuserSharedData->BaselineSystemTimeQpc - HiddenProcess->Kusd.DeltaBaselineSystemQpc;
				HiddenProcess->Kusd.KuserSharedData->BaselineInterruptTimeQpc = HiddenProcess->Kusd.KuserSharedData->BaselineSystemTimeQpc;
			}
		}
		KeReleaseGuardedMutex(&Hider::HiderMutex);
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID GetBegin(PEPROCESS DebuggedProcess)
{
	KeAcquireGuardedMutex(&Hider::HiderMutex);

	PLIST_ENTRY current = Hider::HiddenProcessesHead.Flink;
	while (current != &Hider::HiddenProcessesHead)
	{
		Hider::PHIDDEN_PROCESS HiddenProcess = (Hider::PHIDDEN_PROCESS)CONTAINING_RECORD(current, Hider::HIDDEN_PROCESS, HiddenProcessesList);
		current = current->Flink;

		if (DebuggedProcess == HiddenProcess->DebuggedProcess &&
			HiddenProcess->Kusd.BeginInterruptTime == NULL)
		{
			HiddenProcess->Kusd.BeginInterruptTime = *(ULONG64*)&KernelKuserSharedData->InterruptTime;
			HiddenProcess->Kusd.BeginSystemTime = *(ULONG64*)&KernelKuserSharedData->SystemTime;
			HiddenProcess->Kusd.BeginLastSystemRITEventTickCount = KernelKuserSharedData->LastSystemRITEventTickCount;
			HiddenProcess->Kusd.BeginTickCount = *(ULONG64*)&KernelKuserSharedData->TickCount;
			HiddenProcess->Kusd.BeginTimeUpdateLock = KernelKuserSharedData->TimeUpdateLock;
			HiddenProcess->Kusd.BeginBaselineSystemQpc = KernelKuserSharedData->BaselineSystemTimeQpc;
			break;
		}
	}

	KeReleaseGuardedMutex(&Hider::HiderMutex);
}

VOID UpdateDelta(PEPROCESS DebuggedProcess)
{
	KeAcquireGuardedMutex(&Hider::HiderMutex);
	PLIST_ENTRY current = Hider::HiddenProcessesHead.Flink;
	while (current != &Hider::HiddenProcessesHead)
	{
		Hider::PHIDDEN_PROCESS HiddenProcess = (Hider::PHIDDEN_PROCESS)CONTAINING_RECORD(current, Hider::HIDDEN_PROCESS, HiddenProcessesList);
		current = current->Flink;

		if (DebuggedProcess == HiddenProcess->DebuggedProcess &&
			HiddenProcess->Kusd.BeginInterruptTime != NULL)
		{
			HiddenProcess->Kusd.DeltaInterruptTime += *(ULONG64*)&KernelKuserSharedData->InterruptTime - HiddenProcess->Kusd.BeginInterruptTime;
			HiddenProcess->Kusd.DeltaSystemTime += *(ULONG64*)&KernelKuserSharedData->SystemTime - HiddenProcess->Kusd.BeginSystemTime;
			HiddenProcess->Kusd.DeltaLastSystemRITEventTickCount += KernelKuserSharedData->LastSystemRITEventTickCount - HiddenProcess->Kusd.BeginLastSystemRITEventTickCount;
			HiddenProcess->Kusd.DeltaTickCount += *(ULONG64*)&KernelKuserSharedData->TickCount - HiddenProcess->Kusd.BeginTickCount;
			HiddenProcess->Kusd.DeltaTimeUpdateLock += KernelKuserSharedData->TimeUpdateLock - HiddenProcess->Kusd.BeginTimeUpdateLock;
			HiddenProcess->Kusd.DeltaBaselineSystemQpc += KernelKuserSharedData->BaselineSystemTimeQpc - HiddenProcess->Kusd.BeginBaselineSystemQpc;

			RtlZeroMemory(&HiddenProcess->Kusd.BeginInterruptTime, sizeof(ULONG64) * 5 + 4);

			break;
		}
	}
	KeReleaseGuardedMutex(&Hider::HiderMutex);
}
