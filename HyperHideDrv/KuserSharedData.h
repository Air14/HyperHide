#pragma once
#include <ntddk.h>
#include "Hider.h"

VOID HookKuserSharedData(Hider::PHIDDEN_PROCESS HiddenProcess);

VOID UnHookKuserSharedData(Hider::PHIDDEN_PROCESS HiddenProcess);

VOID GetBegin(PEPROCESS DebuggedProcess);

VOID UpdateDelta(PEPROCESS DebuggedProcess);

VOID CounterUpdater(PVOID Context);

VOID ClearKuserSharedData(PEPROCESS DebuggedProcess);