#pragma once
#include <ntddk.h>
#include "Hider.h"

typedef struct _MMPFN
{
	union
	{
		LIST_ENTRY ListEntry;                                       //0x0
		RTL_BALANCED_NODE TreeNode;                                 //0x0
		struct
		{
			union
			{
				SINGLE_LIST_ENTRY NextSlistPfn;                     //0x0
				VOID* Next;                                                 //0x0
				ULONGLONG Flink : 36;                                         //0x0
				ULONGLONG NodeFlinkHigh : 28;                                 //0x0
				ULONGLONG Active;                               //0x0
			} u1;                                                           //0x0
			union
			{
				ULONGLONG* PteAddress;                                  //0x8
				ULONGLONG PteLong;                                          //0x8
			};
			ULONGLONG OriginalPte;                                      //0x10
		};
	};
	ULONGLONG u2;                                                  //0x18
	union
	{
		struct
		{
			USHORT ReferenceCount;                                          //0x20
			UCHAR e1;                                         //0x22
		};
		struct
		{
			UCHAR e3;                                         //0x23
			struct
			{
				USHORT ReferenceCount;                                          //0x20
			} e2;                                                               //0x20
		};
		struct
		{
			ULONG EntireField;                                              //0x20
		} e4;                                                               //0x20
	} u3;                                                                   //0x20
	USHORT NodeBlinkLow;                                                    //0x24
	UCHAR Unused : 4;                                                         //0x26
	UCHAR Unused2 : 4;                                                        //0x26
	union
	{
		UCHAR ViewCount;                                                    //0x27
		UCHAR NodeFlinkLow;                                                 //0x27
	};
	union
	{
		ULONGLONG PteFrame : 36;                                              //0x28
		ULONGLONG Channel : 2;                                                //0x28
		ULONGLONG Unused1 : 1;                                                //0x28
		ULONGLONG Unused2 : 1;                                                //0x28
		ULONGLONG Partition : 10;                                             //0x28
		ULONGLONG Spare : 2;                                                  //0x28
		ULONGLONG FileOnly : 1;                                               //0x28
		ULONGLONG PfnExists : 1;                                              //0x28
		ULONGLONG PageIdentity : 3;                                           //0x28
		ULONGLONG PrototypePte : 1;                                           //0x28
		ULONGLONG PageColor : 6;                                              //0x28
		ULONGLONG EntireField;                                              //0x28
	} u4;                                                                   //0x28
}MMPFN,*PMMPFN;

VOID HookKuserSharedData(Hider::PHIDDEN_PROCESS HiddenProcess);

VOID UnHookKuserSharedData(Hider::PHIDDEN_PROCESS HiddenProcess);

VOID GetBegin(PEPROCESS DebuggedProcess);

VOID UpdateDelta(PEPROCESS DebuggedProcess);

VOID CounterUpdater(PVOID Context);

BOOLEAN GetPfnDatabase();