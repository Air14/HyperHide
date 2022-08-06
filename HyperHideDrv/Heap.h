#pragma once
#include <ntifs.h>

typedef struct _HEAP_UNPACKED_ENTRY
{
    VOID* PreviousBlockPrivateData;                                         //0x0
    union
    {
        struct
        {
            USHORT Size;                                                    //0x8
            UCHAR Flags;                                                    //0xa
            UCHAR SmallTagIndex;                                            //0xb
        }set1;
        struct
        {
            ULONG SubSegmentCode;                                           //0x8
            USHORT PreviousSize;                                            //0xc
            union
            {
                UCHAR SegmentOffset;                                        //0xe
                UCHAR LFHFlags;                                             //0xe
            };
            UCHAR UnusedBytes;                                              //0xf
        }set2;
        ULONGLONG CompactHeader;                                            //0x8
    };
}HEAP_UNPACKED_ENTRY, * PHEAP_UNPACKED_ENTRY;

typedef struct _HEAP_EXTENDED_ENTRY
{
    VOID* Reserved;                                                         //0x0
    union
    {
        struct
        {
            USHORT FunctionIndex;                                           //0x8
            USHORT ContextValue;                                            //0xa
        };
        ULONG InterceptorValue;                                             //0x8
    };
    USHORT UnusedBytesLength;                                               //0xc
    UCHAR EntryOffset;                                                      //0xe
    UCHAR ExtendedBlockSignature;                                           //0xf
}HEAP_EXTENDED_ENTRY, * PHEAP_EXTENDED_ENTRY;

typedef struct _HEAP_ENTRY
{
    union
    {
        HEAP_UNPACKED_ENTRY UnpackedEntry;                          //0x0
        struct
        {
            VOID* PreviousBlockPrivateData;                                 //0x0
            union
            {
                struct
                {
                    USHORT Size;                                            //0x8
                    UCHAR Flags;                                            //0xa
                    UCHAR SmallTagIndex;                                    //0xb
                };
                struct
                {
                    ULONG SubSegmentCode;                                   //0x8
                    USHORT PreviousSize;                                    //0xc
                    union
                    {
                        UCHAR SegmentOffset;                                //0xe
                        UCHAR LFHFlags;                                     //0xe
                    };
                    UCHAR UnusedBytes;                                      //0xf
                };
                ULONGLONG CompactHeader;                                    //0x8
            };
        };
        HEAP_EXTENDED_ENTRY ExtendedEntry;                          //0x0
        struct
        {
            VOID* Reserved;                                                 //0x0
            union
            {
                struct
                {
                    USHORT FunctionIndex;                                   //0x8
                    USHORT ContextValue;                                    //0xa
                };
                ULONG InterceptorValue;                                     //0x8
            };
            USHORT UnusedBytesLength;                                       //0xc
            UCHAR EntryOffset;                                              //0xe
            UCHAR ExtendedBlockSignature;                                   //0xf
        };
        struct
        {
            VOID* ReservedForAlignment;                                     //0x0
            union
            {
                struct
                {
                    ULONG Code1;                                            //0x8
                    union
                    {
                        struct
                        {
                            USHORT Code2;                                   //0xc
                            UCHAR Code3;                                    //0xe
                            UCHAR Code4;                                    //0xf
                        };
                        ULONG Code234;                                      //0xc
                    };
                };
                ULONGLONG AgregateCode;                                     //0x8
            };
        };
    };
}HEAP_ENTRY, * PHEAP_ENTRY;

typedef struct _HEAP_SEGMENT
{
    HEAP_ENTRY Entry;                                                       //0x0
    ULONG SegmentSignature;                                                 //0x10
    ULONG SegmentFlags;                                                     //0x14
    LIST_ENTRY SegmentListEntry;                                            //0x18
    VOID* Heap;                                                             //0x28
    VOID* BaseAddress;                                                      //0x30
    ULONG NumberOfPages;                                                    //0x38
    HEAP_ENTRY* FirstEntry;                                                 //0x40
    HEAP_ENTRY* LastValidEntry;                                             //0x48
    ULONG NumberOfUnCommittedPages;                                         //0x50
    ULONG NumberOfUnCommittedRanges;                                        //0x54
    USHORT SegmentAllocatorBackTraceIndex;                                  //0x58
    USHORT Reserved;                                                        //0x5a
    LIST_ENTRY UCRSegmentList;                                              //0x60
}HEAP_SEGMENT, * PHEAP_SEGMENT;

typedef struct _HEAP_TAG_ENTRY
{
    ULONG Allocs;                                                           //0x0
    ULONG Frees;                                                            //0x4
    ULONGLONG Size;                                                         //0x8
    USHORT TagIndex;                                                        //0x10
    USHORT CreatorBackTraceIndex;                                           //0x12
    WCHAR TagName[24];                                                      //0x14
}HEAP_TAG_ENTRY, * PHEAP_TAG_ENTRY;

typedef struct _HEAP_PSEUDO_TAG_ENTRY
{
    ULONG Allocs;                                                           //0x0
    ULONG Frees;                                                            //0x4
    ULONGLONG Size;                                                         //0x8
}HEAP_PSEUDO_TAG_ENTRY, * PHEAP_PSEUDO_TAG_ENTRY;

//typedef struct _HEAP_LOCK
//{
//    union
//    {
//        RTL_CRITICAL_SECTION CriticalSection;                       //0x0
//        ERESOURCE Resource;                                         //0x0
//    } Lock;                                                                 //0x0
//}HEAP_LOCK, * PHEAP_LOCK;

//typedef struct _RTL_HEAP_MEMORY_LIMIT_DATA
//{
//    ULONGLONG CommitLimitBytes;                                             //0x0
//    ULONGLONG CommitLimitFailureCode;                                       //0x8
//    ULONGLONG MaxAllocationSizeBytes;                                       //0x10
//    ULONGLONG AllocationLimitFailureCode;                                   //0x18
//}RTL_HEAP_MEMORY_LIMIT_DATA, * PRTL_HEAP_MEMORY_LIMIT_DATA;

typedef struct _HEAP_COUNTERS
{
    ULONGLONG TotalMemoryReserved;                                          //0x0
    ULONGLONG TotalMemoryCommitted;                                         //0x8
    ULONGLONG TotalMemoryLargeUCR;                                          //0x10
    ULONGLONG TotalSizeInVirtualBlocks;                                     //0x18
    ULONG TotalSegments;                                                    //0x20
    ULONG TotalUCRs;                                                        //0x24
    ULONG CommittOps;                                                       //0x28
    ULONG DeCommitOps;                                                      //0x2c
    ULONG LockAcquires;                                                     //0x30
    ULONG LockCollisions;                                                   //0x34
    ULONG CommitRate;                                                       //0x38
    ULONG DecommittRate;                                                    //0x3c
    ULONG CommitFailures;                                                   //0x40
    ULONG InBlockCommitFailures;                                            //0x44
    ULONG PollIntervalCounter;                                              //0x48
    ULONG DecommitsSinceLastCheck;                                          //0x4c
    ULONG HeapPollInterval;                                                 //0x50
    ULONG AllocAndFreeOps;                                                  //0x54
    ULONG AllocationIndicesActive;                                          //0x58
    ULONG InBlockDeccommits;                                                //0x5c
    ULONGLONG InBlockDeccomitSize;                                          //0x60
    ULONGLONG HighWatermarkSize;                                            //0x68
    ULONGLONG LastPolledSize;                                               //0x70
}HEAP_COUNTERS, * PHEAP_COUNTERS;

typedef struct _HEAP_TUNING_PARAMETERS
{
    ULONG CommittThresholdShift;                                            //0x0
    ULONGLONG MaxPreCommittThreshold;                                       //0x8
}HEAP_TUNING_PARAMETERS, * PHEAP_TUNING_PARAMETERS;

typedef struct _HEAP
{
    union
    {
        HEAP_SEGMENT Segment;                                       //0x0
        struct
        {
            HEAP_ENTRY Entry;                                       //0x0
            ULONG SegmentSignature;                                         //0x10 //0x8
            ULONG SegmentFlags;                                             //0x14 //0xC
            LIST_ENTRY SegmentListEntry;                                    //0x18  //0x10
            VOID* Heap;                                                     //0x28  //0x18
            VOID* BaseAddress;                                              //0x30  //0x1c
            ULONG NumberOfPages;                                            //0x38  //0x20
            HEAP_ENTRY* FirstEntry;                                         //0x40  //0x24
            HEAP_ENTRY* LastValidEntry;                                     //0x48  //0x28
            ULONG NumberOfUnCommittedPages;                                 //0x50  //0x2c
            ULONG NumberOfUnCommittedRanges;                                //0x54
            USHORT SegmentAllocatorBackTraceIndex;                          //0x58
            USHORT Reserved;                                                //0x5a
            LIST_ENTRY UCRSegmentList;                                      //0x60
        };
    };
    ULONG Flags;                                                            //0x70
    ULONG ForceFlags;                                                       //0x74
    ULONG CompatibilityFlags;                                               //0x78
    ULONG EncodeFlagMask;                                                   //0x7c
    HEAP_ENTRY Encoding;                                                    //0x80
    ULONG Interceptor;                                                      //0x90
    ULONG VirtualMemoryThreshold;                                           //0x94
    ULONG Signature;                                                        //0x98
    ULONGLONG SegmentReserve;                                               //0xa0
    ULONGLONG SegmentCommit;                                                //0xa8
    ULONGLONG DeCommitFreeBlockThreshold;                                   //0xb0
    ULONGLONG DeCommitTotalFreeThreshold;                                   //0xb8
    ULONGLONG TotalFreeSize;                                                //0xc0
    ULONGLONG MaximumAllocationSize;                                        //0xc8
    USHORT ProcessHeapsListIndex;                                           //0xd0
    USHORT HeaderValidateLength;                                            //0xd2
    VOID* HeaderValidateCopy;                                               //0xd8
    USHORT NextAvailableTagIndex;                                           //0xe0
    USHORT MaximumTagIndex;                                                 //0xe2
    PHEAP_TAG_ENTRY TagEntries;                                     //0xe8
    LIST_ENTRY UCRList;                                             //0xf0
    ULONGLONG AlignRound;                                                   //0x100
    ULONGLONG AlignMask;                                                    //0x108
    LIST_ENTRY VirtualAllocdBlocks;                                 //0x110
    LIST_ENTRY SegmentList;                                         //0x120
    USHORT AllocatorBackTraceIndex;                                         //0x130
    ULONG NonDedicatedListLength;                                           //0x134
    VOID* BlocksIndex;                                                      //0x138
    VOID* UCRIndex;                                                         //0x140
    PHEAP_PSEUDO_TAG_ENTRY PseudoTagEntries;                        //0x148
    LIST_ENTRY FreeLists;                                           //0x150
    PVOID LockVariable;                                        //0x160
    LONG(*CommitRoutine)(VOID* arg1, VOID** arg2, ULONGLONG* arg3);        //0x168
    RTL_RUN_ONCE StackTraceInitVar;                                  //0x170
    VOID* CommitLimitData;                     //0x178
    VOID* FrontEndHeap;                                                     //0x198
    USHORT FrontHeapLockCount;                                              //0x1a0
    UCHAR FrontEndHeapType;                                                 //0x1a2
    UCHAR RequestedFrontEndHeapType;                                        //0x1a3
    WCHAR* FrontEndHeapUsageData;                                           //0x1a8
    USHORT FrontEndHeapMaximumIndex;                                        //0x1b0
    volatile UCHAR FrontEndHeapStatusBitmap[129];                           //0x1b2
    HEAP_COUNTERS Counters;                                         //0x238
    HEAP_TUNING_PARAMETERS TuningParameters;                        //0x2b0
}HEAP, * PHEAP;

BOOLEAN ClearHeapFlags(PEPROCESS pProcess);