#pragma once
#include <ntddk.h>
#include "Heap.h"

typedef enum _SYSTEM_DLL_TYPE
{
    PsNativeSystemDll = 0,
    PsWowX86SystemDll = 1,
    PsWowArm32SystemDll = 2,
    PsWowAmd64SystemDll = 3,
    PsWowChpeX86SystemDll = 4,
    PsVsmEnclaveRuntimeDll = 5,
    PsSystemDllTotalTypes = 6
}SYSTEM_DLL_TYPE;

typedef struct _PEB_LDR_DATA32
{
    ULONG 	Length;
    BOOLEAN 	Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 	InLoadOrderModuleList;
    LIST_ENTRY32 	InMemoryOrderModuleList;
    LIST_ENTRY32 	InInitializationOrderModuleList;
    BOOLEAN 	ShutdownInProgress;
}PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _PEB_LDR_DATA {
    ULONG 	Length;
    BOOLEAN Initialized;
    HANDLE 	SsHandle;
    LIST_ENTRY 	InLoadOrderModuleList;
    LIST_ENTRY 	InMemoryOrderModuleList;
    LIST_ENTRY 	InInitializationOrderModuleList;
    PVOID 	EntryInProgress;
    BOOLEAN 	ShutdownInProgress;
    HANDLE 	ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _EWOW64PROCESS
{
    VOID* Peb;                                                              //0x0
    USHORT Machine;                                                         //0x8
    SYSTEM_DLL_TYPE NtdllType;                                        //0xc
}EWOW64PROCESS, * PEWOW64PROCESS;

typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
    USHORT Type;                                                            //0x0
    USHORT CreatorBackTraceIndex;                                           //0x2
    VOID* CriticalSection;                                  //0x8
    LIST_ENTRY ProcessLocksList;                                            //0x10
    ULONG EntryCount;                                                       //0x20
    ULONG ContentionCount;                                                  //0x24
    ULONG Flags;                                                            //0x28
    USHORT CreatorBackTraceIndexHigh;                                       //0x2c
    USHORT SpareUSHORT;                                                     //0x2e
}RTL_CRITICAL_SECTION_DEBUG, * PRTL_CRITICAL_SECTION_DEBUG;


typedef struct _RTL_CRITICAL_SECTION
{
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;                          //0x0
    LONG LockCount;                                                         //0x8
    LONG RecursionCount;                                                    //0xc
    VOID* OwningThread;                                                     //0x10
    VOID* LockSemaphore;                                                    //0x18
    ULONGLONG SpinCount;                                                    //0x20
}RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;

typedef struct _LEAP_SECOND_DATA
{
    UCHAR Enabled;                                                          //0x0
    ULONG Count;                                                            //0x4
    LARGE_INTEGER Data[1];                                           //0x8
}LEAP_SECOND_DATA, * PLEAP_SECOND_DATA;


typedef struct _PEB
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    VOID* Mutant;                                                           //0x8
    VOID* ImageBaseAddress;                                                 //0x10
    PEB_LDR_DATA* Ldr;                                              //0x18
    RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
    VOID* SubSystemData;                                                    //0x28
    VOID* ProcessHeap;                                                      //0x30
    RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
    SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
    VOID* IFEOKey;                                                          //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob : 1;                                           //0x50
            ULONG ProcessInitializing : 1;                                    //0x50
            ULONG ProcessUsingVEH : 1;                                        //0x50
            ULONG ProcessUsingVCH : 1;                                        //0x50
            ULONG ProcessUsingFTH : 1;                                        //0x50
            ULONG ProcessPreviouslyThrottled : 1;                             //0x50
            ULONG ProcessCurrentlyThrottled : 1;                              //0x50
            ULONG ProcessImagesHotPatched : 1;                                //0x50
            ULONG ReservedBits0 : 24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        VOID* KernelCallbackTable;                                          //0x58
        VOID* UserSharedInfoPtr;                                            //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    VOID* ApiSetMap;                                                        //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    VOID* TlsBitmap;                                                        //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    VOID* ReadOnlySharedMemoryBase;                                         //0x88
    VOID* SharedData;                                                       //0x90
    VOID** ReadOnlyStaticServerData;                                        //0x98
    VOID* AnsiCodePageData;                                                 //0xa0
    VOID* OemCodePageData;                                                  //0xa8
    VOID* UnicodeCaseTableData;                                             //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    VOID** ProcessHeaps;                                                    //0xf0
    VOID* GdiSharedHandleTable;                                             //0xf8
    VOID* ProcessStarterHelper;                                             //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    UCHAR Padding4[4];                                                      //0x134
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    VOID(*PostProcessInitRoutine)();                                       //0x230
    VOID* TlsExpansionBitmap;                                               //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    VOID* pShimData;                                                        //0x2d8
    VOID* AppCompatInfo;                                                    //0x2e0
    UNICODE_STRING CSDVersion;                                      //0x2e8
    VOID* ActivationContextData;                 //0x2f8
    VOID* ProcessAssemblyStorageMap;                //0x300
    VOID* SystemDefaultActivationContextData;    //0x308
    VOID* SystemAssemblyStorageMap;                 //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    VOID* SparePointers[4];                                                 //0x320
    ULONG SpareUlongs[5];                                                   //0x340
    VOID* WerRegistrationData;                                              //0x358
    VOID* WerShipAssertPtr;                                                 //0x360
    VOID* pUnused;                                                          //0x368
    VOID* pImageHeaderHash;                                                 //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled : 1;                                     //0x378
            ULONG CritSecTracingEnabled : 1;                                  //0x378
            ULONG LibLoaderTracingEnabled : 1;                                //0x378
            ULONG SpareTracingBits : 29;                                      //0x378
        };
    };
    UCHAR Padding6[4];                                                      //0x37c
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
    ULONGLONG TppWorkerpListLock;                                           //0x388
    LIST_ENTRY TppWorkerpList;                                      //0x390
    VOID* WaitOnAddressHashTable[128];                                      //0x3a0
    VOID* TelemetryCoverageHeader;                                          //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    PLEAP_SECOND_DATA LeapSecondData;                               //0x7b8
    union
    {
        ULONG LeapSecondFlags;                                              //0x7c0
        struct
        {
            ULONG SixtySecondEnabled : 1;                                     //0x7c0
            ULONG Reserved : 31;                                              //0x7c0
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x7c4
}PEB, * PPEB;


typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    ULONG Mutant;                                                           //0x4
    ULONG ImageBaseAddress;                                                 //0x8
    ULONG Ldr;                                                              //0xc
    ULONG ProcessParameters;                                                //0x10
    ULONG SubSystemData;                                                    //0x14
    ULONG ProcessHeap;                                                      //0x18
    ULONG FastPebLock;                                                      //0x1c
    ULONG AtlThunkSListPtr;                                                 //0x20
    ULONG IFEOKey;                                                          //0x24
    union
    {
        ULONG CrossProcessFlags;                                            //0x28
        struct
        {
            ULONG ProcessInJob : 1;                                           //0x28
            ULONG ProcessInitializing : 1;                                    //0x28
            ULONG ProcessUsingVEH : 1;                                        //0x28
            ULONG ProcessUsingVCH : 1;                                        //0x28
            ULONG ProcessUsingFTH : 1;                                        //0x28
            ULONG ProcessPreviouslyThrottled : 1;                             //0x28
            ULONG ProcessCurrentlyThrottled : 1;                              //0x28
            ULONG ProcessImagesHotPatched : 1;                                //0x28
            ULONG ReservedBits0 : 24;                                         //0x28
        };
    };
    union
    {
        ULONG KernelCallbackTable;                                          //0x2c
        ULONG UserSharedInfoPtr;                                            //0x2c
    };
    ULONG SystemReserved;                                                   //0x30
    ULONG AtlThunkSListPtr32;                                               //0x34
    ULONG ApiSetMap;                                                        //0x38
    ULONG TlsExpansionCounter;                                              //0x3c
    ULONG TlsBitmap;                                                        //0x40
    ULONG TlsBitmapBits[2];                                                 //0x44
    ULONG ReadOnlySharedMemoryBase;                                         //0x4c
    ULONG SharedData;                                                       //0x50
    ULONG ReadOnlyStaticServerData;                                         //0x54
    ULONG AnsiCodePageData;                                                 //0x58
    ULONG OemCodePageData;                                                  //0x5c
    ULONG UnicodeCaseTableData;                                             //0x60
    ULONG NumberOfProcessors;                                               //0x64
    ULONG NtGlobalFlag;                                                     //0x68
    LARGE_INTEGER CriticalSectionTimeout;                            //0x70
    ULONG HeapSegmentReserve;                                               //0x78
    ULONG HeapSegmentCommit;                                                //0x7c
    ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
    ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
    ULONG NumberOfHeaps;                                                    //0x88
    ULONG MaximumNumberOfHeaps;                                             //0x8c
    ULONG ProcessHeaps;                                                     //0x90
    ULONG GdiSharedHandleTable;                                             //0x94
    ULONG ProcessStarterHelper;                                             //0x98
    ULONG GdiDCAttributeList;                                               //0x9c
    ULONG LoaderLock;                                                       //0xa0
    ULONG OSMajorVersion;                                                   //0xa4
    ULONG OSMinorVersion;                                                   //0xa8
    USHORT OSBuildNumber;                                                   //0xac
    USHORT OSCSDVersion;                                                    //0xae
    ULONG OSPlatformId;                                                     //0xb0
    ULONG ImageSubsystem;                                                   //0xb4
    ULONG ImageSubsystemMajorVersion;                                       //0xb8
    ULONG ImageSubsystemMinorVersion;                                       //0xbc
    ULONG ActiveProcessAffinityMask;                                        //0xc0
    ULONG GdiHandleBuffer[34];                                              //0xc4
    ULONG PostProcessInitRoutine;                                           //0x14c
    ULONG TlsExpansionBitmap;                                               //0x150
    ULONG TlsExpansionBitmapBits[32];                                       //0x154
    ULONG SessionId;                                                        //0x1d4
    ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
    ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
    ULONG pShimData;                                                        //0x1e8
    ULONG AppCompatInfo;                                                    //0x1ec
    STRING32 CSDVersion;                                            //0x1f0
    ULONG ActivationContextData;                                            //0x1f8
    ULONG ProcessAssemblyStorageMap;                                        //0x1fc
    ULONG SystemDefaultActivationContextData;                               //0x200
    ULONG SystemAssemblyStorageMap;                                         //0x204
    ULONG MinimumStackCommit;                                               //0x208
    ULONG SparePointers[4];                                                 //0x20c
    ULONG SpareUlongs[5];                                                   //0x21c
    ULONG WerRegistrationData;                                              //0x230
    ULONG WerShipAssertPtr;                                                 //0x234
    ULONG pUnused;                                                          //0x238
    ULONG pImageHeaderHash;                                                 //0x23c
    union
    {
        ULONG TracingFlags;                                                 //0x240
        struct
        {
            ULONG HeapTracingEnabled : 1;                                     //0x240
            ULONG CritSecTracingEnabled : 1;                                  //0x240
            ULONG LibLoaderTracingEnabled : 1;                                //0x240
            ULONG SpareTracingBits : 29;                                      //0x240
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
    ULONG TppWorkerpListLock;                                               //0x250
    LIST_ENTRY32 TppWorkerpList;                                     //0x254
    ULONG WaitOnAddressHashTable[128];                                      //0x25c
    ULONG TelemetryCoverageHeader;                                          //0x45c
    ULONG CloudFileFlags;                                                   //0x460
    ULONG CloudFileDiagFlags;                                               //0x464
    CHAR PlaceholderCompatibilityMode;                                      //0x468
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x469
    ULONG LeapSecondData;                                                   //0x470
    union
    {
        ULONG LeapSecondFlags;                                              //0x474
        struct
        {
            ULONG SixtySecondEnabled : 1;                                     //0x474
            ULONG Reserved : 31;                                              //0x474
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x478
}PEB32, * PPEB32;

BOOLEAN SetPebDeuggerFlag(PEPROCESS TargetProcess, BOOLEAN Value);

BOOLEAN ClearPebNtGlobalFlag(PEPROCESS TargetProcess);