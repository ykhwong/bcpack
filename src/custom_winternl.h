/*

 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA

*/
#ifndef _WIN64
#ifndef _WINTERNL_
#define _WINTERNL_

#pragma region Desktop Family

#if (_WIN32_WINNT >= 0x0500)

#include <windef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

typedef CONST char *PCSZ;

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

// ykhwong modified start
typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
// ykhwong modified end
/*
typedef struct _PEB_LDR_DATA {
BYTE Reserved1[8];
PVOID Reserved2[3];
LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
*/

typedef struct _LDR_DATA_TABLE_ENTRY {
	/*
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
	ULONG CheckSum;
	PVOID Reserved6;
	} DUMMYUNIONNAME;
	ULONG TimeDateStamp;
	*/
	LIST_ENTRY			InLoadOrderLinks;				/* 0x00 */
	LIST_ENTRY			InMemoryOrderLinks;				/* 0x10 */
	LIST_ENTRY			InInitializationOrderLinks;		/* 0x20 */
	void*				DllBase;						/* 0x30 */
	void*				EntryPoint;						/* 0x38 */
	unsigned long		SizeOfImage;					/* 0x40 */
	UNICODE_STRING		FullDllName;					/* 0x48 */
	UNICODE_STRING		BaseDllName;					/* 0x58 */
	unsigned long Flags;
	unsigned short LoadCount;
	unsigned short TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			void* SectionPointer;
			unsigned long CheckSum;
		};
	};
	union
	{
		unsigned long TimeDateStamp;
		void* LoadedImports;
	};
	_ACTIVATION_CONTEXT * EntryPointActivationContext;
	void* PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef
	VOID
	(NTAPI *PPS_POST_PROCESS_INIT_ROUTINE) (
		VOID
		);

// ykhwong modified start
#if (defined(_WIN64) && !defined(EXPLICIT_32BIT)) || defined(EXPLICIT_64BIT)
#define _STRUCT64
#define _SELECT3264(x32, x64) (x64)
#define GDI_HANDLE_BUFFER_SIZE 60
#else
#undef _STRUCT64
#define _SELECT3264(x32, x64) (x32)
#define GDI_HANDLE_BUFFER_SIZE 34
#endif

typedef NTSTATUS
(NTAPI *PPOST_PROCESS_INIT_ROUTINE)(
	VOID
	);

typedef struct _PEB_FREE_BLOCK {
	struct _PEB_FREE_BLOCK *Next;
	ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

#define PEB_MACRO \
	BOOLEAN InheritedAddressSpace; \
	BOOLEAN ReadImageFileExecOptions; \
	BOOLEAN BeingDebugged; \
	union \
	{ \
		BOOLEAN BitField; \
		struct \
		{ \
			BOOLEAN ImageUsesLargePages : 1; \
			BOOLEAN IsProtectedProcess : 1; \
			BOOLEAN IsLegacyProcess : 1; \
			BOOLEAN IsImageDynamicallyRelocated : 1; \
			BOOLEAN SkipPatchingUser32Forwarders : 1; \
			BOOLEAN SpareBits : 3; \
		}; \
	}; \
	HANDLE Mutant; \
	PVOID ImageBaseAddress; \
	PPEB_LDR_DATA Ldr; \
	struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters; \
	PVOID SubSystemData; \
	PVOID ProcessHeap; \
	struct _RTL_CRITICAL_SECTION* FastPebLock; \
	PVOID AltThunkSListPtr; \
	PVOID IFEOKey; \
	union \
	{ \
		ULONG CrossProcessFlags; \
		struct \
		{ \
			ULONG ProcessInJob : 1; \
			ULONG ProcessInitializing : 1; \
			ULONG ProcessUsingVEH : 1; \
			ULONG ProcessUsingVCH : 1; \
			ULONG ReservedBits0 : 28; \
		}; \
	}; \
	union \
	{ \
		PVOID KernelCallbackTable; \
		PVOID UserSharedInfoPtr; \
	}; \
	ULONG SystemReserved[1]; \
	ULONG SpareUlong; \
	PPEB_FREE_BLOCK FreeList; \
	ULONG TlsExpansionCounter; \
	PVOID TlsBitmap; \
	ULONG TlsBitmapBits[2]; \
	PVOID ReadOnlySharedMemoryBase; \
	PVOID HotpatchInformation; \
	PVOID* ReadOnlyStaticServerData; \
	PVOID AnsiCodePageData; \
	PVOID OemCodePageData; \
	PVOID UnicodeCaseTableData; \
	ULONG NumberOfProcessors; \
	ULONG NtGlobalFlag; \
	LARGE_INTEGER CriticalSectionTimeout; \
	ULONG_PTR HeapSegmentReserve; \
	ULONG_PTR HeapSegmentCommit; \
	ULONG_PTR HeapDeCommitTotalFreeThreshold; \
	ULONG_PTR HeapDeCommitFreeBlockThreshold; \
	ULONG NumberOfHeaps; \
	ULONG MaximumNumberOfHeaps; \
	PVOID* ProcessHeaps; \
	PVOID GdiSharedHandleTable; \
	PVOID ProcessStarterHelper; \
	ULONG GdiDCAttributeList; \
	struct _RTL_CRITICAL_SECTION* LoaderLock; \
	ULONG OSMajorVersion; \
	ULONG OSMinorVersion; \
	USHORT OSBuildNumber; \
	USHORT OSCSDVersion; \
	ULONG OSPlatformId; \
	ULONG ImageSubsystem; \
	ULONG ImageSubsystemMajorVersion; \
	ULONG ImageSubsystemMinorVersion; \
	ULONG_PTR ImageProcessAffinityMask; \
	ULONG GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE]; \
	PPOST_PROCESS_INIT_ROUTINE PostProcessInitRoutine; \
	PVOID TlsExpansionBitmap; \
	ULONG TlsExpansionBitmapBits[32]; \
	ULONG SessionId; \
	ULARGE_INTEGER AppCompatFlags; \
	ULARGE_INTEGER AppCompatFlagsUser; \
	PVOID pShimData; \
	PVOID AppCompatInfo; \
	UNICODE_STRING CSDVersion; \
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData; \
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap; \
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData; \
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap; \
	ULONG_PTR MinimumStackCommit; \
	PVOID* FlsCallback; \
	LIST_ENTRY FlsListHead; \
	PVOID FlsBitmap; \
	ULONG FlsBitmapBits[4]; \
	ULONG FlsHighIndex; \
	PVOID WerRegistrationData; \
	PVOID WerShipAssertPtr;

typedef struct _PEB_ {
	PEB_MACRO
} PEB_, *PPEB_, *PPEB;
// ykhwong modified end
/*
typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, *PPEB;
*/

//ykhwong modified start
#define GDI_BATCH_BUFFER_SIZE 0x136
typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	HANDLE HDC;
	ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	LPSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;
typedef const struct _TEB_ACTIVE_FRAME_CONTEXT *PCTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME *Previous;
	PCTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;
typedef const struct _TEB_ACTIVE_FRAME *PCTEB_ACTIVE_FRAME;

typedef struct _TEB
{
	NT_TIB          Tib;                        /* 000 */
	PVOID           EnvironmentPointer;         /* 01c */
	CLIENT_ID       ClientId;                   /* 020 */
	PVOID           ActiveRpcHandle;            /* 028 */
	PVOID           ThreadLocalStoragePointer;  /* 02c */
	PVOID           Peb;                        /* 030 */
	ULONG           LastErrorValue;             /* 034 */
	ULONG           CountOfOwnedCriticalSections;/* 038 */
	PVOID           CsrClientThread;            /* 03c */
	PVOID           Win32ThreadInfo;            /* 040 */
	ULONG           Win32ClientInfo[31];        /* 044 used for user32 private data in Wine */
	PVOID           WOW32Reserved;              /* 0c0 */
	ULONG           CurrentLocale;              /* 0c4 */
	ULONG           FpSoftwareStatusRegister;   /* 0c8 */
	PVOID           SystemReserved1[54];        /* 0cc used for kernel32 private data in Wine */
	PVOID           Spare1;                     /* 1a4 */
	LONG            ExceptionCode;              /* 1a8 */
	PVOID     ActivationContextStackPointer;            /* 1a8/02c8 */
	BYTE            SpareBytes1[36];            /* 1ac */
	PVOID           SystemReserved2[10];        /* 1d4 used for ntdll private data in Wine */
	GDI_TEB_BATCH   GdiTebBatch;                /* 1fc */
	ULONG           gdiRgn;                     /* 6dc */
	ULONG           gdiPen;                     /* 6e0 */
	ULONG           gdiBrush;                   /* 6e4 */
	CLIENT_ID       RealClientId;               /* 6e8 */
	HANDLE          GdiCachedProcessHandle;     /* 6f0 */
	ULONG           GdiClientPID;               /* 6f4 */
	ULONG           GdiClientTID;               /* 6f8 */
	PVOID           GdiThreadLocaleInfo;        /* 6fc */
	PVOID           UserReserved[5];            /* 700 */
	PVOID           glDispatchTable[280];        /* 714 */
	ULONG           glReserved1[26];            /* b74 */
	PVOID           glReserved2;                /* bdc */
	PVOID           glSectionInfo;              /* be0 */
	PVOID           glSection;                  /* be4 */
	PVOID           glTable;                    /* be8 */
	PVOID           glCurrentRC;                /* bec */
	PVOID           glContext;                  /* bf0 */
	ULONG           LastStatusValue;            /* bf4 */
	UNICODE_STRING  StaticUnicodeString;        /* bf8 used by advapi32 */
	WCHAR           StaticUnicodeBuffer[261];   /* c00 used by advapi32 */
	PVOID           DeallocationStack;          /* e0c */
	PVOID           TlsSlots[64];               /* e10 */
	LIST_ENTRY      TlsLinks;                   /* f10 */
	PVOID           Vdm;                        /* f18 */
	PVOID           ReservedForNtRpc;           /* f1c */
	PVOID           DbgSsReserved[2];           /* f20 */
	ULONG           HardErrorDisabled;          /* f28 */
	PVOID           Instrumentation[16];        /* f2c */
	PVOID           WinSockData;                /* f6c */
	ULONG           GdiBatchCount;              /* f70 */
	ULONG           Spare2;                     /* f74 */
	ULONG           Spare3;                     /* f78 */
	ULONG           Spare4;                     /* f7c */
	PVOID           ReservedForOle;             /* f80 */
	ULONG           WaitingOnLoaderLock;        /* f84 */
												//     PVOID           Reserved5[3];               /* f88 */
												//     PVOID          *TlsExpansionSlots;          /* f94 */
#ifdef _STRUCT64
	UCHAR                  Padding6[4];
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID             SavedPriorityState;
#if (NTDDI_VERSION >= NTDDI_WIN8)
	ULONG_PTR         ReservedForCodeCoverage;
#else
	ULONG_PTR         SoftPatchPtr1;
#endif
	ULONG_PTR         ThreadPoolData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	ULONG_PTR         SparePointer1;
	ULONG_PTR         SoftPatchPtr1;
	ULONG_PTR         SoftPatchPtr2;
#else
	Wx86ThreadState        Wx86Thread;
#endif
	PVOID*            TlsExpansionSlots;
#ifdef _STRUCT64
	PVOID             DeallocationBStore;
	PVOID             BStoreLimit;
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10)
	ULONG                  MuiGeneration;
#else
	ULONG                  ImpersonationLocale;
#endif
	ULONG                  IsImpersonating;
	PVOID             NlsCache;
	PVOID             pShimData;
#if (NTDDI_VERSION >= NTDDI_WIN8)
	USHORT                 HeapVirtualAffinity;
	USHORT                 LowFragHeapDataSlot;
#else
	ULONG                  HeapVirtualAffinity;
#endif
#ifdef _STRUCT64
	UCHAR                  Padding7[4];
#endif
	HANDLE            CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
#if (NTDDI_VERSION >= NTDDI_WS03)
	PVOID FlsData;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	union
	{
		USHORT CrossTebFlags;
		struct
		{
			USHORT SpareCrossTebBits : 16;
		};
	};
	union
	{
		USHORT SameTebFlags;
		struct
		{
			USHORT DbgSafeThunkCall : 1;
			USHORT DbgInDebugPrint : 1;
			USHORT DbgHasFiberData : 1;
			USHORT DbgSkipThreadAttach : 1;
			USHORT DbgWerInShipAssertCode : 1;
			USHORT DbgIssuedInitialBp : 1;
			USHORT DbgClonedThread : 1;
			USHORT SpareSameTebBits : 9;
		};
	};
	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
#else
	BOOLEAN SafeThunkCall;
	BOOLEAN BooleanSpare[3];
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10) // since 10.0.10041.0
	LONG WowTebOffset;
#elif (NTDDI_VERSION >= NTDDI_WIN7)
	ULONG SpareUlong0;
#elif (NTDDI_VERSION >= NTDDI_LONGHORN)
	ULONG ProcessRundown;
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
	PVOID ResourceRetValue;
#elif (NTDDI_VERSION >= NTDDI_LONGHORN)
	ULONG64 LastSwitchTime;
	ULONG64 TotalSwitchOutTime;
	LARGE_INTEGER WaitReasonBitMap;
#endif

#if (NTDDI_VERSION >= NTDDI_WIN8)
	PVOID ReservedForWdf;
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10)
	ULONG64 ReservedForCrt;
	GUID EffectiveContainerId;
#endif
} TEB, *PTEB;
// ykhwong start end
/*
typedef struct _TEB {
	PVOID Reserved1[12];
	PPEB ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;  // Windows 2000 only
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, *PTEB;
*/
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef
	VOID
	(NTAPI *PIO_APC_ROUTINE) (
		IN PVOID ApcContext,
		IN PIO_STATUS_BLOCK IoStatusBlock,
		IN ULONG Reserved
		);

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER Reserved1[2];
	ULONG Reserved2;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	BYTE Reserved1[52];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION {
	ULONG RegistryQuotaAllowed;
	ULONG RegistryQuotaUsed;
	PVOID Reserved1;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, *PSYSTEM_REGISTRY_QUOTA_INFORMATION;

/*
typedef struct _SYSTEM_BASIC_INFORMATION {
	BYTE Reserved1[24];
	PVOID Reserved2[4];
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;
*/

typedef struct _SYSTEM_BASIC_INFORMATION
{
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	ULONG_PTR ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
	USHORT ProcessorArchitecture;
	USHORT ProcessorLevel;
	USHORT ProcessorRevision;
	USHORT Reserved;
	ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
	// ykhwong modified start
	//BYTE Reserved1[48];
	LARGE_INTEGER TimeOfBoot;
	BYTE unused[40];
	// ykhwong modified end
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

/*
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;
*/

#define USE_REACTOS_DDK 1
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
#ifndef USE_REACTOS_DDK
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
#else
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
#endif // USE_REACTOS_DDK
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
#ifdef USE_REACTOS_DDK
	SystemPowerInformationNative,
#elif defined IRP_MN_START_DEVICE
	SystemPowerInformationInfo,
#else
	SystemPowerInformation,
#endif // USE_REACTOS_DDK
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
#ifdef USE_REACTOS_DDK
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation,
	SystemLoadGdiDriverInSystemSpaceInformation,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHanfleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchDogTimerHandler,
	SystemWatchDogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWo64SharedInformationObosolete,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	SystemThreadPriorityClientIdInformation,
	SystemProcessorIdleCycleTimeInformation,
	SystemVerifierCancellationInformation,
	SystemProcessorPowerInformationEx,
	SystemRefTraceInformation,
	SystemSpecialPoolInformation,
	SystemProcessIdInformation,
	SystemErrorPortInformation,
	SystemBootEnvironmentInformation,
	SystemHypervisorInformation,
	SystemVerifierInformationEx,
	SystemTimeZoneInformation,
	SystemImageFileExecutionOptionsInformation,
	SystemCoverageInformation,
	SystemPrefetchPathInformation,
	SystemVerifierFaultsInformation,
	MaxSystemInfoClass,
#endif // USE_REACTOS_DDK
} SYSTEM_INFORMATION_CLASS;



// ykhwong add start
typedef struct ExceptionVector_s {
	struct ExceptionVector_s   *next;
	PVECTORED_EXCEPTION_HANDLER handler;
} ExceptionVector_t;

typedef struct ExceptionVectorList_s {
	ExceptionVector_t   *head;
	ExceptionVector_t   *tail;
	RTL_CRITICAL_SECTION lock;
} ExceptionVectorList_t;
/*
typedef enum _DDK_PROCESSINFOCLASS {
	DDK_ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,          // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	DDK_ProcessWow64Information,
	MaxProcessInfoClass
} DDK_PROCESSINFOCLASS;
*/
typedef struct _RTL_USER_PROCESS_PARAMETERS_2K {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StdInputHandle;
	HANDLE StdOutputHandle;
	HANDLE StdErrorHandle;
} RTL_USER_PROCESS_PARAMETERS_2K, *PRTL_USER_PROCESS_PARAMETERS_2K;

typedef struct _LDR_MODULE {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID BaseAddress;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA_2K {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_2K, *PPEB_LDR_DATA_2K;

typedef struct _PEB_2K {
	/*
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN Spare;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA_2K LoaderData;
	PRTL_USER_PROCESS_PARAMETERS_2K ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	//And more but we don't care...
	DWORD reserved[0x21];
	PRTL_CRITICAL_SECTION LoaderLock;
	*/
	PEB_MACRO
} PEB_2K, *PPEB_2K;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	//KPRIORITY Priority;
	//KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

#define ThreadBasicInformation 0

typedef DWORD (WINAPI *GetLocaleCompare_t) (LCID locale, DWORD dwCmpFlags);

/*
struct   _NT_TIB (sizeof=28)
+00 struct   _EXCEPTION_REGISTRATION_RECORD *ExceptionList
+04 void     *StackBase
+08 void     *StackLimit
+0c void     *SubSystemTib
+10 void     *FiberData
+10 uint32   Version
+14 void     *ArbitraryUserPointer
+18 struct   _NT_TIB *Self
*/

typedef struct _TEB_2K {
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID Cid;
	PVOID ActiveRpcInfo;
	PVOID ThreadLocalStoragePointer;
	PPEB_2K Peb;
	DWORD reserved[0x3D0];
	BOOLEAN InDbgPrint; // 0xF74
	BOOLEAN FreeStackOnTermination;
	BOOLEAN HasFiberData;
	UCHAR IdealProcessor;
} TEB_2K, *PTEB_2K;

static struct _TEB * _NtCurrentTeb(void) {
	return (struct _TEB *) (ULONG_PTR) __readfsdword(PcTeb);
}

static inline PTEB_2K NtCurrentTeb2k(void) {
	return (PTEB_2K)_NtCurrentTeb();
}

static inline PNT_TIB NtCurrentTib(void) {
	return &NtCurrentTeb2k()->NtTib;
}

static inline PPEB_2K NtCurrentPeb(void) {
	return NtCurrentTeb2k()->Peb;
}
// ykhwong add end

#ifdef __cplusplus
}
#endif

#endif // (_WIN32_WINNT >= 0x0500)


//#endif /* WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP) */
#pragma endregion

#endif // _WINTERNL_
#endif //_WIN64
