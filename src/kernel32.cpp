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
#include "common.h"
#include "kernel32.h"
#include "util.h"
#include "debug.h"

#if _WIN64
#else

/* SpinCount start */
static BOOLEAN RtlpCritSectInitialized = FALSE;
static RTL_CRITICAL_SECTION RtlCriticalSectionLock;
static BOOLEAN RtlpDebugInfoFreeList[64];
static RTL_CRITICAL_SECTION_DEBUG RtlpStaticDebugInfo[64];
static LIST_ENTRY RtlCriticalSectionList;
PVOID FrLdrDefaultHeap;

typedef struct _BLOCK_DATA {
    ULONG_PTR Flink:32;
    ULONG_PTR Blink:32;
} BLOCK_DATA, *PBLOCK_DATA;

typedef struct _HEAP_BLOCK {
    USHORT Size;
    USHORT PreviousSize;
    ULONG Tag;
    BLOCK_DATA Data[];
} HEAP_BLOCK, *PHEAP_BLOCK;

typedef struct _HEAP {
    SIZE_T MaximumSize;
    SIZE_T CurrentAllocBytes;
    SIZE_T MaxAllocBytes;
    ULONG NumAllocs;
    ULONG NumFrees;
    SIZE_T LargestAllocation;
    ULONGLONG AllocationTime;
    ULONGLONG FreeTime;
    ULONG_PTR TerminatingBlock;
    HEAP_BLOCK Blocks;
} HEAP, *PHEAP;

/* SpinCount end */

typedef struct _KSYSTEM_TIME {
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE {
	NtProductWinNt = 1,
	NtProductLanManNt,
	NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
	StandardDesign,
	NEC98x86,
	EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA {
	ULONG TickCountLowDeprecated;
	ULONG TickCountMultiplier;
	volatile KSYSTEM_TIME InterruptTime;
	volatile KSYSTEM_TIME SystemTime;
	volatile KSYSTEM_TIME TimeZoneBias;
	USHORT ImageNumberLow;
	USHORT ImageNumberHigh;
	WCHAR NtSystemRoot[260];
	ULONG MaxStackTraceDepth;
	ULONG CryptoExponent;
	ULONG TimeZoneId;
	ULONG LargePageMinimum;
	ULONG Reserved2[7];
	NT_PRODUCT_TYPE NtProductType;
	BOOLEAN ProductTypeIsValid;
	ULONG NtMajorVersion;
	ULONG NtMinorVersion;
	BOOLEAN ProcessorFeatures[64];
	ULONG Reserved1;
	ULONG Reserved3;
	volatile ULONG TimeSlip;
	ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
	LARGE_INTEGER SystemExpirationDate;
	ULONG SuiteMask;
	BOOLEAN KdDebuggerEnabled;
	UCHAR NXSupportPolicy;
	volatile ULONG ActiveConsoleId;
	volatile ULONG DismountCount;
	ULONG ComPlusPackage;
	ULONG LastSystemRITEventTickCount;
	ULONG NumberOfPhysicalPages;
	BOOLEAN SafeBootMode;
	ULONG TraceLogging;
	ULONGLONG TestRetInstruction;
	ULONG SystemCall;
	ULONG SystemCallReturn;
	ULONGLONG SystemCallPad[3];
	union {
		volatile KSYSTEM_TIME TickCount;
		volatile ULONG64 TickCountQuad;
	} DUMMYUNIONNAME;
	ULONG Cookie;
	ULONG Wow64SharedInformation[16];
} KSHARED_USER_DATA, *PKSHARED_USER_DATA;

#define SHARED_DATA     ((KSHARED_USER_DATA*)0x7ffe0000)

static size_t _wcslen(const wchar_t *s) {
	const wchar_t *p;
	p = s;
	while (*p)
		p++;

	return p - s;
}

static VOID _LoaderLock(BOOL lock) {
	if (lock)
		EnterCriticalSection(NtCurrentPeb()->LoaderLock);
	else
		LeaveCriticalSection(NtCurrentPeb()->LoaderLock);
}

static BOOL _IncLoadCount(HMODULE hMod) {
	WCHAR buffer[MAX_PATH + 1];
	DWORD nSize;
	nSize = GetModuleFileNameW(hMod, buffer, MAX_PATH + 1);
	if (nSize <= MAX_PATH) {
		if (LoadLibraryW(buffer)) return TRUE;
		else return FALSE;
	}
	return FALSE;
}

static PLDR_MODULE WINAPI _GetLdrModule(LPCVOID address) {
	PLDR_MODULE first_mod, mod;
	first_mod = mod = (PLDR_MODULE)NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink;
	do {
		if ((ULONG_PTR)mod->BaseAddress <= (ULONG_PTR)address &&
			(ULONG_PTR)address < (ULONG_PTR)mod->BaseAddress + mod->SizeOfImage)
			return mod;
		mod = (PLDR_MODULE)mod->InLoadOrderModuleList.Flink;
	} while (mod != first_mod);
	return NULL;
}

static HMODULE _GetModuleHandleFromPtr(LPCVOID p) {
	PLDR_MODULE pLM;
	HMODULE ret;
	_LoaderLock(TRUE);
	pLM = _GetLdrModule(p);
	ret = pLM ? (HMODULE)pLM->BaseAddress : NULL;
	_LoaderLock(FALSE);
	return ret;
}

#if ADDITIONAL_COMP
static PWCHAR _FilenameA2W(LPCSTR NameA, BOOL alloc) {
	ANSI_STRING str;
	UNICODE_STRING strW;
	PUNICODE_STRING pstrW;
	NTSTATUS Status;

	//ASSERT(NtCurrentTeb()->StaticUnicodeString.Buffer == NtCurrentTeb()->StaticUnicodeBuffer);
	//ASSERT(NtCurrentTeb()->StaticUnicodeString.MaximumLength == sizeof(NtCurrentTeb()->StaticUnicodeBuffer));

	_RtlInitAnsiString(&str, NameA);

	pstrW = alloc ? &strW : &_NtCurrentTeb()->StaticUnicodeString;

	Status = _RtlAnsiStringToUnicodeString(pstrW, &str, (BOOLEAN)alloc);

	if (NT_SUCCESS(Status))
		return pstrW->Buffer;

	if (Status == ((NTSTATUS)0x80000005L))
		SetLastError(ERROR_FILENAME_EXCED_RANGE);
	else
		SetLastError(Status);
	//BaseSetLastNTError(Status);

	return NULL;
}
#endif

static VOID FrLdrHeapInsertFreeList(
    PHEAP Heap,
    PHEAP_BLOCK FreeBlock)
{
    PHEAP_BLOCK ListHead, NextBlock;
    //ASSERT(FreeBlock->Tag == 0);

    /* Terminating block serves as free list head */
    ListHead = &Heap->Blocks + Heap->TerminatingBlock;

    for (NextBlock = &Heap->Blocks + ListHead->Data[0].Flink;
         NextBlock < FreeBlock;
         NextBlock = &Heap->Blocks + NextBlock->Data[0].Flink);

    FreeBlock->Data[0].Flink = NextBlock - &Heap->Blocks;
    FreeBlock->Data[0].Blink = NextBlock->Data[0].Blink;
    NextBlock->Data[0].Blink = FreeBlock - &Heap->Blocks;
    NextBlock = &Heap->Blocks + FreeBlock->Data[0].Blink;
    NextBlock->Data[0].Flink = FreeBlock - &Heap->Blocks;
}

static VOID FrLdrHeapRemoveFreeList(
    PHEAP Heap,
    PHEAP_BLOCK Block)
{
    PHEAP_BLOCK Previous, Next;

    Next = &Heap->Blocks + Block->Data[0].Flink;
    Previous = &Heap->Blocks + Block->Data[0].Blink;
    //ASSERT((Next->Tag == 0) || (Next->Tag == 'dnE#'));
    //ASSERT(Next->Data[0].Blink == Block - &Heap->Blocks);
    //ASSERT((Previous->Tag == 0) || (Previous->Tag == 'dnE#'));
    //ASSERT(Previous->Data[0].Flink == Block - &Heap->Blocks);

    Next->Data[0].Blink = Previous - &Heap->Blocks;
    Previous->Data[0].Flink = Next - &Heap->Blocks;
}

static PVOID FrLdrHeapAllocateEx(
    PVOID HeapHandle,
    SIZE_T ByteSize,
    ULONG Tag)
{
    PHEAP Heap = (PHEAP)HeapHandle;
    PHEAP_BLOCK Block, NextBlock;
    USHORT BlockSize, Remaining;
#if DBG && !defined(_M_ARM)
    ULONGLONG Time = __rdtsc();
#endif

#ifdef FREELDR_HEAP_VERIFIER
    /* Verify the heap */
    FrLdrHeapVerify(HeapHandle);

    /* Add space for a size field and 2 redzones */
    ByteSize += REDZONE_ALLOCATION;
#endif

    /* Check if the allocation is too large */
    if ((ByteSize +  sizeof(HEAP_BLOCK)) > USHRT_MAX * sizeof(HEAP_BLOCK))
    {
        //ERR("HEAP: Allocation of 0x%lx bytes too large\n", ByteSize);
        return NULL;
    }

    /* We need a proper tag */
    if (Tag == 0) Tag = 'enoN';

    /* Calculate alloc size */
    BlockSize = (USHORT)((ByteSize + sizeof(HEAP_BLOCK) - 1) / sizeof(HEAP_BLOCK));

    /* Walk the free block list */
    Block = &Heap->Blocks + Heap->TerminatingBlock;
    for (Block = &Heap->Blocks + Block->Data[0].Flink;
         Block->Size != 0;
         Block = &Heap->Blocks + Block->Data[0].Flink)
    {
        //ASSERT(Block->Tag == 0);

        /* Continue, if its too small */
        if (Block->Size < BlockSize) continue;

        /* This block is just fine, use it */
        Block->Tag = Tag;

        /* Remove this entry from the free list */
        FrLdrHeapRemoveFreeList(Heap, Block);

        /* Calculate the remaining size */
        Remaining = Block->Size - BlockSize;

        /* Check if the remaining space is large enough for a new block */
        if (Remaining > 1)
        {
            /* Make the allocated block as large as necessary */
            Block->Size = BlockSize;

            /* Get pointer to the new block */
            NextBlock = Block + 1 + BlockSize;

            /* Make it a free block */
            NextBlock->Tag = 0;
            NextBlock->Size = Remaining - 1;
            NextBlock->PreviousSize = BlockSize;
            BlockSize = NextBlock->Size;
            FrLdrHeapInsertFreeList(Heap, NextBlock);

            /* Advance to the next block */
            NextBlock = NextBlock + 1 + BlockSize;
        }
        else
        {
            /* Not enough left, use the full block */
            BlockSize = Block->Size;

            /* Get the next block */
            NextBlock = Block + 1 + BlockSize;
        }

        /* Update the next blocks back link */
        NextBlock->PreviousSize = BlockSize;

        /* Update heap usage */
        Heap->NumAllocs++;
        Heap->CurrentAllocBytes += Block->Size * sizeof(HEAP_BLOCK);
        Heap->MaxAllocBytes = max(Heap->MaxAllocBytes, Heap->CurrentAllocBytes);
        Heap->LargestAllocation = max(Heap->LargestAllocation,
                                      Block->Size * sizeof(HEAP_BLOCK));
//#if DBG && !defined(_M_ARM)
//        Heap->AllocationTime += (__rdtsc() - Time);
//#endif
        //TRACE("HeapAllocate(%p, %ld, %.4s) -> return %p\n",
        //      HeapHandle, ByteSize, &Tag, Block->Data);

        /* HACK: zero out the allocation */
        RtlZeroMemory(Block->Data, Block->Size * sizeof(HEAP_BLOCK));

#ifdef FREELDR_HEAP_VERIFIER
        /* Write size and redzones */
        *REDZONE_SIZE(Block) = ByteSize - REDZONE_ALLOCATION;
        *REDZONE_LOW(Block) = REDZONE_MARK;
        *REDZONE_HI(Block) = REDZONE_MARK;

        /* Allocation starts after size field and redzone */
        return (PUCHAR)Block->Data + REDZONE_LOW_OFFSET;
#endif
        /* Return pointer to the data */
        return Block->Data;
    }

    /* We found nothing */
    //WARN("HEAP: nothing suitable found for 0x%lx bytes\n", ByteSize);
    return NULL;
}

static PVOID NTAPI RtlAllocateHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN SIZE_T Size) {
    PVOID ptr;

    ptr = FrLdrHeapAllocateEx(FrLdrDefaultHeap, Size, ' ltR');
    if (ptr && (Flags & HEAP_ZERO_MEMORY))
    {
        RtlZeroMemory(ptr, Size);
    }

    return ptr;
}

static PRTL_CRITICAL_SECTION_DEBUG NTAPI RtlpAllocateDebugInfo(VOID) {
      ULONG i;
  
      /* Try to allocate from our buffer first */
      for (i = 0; i < 64; i++)
      {
          /* Check if Entry is free */
          if (!RtlpDebugInfoFreeList[i])
          {
              /* Mark entry in use */
              RtlpDebugInfoFreeList[i] = TRUE;
  
              /* Use free entry found */
              return &RtlpStaticDebugInfo[i];
          }
      }
  
      /* We are out of static buffer, allocate dynamic */
      return (PRTL_CRITICAL_SECTION_DEBUG)RtlAllocateHeap(GetProcessHeap(), // RtlGetProcessHeap
                             0,
                             sizeof(RTL_CRITICAL_SECTION_DEBUG));
  }

#define InsertTailList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Blink = _EX_ListHead->Blink;\
    (Entry)->Flink = _EX_ListHead;\
    (Entry)->Blink = _EX_Blink;\
    _EX_Blink->Flink = (Entry);\
    _EX_ListHead->Blink = (Entry);\
    }

static NTSTATUS NTAPI _RtlInitializeCriticalSectionAndSpinCount(PRTL_CRITICAL_SECTION CriticalSection, ULONG SpinCount) {
	//PRTL_CRITICAL_SECTION_DEBUG CritcalSectionDebugData;

	/* First things first, set up the Object */
	CriticalSection->LockCount = -1;
	CriticalSection->RecursionCount = 0;
	CriticalSection->OwningThread = 0;
	//CriticalSection->SpinCount = (NtCurrentPeb()->NumberOfProcessors > 1) ? SpinCount : 0;
	CriticalSection->SpinCount = 0;
	CriticalSection->LockSemaphore = 0;

	/* Allocate the Debug Data */
	//DEBUG_LOG("KERNEL32 RtlInitializeCriticalSectionAndSpinCount: D1\r\n");
	//CritcalSectionDebugData = RtlpAllocateDebugInfo();
	//DEBUG_LOG("KERNEL32 RtlInitializeCriticalSectionAndSpinCount: D2\r\n");

	//if (!CritcalSectionDebugData)
	//{
		/* This is bad! */
	//	DEBUG_LOG("KERNEL32 RtlInitializeCriticalSectionAndSpinCount: END (1)\r\n");
	//	return STATUS_NO_MEMORY;
	//}

	/* Set it up */
	//CritcalSectionDebugData->Type = 0;
	//CritcalSectionDebugData->ContentionCount = 0;
	//CritcalSectionDebugData->EntryCount = 0;
	//CritcalSectionDebugData->CriticalSection = CriticalSection;
	//CritcalSectionDebugData->Flags = 0;
	//DEBUG_LOG("KERNEL32 RtlInitializeCriticalSectionAndSpinCount: D3\r\n");
	//CriticalSection->DebugInfo = CritcalSectionDebugData;
	//DEBUG_LOG("KERNEL32 RtlInitializeCriticalSectionAndSpinCount: D4\r\n");

	/*
	* Add it to the List of Critical Sections owned by the process.
	* If we've initialized the Lock, then use it. If not, then probably
	* this is the lock initialization itself, so insert it directly.
	*/
	if ((CriticalSection != &RtlCriticalSectionLock) && (RtlpCritSectInitialized)) {
		/* Protect List */
		EnterCriticalSection(&RtlCriticalSectionLock);

		/* Add this one */
		//InsertTailList(&RtlCriticalSectionList, &CritcalSectionDebugData->ProcessLocksList);

		/* Unprotect */
		LeaveCriticalSection(&RtlCriticalSectionLock);
	}
	else {
		/* Add it directly */
		//InsertTailList(&RtlCriticalSectionList, &CritcalSectionDebugData->ProcessLocksList);
	}
	return 1;
}


#if WIN2K_COMP
MAKE_FUNC_READY(EncodePointer, IsXpOrHigher_2K, "KERNEL32.DLL", PVOID, PVOID ptr)
MAKE_FUNC_BEGIN(EncodePointer, ptr)  {
	DEBUG_LOG("KERNEL32 EncodePointer: START\r\n");
	DEBUG_LOG("KERNEL32 EncodePointer: END\r\n");
	return (PVOID)((UINT_PTR)ptr ^ 0xDEADBEEF);
}
MAKE_FUNC_END


MAKE_FUNC_READY(DecodePointer, IsXpOrHigher_2K, "KERNEL32.DLL", PVOID, PVOID ptr)
MAKE_FUNC_BEGIN(DecodePointer, ptr) {
	DEBUG_LOG("KERNEL32 DecodePointer: START\r\n");
	DEBUG_LOG("KERNEL32 DecodePointer: END\r\n");
	return (PVOID)((UINT_PTR)ptr ^ 0xDEADBEEF);
}
MAKE_FUNC_END


MAKE_FUNC_READY(InitializeSListHead, IsXpOrHigher_2K, "KERNEL32.DLL", VOID, PSLIST_HEADER list)
MAKE_FUNC_BEGIN(InitializeSListHead, list) {
	DEBUG_LOG("KERNEL32 InitializeSListHead: START\r\n");
	DEBUG_LOG("KERNEL32 InitializeSListHead: END\r\n");
	RtlZeroMemory(list, sizeof(SLIST_HEADER));
}
MAKE_FUNC_END


MAKE_FUNC_READY(GetModuleHandleExW, IsXpOrHigher_2K, "KERNEL32.DLL", BOOL, DWORD dwFlags, PWSTR lpModuleName, HMODULE *phModule)
MAKE_FUNC_BEGIN(GetModuleHandleExW, dwFlags, lpModuleName, phModule) {
	DEBUG_LOG("KERNEL32 InitializeSListHead: START\r\n");
	_LoaderLock(TRUE);
	if (dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)
		*phModule = _GetModuleHandleFromPtr(lpModuleName);
	else
		*phModule = GetModuleHandleW(lpModuleName);
	if (*phModule == NULL) {
		_LoaderLock(FALSE);
		DEBUG_LOG("KERNEL32 InitializeSListHead: END (1)\r\n");
		return FALSE;
	}

	if (!(dwFlags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT) ||
		dwFlags & GET_MODULE_HANDLE_EX_FLAG_PIN) {
		_IncLoadCount(*phModule);
	}
	_LoaderLock(FALSE);
	DEBUG_LOG("KERNEL32 InitializeSListHead: END (2)\r\n");
	return TRUE;
}
MAKE_FUNC_END


MAKE_FUNC_READY(InterlockedFlushSList, IsXpOrHigher_2K, "KERNEL32.DLL", PSLIST_ENTRY, PSLIST_HEADER list)
MAKE_FUNC_BEGIN(InterlockedFlushSList, list) {
	DEBUG_LOG("KERNEL32 InterlockedFlushSList: START\r\n");
	SLIST_HEADER OldHeader, NewHeader;
	ULONGLONG Compare;

	/* Read the header */
	OldHeader = *list;

	do {
		/* Check for empty list */
		if (OldHeader.Next.Next == NULL) {
			DEBUG_LOG("KERNEL32 InterlockedFlushSList: END (1)\r\n");
			return NULL;
		}

		/* Create a new header (keep the sequence number) */
		NewHeader = OldHeader;
		NewHeader.Next.Next = NULL;
		NewHeader.Depth = 0;

		/* Try to exchange atomically */
		Compare = OldHeader.Alignment;
		OldHeader.Alignment = InterlockedCompareExchange64((PLONGLONG)&list->Alignment,
			NewHeader.Alignment,
			Compare);
	} while (OldHeader.Alignment != Compare);

	/* Return the old first entry */
	DEBUG_LOG("KERNEL32 InterlockedFlushSList: END (2)\r\n");
	return OldHeader.Next.Next;
}
MAKE_FUNC_END


MAKE_FUNC_READY(InterlockedPushEntrySList, IsXpOrHigher_2K, "KERNEL32.DLL", PSLIST_ENTRY, PSLIST_HEADER ListHead, PSLIST_ENTRY ListEntry)
MAKE_FUNC_BEGIN(InterlockedPushEntrySList, ListHead, ListEntry) {
	DEBUG_LOG("KERNEL32 InterlockedPushEntrySList: START\r\n");
	PVOID PrevValue;

	do {
		PrevValue = ListHead->Next.Next;
		ListEntry->Next = (_SINGLE_LIST_ENTRY *)PrevValue;
	} while (_InterlockedCompareExchangePointer((PVOID*)&ListHead->Next.Next,
		ListEntry,
		PrevValue) != PrevValue);

	DEBUG_LOG("KERNEL32 InterlockedPushEntrySList: END\r\n");
	return (PSLIST_ENTRY)PrevValue;
}
MAKE_FUNC_END
#endif // WIN2K_COMP

#if WIN98_COMP
MAKE_FUNC_READY(SetFilePointerEx, Is2kOrHigher_98MENT, "KERNEL32.DLL", BOOL, HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)
MAKE_FUNC_BEGIN(SetFilePointerEx, hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod) {
	DEBUG_LOG("KERNEL32 SetFilePointerEx: START\r\n");
	DEBUG_LOG("KERNEL32 SetFilePointerEx: END\r\n");
	return SetFilePointer(hFile, liDistanceToMove.LowPart, &liDistanceToMove.HighPart, dwMoveMethod);
}
MAKE_FUNC_END
#endif // WIN98_COMP




#if WIN95_COMP
MAKE_FUNC_READY(IsDebuggerPresent, Is98OrHigher_95, "KERNEL32.DLL", BOOL, VOID)
MAKE_FUNC_BEGIN(IsDebuggerPresent, ) {
	DEBUG_LOG("KERNEL32 IsDebuggerPresent: START\r\n");
	DEBUG_LOG("KERNEL32 IsDebuggerPresent: END\r\n");
	return (BOOL)NtCurrentPeb()->BeingDebugged;
}
MAKE_FUNC_END


MAKE_FUNC_READY(FindFirstFileExA, Is98OrHigher_95, "KERNEL32.DLL", HANDLE, IN LPCSTR lpFileName, IN FINDEX_INFO_LEVELS fInfoLevelId, OUT LPVOID lpFindFileData, IN FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, IN DWORD dwAdditionalFlags)
MAKE_FUNC_BEGIN(FindFirstFileExA, lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags) {
	DEBUG_LOG("KERNEL32 FindFirstFileExA: NOT_IMPLEMENTED\r\n");
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return INVALID_HANDLE_VALUE;
}
MAKE_FUNC_END


MAKE_FUNC_READY(FindFirstFileExW, Is98OrHigher_95, "KERNEL32.DLL", HANDLE, IN LPCWSTR lpFileName, IN FINDEX_INFO_LEVELS fInfoLevelId, OUT LPVOID lpFindFileData, IN FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, IN DWORD dwAdditionalFlags)
MAKE_FUNC_BEGIN(FindFirstFileExW, lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags) {
	DEBUG_LOG("KERNEL32 FindFirstFileExW: NOT_IMPLEMENTED\r\n");
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return INVALID_HANDLE_VALUE;
}
MAKE_FUNC_END


#define cpuid(func,a,b,c,d)\
    __asm mov eax, func\
    __asm cpuid\
    __asm mov a, eax\
    __asm mov b, ebx\
    __asm mov c, ecx\
    __asm mov d, edx


MAKE_FUNC_READY(IsProcessorFeaturePresent, Is98OrHigher_95, "KERNEL32.DLL", BOOL, IN DWORD ProcessorFeature)
MAKE_FUNC_BEGIN(IsProcessorFeaturePresent, ProcessorFeature) {
	DEBUG_LOG("KERNEL32 IsProcessorFeaturePresent: START\r\n");
	if (ProcessorFeature >= 64) {
		DEBUG_LOG("KERNEL32 IsProcessorFeaturePresent: END (1)\r\n");
		return FALSE;
	}
	if (ProcessorFeature == PF_XMMI64_INSTRUCTIONS_AVAILABLE) {
		uintptr_t a, b, c, d;
		cpuid(1, a, b, c, d);
		if ((d >> 26) & 1) {
			DEBUG_LOG("KERNEL32 IsProcessorFeaturePresent: END (2)\r\n");
			return true;
		}
	}
	//return ((BOOL)(SHARED_DATA->ProcessorFeatures[ProcessorFeature]));
	DEBUG_LOG("KERNEL32 IsProcessorFeaturePresent: END (3)\r\n");
	return false;
}
MAKE_FUNC_END



MAKE_FUNC_READY(InitializeCriticalSectionAndSpinCount, Is98OrHigher_95, "KERNEL32.DLL", BOOL, OUT LPCRITICAL_SECTION lpCriticalSection, IN DWORD dwSpinCount)
MAKE_FUNC_BEGIN(InitializeCriticalSectionAndSpinCount, lpCriticalSection, dwSpinCount) {
	DEBUG_LOG("KERNEL32 InitializeCriticalSectionAndSpinCount: START\r\n");
	NTSTATUS Status;

	/* Initialize the critical section */
	Status = _RtlInitializeCriticalSectionAndSpinCount(lpCriticalSection, dwSpinCount);
	if (!NT_SUCCESS(Status)) {
		/* Set failure code */
		//BaseSetLastNTError(Status);
		SetLastError(Status);
		DEBUG_LOG("KERNEL32 InitializeCriticalSectionAndSpinCount: END (1)\r\n");
		return FALSE;
	}

	/* Success */
	DEBUG_LOG("KERNEL32 InitializeCriticalSectionAndSpinCount: END (2)\r\n");
	return TRUE;
}
MAKE_FUNC_END

MAKE_FUNC_READY(GetFileAttributesExW, Is98OrHigher_95, "KERNEL32.DLL", BOOL, LPCWSTR name, GET_FILEEX_INFO_LEVELS level, LPVOID ptr)
MAKE_FUNC_BEGIN(GetFileAttributesExW, name, level, ptr) {
	DEBUG_LOG("KERNEL32 GetFileAttributesExW: NOT_IMPLEMENTED\r\n");
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return TRUE;
}
MAKE_FUNC_END
#endif // WIN95_COMP

#if DEBUG_COMP
static NTSTATUS WINAPI _RtlQueryHeapInformation(HANDLE heap, HEAP_INFORMATION_CLASS info_class, PVOID info, SIZE_T size_in, PSIZE_T size_out) {
	switch (info_class) {
	case HeapCompatibilityInformation:
		if (size_out) *size_out = sizeof(ULONG);

		if (size_in < sizeof(ULONG)) {
			return ((NTSTATUS)0xC0000023L);
		}

		*(ULONG *)info = 0; /* standard heap */
		return 1;

	default:
		//FIXME("Unknown heap information class %u\r\n", info_class);
		return ((NTSTATUS)0xC0000003);
	}
}


MAKE_FUNC_READY(HeapQueryInformation, IsXpOrHigher_2K, "KERNEL32.DLL", BOOL, HANDLE HeapHandle, HEAP_INFORMATION_CLASS HeapInformationClass, PVOID HeapInformation OPTIONAL, SIZE_T HeapInformationLength OPTIONAL, PSIZE_T ReturnLength OPTIONAL)
MAKE_FUNC_BEGIN(HeapQueryInformation, HeapHandle, HeapInformationClass, HeapInformation, HeapInformationLength, ReturnLength)
	DEBUG_LOG("KERNEL32 HeapQueryInformation: START\r\n");
	NTSTATUS Status;
	Status = _RtlQueryHeapInformation(HeapHandle, HeapInformationClass, HeapInformation, HeapInformationLength, ReturnLength);

	if (!NT_SUCCESS(Status)) {
		//BaseSetLastNTError(Status);
		DEBUG_LOG("KERNEL32 HeapQueryInformation: END (1)\r\n");
		return FALSE;
	}

	DEBUG_LOG("KERNEL32 HeapQueryInformation: END (2)\r\n");
	return TRUE;
MAKE_FUNC_END
#endif // DEBUG_COMP


#if ADDITIONAL_COMP
MAKE_FUNC_READY(GetModuleHandleExA, IsXpOrHigher_2K, "KERNEL32.DLL", BOOL, DWORD dwFlags, PWSTR lpModuleName, HMODULE *phModule)
MAKE_FUNC_BEGIN(GetModuleHandleExA, dwFlags, lpModuleName, phModule) {
	DEBUG_LOG("KERNEL32 GetModuleHandleExA: START\r\n");
	BOOL ret;
	UNICODE_STRING unicode;
	STRING ansi;
	if (!(dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) && lpModuleName) {
		_RtlInitString(&ansi, (PCSZ)lpModuleName);
		//TED
		_RtlAnsiStringToUnicodeString(&unicode, &ansi, TRUE);
		ret = _GetModuleHandleExW(dwFlags, unicode.Buffer, phModule);
		_RtlFreeUnicodeString(&unicode);
		DEBUG_LOG("KERNEL32 GetModuleHandleExA: END (1)\r\n");
		return ret;
	}
	DEBUG_LOG("KERNEL32 GetModuleHandleExA: END (2)\r\n");
	return false;
}
MAKE_FUNC_END


MAKE_FUNC_READY(InterlockedPopEntrySList, IsXpOrHigher_2K, "KERNEL32.DLL", PSLIST_ENTRY, PSLIST_HEADER list)
MAKE_FUNC_BEGIN(InterlockedPopEntrySList, list) {
	DEBUG_LOG("KERNEL32 InterlockedPopEntrySList: START\r\n");
	PSLIST_ENTRY Result = NULL;
	//UCHAR OldIrql;
	static BOOLEAN GLLInit = FALSE;
	static KSPIN_LOCK GlobalListLock;

	if (!GLLInit) {
		KeInitializeSpinLock(&GlobalListLock);
		GLLInit = TRUE;
	}

	KeAcquireSpinLock(&GlobalListLock, &OldIrql);
	if (list->Next.Next) {
		Result = list->Next.Next;
		list->Next.Next = Result->Next;
	}
	KeReleaseSpinLock(&GlobalListLock, OldIrql);
	DEBUG_LOG("KERNEL32 InterlockedPopEntrySList: END\r\n");
	return Result;
}
MAKE_FUNC_END


MAKE_FUNC_READY(QueryDepthSList, IsXpOrHigher_2K, "KERNEL32.DLL", WORD, PSLIST_HEADER list)
MAKE_FUNC_BEGIN(QueryDepthSList, list) {
	DEBUG_LOG("KERNEL32 QueryDepthSList: START\r\n");
	DEBUG_LOG("KERNEL32 QueryDepthSList: END\r\n");
	return (USHORT)(list->Alignment & 0xffff);
}
MAKE_FUNC_END


/* From Wine implementation over their unicode library */
MAKE_FUNC_READY(WideCharToMultiByte, Is2kOrHigher_98MENT, "KERNEL32.DLL", INT, UINT page, DWORD flags, LPCWSTR src, INT srclen, LPSTR dst, INT dstlen, LPCSTR defchar, BOOL *used)
MAKE_FUNC_BEGIN(WideCharToMultiByte, page, flags, src, srclen, dst, dstlen, defchar, used) {
	DEBUG_LOG("KERNEL32 WideCharToMultiByte: START\r\n");
	int i;

	if (!src || !srclen || (!dst && dstlen)) {
		SetLastError(ERROR_INVALID_PARAMETER);
		DEBUG_LOG("KERNEL32 WideCharToMultiByte: END (1)\r\n");
		return 0;
	}

	if (srclen < 0) srclen = strlenW(src) + 1;

	if (!dstlen) {
		DEBUG_LOG("KERNEL32 WideCharToMultiByte: END (2)\r\n");
		return srclen;
	}

	for (i = 0; i<srclen && i<dstlen; i++)
		dst[i] = src[i] & 0xFF;

	if (used) *used = FALSE;

	DEBUG_LOG("KERNEL32 WideCharToMultiByte: END (3)\r\n");
	return i;
}
MAKE_FUNC_END


MAKE_FUNC_READY(AttachConsole, IsXpOrHigher_2K, "KERNEL32.DLL", BOOL, DWORD dwProcessId)
MAKE_FUNC_BEGIN(AttachConsole, dwProcessId) {
	DEBUG_LOG("KERNEL32 AttachConsole: START\r\n");
	if (dwProcessId != GetCurrentProcessId()) {
		DEBUG_LOG("KERNEL32 AttachConsole: AttachConsole does not support other processes\r\n");
	}
	//Just make sure we have a console
	AllocConsole();
	DEBUG_LOG("KERNEL32 AttachConsole: END\r\n");
	return TRUE;
}
MAKE_FUNC_END


MAKE_FUNC_READY(CompareStringW, Is2kOrHigher_98MENT, "KERNEL32.DLL", INT, DWORD lcid, DWORD flags, LPCWSTR str1, INT len1, LPCWSTR str2, INT len2)
MAKE_FUNC_BEGIN(CompareStringW, lcid, flags, str1, len1, str2, len2) {
	DEBUG_LOG("KERNEL32 CompareStringW: START\r\n");
	static const DWORD supported_flags = NORM_IGNORECASE | NORM_IGNORENONSPACE | NORM_IGNORESYMBOLS | SORT_STRINGSORT
		| NORM_IGNOREKANATYPE | NORM_IGNOREWIDTH | LOCALE_USE_CP_ACP
		| NORM_LINGUISTIC_CASING | LINGUISTIC_IGNORECASE | 0x10000000;
	static DWORD semistub_flags = NORM_LINGUISTIC_CASING | LINGUISTIC_IGNORECASE | 0x10000000;
	/* 0x10000000 is related to diacritics in Arabic, Japanese, and Hebrew */
	INT ret;

	if (!str1 || !str2) {
		SetLastError(ERROR_INVALID_PARAMETER);
		DEBUG_LOG("KERNEL32 CompareStringW: END (1)\r\n");
		return 0;
	}

	if (flags & ~supported_flags) {
		SetLastError(ERROR_INVALID_FLAGS);
		DEBUG_LOG("KERNEL32 CompareStringW: END (2)\r\n");
		return 0;
	}

	if (flags & semistub_flags) {
		//FIXME("semi-stub behavior for flag(s) 0x%x\r\n", flags & semistub_flags);
		semistub_flags &= ~flags;
	}

	if (len1 < 0) len1 = strlenW(str1);
	if (len2 < 0) len2 = strlenW(str2);

	ret = wine_compare_string(flags, str1, len1, str2, len2);

	if (ret) {
		/* need to translate result */
		DEBUG_LOG("KERNEL32 CompareStringW: END (3)\r\n");
		return (ret < 0) ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
	}
	DEBUG_LOG("KERNEL32 CompareStringW: END (4)\r\n");
	return CSTR_EQUAL;
}
MAKE_FUNC_END


MAKE_FUNC_READY(GetFileAttributesExA, IsXpOrHigher_2K, "KERNEL32.DLL", BOOL, LPCSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation)
MAKE_FUNC_BEGIN(GetFileAttributesExA, lpFileName, fInfoLevelId, lpFileInformation) {
	DEBUG_LOG("KERNEL32 GetFileAttributesExA: START\r\n");
	PWCHAR FileNameW;

	if (!(FileNameW = _FilenameA2W(lpFileName, FALSE))) {
		DEBUG_LOG("KERNEL32 GetFileAttributesExA: END (1)\r\n");
		return FALSE;
	}
#if WIN98_COMP && !WIN95_COMP
	DEBUG_LOG("KERNEL32 GetFileAttributesExA: END (2)\r\n");
	return FALSE;
#else
	DEBUG_LOG("KERNEL32 GetFileAttributesExA: END (3)\r\n");
	return _GetFileAttributesExW(FileNameW, fInfoLevelId, lpFileInformation);
#endif
}
MAKE_FUNC_END

MAKE_FUNC_READY(GetFileSizeEx, IsXpOrHigher_2K, "KERNEL32.DLL", BOOL, HANDLE file, PLARGE_INTEGER fsize)
MAKE_FUNC_BEGIN(GetFileSizeEx, file, fsize) {
	//if (_fseek((FILE*)file, 0, 2) == -1)
	//	return FALSE;
	//fsize->QuadPart = _ftell((FILE*)file);
	DEBUG_LOG("KERNEL32 GetFileSizeEx: NOT_IMPLEMENTED\r\n");
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return TRUE;
}
MAKE_FUNC_END


MAKE_FUNC_READY(lstrcmpW, Is2kOrHigher_98MENT, "KERNEL32.DLL", INT, LPCWSTR lpString1, LPCWSTR lpString2)
MAKE_FUNC_BEGIN(lstrcmpW, lpString1, lpString2) {
	DEBUG_LOG("KERNEL32 lstrcmpW: START\r\n");
	int Result;

	if (lpString1 == lpString2) {
		DEBUG_LOG("KERNEL32 lstrcmpW: END (1)\r\n");
		return 0;
	}
	if (lpString1 == NULL) {
		DEBUG_LOG("KERNEL32 lstrcmpW: END (2)\r\n");
		return -1;
	}
	if (lpString2 == NULL) {
		DEBUG_LOG("KERNEL32 lstrcmpW: END (3)\r\n");
		return 1;
	}
	Result = CompareStringW(GetThreadLocale(), 0, lpString1, -1, lpString2, -1);
	if (Result)
		Result -= 2;

	DEBUG_LOG("KERNEL32 lstrcmpW: END (4)\r\n");
	return Result;
}
MAKE_FUNC_END


MAKE_FUNC_READY(lstrlenW, Is2kOrHigher_98MENT, "KERNEL32.DLL", INT, LPCWSTR lpString)
MAKE_FUNC_BEGIN(lstrlenW, lpString) {
	DEBUG_LOG("KERNEL32 lstrlenW: START\r\n");
	INT Ret = 0;
	Ret = _wcslen(lpString);
	DEBUG_LOG("KERNEL32 lstrlenW: END\r\n");
	return Ret;
}
MAKE_FUNC_END


MAKE_FUNC_READY(GetLocaleInfoW, Is2kOrHigher_98MENT, "KERNEL32.DLL", INT, LCID lcid, LCTYPE lctype, LPWSTR buffer, INT len)
MAKE_FUNC_BEGIN(GetLocaleInfoW, lcid, lctype, buffer, len) {
	DEBUG_LOG("KERNEL32 GetLocaleInfoW: NOT_IMPLEMENTED\r\n");
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return 1;
}
MAKE_FUNC_END


MAKE_FUNC_READY(GetStringTypeW, Is2kOrHigher_98MENT, "KERNEL32.DLL", BOOL, DWORD type, LPCWSTR src, INT count, LPWORD chartype)
MAKE_FUNC_BEGIN(GetStringTypeW,type, src, count, chartype) {
	DEBUG_LOG("KERNEL32 GetStringTypeW: START\r\n");
	static const unsigned char type2_map[16] =
	{
		C2_NOTAPPLICABLE,      /* unassigned */
		C2_LEFTTORIGHT,        /* L */
		C2_RIGHTTOLEFT,        /* R */
		C2_EUROPENUMBER,       /* EN */
		C2_EUROPESEPARATOR,    /* ES */
		C2_EUROPETERMINATOR,   /* ET */
		C2_ARABICNUMBER,       /* AN */
		C2_COMMONSEPARATOR,    /* CS */
		C2_BLOCKSEPARATOR,     /* B */
		C2_SEGMENTSEPARATOR,   /* S */
		C2_WHITESPACE,         /* WS */
		C2_OTHERNEUTRAL,       /* ON */
		C2_RIGHTTOLEFT,        /* AL */
		C2_NOTAPPLICABLE,      /* NSM */
		C2_NOTAPPLICABLE,      /* BN */
		C2_OTHERNEUTRAL        /* LRE, LRO, RLE, RLO, PDF */
	};

	if (!src) /* Abort and return FALSE when src is null */
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		DEBUG_LOG("KERNEL32 GetStringTypeW: END (1)\r\n");
		return FALSE;
	}
	if (count == -1) count = strlenW(src) + 1;
	switch (type)
	{
	case CT_CTYPE1:
		while (count--) *chartype++ = get_char_typeW(*src++) & 0xfff;
		break;
	case CT_CTYPE2:
		while (count--) *chartype++ = type2_map[get_char_typeW(*src++) >> 12];
		break;
	case CT_CTYPE3:
	{
		//WARN("CT_CTYPE3: semi-stub.\r\n");
		while (count--)
		{
			int c = *src;
			WORD type1, type3 = 0; /* C3_NOTAPPLICABLE */

			type1 = get_char_typeW(*src++) & 0xfff;
			/* try to construct type3 from type1 */
			if (type1 & C1_SPACE) type3 |= C3_SYMBOL;
			if (type1 & C1_ALPHA) type3 |= C3_ALPHA;
			if ((c >= 0x30A0) && (c <= 0x30FF)) type3 |= C3_KATAKANA;
			if ((c >= 0x3040) && (c <= 0x309F)) type3 |= C3_HIRAGANA;
			if ((c >= 0x4E00) && (c <= 0x9FAF)) type3 |= C3_IDEOGRAPH;
			if ((c >= 0x0600) && (c <= 0x06FF)) type3 |= C3_KASHIDA;
			if ((c >= 0x3000) && (c <= 0x303F)) type3 |= C3_SYMBOL;

			if ((c >= 0xD800) && (c <= 0xDBFF)) type3 |= C3_HIGHSURROGATE;
			if ((c >= 0xDC00) && (c <= 0xDFFF)) type3 |= C3_LOWSURROGATE;

			if ((c >= 0xFF00) && (c <= 0xFF60)) type3 |= C3_FULLWIDTH;
			if ((c >= 0xFF00) && (c <= 0xFF20)) type3 |= C3_SYMBOL;
			if ((c >= 0xFF3B) && (c <= 0xFF40)) type3 |= C3_SYMBOL;
			if ((c >= 0xFF5B) && (c <= 0xFF60)) type3 |= C3_SYMBOL;
			if ((c >= 0xFF21) && (c <= 0xFF3A)) type3 |= C3_ALPHA;
			if ((c >= 0xFF41) && (c <= 0xFF5A)) type3 |= C3_ALPHA;
			if ((c >= 0xFFE0) && (c <= 0xFFE6)) type3 |= C3_FULLWIDTH;
			if ((c >= 0xFFE0) && (c <= 0xFFE6)) type3 |= C3_SYMBOL;

			if ((c >= 0xFF61) && (c <= 0xFFDC)) type3 |= C3_HALFWIDTH;
			if ((c >= 0xFF61) && (c <= 0xFF64)) type3 |= C3_SYMBOL;
			if ((c >= 0xFF65) && (c <= 0xFF9F)) type3 |= C3_KATAKANA;
			if ((c >= 0xFF65) && (c <= 0xFF9F)) type3 |= C3_ALPHA;
			if ((c >= 0xFFE8) && (c <= 0xFFEE)) type3 |= C3_HALFWIDTH;
			if ((c >= 0xFFE8) && (c <= 0xFFEE)) type3 |= C3_SYMBOL;
			*chartype++ = type3;
		}
		break;
	}
	default:
		SetLastError(ERROR_INVALID_PARAMETER);
		DEBUG_LOG("KERNEL32 GetStringTypeW: END (2)\r\n");
		return FALSE;
	}
	DEBUG_LOG("KERNEL32 GetStringTypeW: END (3)\r\n");
	return TRUE;
}
MAKE_FUNC_END

MAKE_FUNC_READY(InitializeCriticalSectionEx, Is2kOrHigher_98MENT, "KERNEL32.DLL", BOOL, OUT LPCRITICAL_SECTION lpCriticalSection, IN DWORD dwSpinCount, IN DWORD flags)
MAKE_FUNC_BEGIN(InitializeCriticalSectionEx, lpCriticalSection, dwSpinCount, flags) {
	DEBUG_LOG("KERNEL32 InitializeCriticalSectionEx: START\r\n");
	NTSTATUS Status;

    /* Initialize the critical section */
    Status = _RtlInitializeCriticalSectionAndSpinCount(
        (PRTL_CRITICAL_SECTION)lpCriticalSection,
        dwSpinCount);
    if (!NT_SUCCESS(Status)) {
		//BaseSetLastNTError(Status);
		SetLastError(Status);
		DEBUG_LOG("KERNEL32 InitializeCriticalSectionEx: END (1)\r\n");
        return FALSE;
    }

    /* Success */
	DEBUG_LOG("KERNEL32 InitializeCriticalSectionEx: END (2)\r\n");
    return TRUE;
}
MAKE_FUNC_END

MAKE_FUNC_READY(LeaveCriticalSection, Is2kOrHigher_98MENT, "KERNEL32.DLL", NTSTATUS, PRTL_CRITICAL_SECTION CriticalSection)
MAKE_FUNC_BEGIN(LeaveCriticalSection, CriticalSection) {
	DEBUG_LOG("KERNEL32 LeaveCriticalSection: START\r\n");
	if (--CriticalSection->RecursionCount) {
		/* Someone still owns us, but we are free. This needs to be done atomically. */
		InterlockedDecrement(&CriticalSection->LockCount);

	} else {
		/*
		* Nobody owns us anymore. No need to do this atomically.
		* See comment above.
		*/
		CriticalSection->OwningThread = 0;

		/* Was someone wanting us? This needs to be done atomically. */
		if (-1 != InterlockedDecrement(&CriticalSection->LockCount))
		{
			/* Let him have us */
			//RtlpUnWaitCriticalSection(CriticalSection);
		}
	}

	/* Sucessful! */
	DEBUG_LOG("KERNEL32 LeaveCriticalSection: END\r\n");
	return 1;
}
MAKE_FUNC_END

MAKE_FUNC_READY(EnterCriticalSection, Is2kOrHigher_98MENT, "KERNEL32.DLL", NTSTATUS, PRTL_CRITICAL_SECTION CriticalSection)
MAKE_FUNC_BEGIN(EnterCriticalSection, CriticalSection) {
	DEBUG_LOG("KERNEL32 EnterCriticalSection: START\r\n");
	HANDLE Thread = (HANDLE)NtCurrentTeb()->ClientId.UniqueThread;  
	if (InterlockedIncrement(&CriticalSection->LockCount) != 0) {  
		if (Thread == CriticalSection->OwningThread) {  
			CriticalSection->RecursionCount++;  
			DEBUG_LOG("KERNEL32 EnterCriticalSection: END (1)\r\n");
			return 1;
		}
		//RtlpWaitForCriticalSection(CriticalSection);  
	}  
	CriticalSection->OwningThread = Thread;  
	CriticalSection->RecursionCount = 1;  
	DEBUG_LOG("KERNEL32 EnterCriticalSection: END (2)\r\n");
	return 1;
}
MAKE_FUNC_END

MAKE_FUNC_READY(GetCurrentProcess, Is2kOrHigher_98MENT, "KERNEL32.DLL", HANDLE, VOID)
MAKE_FUNC_BEGIN(GetCurrentProcess, ) {
	DEBUG_LOG("KERNEL32 GetCurrentProcess: START\r\n");
	DEBUG_LOG("KERNEL32 GetCurrentProcess: END\r\n");
	//return (HANDLE)((HANDLE)-1);
	return (HANDLE)~(ULONG_PTR)0;
}
MAKE_FUNC_END


MAKE_FUNC_READY(SetUnhandledExceptionFilter, Is2kOrHigher_98MENT, "KERNEL32.DLL", LPTOP_LEVEL_EXCEPTION_FILTER, IN LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
MAKE_FUNC_BEGIN(SetUnhandledExceptionFilter, lpTopLevelExceptionFilter) {
	DEBUG_LOG("KERNEL32 SetUnhandledExceptionFilter: START\r\n");
	LPTOP_LEVEL_EXCEPTION_FILTER GlobalTopLevelExceptionFilter;
	PVOID EncodedPointer, EncodedOldPointer;

    EncodedPointer = _EncodePointer(lpTopLevelExceptionFilter);
    EncodedOldPointer = InterlockedExchangePointer((PVOID*)&GlobalTopLevelExceptionFilter,
                                            EncodedPointer);
	DEBUG_LOG("KERNEL32 SetUnhandledExceptionFilter: END\r\n");
    return (LPTOP_LEVEL_EXCEPTION_FILTER)_DecodePointer(EncodedOldPointer);
}
MAKE_FUNC_END


MAKE_FUNC_READY(UnhandledExceptionFilter, Is2kOrHigher_98MENT, "KERNEL32.DLL", LONG, IN PEXCEPTION_POINTERS ExceptionInfo)
MAKE_FUNC_BEGIN(UnhandledExceptionFilter, ExceptionInfo) {
	DEBUG_LOG("KERNEL32 UnhandledExceptionFilter: NOT_IMPLEMENTED\r\n");
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return EXCEPTION_CONTINUE_EXECUTION;
}
MAKE_FUNC_END


#define BUFFER_SIZE 100
#define ARRAY_SIZE(x) (sizeof((x))/sizeof((x)[0]))

typedef HMODULE(WINAPI *pLoadLibraryExW)(LPCWSTR libnameW, HANDLE hfile, DWORD flags);
extern "C" HMODULE WINAPI _LoadLibraryExW(LPCWSTR libnameW, HANDLE hfile, DWORD flags) {
#if 0
	static pLoadLibraryExW LoadLibraryExW_p = NULL;
#endif
	static const WCHAR *filter_dlls[] = {
		L"kernel32", L"user32", L"advapi32", L"shell32", L"ws2_32", 
		L"wtsapi32", L"imm32", L"uxtheme", L"imagehlp", L"hid"
	};
	const WCHAR *p, *q, *dll;
	char data_s[300];
	char pMBBuffer[BUFFER_SIZE] = ""; 
	char origBuffer[BUFFER_SIZE] = "";
	bool loadlib=false;
	int i;
	HMODULE temp;

	wcstombs(origBuffer, libnameW, BUFFER_SIZE );
	sprintf(data_s, "KERNEL32 LoadLibraryExW: START1 (%s)\r\n", origBuffer);
	DEBUG_LOG(data_s);
	if (
	!strcmp(origBuffer, "api-ms-win-core-synch-l1-2-0") ||
	!strcmp(origBuffer, "api-ms-win-core-fibers-l1-1-1") ||
	!strcmp(origBuffer, "api-ms-win-core-localization-l1-2-1") ||
	!strcmp(origBuffer, "api-ms-win-appmodel-runtime-l1-1-2")
	) {
		char text[] = "kernel32";
		wchar_t wtext[10];
		mbstowcs(wtext, text, strlen(text)+1);
		libnameW = wtext;
	}
#if 0
	if (!LoadLibraryExW_p) {
		DEBUG_LOG("KERNEL32 LoadLibraryExW: D1\r\n");
		HMODULE mod = GetModuleHandle(_T("KERNEL32"));
		if (!mod) {
			mod=LoadLibraryA("KERNEL32.DLL");
			loadlib=true;
		}
		if (mod) {
			DEBUG_LOG("KERNEL32 LoadLibraryExW: D2\r\n");
			LoadLibraryExW_p = (pLoadLibraryExW)GetProcAddress(mod, "LoadLibraryExW");
			if(loadlib) {
				FreeLibrary(mod);
			}
		} else {
			DEBUG_LOG("KERNEL32 LoadLibraryExW: D3\r\n");
		}
	}
#endif
	for(p = dll = libnameW; *p; p++) if(*p == L'\\' || *p == L'/') dll = p + 1;
	for(i=0; i<ARRAY_SIZE(filter_dlls); i++) {
		for(p = filter_dlls[i], q = dll;
		  *p; p++, q++) {
			if(!*q || towupper(*p) != towupper(*q)) goto nexti;
		}
		if(*q && _wcsicmp(L".dll", q) != 0) goto nexti;
#if 0
		sprintf(data_s, "KERNEL32: intercepted LoadLibrary(%S) redirecting to %S\r\n", libnameW, filter_dlls[i]);
		DEBUG_LOG(data_s);
		temp = LoadLibraryExW_p(filter_dlls[i], hfile, flags);
#endif
		if (temp == NULL) {
			wcstombs(pMBBuffer, filter_dlls[i], BUFFER_SIZE );
			temp = LoadLibraryA(pMBBuffer);
		}
		DEBUG_LOG("KERNEL32 LoadLibraryExW: END (1)\r\n");
		return temp;
		nexti:;
	}

#if 0
	sprintf(data_s, "KERNEL32: intercepted LoadLibrary(%S) without redirect\r\n", libnameW);
	DEBUG_LOG(data_s);
	temp = LoadLibraryExW_p(libnameW, hfile, flags);
#endif
	if (temp == NULL) {
		wcstombs(pMBBuffer, libnameW, BUFFER_SIZE );
		temp = LoadLibraryA(pMBBuffer);
	}
	DEBUG_LOG("KERNEL32 LoadLibraryExW: END (2)\r\n");
	return temp;
}


MAKE_FUNC_READY(LoadLibraryW, Is2kOrHigher_98MENT, "KERNEL32.DLL", HMODULE, LPCTSTR lpFileName)
MAKE_FUNC_BEGIN(LoadLibraryW, lpFileName) {
	DEBUG_LOG("KERNEL32 LoadLibraryW: START\r\n");
	DEBUG_LOG("KERNEL32 LoadLibraryW: END\r\n");
	return LoadLibraryExW(lpFileName, 0, 0);
}
MAKE_FUNC_END

static VOID NTAPI RtlAcquirePebLock(VOID)
{
   PPEB_2K Peb = NtCurrentPeb();
   EnterCriticalSection(Peb->FastPebLock);
}

typedef struct _RTL_BITMAP
{
    ULONG  SizeOfBitMap;
    PULONG  Buffer;
} RTL_BITMAP, *PRTL_BITMAP;

#define _BITCOUNT 32
#define MAXINDEX 0xFFFFFFFF
#define RtlFillMemoryUlong(dst, len, val) memset(dst, val, len)
typedef ULONG BITMAP_INDEX, *PBITMAP_INDEX;
typedef ULONG BITMAP_BUFFER, *PBITMAP_BUFFER;

VOID
NTAPI
RtlClearBits(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(0, BitMapHeader->SizeOfBitMap - NumberToClear) BITMAP_INDEX StartingIndex,
    _In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) BITMAP_INDEX NumberToClear)
{
    BITMAP_INDEX Bits, Mask;
    PBITMAP_BUFFER Buffer;

    /* Calculate buffer start and first bit index */
    Buffer = &BitMapHeader->Buffer[StartingIndex / _BITCOUNT];
    Bits = StartingIndex & (_BITCOUNT - 1);

    /* Are we unaligned? */
    if (Bits)
    {
        /* Create an inverse mask by shifting MAXINDEX */
        Mask = MAXINDEX << Bits;

        /* This is what's left in the first ULONG */
        Bits = _BITCOUNT - Bits;

        /* Even less bits to clear? */
        if (NumberToClear < Bits)
        {
            /* Calculate how many bits are left */
            Bits -= NumberToClear;

            /* Fixup the mask on the high side */
            Mask = Mask << Bits >> Bits;

            /* Clear bits and return */
            *Buffer &= ~Mask;
            return;
        }

        /* Clear bits */
        *Buffer &= ~Mask;

        /* Update buffer and left bits */
        Buffer++;
        NumberToClear -= Bits;
    }

    /* Clear all full ULONGs */
    RtlFillMemoryUlong(Buffer, NumberToClear >> 3, 0);
    Buffer += NumberToClear / _BITCOUNT;

    /* Clear what's left */
    NumberToClear &= (_BITCOUNT - 1);
    if (NumberToClear != 0)
    {
        Mask = MAXINDEX << NumberToClear;
        *Buffer &= Mask;
    }
}

static __inline
BITMAP_INDEX
RtlpGetLengthOfRunSet(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ BITMAP_INDEX StartingIndex,
    _In_ BITMAP_INDEX MaxLength)
{
    BITMAP_INDEX InvValue, BitPos, Length;
    PBITMAP_BUFFER Buffer, MaxBuffer;

    /* If we are already at the end, the length of the run is zero */
    //ASSERT(StartingIndex <= BitMapHeader->SizeOfBitMap);
    if (StartingIndex >= BitMapHeader->SizeOfBitMap)
        return 0;

    /* Calculate positions */
    Buffer = BitMapHeader->Buffer + StartingIndex / _BITCOUNT;
    BitPos = StartingIndex & (_BITCOUNT - 1);

    /* Calculate the maximum length */
    MaxLength = min(MaxLength, BitMapHeader->SizeOfBitMap - StartingIndex);
    MaxBuffer = Buffer + (BitPos + MaxLength + _BITCOUNT - 1) / _BITCOUNT;

    /* Get the inversed value, clear bits that don't belong to the run */
    InvValue = ~(*Buffer++) >> BitPos << BitPos;

    /* Skip all set ULONGs */
    while (InvValue == 0 && Buffer < MaxBuffer)
    {
        InvValue = ~(*Buffer++);
    }

    /* Did we reach the end? */
    if (InvValue == 0)
    {
        /* Yes, return maximum */
        return MaxLength;
    }

    /* We hit a clear bit, check how many set bits are left */
    BitScanForward(&BitPos, InvValue);

    /* Calculate length up to where we read */
    Length = (ULONG)(Buffer - BitMapHeader->Buffer) * _BITCOUNT - StartingIndex;
    Length += BitPos - _BITCOUNT;

    /* Make sure we don't go past the last bit */
    if (Length > BitMapHeader->SizeOfBitMap - StartingIndex)
        Length = BitMapHeader->SizeOfBitMap - StartingIndex;

    /* Return the result */
    return Length;
}

static __inline
BITMAP_INDEX
RtlpGetLengthOfRunClear(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ BITMAP_INDEX StartingIndex,
    _In_ BITMAP_INDEX MaxLength)
{
    BITMAP_INDEX Value, BitPos, Length;
    PBITMAP_BUFFER Buffer, MaxBuffer;

    /* If we are already at the end, the length of the run is zero */
    //ASSERT(StartingIndex <= BitMapHeader->SizeOfBitMap);
    if (StartingIndex >= BitMapHeader->SizeOfBitMap)
        return 0;

    /* Calculate positions */
    Buffer = BitMapHeader->Buffer + StartingIndex / _BITCOUNT;
    BitPos = StartingIndex & (_BITCOUNT - 1);

    /* Calculate the maximum length */
    MaxLength = min(MaxLength, BitMapHeader->SizeOfBitMap - StartingIndex);
    MaxBuffer = Buffer + (BitPos + MaxLength + _BITCOUNT - 1) / _BITCOUNT;

    /* Clear the bits that don't belong to this run */
    Value = *Buffer++ >> BitPos << BitPos;

    /* Skip all clear ULONGs */
    while (Value == 0 && Buffer < MaxBuffer)
    {
        Value = *Buffer++;
    }

    /* Did we reach the end? */
    if (Value == 0)
    {
        /* Return maximum length */
        return MaxLength;
    }

    /* We hit a set bit, check how many clear bits are left */
    BitScanForward(&BitPos, Value);

    /* Calculate length up to where we read */
    Length = (BITMAP_INDEX)(Buffer - BitMapHeader->Buffer) * _BITCOUNT - StartingIndex;
    Length += BitPos - _BITCOUNT;

    /* Make sure we don't go past the last bit */
    if (Length > BitMapHeader->SizeOfBitMap - StartingIndex)
        Length = BitMapHeader->SizeOfBitMap - StartingIndex;

    /* Return the result */
    return Length;
}

BITMAP_INDEX
NTAPI
RtlFindClearBits(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ BITMAP_INDEX NumberToFind,
    _In_ BITMAP_INDEX HintIndex)
{
    BITMAP_INDEX CurrentBit, Margin, CurrentLength;

    /* Check for valid parameters */
    if (!BitMapHeader || NumberToFind > BitMapHeader->SizeOfBitMap)
    {
        return MAXINDEX;
    }

    /* Check if the hint is outside the bitmap */
    if (HintIndex >= BitMapHeader->SizeOfBitMap) HintIndex = 0;

    /* Check for trivial case */
    if (NumberToFind == 0)
    {
        /* Return hint rounded down to byte margin */
        return HintIndex & ~7;
    }

    /* First margin is end of bitmap */
    Margin = BitMapHeader->SizeOfBitMap;

retry:
    /* Start with hint index, length is 0 */
    CurrentBit = HintIndex;

    /* Loop until something is found or the end is reached */
    while (CurrentBit + NumberToFind < Margin)
    {
        /* Search for the next clear run, by skipping a set run */
        CurrentBit += RtlpGetLengthOfRunSet(BitMapHeader,
                                            CurrentBit,
                                            MAXINDEX);

        /* Get length of the clear bit run */
        CurrentLength = RtlpGetLengthOfRunClear(BitMapHeader,
                                                CurrentBit,
                                                NumberToFind);

        /* Is this long enough? */
        if (CurrentLength >= NumberToFind)
        {
            /* It is */
            return CurrentBit;
        }

        CurrentBit += CurrentLength;
    }

    /* Did we start at a hint? */
    if (HintIndex)
    {
        /* Retry at the start */
        Margin = min(HintIndex + NumberToFind, BitMapHeader->SizeOfBitMap);
        HintIndex = 0;
        goto retry;
    }

    /* Nothing found */
    return MAXINDEX;
}

 VOID
 NTAPI
 RtlSetBits(
     _In_ PRTL_BITMAP BitMapHeader,
     _In_range_(0, BitMapHeader->SizeOfBitMap - NumberToSet) BITMAP_INDEX StartingIndex,
     _In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) BITMAP_INDEX NumberToSet)
 {
     BITMAP_INDEX Bits, Mask;
     PBITMAP_BUFFER Buffer;
 
     //ASSERT(StartingIndex + NumberToSet <= BitMapHeader->SizeOfBitMap);
 
     /* Calculate buffer start and first bit index */
     Buffer = &BitMapHeader->Buffer[StartingIndex / _BITCOUNT];
     Bits = StartingIndex & (_BITCOUNT - 1);
 
     /* Are we unaligned? */
     if (Bits)
     {
         /* Create a mask by shifting MAXINDEX */
         Mask = MAXINDEX << Bits;
 
         /* This is what's left in the first ULONG */
         Bits = _BITCOUNT - Bits;
 
         /* Even less bits to clear? */
         if (NumberToSet < Bits)
         {
             /* Calculate how many bits are left */
             Bits -= NumberToSet;
 
             /* Fixup the mask on the high side */
             Mask = Mask << Bits >> Bits;
 
             /* Set bits and return */
             *Buffer |= Mask;
             return;
         }
 
         /* Set bits */
         *Buffer |= Mask;
 
         /* Update buffer and left bits */
         Buffer++;
         NumberToSet -= Bits;
     }
 
     /* Set all full ULONGs */
     RtlFillMemoryUlong(Buffer, NumberToSet >> 3, MAXINDEX);
     Buffer += NumberToSet / _BITCOUNT;
 
     /* Set what's left */
     NumberToSet &= (_BITCOUNT - 1);
     if (NumberToSet != 0)
     {
         Mask = MAXINDEX << NumberToSet;
         *Buffer |= ~Mask;
     }
 }

static BITMAP_INDEX
NTAPI
RtlFindClearBitsAndSet(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ BITMAP_INDEX NumberToFind,
    _In_ BITMAP_INDEX HintIndex)
{
    BITMAP_INDEX Position;

    /* Try to find clear bits */
    Position = RtlFindClearBits(BitMapHeader, NumberToFind, HintIndex);

    /* Did we get something? */
    if (Position != MAXINDEX)
    {
        /* Yes, set the bits */
        RtlSetBits(BitMapHeader, Position, NumberToFind);
    }

    /* Return what we found */
    return Position;
}

VOID NTAPI
RtlReleasePebLock(VOID)
{
   PPEB_2K Peb = NtCurrentPeb ();
   LeaveCriticalSection(Peb->FastPebLock);
}

MAKE_FUNC_READY(FlsAlloc, Is2kOrHigher_98MENT, "KERNEL32.DLL", DWORD, PFLS_CALLBACK_FUNCTION lpCallback)
MAKE_FUNC_BEGIN(FlsAlloc, lpCallback) {
	DEBUG_LOG("KERNEL32 FlsAlloc: START (1)\r\n");
	DWORD dwFlsIndex;
	PPEB_2K Peb = NtCurrentPeb();
	PVOID *ppFlsSlots;

	RtlAcquirePebLock();

	ppFlsSlots = (PVOID *)NtCurrentTeb()->FlsData;

	if (!Peb->FlsCallback &&
		!(Peb->FlsCallback = (PVOID *)RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY,
			FLS_MAXIMUM_AVAILABLE * sizeof(PVOID))))
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		dwFlsIndex = FLS_OUT_OF_INDEXES;
	}
	else
	{
		dwFlsIndex = RtlFindClearBitsAndSet((PRTL_BITMAP)Peb->FlsBitmap, 1, 1);
		if (dwFlsIndex != FLS_OUT_OF_INDEXES)
		{
			if (!ppFlsSlots &&
				!(ppFlsSlots = (PVOID *)RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY,
				(FLS_MAXIMUM_AVAILABLE + 2) * sizeof(PVOID))))
			{
				RtlClearBits((PRTL_BITMAP)Peb->FlsBitmap, dwFlsIndex, 1);
				dwFlsIndex = FLS_OUT_OF_INDEXES;
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			}
			else
			{
				if (!NtCurrentTeb()->FlsData)
					NtCurrentTeb()->FlsData = ppFlsSlots;

				if (lpCallback) {
					//DPRINT1("FlsAlloc: Got lpCallback 0x%p, UNIMPLEMENTED!\n", lpCallback);
				}
				ppFlsSlots[dwFlsIndex + 2] = NULL; /* clear the value */
				Peb->FlsCallback[dwFlsIndex] = lpCallback;
			}
		}
		else
		{
			SetLastError(ERROR_NO_MORE_ITEMS);
		}
	}
	RtlReleasePebLock();
	DEBUG_LOG("KERNEL32 FlsAlloc: END\r\n");
	return dwFlsIndex;
}
MAKE_FUNC_END

MAKE_FUNC_READY(FlsGetValue, Is2kOrHigher_98MENT, "KERNEL32.DLL", PVOID, DWORD dwFlsIndex)
MAKE_FUNC_BEGIN(FlsGetValue, dwFlsIndex) {
	DEBUG_LOG("KERNEL32 FlsGetValue: START\r\n");
	PVOID *ppFlsSlots;

	ppFlsSlots = (PVOID*)NtCurrentTeb()->FlsData;
	if (!dwFlsIndex || dwFlsIndex >= FLS_MAXIMUM_AVAILABLE || !ppFlsSlots)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		DEBUG_LOG("KERNEL32 FlsGetValue: END (1)\r\n");
		return NULL;
	}

	SetLastError(ERROR_SUCCESS);
	DEBUG_LOG("KERNEL32 FlsGetValue: END (2)\r\n");
	return ppFlsSlots[dwFlsIndex + 2];
}
MAKE_FUNC_END

MAKE_FUNC_READY(FlsSetValue, Is2kOrHigher_98MENT, "KERNEL32.DLL", BOOL, DWORD dwFlsIndex, PVOID lpFlsData)
MAKE_FUNC_BEGIN(FlsSetValue, dwFlsIndex, lpFlsData) {
	DEBUG_LOG("KERNEL32 FlsSetValue: START\r\n");
	PVOID *ppFlsSlots;
	
	if (!dwFlsIndex || dwFlsIndex >= FLS_MAXIMUM_AVAILABLE)
	{
	    SetLastError(ERROR_INVALID_PARAMETER);
		DEBUG_LOG("KERNEL32 FlsSetValue: END (1)\r\n");
	    return FALSE;
	}
	if (!NtCurrentTeb()->FlsData &&
	    !(NtCurrentTeb()->FlsData = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY,
	                                                (FLS_MAXIMUM_AVAILABLE + 2) * sizeof(PVOID))))
	{
	    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		DEBUG_LOG("KERNEL32 FlsSetValue: END (2)\r\n");
	    return FALSE;
	}
	ppFlsSlots = (PVOID*)NtCurrentTeb()->FlsData;
	ppFlsSlots[dwFlsIndex + 2] = lpFlsData;
	DEBUG_LOG("KERNEL32 FlsSetValue: END (3)\r\n");
	return TRUE;
}
MAKE_FUNC_END

static int wine_get_sortkey(int flags, const WCHAR *src, int srclen, char *dst, int dstlen) {
    WCHAR dummy[4]; /* no decomposition is larger than 4 chars */
    int key_len[4];
    char *key_ptr[4];
    const WCHAR *src_save = src;
    int srclen_save = srclen;

    key_len[0] = key_len[1] = key_len[2] = key_len[3] = 0;
    for (; srclen; srclen--, src++)
    {
        unsigned int i, decomposed_len = 1;/*wine_decompose(*src, dummy, 4);*/
        dummy[0] = *src;
        if (decomposed_len)
        {
            for (i = 0; i < decomposed_len; i++)
            {
                WCHAR wch = dummy[i];
                unsigned int ce;

                /* tests show that win2k just ignores NORM_IGNORENONSPACE,
                 * and skips white space and punctuation characters for
                 * NORM_IGNORESYMBOLS.
                 */
                if ((flags & NORM_IGNORESYMBOLS) && (get_char_typeW(wch) & (C1_PUNCT | C1_SPACE)))
                    continue;

                if (flags & NORM_IGNORECASE) wch = tolowerW(wch);

                ce = collation_table[collation_table[wch >> 8] + (wch & 0xff)];
                if (ce != (unsigned int)-1)
                {
                    if (ce >> 16) key_len[0] += 2;
                    if ((ce >> 8) & 0xff) key_len[1]++;
                    if ((ce >> 4) & 0x0f) key_len[2]++;
                    if (ce & 1)
                    {
                        if (wch >> 8) key_len[3]++;
                        key_len[3]++;
                    }
                }
                else
                {
                    key_len[0] += 2;
                    if (wch >> 8) key_len[0]++;
                    if (wch & 0xff) key_len[0]++;
        }
            }
        }
    }

    if (!dstlen) /* compute length */
        /* 4 * '\1' + 1 * '\0' + key length */
        return key_len[0] + key_len[1] + key_len[2] + key_len[3] + 4 + 1;

    if (dstlen < key_len[0] + key_len[1] + key_len[2] + key_len[3] + 4 + 1)
        return 0; /* overflow */

    src = src_save;
    srclen = srclen_save;

    key_ptr[0] = dst;
    key_ptr[1] = key_ptr[0] + key_len[0] + 1;
    key_ptr[2] = key_ptr[1] + key_len[1] + 1;
    key_ptr[3] = key_ptr[2] + key_len[2] + 1;

    for (; srclen; srclen--, src++)
    {
        unsigned int i, decomposed_len = 1;/*wine_decompose(*src, dummy, 4);*/
        dummy[0] = *src;
        if (decomposed_len)
        {
            for (i = 0; i < decomposed_len; i++)
            {
                WCHAR wch = dummy[i];
                unsigned int ce;

                /* tests show that win2k just ignores NORM_IGNORENONSPACE,
                 * and skips white space and punctuation characters for
                 * NORM_IGNORESYMBOLS.
                 */
                if ((flags & NORM_IGNORESYMBOLS) && (get_char_typeW(wch) & (C1_PUNCT | C1_SPACE)))
                    continue;

                if (flags & NORM_IGNORECASE) wch = tolowerW(wch);

                ce = collation_table[collation_table[wch >> 8] + (wch & 0xff)];
                if (ce != (unsigned int)-1)
                {
                    WCHAR key;
                    if ((key = ce >> 16))
                    {
                        *key_ptr[0]++ = key >> 8;
                        *key_ptr[0]++ = key & 0xff;
                    }
                    /* make key 1 start from 2 */
                    if ((key = (ce >> 8) & 0xff)) *key_ptr[1]++ = key + 1;
                    /* make key 2 start from 2 */
                    if ((key = (ce >> 4) & 0x0f)) *key_ptr[2]++ = key + 1;
                    /* key 3 is always a character code */
                    if (ce & 1)
                    {
                        if (wch >> 8) *key_ptr[3]++ = wch >> 8;
                        if (wch & 0xff) *key_ptr[3]++ = wch & 0xff;
                    }
                }
                else
                {
                    *key_ptr[0]++ = 0xff;
                    *key_ptr[0]++ = 0xfe;
                    if (wch >> 8) *key_ptr[0]++ = wch >> 8;
                    if (wch & 0xff) *key_ptr[0]++ = wch & 0xff;
                }
            }
        }
    }

    *key_ptr[0] = '\1';
    *key_ptr[1] = '\1';
    *key_ptr[2] = '\1';
    *key_ptr[3]++ = '\1';
    *key_ptr[3] = 0;

    return key_ptr[3] - dst;
}

MAKE_FUNC_READY(LCMapStringEx, Is2kOrHigher_98MENT, "KERNEL32.DLL", INT, LPCWSTR name, DWORD flags, LPCWSTR src, INT srclen, LPWSTR dst, INT dstlen, LPNLSVERSIONINFO version, LPVOID reserved, LPARAM lparam)
MAKE_FUNC_BEGIN(LCMapStringEx, name, flags, src, srclen, dst, dstlen, version, reserved, lparam) {
	DEBUG_LOG("KERNEL32 LCMapStringEx: START\r\n");
    LPWSTR dst_ptr;

    if (!src || !srclen || dstlen < 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
		DEBUG_LOG("KERNEL32 LCMapStringEx: END (1)\r\n");
        return 0;
    }

    /* mutually exclusive flags */
    if ((flags & (LCMAP_LOWERCASE | LCMAP_UPPERCASE)) == (LCMAP_LOWERCASE | LCMAP_UPPERCASE) ||
        (flags & (LCMAP_HIRAGANA | LCMAP_KATAKANA)) == (LCMAP_HIRAGANA | LCMAP_KATAKANA) ||
        (flags & (LCMAP_HALFWIDTH | LCMAP_FULLWIDTH)) == (LCMAP_HALFWIDTH | LCMAP_FULLWIDTH) ||
        (flags & (LCMAP_TRADITIONAL_CHINESE | LCMAP_SIMPLIFIED_CHINESE)) == (LCMAP_TRADITIONAL_CHINESE | LCMAP_SIMPLIFIED_CHINESE))
    {
        SetLastError(ERROR_INVALID_FLAGS);
		DEBUG_LOG("KERNEL32 LCMapStringEx: END (2)\r\n");
        return 0;
    }

    if (!dstlen) dst = NULL;

    if (flags & LCMAP_SORTKEY)
    {
        INT ret;
        if (src == dst)
        {
            SetLastError(ERROR_INVALID_FLAGS);
			DEBUG_LOG("KERNEL32 LCMapStringEx: END (3)\r\n");
            return 0;
        }

        if (srclen < 0) srclen = strlenW(src);

        ret = wine_get_sortkey(flags, src, srclen, (char *)dst, dstlen);
        if (ret == 0)
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
        else
            ret++;
		DEBUG_LOG("KERNEL32 LCMapStringEx: END (4)\r\n");
        return ret;
    }

    /* SORT_STRINGSORT must be used exclusively with LCMAP_SORTKEY */
    if (flags & SORT_STRINGSORT)
    {
        SetLastError(ERROR_INVALID_FLAGS);
		DEBUG_LOG("KERNEL32 LCMapStringEx: END (5)\r\n");
        return 0;
    }

    if (srclen < 0) srclen = strlenW(src) + 1;

    if (!dst) /* return required string length */
    {
        INT len;

        for (len = 0; srclen; src++, srclen--)
        {
            WCHAR wch = *src;
            /* tests show that win2k just ignores NORM_IGNORENONSPACE,
             * and skips white space and punctuation characters for
             * NORM_IGNORESYMBOLS.
             */
            if ((flags & NORM_IGNORESYMBOLS) && (get_char_typeW(wch) & (C1_PUNCT | C1_SPACE)))
                continue;
            len++;
        }
		DEBUG_LOG("KERNEL32 LCMapStringEx: END (6)\r\n");
        return len;
    }

    if (flags & LCMAP_UPPERCASE)
    {
        for (dst_ptr = dst; srclen && dstlen; src++, srclen--)
        {
            WCHAR wch = *src;
            if ((flags & NORM_IGNORESYMBOLS) && (get_char_typeW(wch) & (C1_PUNCT | C1_SPACE)))
                continue;
            *dst_ptr++ = toupperW(wch);
            dstlen--;
        }
    }
    else if (flags & LCMAP_LOWERCASE)
    {
        for (dst_ptr = dst; srclen && dstlen; src++, srclen--)
        {
            WCHAR wch = *src;
            if ((flags & NORM_IGNORESYMBOLS) && (get_char_typeW(wch) & (C1_PUNCT | C1_SPACE)))
                continue;
            *dst_ptr++ = tolowerW(wch);
            dstlen--;
        }
    }
    else
    {
        if (src == dst)
        {
            SetLastError(ERROR_INVALID_FLAGS);
			DEBUG_LOG("KERNEL32 LCMapStringEx: END (7)\r\n");
            return 0;
        }
        for (dst_ptr = dst; srclen && dstlen; src++, srclen--)
        {
            WCHAR wch = *src;
            if ((flags & NORM_IGNORESYMBOLS) && (get_char_typeW(wch) & (C1_PUNCT | C1_SPACE)))
                continue;
            *dst_ptr++ = wch;
            dstlen--;
        }
    }

    if (srclen)
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
		DEBUG_LOG("KERNEL32 LCMapStringEx: END (8)\r\n");
        return 0;
    }
	DEBUG_LOG("KERNEL32 LCMapStringEx: END (9)\r\n");
    return dst_ptr - dst;
}
MAKE_FUNC_END

#if 0
//typedef void*(WINAPI *pGetProcAddress)(HMODULE module, const char *proc_name);
extern "C" void* WINAPI _GetProcAddress(HMODULE module, const char *proc_name) {
	DEBUG_LOG("KERNEL32 GetProcAddress: START (");
	DEBUG_LOG((char*)proc_name);
	DEBUG_LOG(")\r\n");

	if(((DWORD)proc_name) >> 16) {
		if (strcmp(proc_name, "FlsGetValue") == 0) {
			return &FlsGetValue;
		} else if (strcmp(proc_name, "FlsSetValue") == 0) {
			return &FlsSetValue;
		} else if (strcmp(proc_name, "FlsAlloc") == 0) {
			return &FlsAlloc;
		} else if (strcmp(proc_name, "LoadLibraryExW") == 0) {
			return &LoadLibraryExW;
		} else if (strcmp(proc_name, "InitializeCriticalSectionEx") == 0) {
			return &InitializeCriticalSectionEx;
		} else if (strcmp(proc_name, "LCMapStringEx") == 0) {
			return &LCMapStringEx;
		} else if (strcmp(proc_name, "EnterCriticalSection") == 0) {
			return &EnterCriticalSection;
		}
	}
	
	// Source: http://www.rohitab.com/discuss/topic/38615-getprocaddress-replacement/
	char *modb = (char *)module;

	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)modb;
	IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)(modb + dos_header->e_lfanew);
	IMAGE_OPTIONAL_HEADER *opt_header = &nt_headers->OptionalHeader;
	IMAGE_DATA_DIRECTORY *exp_entry = (IMAGE_DATA_DIRECTORY *)
		(&opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY *exp_dir = (IMAGE_EXPORT_DIRECTORY *)(modb + exp_entry->VirtualAddress);
	void **func_table = (void **)(modb + exp_dir->AddressOfFunctions);
	WORD *ord_table = (WORD *)(modb + exp_dir->AddressOfNameOrdinals);
	char **name_table = (char **)(modb + exp_dir->AddressOfNames);
	void *address = NULL;

	DWORD i;

	/* is ordinal? */
	if (((DWORD)proc_name >> 16) == 0) {
		WORD ordinal = LOWORD(proc_name);
		DWORD ord_base = exp_dir->Base;
		/* is valid ordinal? */
		if (ordinal < ord_base || ordinal >= ord_base + exp_dir->NumberOfFunctions) {
			DEBUG_LOG("KERNEL32 GetProcAddress: D1\r\n");
			return NULL;
		}
		/* taking ordinal base into consideration */
		address = (void *)(modb + (DWORD)func_table[ordinal - ord_base]);
	}
	else {
		DEBUG_LOG("KERNEL32 GetProcAddress: D2\r\n");
		/* import by name */
		for (i = 0; i < exp_dir->NumberOfNames; i++) {
			/* name table pointers are rvas */
			if (strcmp(proc_name, modb + (DWORD)name_table[i]) == 0)
				address = (void *)(modb + (DWORD)func_table[ord_table[i]]);
		}
	}
	/* is forwarded? */
	if ((char *)address >= (char *)exp_dir &&
		(char *)address < (char *)exp_dir + exp_entry->Size) {
		DEBUG_LOG("KERNEL32 GetProcAddress: D3\r\n");
		char *dll_name, *func_name;
		HMODULE frwd_module;
		dll_name = strdup((char *)address);
		if (!dll_name)
			return NULL;
		address = NULL;
		func_name = strchr(dll_name, '.');
		*func_name++ = 0;

		/* is already loaded? */
		frwd_module = GetModuleHandleA(dll_name);
		if (!frwd_module) {
			DEBUG_LOG("KERNEL32 GetProcAddress: D4\r\n");
			frwd_module = LoadLibraryA(dll_name);
		}
		if (frwd_module) {
			DEBUG_LOG("KERNEL32 GetProcAddress: D5\r\n");
			address = GetProcAddress(frwd_module, func_name);
		}
		free(dll_name);
	}
	DEBUG_LOG("KERNEL32 GetProcAddress: END\r\n");
	return address;
}
#endif

#endif // ADDITIONAL_COMP

#endif //_WIN64
