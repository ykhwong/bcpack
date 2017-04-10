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

#if _WIN64
#else

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
	first_mod = mod = (PLDR_MODULE)NtCurrentPeb()->LoaderData->InLoadOrderModuleList.Flink;
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

static NTSTATUS NTAPI _RtlInitializeCriticalSectionAndSpinCount(PRTL_CRITICAL_SECTION CriticalSection, ULONG SpinCount) {
	//PRTL_CRITICAL_SECTION_DEBUG CritcalSectionDebugData;

	/* First things first, set up the Object */
	CriticalSection->LockCount = -1;
	CriticalSection->RecursionCount = 0;
	CriticalSection->OwningThread = 0;

	//CriticalSection->SpinCount = (NtCurrentPeb()->NumberOfProcessors > 1) ? SpinCount : 0;
	CriticalSection->SpinCount = 0;
	CriticalSection->LockSemaphore = 0;

#if 0
	/* Allocate the Debug Data */
	CritcalSectionDebugData = RtlpAllocateDebugInfo();

	if (!CritcalSectionDebugData)
	{
		/* This is bad! */
		return STATUS_NO_MEMORY;
	}

	/* Set it up */
	CritcalSectionDebugData->Type = RTL_CRITSECT_TYPE;
	CritcalSectionDebugData->ContentionCount = 0;
	CritcalSectionDebugData->EntryCount = 0;
	CritcalSectionDebugData->CriticalSection = CriticalSection;
	CritcalSectionDebugData->Flags = 0;
	CriticalSection->DebugInfo = CritcalSectionDebugData;

	/*
	* Add it to the List of Critical Sections owned by the process.
	* If we've initialized the Lock, then use it. If not, then probably
	* this is the lock initialization itself, so insert it directly.
	*/
	if ((CriticalSection != &RtlCriticalSectionLock) && (RtlpCritSectInitialized)) {
		/* Protect List */
		RtlEnterCriticalSection(&RtlCriticalSectionLock);

		/* Add this one */
		InsertTailList(&RtlCriticalSectionList, &CritcalSectionDebugData->ProcessLocksList);

		/* Unprotect */
		RtlLeaveCriticalSection(&RtlCriticalSectionLock);
	}
	else {
		/* Add it directly */
		InsertTailList(&RtlCriticalSectionList, &CritcalSectionDebugData->ProcessLocksList);
	}
#endif
	return 1;
}


#if WIN2K_COMP
MAKE_FUNC_READY(EncodePointer, IsXpOrHigher_2K, "KERNEL32.DLL", PVOID, PVOID ptr)
MAKE_FUNC_BEGIN(EncodePointer, ptr)  {
	return (PVOID)((UINT_PTR)ptr ^ 0xDEADBEEF);
}
MAKE_FUNC_END


MAKE_FUNC_READY(DecodePointer, IsXpOrHigher_2K, "KERNEL32.DLL", PVOID, PVOID ptr)
MAKE_FUNC_BEGIN(DecodePointer, ptr) {
	return (PVOID)((UINT_PTR)ptr ^ 0xDEADBEEF);
}
MAKE_FUNC_END


MAKE_FUNC_READY(InitializeSListHead, IsXpOrHigher_2K, "KERNEL32.DLL", VOID, PSLIST_HEADER list)
MAKE_FUNC_BEGIN(InitializeSListHead, list) {
	RtlZeroMemory(list, sizeof(SLIST_HEADER));
}
MAKE_FUNC_END


MAKE_FUNC_READY(GetModuleHandleExW, IsXpOrHigher_2K, "KERNEL32.DLL", BOOL, DWORD dwFlags, PWSTR lpModuleName, HMODULE *phModule)
MAKE_FUNC_BEGIN(GetModuleHandleExW, dwFlags, lpModuleName, phModule) {
		_LoaderLock(TRUE);
		if (dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)
			*phModule = _GetModuleHandleFromPtr(lpModuleName);
		else
			*phModule = GetModuleHandleW(lpModuleName);

		if (*phModule == NULL) {
			_LoaderLock(FALSE);
			return FALSE;
		}

		if (!(dwFlags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT) ||
			dwFlags & GET_MODULE_HANDLE_EX_FLAG_PIN) {
			_IncLoadCount(*phModule);
		}
		_LoaderLock(FALSE);
		return TRUE;
}
MAKE_FUNC_END


MAKE_FUNC_READY(InterlockedFlushSList, IsXpOrHigher_2K, "KERNEL32.DLL", PSLIST_ENTRY, PSLIST_HEADER list)
MAKE_FUNC_BEGIN(InterlockedFlushSList, list) {
	SLIST_HEADER OldHeader, NewHeader;
	ULONGLONG Compare;

	/* Read the header */
	OldHeader = *list;

	do {
		/* Check for empty list */
		if (OldHeader.Next.Next == NULL) {
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
	return OldHeader.Next.Next;
}
MAKE_FUNC_END


MAKE_FUNC_READY(InterlockedPushEntrySList, IsXpOrHigher_2K, "KERNEL32.DLL", PSLIST_ENTRY, PSLIST_HEADER ListHead, PSLIST_ENTRY ListEntry)
MAKE_FUNC_BEGIN(InterlockedPushEntrySList, ListHead, ListEntry) {
	PVOID PrevValue;

	do {
		PrevValue = ListHead->Next.Next;
		ListEntry->Next = (_SINGLE_LIST_ENTRY *)PrevValue;
	} while (_InterlockedCompareExchangePointer((PVOID*)&ListHead->Next.Next,
		ListEntry,
		PrevValue) != PrevValue);

	return (PSLIST_ENTRY)PrevValue;
}
MAKE_FUNC_END
#endif // WIN2K_COMP

#if WIN98_COMP
MAKE_FUNC_READY(SetFilePointerEx, Is2kOrHigher_98MENT, "KERNEL32.DLL", BOOL, HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)
MAKE_FUNC_BEGIN(SetFilePointerEx, hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod) {
	return SetFilePointer(hFile, liDistanceToMove.LowPart, &liDistanceToMove.HighPart, dwMoveMethod);
}
MAKE_FUNC_END
#endif // WIN98_COMP




#if WIN95_COMP
MAKE_FUNC_READY(IsDebuggerPresent, Is98OrHigher_95, "KERNEL32.DLL", BOOL, VOID)
MAKE_FUNC_BEGIN(IsDebuggerPresent, ) {
	return (BOOL)NtCurrentPeb()->BeingDebugged;
}
MAKE_FUNC_END


MAKE_FUNC_READY(FindFirstFileExA, Is98OrHigher_95, "KERNEL32.DLL", HANDLE, IN LPCSTR lpFileName, IN FINDEX_INFO_LEVELS fInfoLevelId, OUT LPVOID lpFindFileData, IN FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, IN DWORD dwAdditionalFlags)
MAKE_FUNC_DUMMY(FindFirstFileExA, INVALID_HANDLE_VALUE, lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags)




MAKE_FUNC_READY(FindFirstFileExW, Is98OrHigher_95, "KERNEL32.DLL", HANDLE, IN LPCWSTR lpFileName, IN FINDEX_INFO_LEVELS fInfoLevelId, OUT LPVOID lpFindFileData, IN FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, IN DWORD dwAdditionalFlags)
MAKE_FUNC_DUMMY(FindFirstFileExW, INVALID_HANDLE_VALUE, lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags)


#define cpuid(func,a,b,c,d)\
    __asm mov eax, func\
    __asm cpuid\
    __asm mov a, eax\
    __asm mov b, ebx\
    __asm mov c, ecx\
    __asm mov d, edx


MAKE_FUNC_READY(IsProcessorFeaturePresent, Is98OrHigher_95, "KERNEL32.DLL", BOOL, IN DWORD ProcessorFeature)
MAKE_FUNC_BEGIN(IsProcessorFeaturePresent, ProcessorFeature) {
	if (ProcessorFeature >= 64) return FALSE;
	if (ProcessorFeature == PF_XMMI64_INSTRUCTIONS_AVAILABLE) {
		uintptr_t a, b, c, d;
		cpuid(1, a, b, c, d);
		if ((d >> 26) & 1) {
			return true;
		}
	}
	//return ((BOOL)(SHARED_DATA->ProcessorFeatures[ProcessorFeature]));
	return false;
}
MAKE_FUNC_END



MAKE_FUNC_READY(InitializeCriticalSectionAndSpinCount, Is98OrHigher_95, "KERNEL32.DLL", BOOL, OUT LPCRITICAL_SECTION lpCriticalSection, IN DWORD dwSpinCount)
MAKE_FUNC_BEGIN(InitializeCriticalSectionAndSpinCount, lpCriticalSection, dwSpinCount) {
	NTSTATUS Status;

	/* Initialize the critical section */
	Status = _RtlInitializeCriticalSectionAndSpinCount(lpCriticalSection,
		dwSpinCount);
	if (!NT_SUCCESS(Status)) {
		/* Set failure code */
		//BaseSetLastNTError(Status);
		SetLastError(Status);
		return FALSE;
	}

	/* Success */
	return TRUE;
}
MAKE_FUNC_END

MAKE_FUNC_READY(GetFileAttributesExW, Is98OrHigher_95, "KERNEL32.DLL", BOOL, LPCWSTR name, GET_FILEEX_INFO_LEVELS level, LPVOID ptr)
MAKE_FUNC_DUMMY(GetFileAttributesExW, TRUE, name, level, ptr)
#endif // WIN95_COMP

#if DEBUG_COMP
static NTSTATUS WINAPI _RtlQueryHeapInformation(HANDLE heap, HEAP_INFORMATION_CLASS info_class, PVOID info, SIZE_T size_in, PSIZE_T size_out) {
	switch (info_class) {
	case HeapCompatibilityInformation:
		if (size_out) *size_out = sizeof(ULONG);

		if (size_in < sizeof(ULONG))
			return ((NTSTATUS)0xC0000023L);

		*(ULONG *)info = 0; /* standard heap */
		return 1;

	default:
		//FIXME("Unknown heap information class %u\n", info_class);
		return ((NTSTATUS)0xC0000003);
	}
}


MAKE_FUNC_READY(HeapQueryInformation, IsXpOrHigher_2K, "KERNEL32.DLL", BOOL, HANDLE HeapHandle, HEAP_INFORMATION_CLASS HeapInformationClass, PVOID HeapInformation OPTIONAL, SIZE_T HeapInformationLength OPTIONAL, PSIZE_T ReturnLength OPTIONAL)
MAKE_FUNC_BEGIN(HeapQueryInformation, HeapHandle, HeapInformationClass, HeapInformation, HeapInformationLength, ReturnLength)
NTSTATUS Status;
Status = _RtlQueryHeapInformation(HeapHandle, HeapInformationClass, HeapInformation, HeapInformationLength, ReturnLength);

if (!NT_SUCCESS(Status)) {
	//BaseSetLastNTError(Status);
	return FALSE;
}

return TRUE;
MAKE_FUNC_END
#endif // DEBUG_COMP


#if ADDITIONAL_COMP
MAKE_FUNC_READY(GetModuleHandleExA, IsXpOrHigher_2K, "KERNEL32.DLL", BOOL, DWORD dwFlags, PWSTR lpModuleName, HMODULE *phModule)
MAKE_FUNC_BEGIN(GetModuleHandleExA, dwFlags, lpModuleName, phModule) {
	BOOL ret;
	UNICODE_STRING unicode;
	STRING ansi;
	if (!(dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) && lpModuleName) {
		_RtlInitString(&ansi, (PCSZ)lpModuleName);
		//TED
		_RtlAnsiStringToUnicodeString(&unicode, &ansi, TRUE);
		ret = _GetModuleHandleExW(dwFlags, unicode.Buffer, phModule);
		_RtlFreeUnicodeString(&unicode);
		return ret;
	}
	return false;
}
MAKE_FUNC_END


MAKE_FUNC_READY(InterlockedPopEntrySList, IsXpOrHigher_2K, "KERNEL32.DLL", PSLIST_ENTRY, PSLIST_HEADER list)
MAKE_FUNC_BEGIN(InterlockedPopEntrySList, list) {
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
	return Result;
}
MAKE_FUNC_END


MAKE_FUNC_READY(QueryDepthSList, IsXpOrHigher_2K, "KERNEL32.DLL", WORD, PSLIST_HEADER list)
MAKE_FUNC_BEGIN(QueryDepthSList, list) {
	return (USHORT)(list->Alignment & 0xffff);
}
MAKE_FUNC_END


/* From Wine implementation over their unicode library */
MAKE_FUNC_READY(WideCharToMultiByte, Is2kOrHigher_98MENT, "KERNEL32.DLL", INT, UINT page, DWORD flags, LPCWSTR src, INT srclen, LPSTR dst, INT dstlen, LPCSTR defchar, BOOL *used)
MAKE_FUNC_BEGIN(WideCharToMultiByte, page, flags, src, srclen, dst, dstlen, defchar, used) {
	int i;

	if (!src || !srclen || (!dst && dstlen)) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	if (srclen < 0) srclen = strlenW(src) + 1;

	if (!dstlen)
		return srclen;

	for (i = 0; i<srclen && i<dstlen; i++)
		dst[i] = src[i] & 0xFF;

	if (used) *used = FALSE;

	return i;
}
MAKE_FUNC_END


MAKE_FUNC_READY(AttachConsole, IsXpOrHigher_2K, "KERNEL32.DLL", BOOL, DWORD dwProcessId)
MAKE_FUNC_BEGIN(AttachConsole, dwProcessId) {
	if (dwProcessId != GetCurrentProcessId()) {
		//LOG_WARN("AttachConsole does not support other processes");
	}
	//Just make sure we have a console
	AllocConsole();
	return TRUE;
}
MAKE_FUNC_END


MAKE_FUNC_READY(CompareStringW, Is2kOrHigher_98MENT, "KERNEL32.DLL", INT, DWORD lcid, DWORD flags, LPCWSTR str1, INT len1, LPCWSTR str2, INT len2)
MAKE_FUNC_BEGIN(CompareStringW, lcid, flags, str1, len1, str2, len2) {
	static const DWORD supported_flags = NORM_IGNORECASE | NORM_IGNORENONSPACE | NORM_IGNORESYMBOLS | SORT_STRINGSORT
		| NORM_IGNOREKANATYPE | NORM_IGNOREWIDTH | LOCALE_USE_CP_ACP
		| NORM_LINGUISTIC_CASING | LINGUISTIC_IGNORECASE | 0x10000000;
	static DWORD semistub_flags = NORM_LINGUISTIC_CASING | LINGUISTIC_IGNORECASE | 0x10000000;
	/* 0x10000000 is related to diacritics in Arabic, Japanese, and Hebrew */
	INT ret;

	if (!str1 || !str2) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	if (flags & ~supported_flags) {
		SetLastError(ERROR_INVALID_FLAGS);
		return 0;
	}

	if (flags & semistub_flags) {
		//FIXME("semi-stub behavior for flag(s) 0x%x\n", flags & semistub_flags);
		semistub_flags &= ~flags;
	}

	if (len1 < 0) len1 = strlenW(str1);
	if (len2 < 0) len2 = strlenW(str2);

	ret = wine_compare_string(flags, str1, len1, str2, len2);

	if (ret) /* need to translate result */
		return (ret < 0) ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
	return CSTR_EQUAL;
}
MAKE_FUNC_END


MAKE_FUNC_READY(GetFileAttributesExA, IsXpOrHigher_2K, "KERNEL32.DLL", BOOL, LPCSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation)
MAKE_FUNC_BEGIN(GetFileAttributesExA, lpFileName, fInfoLevelId, lpFileInformation) {
	PWCHAR FileNameW;

	if (!(FileNameW = _FilenameA2W(lpFileName, FALSE)))
		return FALSE;
#if WIN98_COMP && !WIN95_COMP
	return FALSE;
#else
	return _GetFileAttributesExW(FileNameW, fInfoLevelId, lpFileInformation);
#endif
}
MAKE_FUNC_END

MAKE_FUNC_READY(GetFileSizeEx, IsXpOrHigher_2K, "KERNEL32.DLL", BOOL, HANDLE file, PLARGE_INTEGER fsize)
MAKE_FUNC_BEGIN(GetFileSizeEx, file, fsize) {
	//if (_fseek((FILE*)file, 0, 2) == -1)
	//	return FALSE;
	//fsize->QuadPart = _ftell((FILE*)file);
	return TRUE;
}
MAKE_FUNC_END


MAKE_FUNC_READY(lstrcmpW, Is2kOrHigher_98MENT, "KERNEL32.DLL", INT, LPCWSTR lpString1, LPCWSTR lpString2)
MAKE_FUNC_BEGIN(lstrcmpW, lpString1, lpString2) {
	int Result;

	if (lpString1 == lpString2)
		return 0;
	if (lpString1 == NULL)
		return -1;
	if (lpString2 == NULL)
		return 1;

	Result = CompareStringW(GetThreadLocale(), 0, lpString1, -1, lpString2, -1);
	if (Result)
		Result -= 2;

	return Result;
}
MAKE_FUNC_END


MAKE_FUNC_READY(lstrlenW, Is2kOrHigher_98MENT, "KERNEL32.DLL", INT, LPCWSTR lpString)
MAKE_FUNC_BEGIN(lstrlenW, lpString) {
	INT Ret = 0;
	Ret = _wcslen(lpString);
	return Ret;
}
MAKE_FUNC_END


MAKE_FUNC_READY(GetLocaleInfoW, Is2kOrHigher_98MENT, "KERNEL32.DLL", INT, LCID lcid, LCTYPE lctype, LPWSTR buffer, INT len)
MAKE_FUNC_DUMMY(GetLocaleInfoW, 1, lcid, lctype, buffer, len)


MAKE_FUNC_READY(GetStringTypeW, Is2kOrHigher_98MENT, "KERNEL32.DLL", BOOL, DWORD type, LPCWSTR src, INT count, LPWORD chartype)
MAKE_FUNC_BEGIN(GetStringTypeW,type, src, count, chartype) {
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
		//WARN("CT_CTYPE3: semi-stub.\n");
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
		return FALSE;
	}
	return TRUE;
}
MAKE_FUNC_END

MAKE_FUNC_READY(InitializeCriticalSectionEx, Is2kOrHigher_98MENT, "KERNEL32.DLL", BOOL, OUT LPCRITICAL_SECTION lpCriticalSection, IN DWORD dwSpinCount, IN DWORD flags)
MAKE_FUNC_BEGIN(InitializeCriticalSectionEx, lpCriticalSection, dwSpinCount, flags) {
	NTSTATUS Status;

    /* Initialize the critical section */
    Status = _RtlInitializeCriticalSectionAndSpinCount(
        (PRTL_CRITICAL_SECTION)lpCriticalSection,
        dwSpinCount);
    if (!NT_SUCCESS(Status)) {
		//BaseSetLastNTError(Status);
		SetLastError(Status);
        return FALSE;
    }

    /* Success */
    return TRUE;
}
MAKE_FUNC_END

MAKE_FUNC_READY(LeaveCriticalSection, Is2kOrHigher_98MENT, "KERNEL32.DLL", NTSTATUS, PRTL_CRITICAL_SECTION CriticalSection)
MAKE_FUNC_BEGIN(LeaveCriticalSection, CriticalSection) {
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
	return 1;
}
MAKE_FUNC_END

MAKE_FUNC_READY(EnterCriticalSection, Is2kOrHigher_98MENT, "KERNEL32.DLL", NTSTATUS, PRTL_CRITICAL_SECTION CriticalSection)
MAKE_FUNC_BEGIN(EnterCriticalSection, CriticalSection) {
	HANDLE Thread = (HANDLE)NtCurrentTeb()->ClientId.UniqueThread;  
  if (InterlockedIncrement(&CriticalSection->LockCount) != 0) {  
     if (Thread == CriticalSection->OwningThread) {  
       CriticalSection->RecursionCount++;  
       return 1;
     }
	 //RtlpWaitForCriticalSection(CriticalSection);  
  }  
   CriticalSection->OwningThread = Thread;  
   CriticalSection->RecursionCount = 1;  
   return 1;
}  
MAKE_FUNC_END


MAKE_FUNC_READY(GetCurrentProcess, Is2kOrHigher_98MENT, "KERNEL32.DLL", HANDLE, VOID)
MAKE_FUNC_BEGIN(GetCurrentProcess, ) {
	//return (HANDLE)((HANDLE)-1);
	return (HANDLE)~(ULONG_PTR)0;
}
MAKE_FUNC_END


MAKE_FUNC_READY(SetUnhandledExceptionFilter, Is2kOrHigher_98MENT, "KERNEL32.DLL", LPTOP_LEVEL_EXCEPTION_FILTER, IN LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
MAKE_FUNC_BEGIN(SetUnhandledExceptionFilter, lpTopLevelExceptionFilter) {
	LPTOP_LEVEL_EXCEPTION_FILTER GlobalTopLevelExceptionFilter;
	PVOID EncodedPointer, EncodedOldPointer;

    EncodedPointer = _EncodePointer(lpTopLevelExceptionFilter);
    EncodedOldPointer = InterlockedExchangePointer((PVOID*)&GlobalTopLevelExceptionFilter,
                                            EncodedPointer);
    return (LPTOP_LEVEL_EXCEPTION_FILTER)_DecodePointer(EncodedOldPointer);
}
MAKE_FUNC_END


MAKE_FUNC_READY(UnhandledExceptionFilter, Is2kOrHigher_98MENT, "KERNEL32.DLL", LONG, IN PEXCEPTION_POINTERS ExceptionInfo)
MAKE_FUNC_BEGIN(UnhandledExceptionFilter, ExceptionInfo) {
	return EXCEPTION_CONTINUE_EXECUTION;
}
MAKE_FUNC_END


MAKE_FUNC_READY(LoadLibraryExW, Is2kOrHigher_98MENT, "KERNEL32.DLL", HMODULE, LPCWSTR libnameW, HANDLE hfile, DWORD flags)
MAKE_FUNC_BEGIN(LoadLibraryExW, libnameW, hfile, flags) {
	//LoadLibraryEx(libnameW, hfile, flags);
	//return LoadLibraryExA((LPCSTR)libnameW, hfile, flags);
	return LoadLibrary(libnameW);
	//return LoadLibraryA((LPCSTR)libnameW);
}
MAKE_FUNC_END

#endif // ADDITIONAL_COMP

#endif //_WIN64