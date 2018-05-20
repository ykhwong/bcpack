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
#include "util.h"
#include "debug.h"

#if _WIN64
#else

#if ADDITIONAL_COMP
// LIBTBB
static VOID WINAPI _GetSystemInfoInternal(IN PSYSTEM_BASIC_INFORMATION BasicInfo,
	IN PSYSTEM_PROCESSOR_INFORMATION ProcInfo,
	OUT LPSYSTEM_INFO SystemInfo) {
	RtlZeroMemory(SystemInfo, sizeof(SYSTEM_INFO));
	SystemInfo->wProcessorArchitecture = ProcInfo->ProcessorArchitecture;
	SystemInfo->wReserved = 0;
	SystemInfo->dwPageSize = BasicInfo->PageSize;
	SystemInfo->lpMinimumApplicationAddress = (PVOID)BasicInfo->MinimumUserModeAddress;
	SystemInfo->lpMaximumApplicationAddress = (PVOID)BasicInfo->MaximumUserModeAddress;
	SystemInfo->dwActiveProcessorMask = BasicInfo->ActiveProcessorsAffinityMask;
	SystemInfo->dwNumberOfProcessors = BasicInfo->NumberOfProcessors;
	SystemInfo->wProcessorLevel = ProcInfo->ProcessorLevel;
	SystemInfo->wProcessorRevision = ProcInfo->ProcessorRevision;
	SystemInfo->dwAllocationGranularity = BasicInfo->AllocationGranularity;

	switch (ProcInfo->ProcessorArchitecture) {
	case PROCESSOR_ARCHITECTURE_INTEL:
		switch (ProcInfo->ProcessorLevel) {
		case 3: SystemInfo->dwProcessorType = PROCESSOR_INTEL_386; break;
		case 4: SystemInfo->dwProcessorType = PROCESSOR_INTEL_486; break;
		default: SystemInfo->dwProcessorType = PROCESSOR_INTEL_PENTIUM;
		}
		break;
	case PROCESSOR_ARCHITECTURE_AMD64: SystemInfo->dwProcessorType = PROCESSOR_AMD_X8664; break;
	case PROCESSOR_ARCHITECTURE_IA64: SystemInfo->dwProcessorType = PROCESSOR_INTEL_IA64; break;
	default: SystemInfo->dwProcessorType = 0; break;
	}

	if (0x00030033 > GetProcessVersion(0)) {
		SystemInfo->wProcessorLevel = 0;
		SystemInfo->wProcessorRevision = 0;
	}
}

MAKE_FUNC_READY(RtlFreeUnicodeString, Is98OrHigher_95, "NTDLL.DLL", VOID, IN PUNICODE_STRING UnicodeString)
MAKE_FUNC_BEGIN(RtlFreeUnicodeString, UnicodeString) {
	DEBUG_LOG("NTDLL RtlFreeUnicodeString: START\r\n");
	if (UnicodeString->Buffer) {
		//RtlpFreeMemory(UnicodeString->Buffer, TAG_USTR);
		RtlZeroMemory(UnicodeString, sizeof(UNICODE_STRING));
	}
	DEBUG_LOG("NTDLL RtlFreeUnicodeString: END\r\n");
}
MAKE_FUNC_END


MAKE_FUNC_READY(RtlInitString, Is98OrHigher_95, "NTDLL.DLL", VOID, IN OUT PSTRING DestinationString, IN PCSZ SourceString)
MAKE_FUNC_BEGIN(RtlInitString, DestinationString, SourceString) {
	DEBUG_LOG("NTDLL RtlInitString: START\r\n");
	SIZE_T Size;

	if (SourceString) {
		Size = strlen(SourceString);
		if (Size > (0xffff - sizeof(CHAR))) Size = 0xffff - sizeof(CHAR);
		DestinationString->Length = (USHORT)Size;
		DestinationString->MaximumLength = (USHORT)Size + sizeof(CHAR);
	}
	else {
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PCHAR)SourceString;
	DEBUG_LOG("NTDLL RtlInitString: END\r\n");
}
MAKE_FUNC_END


MAKE_FUNC_READY(RtlInitAnsiString, Is2kOrHigher_98MENT, "NTDLL.DLL", VOID, PANSI_STRING target, PCSZ source)
MAKE_FUNC_BEGIN(RtlInitAnsiString, target, source) {
	DEBUG_LOG("NTDLL RtlInitAnsiString: START\r\n");
	if ((target->Buffer = (PCHAR)source)) {
		target->Length = (USHORT)strlen(source);
		target->MaximumLength = target->Length + 1;
	}
	else
		target->Length = target->MaximumLength = 0;
	DEBUG_LOG("NTDLL RtlInitAnsiString: END\r\n");
}
MAKE_FUNC_END


MAKE_FUNC_READY(RtlAnsiStringToUnicodeString, Is98OrHigher_95, "NTDLL.DLL", NTSTATUS, IN OUT PUNICODE_STRING UniDest, IN PANSI_STRING AnsiSource, IN BOOLEAN AllocateDestinationString)
MAKE_FUNC_DUMMY(RtlAnsiStringToUnicodeString, ((NTSTATUS)0xC0000002), UniDest, AnsiSource, AllocateDestinationString)


MAKE_FUNC_READY(NtQuerySystemInformation, Is98OrHigher_95, "NTDLL.DLL", NTSTATUS, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Inout_   PVOID                    SystemInformation, _In_      ULONG                    SystemInformationLength,	_Out_opt_ PULONG                   ReturnLength)
MAKE_FUNC_DUMMY(NtQuerySystemInformation, ((NTSTATUS)0xC0000002), SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength)


MAKE_FUNC_READY(GetNativeSystemInfo, IsXpOrHigher_2K, "NTDLL.DLL", VOID, LPSYSTEM_INFO lpSystemInfo)
MAKE_FUNC_BEGIN(GetNativeSystemInfo, lpSystemInfo) {
	DEBUG_LOG("NTDLL GetNativeSystemInfo: START\r\n");
	SYSTEM_BASIC_INFORMATION BasicInfo;
	SYSTEM_PROCESSOR_INFORMATION ProcInfo;
	NTSTATUS Status;

	//TED
	Status = _NtQuerySystemInformation(SystemBasicInformation, &BasicInfo, sizeof(BasicInfo), 0);
	if (!NT_SUCCESS(Status)) {
		DEBUG_LOG("NTDLL GetNativeSystemInfo: END (1)\r\n");
		return;
	}
	//TED
	Status = _NtQuerySystemInformation(SystemProcessorInformation, &ProcInfo, sizeof(ProcInfo), 0);
	if (!NT_SUCCESS(Status)) {
		DEBUG_LOG("NTDLL GetNativeSystemInfo: END (2)\r\n");
		return;
	}
	_GetSystemInfoInternal(&BasicInfo, &ProcInfo, lpSystemInfo);
	DEBUG_LOG("NTDLL GetNativeSystemInfo: END (3)\r\n");
}
MAKE_FUNC_END


#endif // ADDITIONAL_COMP

#endif // _WIN64
