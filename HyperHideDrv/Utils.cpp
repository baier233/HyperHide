#pragma warning( disable : 4201)
#include <ntifs.h>
#include <ntimage.h>
#include "Ntapi.h"
#include "Utils.h"
#include "Log.h"
#include "GlobalData.h"
#include "Peb.h"

extern HYPER_HIDE_GLOBAL_DATA g_HyperHide;

NTAPI_OFFSETS NtapiOffsets;

INT64(__fastcall* MiGetPteAddress)(UINT64);

BOOLEAN RtlUnicodeStringContains(PUNICODE_STRING Str, PUNICODE_STRING SubStr, BOOLEAN CaseInsensitive)
{
	if (Str == NULL || SubStr == NULL || Str->Length < SubStr->Length)
		return FALSE;

	CONST USHORT NumCharsDiff = (Str->Length - SubStr->Length) / sizeof(WCHAR);
	UNICODE_STRING Slice = *Str;
	Slice.Length = SubStr->Length;

	for (USHORT i = 0; i <= NumCharsDiff; ++i, ++Slice.Buffer, Slice.MaximumLength -= sizeof(WCHAR))
	{
		if (RtlEqualUnicodeString(&Slice, SubStr, CaseInsensitive))
			return TRUE;
	}
	return FALSE;
}

BOOLEAN RtlStringContains(PSTRING Str, PSTRING SubStr, BOOLEAN CaseInsensitive) 
{
	if (Str == NULL || SubStr == NULL || Str->Length < SubStr->Length)
		return FALSE;

	CONST USHORT NumCharsDiff = (Str->Length - SubStr->Length);
	STRING Slice = *Str;
	Slice.Length = SubStr->Length;

	for (USHORT i = 0; i <= NumCharsDiff; ++i, ++Slice.Buffer, Slice.MaximumLength -= 1)
	{
		if (RtlEqualString(&Slice, SubStr, CaseInsensitive))
			return TRUE;
	}
	return FALSE;
}

UNICODE_STRING PsQueryFullProcessImageName(PEPROCESS TargetProcess)
{
	UNICODE_STRING TruncatedFullImageName = { 0 };

	__try 
	{
		PUNICODE_STRING FullImageName = (PUNICODE_STRING) * (ULONG64*)((ULONG64)TargetProcess + NtapiOffsets.SeAuditProcessCreationInfoOffset);
		if (FullImageName->Buffer != NULL || FullImageName->Length != 0)
		{
			for (size_t i = FullImageName->Length / 2; i > 0; i--)
			{
				if (FullImageName->Buffer[i] == L'\\')
				{
					RtlInitUnicodeString(&TruncatedFullImageName, &FullImageName->Buffer[i + 1]);
					break;
				}
			}
		}
	}

	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	return TruncatedFullImageName;
}

PEPROCESS GetCsrssProcess() 
{
	PEPROCESS Process = 0;

	// Sometimes it doesn't return csrss process at the first try which is strange because it must exist
	do
	{
		Process = GetProcessByName(L"csrss.exe");
	} while (Process == 0);

	return Process;
}

PVOID FindSignature(PVOID Memory, ULONG64 Size, PCSZ Pattern, PCSZ Mask)
{
	ULONG64 SigLength = strlen(Mask);
	if (SigLength > Size) return NULL;

	for (ULONG64 i = 0; i < Size - SigLength; i++)
	{
		BOOLEAN Found = TRUE;
		for (ULONG64 j = 0; j < SigLength; j++)
			Found &= Mask[j] == '?' || Pattern[j] == *((PCHAR)Memory + i + j);

		if (Found)
			return (PCHAR)Memory + i;
	}
	return NULL;
}

ULONG64 GetPteAddress(ULONG64 Address) 
{
	if (g_HyperHide.CurrentWindowsBuildNumber <= WINDOWS_10_VERSION_THRESHOLD2)
	{
		return (ULONG64)(((Address >> 9) & 0x7FFFFFFFF8) - 0x98000000000);
	}
	else 
	{
		if (MiGetPteAddress == NULL) 
		{
			const auto MiGetPteAddressPattern = "\x48\xC1\xE9\x00\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x23\xC8\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xC1\xC3";
			const auto MiGetPteAddressMask = "xxx?xx????????xxxxx????????xxxx";

			ULONG64 KernelTextSectionSize = 0;
			PVOID KernelTextSectionBase = 0;

			if (GetSectionData("ntoskrnl.exe", ".text", KernelTextSectionSize, KernelTextSectionBase) == FALSE)
			{
				LogError("Couldn't get ntoskrnl.exe .text section data");
				return FALSE;
			}

			MiGetPteAddress = (INT64(__fastcall*)(UINT64))FindSignature(KernelTextSectionBase, KernelTextSectionSize, MiGetPteAddressPattern, MiGetPteAddressMask);
			if ((ULONG64)MiGetPteAddress <= (ULONG64)KernelTextSectionBase || (ULONG64)MiGetPteAddress >= (ULONG64)KernelTextSectionBase + KernelTextSectionSize)
			{
				LogError("Couldn't get MiGetPte function address");
				return FALSE;
			}

			LogInfo("MiGetPte address: 0x%llx", MiGetPteAddress);
		}

		return MiGetPteAddress(Address);
	}
}

BOOLEAN GetSectionData(CONST CHAR* ImageName,CONST CHAR* SectionName, ULONG64& SectionSize, PVOID& SectionBaseAddress)
{
	ULONG64 ImageSize = 0;
	PVOID ImageBase = 0;

	if (GetProcessInfo(ImageName,ImageSize, ImageBase) == FALSE)
		return FALSE;

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS32 NtHeader = (PIMAGE_NT_HEADERS32)(DosHeader->e_lfanew + (ULONG64)ImageBase);
	ULONG NumSections = NtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);

	STRING TargetSectionName;
	RtlInitString(&TargetSectionName, SectionName);

	for (ULONG i = 0; i < NumSections; i++)
	{
		STRING CurrentSectionName;
		RtlInitString(&CurrentSectionName, (PCSZ)Section->Name);
		if (CurrentSectionName.Length > 8)
			CurrentSectionName.Length = 8;

		if (RtlCompareString(&CurrentSectionName, &TargetSectionName, FALSE) == 0)
		{
			SectionSize = Section->Misc.VirtualSize;
			SectionBaseAddress = (PVOID)((ULONG64)ImageBase + (ULONG64)Section->VirtualAddress);

			return TRUE;
		}
		Section++;
	}

	return FALSE;
}

BOOLEAN GetProcessInfo(CONST CHAR* Name, ULONG64& ImageSize, PVOID& ImageBase)
{
	ULONG Bytes;
	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &Bytes);
	PSYSTEM_MODULE_INFORMATION Mods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool2(NonPagedPool, Bytes, DRIVER_TAG);
	if (Mods == NULL)
		return FALSE;

	RtlSecureZeroMemory(Mods, Bytes);

	Status = ZwQuerySystemInformation(SystemModuleInformation, Mods, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(Mods,DRIVER_TAG);
		return FALSE;
	}

	STRING TargetProcessName;
	RtlInitString(&TargetProcessName, Name);

	for (ULONG i = 0; i < Mods->ModulesCount; i++)
	{
		STRING CurrentModuleName;
		RtlInitString(&CurrentModuleName, (PCSZ)Mods->Modules[i].FullPathName);

		if (RtlStringContains(&CurrentModuleName, &TargetProcessName, TRUE) != NULL)
		{
			if (Mods->Modules[i].ImageSize != NULL)
			{
				ImageSize = Mods->Modules[i].ImageSize;
				ImageBase = Mods->Modules[i].ImageBase;
				ExFreePoolWithTag(Mods,DRIVER_TAG);
				return TRUE;
			}
		}
	}

	ExFreePoolWithTag(Mods,DRIVER_TAG);
	return FALSE;
}

PEPROCESS GetProcessByName(CONST WCHAR* ProcessName)
{
	NTSTATUS Status;
	ULONG Bytes;

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePool2(NonPagedPool, Bytes, DRIVER_TAG);
	if (ProcInfo == NULL)
		return NULL;

	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE) 
	{
		ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
		return NULL;
	}

	UNICODE_STRING ProcessImageName;
	RtlCreateUnicodeString(&ProcessImageName, ProcessName);

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (Entry->ImageName.Buffer != NULL)
		{
			if (RtlCompareUnicodeString(&Entry->ImageName, &ProcessImageName, TRUE) == 0)
			{
				PEPROCESS CurrentPeprocess = PidToProcess(Entry->ProcessId);
				ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
				return CurrentPeprocess;
			}
		}
	}

	ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
	return NULL;
}

PVOID GetExportedFunctionAddress(PEPROCESS TargetProcess, PVOID ModuleBase, CONST CHAR* ExportedFunctionName)
{
	KAPC_STATE State;
	PVOID FunctionAddress = 0;
	if (TargetProcess != NULL)
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

	do
	{
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
		PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(DosHeader->e_lfanew + (ULONG64)ModuleBase);
		IMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (ImageDataDirectory.Size == 0 || ImageDataDirectory.VirtualAddress == 0)
			break;

		PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModuleBase + ImageDataDirectory.VirtualAddress);
		ULONG* Address = (ULONG*)((ULONG64)ModuleBase + ExportDirectory->AddressOfFunctions);
		ULONG* Name = (ULONG*)((ULONG64)ModuleBase + ExportDirectory->AddressOfNames);
		USHORT* Ordinal = (USHORT*)((ULONG64)ModuleBase + ExportDirectory->AddressOfNameOrdinals);

		STRING TargetExportedFunctionName;
		RtlInitString(&TargetExportedFunctionName, ExportedFunctionName);

		for (size_t i = 0; i < ExportDirectory->NumberOfFunctions; i++)
		{
			STRING CurrentExportedFunctionName;
			RtlInitString(&CurrentExportedFunctionName, (PCHAR)ModuleBase + Name[i]);

			if (RtlCompareString(&TargetExportedFunctionName, &CurrentExportedFunctionName, TRUE) == 0)
			{
				FunctionAddress = (PVOID)((ULONG64)ModuleBase + Address[Ordinal[i]]);
				break;
			}
		}

	} while (0);

	if (TargetProcess != NULL)
		KeUnstackDetachProcess(&State);

	return FunctionAddress;
}

PVOID GetUserModeModule(PEPROCESS TargetProcess, CONST WCHAR* ModuleName, BOOLEAN IsWow64)
{
	if (TargetProcess == NULL)
		return NULL;

	KAPC_STATE State;
	PVOID Address = NULL;
	KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

	UNICODE_STRING TargetModuleName;
	RtlCreateUnicodeString(&TargetModuleName, ModuleName);

	__try
	{
		do
		{
			if (IsWow64 == TRUE)
			{
				PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(TargetProcess);

				for (PLIST_ENTRY32 ListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList.Flink;
					ListEntry != &((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList;
					ListEntry = (PLIST_ENTRY32)ListEntry->Flink)
				{
					PLDR_DATA_TABLE_ENTRY32 Entry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

					UNICODE_STRING CurrentModuleName;
					RtlCreateUnicodeString(&CurrentModuleName, (PWCH)Entry->BaseDllName.Buffer);

					if (RtlCompareUnicodeString(&CurrentModuleName, &TargetModuleName, TRUE) == 0)
					{
						Address = (PVOID)Entry->DllBase;
						break;
					}
				}
			}

			else
			{
				PPEB Peb = PsGetProcessPeb(TargetProcess);

				for (PLIST_ENTRY ListEntry = Peb->Ldr->InLoadOrderModuleList.Flink;
					ListEntry != &Peb->Ldr->InLoadOrderModuleList;
					ListEntry = ListEntry->Flink)
				{
					PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

					UNICODE_STRING CurrentModuleName;
					RtlCreateUnicodeString(&CurrentModuleName, Entry->BaseDllName.Buffer);

					if (RtlCompareUnicodeString(&CurrentModuleName, &TargetModuleName, TRUE) == 0)
					{
						Address = Entry->DllBase;
						break;
					}
				}
			}

		} while (0);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	KeUnstackDetachProcess(&State);
	return Address;
}

BOOLEAN ClearBypassProcessFreezeFlag(PEPROCESS TargetProcess)
{
	NTSTATUS Status;
	ULONG Bytes;

	if (g_HyperHide.CurrentWindowsBuildNumber < WINDOWS_10_VERSION_19H1)
	{
		LogError("This flag doesn't exit on this version of windows");
		return FALSE;
	}

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePool2(NonPagedPool, Bytes, DRIVER_TAG);

	if (ProcInfo == NULL)
		return FALSE; 

	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
		return FALSE;
	}

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (PidToProcess(Entry->ProcessId) == TargetProcess)
		{
			for (size_t i = 0; i < Entry->NumberOfThreads; i++)
			{
				PETHREAD Thread;
				Status = PsLookupThreadByThreadId(Entry->Threads[i].ClientId.UniqueThread, (PETHREAD*)&Thread);

				if (NT_SUCCESS(Status) == TRUE) {
					*(ULONG*)((ULONG64)Thread + NtapiOffsets.BypassProcessFreezeFlagOffset) &= ~(1 << 21);
					ObDereferenceObject(Thread);
				}
			}

			ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
			return TRUE;
		}
	}

	ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
	return FALSE;
}
#include "HookedFunctions.h"
#ifdef _M_AMD64
#define PS_THREAD_SEARCH_START                  0x400
#else
#define PS_THREAD_SEARCH_START                  0x200
#endif

// 'Terminated' and 'HideFromDebugger' flags in ETHREAD's CrossThreadFlags. Other flags can't be used as they have changed between versions
#define PS_CROSS_THREAD_FLAGS_TERMINATED        0x00000001UL
#define PS_CROSS_THREAD_FLAGS_HIDEFROMDBG       0x00000004UL

BOOLEAN ClearThreadHideFromDebuggerFlag(PEPROCESS TargetProcess)
{
	NTSTATUS Status;
	ULONG Bytes;

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePool2(NonPagedPool, Bytes, DRIVER_TAG);

	if (ProcInfo == NULL)
		return FALSE;
	
	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
		return FALSE;
	}

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (PidToProcess(Entry->ProcessId) == TargetProcess)
		{
			for (size_t i = 0; i < Entry->NumberOfThreads; i++)
			{
				PETHREAD Thread;
				Status = PsLookupThreadByThreadId(Entry->Threads[i].ClientId.UniqueThread, (PETHREAD*)&Thread);

				if(NT_SUCCESS(Status))
				{
					LONG* CrossThreadFlagsAddress = (LONG*)((ULONG_PTR)Thread + NtapiOffsets.ThreadHideFromDebuggerFlagOffset);

					if ((InterlockedAnd(CrossThreadFlagsAddress, ~PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) != 0)
					{
						Hider::PHIDDEN_THREAD HiddenThread = Hider::AppendThreadList(TargetProcess, Thread);
						if (HiddenThread != NULL)
							HiddenThread->IsThreadHidden = TRUE;

					}

					ObDereferenceObject(Thread);
				}
			}

			ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
			return TRUE;
		}
	}

	ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
	return FALSE;
}

BOOLEAN ClearProcessBreakOnTerminationFlag(Hider::PHIDDEN_PROCESS HiddenProcess) 
{
	HANDLE ProcessHandle;
	if (ObOpenObjectByPointer(HiddenProcess->DebuggedProcess, OBJ_KERNEL_HANDLE, NULL, NULL, *PsProcessType, KernelMode, &ProcessHandle) >= 0)
	{
		ULONG BreakOnTermination;
		if (ZwQueryInformationProcess(ProcessHandle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG), NULL) >= 0)
		{
			HiddenProcess->ValueProcessBreakOnTermination = BreakOnTermination & 1;

			BreakOnTermination = 0;
			if (ZwSetInformationProcess(ProcessHandle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG)) >= 0)
				return TRUE;
		}

		ObCloseHandle(ProcessHandle, KernelMode);
	}

	return FALSE;
}

VOID SaveProcessDebugFlags(Hider::PHIDDEN_PROCESS HiddenProcess)
{
	HANDLE ProcessHandle;
	if (ObOpenObjectByPointer(HiddenProcess->DebuggedProcess, OBJ_KERNEL_HANDLE, NULL, NULL, *PsProcessType, KernelMode, &ProcessHandle) >= 0)
	{
		ULONG DebugFlags;
		if (ZwQueryInformationProcess(ProcessHandle, ProcessDebugFlags, &DebugFlags, sizeof(ULONG), NULL) >= 0 && PsIsProcessBeingDebugged(HiddenProcess->DebuggedProcess) == FALSE)
		{
			HiddenProcess->ValueProcessDebugFlags = !DebugFlags;
		}

		ObCloseHandle(ProcessHandle, KernelMode);
	}
}

VOID SaveProcessHandleTracing(Hider::PHIDDEN_PROCESS HiddenProcess)
{
	HANDLE ProcessHandle;
	if (ObOpenObjectByPointer(HiddenProcess->DebuggedProcess, OBJ_KERNEL_HANDLE, NULL, NULL, *PsProcessType, KernelMode, &ProcessHandle) >= 0)
	{
		ULONG64 ProcessInformationBuffer[2] = { 0 };
		
		NTSTATUS Status = ZwQueryInformationProcess(ProcessHandle, ProcessHandleTracing, &ProcessInformationBuffer[0], 16, NULL);
		if(Status == STATUS_SUCCESS)
			HiddenProcess->ProcessHandleTracingEnabled = 1;
		else if(Status == STATUS_INVALID_PARAMETER)
			HiddenProcess->ProcessHandleTracingEnabled = 0;

		ObCloseHandle(ProcessHandle, KernelMode);
	}
}

BOOLEAN ClearThreadBreakOnTerminationFlags(PEPROCESS TargetProcess)
{
	NTSTATUS Status;
	ULONG Bytes;

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePool2(NonPagedPool, Bytes, DRIVER_TAG);
	if (ProcInfo == NULL)
		return FALSE;

	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
		return FALSE;
	}

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (PidToProcess(Entry->ProcessId) == TargetProcess)
		{
			for (size_t i = 0; i < Entry->NumberOfThreads; i++)
			{
				PETHREAD Thread;
				if (PsLookupThreadByThreadId(Entry->Threads[i].ClientId.UniqueThread, (PETHREAD*)&Thread) >= 0) 
				{
					if (*(ULONG*)((ULONG64)Thread + NtapiOffsets.ThreadBreakOnTerminationFlagOffset) & 0x20)
					{
						Hider::PHIDDEN_THREAD HiddenThread = Hider::AppendThreadList(TargetProcess, Thread);
						if (HiddenThread != NULL)
						{
							HiddenThread->BreakOnTermination = TRUE;

							*(ULONG*)((ULONG64)Thread + NtapiOffsets.ThreadBreakOnTerminationFlagOffset) &= ~0x20;

							ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
							return TRUE;
						}
					}
				}
			}
		}
	}

	ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
	return FALSE;
}

BOOLEAN IsPicoContextNull(PETHREAD TargetThread) 
{
	if (g_HyperHide.CurrentWindowsBuildNumber < WINDOWS_8_1)
		return TRUE;
	else
		return !(*(ULONG64*)((ULONG64)TargetThread + NtapiOffsets.PicoContextOffset));
}

BOOLEAN IsSetThreadContextRestricted(PEPROCESS TargetProcess) 
{
	if (g_HyperHide.CurrentWindowsBuildNumber < WINDOWS_10_VERSION_REDSTONE2)
		return FALSE;
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE2)
		return *(ULONG*)((ULONG64)TargetProcess + NtapiOffsets.RestrictSetThreadContextOffset) & 0x2 ? TRUE : FALSE;
	else
		return *(ULONG*)((ULONG64)TargetProcess + NtapiOffsets.RestrictSetThreadContextOffset) & 0x20000 ? TRUE : FALSE;
}




#include "Ntstructs.h"

NTSTATUS ReferenceProcessByName(_Outptr_ PEPROCESS* Process, _In_ PUNICODE_STRING ProcessName)
{
	ULONG Size;
	if (Undocumented::ZwQuerySystemInformation(SystemProcessInformation, nullptr, 0, &Size) != STATUS_INFO_LENGTH_MISMATCH)
		return STATUS_UNSUCCESSFUL;
	const PSYSTEM_PROCESS_INFO SystemProcessInfo =
		(PSYSTEM_PROCESS_INFO)ExAllocatePool2(NonPagedPool, 2 * Size, 'croP');
	if (SystemProcessInfo == nullptr)
		return STATUS_NO_MEMORY;
	NTSTATUS Status = Undocumented::ZwQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, 2 * Size, nullptr);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(SystemProcessInfo);
		return Status;
	}

	PSYSTEM_PROCESS_INFO Entry = SystemProcessInfo;
	Status = STATUS_NOT_FOUND;

	while (true)
	{
		if (Entry->ImageName.Buffer != nullptr &&
			RtlCompareUnicodeString(&Entry->ImageName, ProcessName, TRUE) == 0)
		{
			Status = PsLookupProcessByProcessId(Entry->ProcessId, Process);
			if (NT_SUCCESS(Status))
				break;
		}

		if (Entry->NextEntryOffset == 0)
			break;

		Entry = (PSYSTEM_PROCESS_INFO)((ULONG_PTR)Entry + Entry->NextEntryOffset);
	}
	ExFreePoolWithTag(SystemProcessInfo, 'croP');

	return Status;
}



NTSTATUS FindCrossThreadFlagsOffset(_Out_ PULONG Offset)
{
	*Offset = 0;

	UNICODE_STRING SvchostName = RTL_CONSTANT_STRING(L"svchost.exe");
	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES((PUNICODE_STRING)nullptr, OBJ_KERNEL_HANDLE);
	PEPROCESS Process = nullptr;
	BOOLEAN Attached = FALSE;
	KAPC_STATE ApcState;
	HANDLE ThreadHandle = nullptr;
	PETHREAD Thread = nullptr;
	ULONG LastMatchFound = 0, MatchesFound = 0;
	ULONG_PTR End;

	// If we are on XP/2003, skip finding the offset dynamically since NtCreateThreadEx was only added in Vista.
	// (NtCreateThread requires elaborate setup of the user mode context, whereas NtCreateThreadEx will work with a NULL thread start address.)
	// Fortunately we can just return hardcoded offsets for these OSes since they will never be updated again
	const ULONG BuildNumber = NtBuildNumber & 0xFFFF;
	if (BuildNumber < 6000)
	{
		if (BuildNumber != 3790
#if defined(_X86_)
			&& BuildNumber != 2600
#endif
			)
		{
			return STATUS_NOT_SUPPORTED;
		}

#ifdef _M_AMD64
		* Offset = 0x3FC;
#elif defined(_X86_)
		*Offset = BuildNumber == 3790 ? 0x240 : 0x248;
#endif
		return STATUS_SUCCESS;
	}

	// Since the ETHREAD struct is opaque and we don't know its size, allocate for 4K possible offsets
	const PULONG CandidateOffsets = (PULONG)ExAllocatePool2(NonPagedPool, PAGE_SIZE * sizeof(ULONG), 'drhT');
	if (CandidateOffsets == nullptr)
		return STATUS_NO_MEMORY;

	// Because on the first scan, a viable candidate for CrossThreadFlags may in fact have value 0, initialize to -1 instead
	RtlFillMemory(CandidateOffsets, sizeof(ULONG) * PAGE_SIZE, (ULONG)-1);

	// Find and attach to a random svchost.exe, because we cannot make user mode threads in the system process
	NTSTATUS Status = ReferenceProcessByName(&Process, &SvchostName);
	if (!NT_SUCCESS(Status))
		goto Exit;

	KeStackAttachProcess(Process, &ApcState);
	Attached = TRUE;

	// Create a dummy thread
	Status = Undocumented::ZwCreateThreadEx(&ThreadHandle,
		THREAD_SET_INFORMATION,
		&ObjectAttributes,
		NtCurrentProcess(),
		nullptr,
		nullptr,
		0x00000001, //THREAD_CREATE_FLAGS_CREATE_SUSPENDED
		0,
		0,
		0,
		nullptr);
	if (!NT_SUCCESS(Status))
		goto Exit;

	Status = ObReferenceObjectByHandle(ThreadHandle,
		THREAD_SET_INFORMATION,
		*PsThreadType,
		KernelMode,
		(PVOID*)&Thread,
		nullptr);
	if (!NT_SUCCESS(Status))
		goto Exit;

	// We now have a freshly created thread with a minimal amount of noise in its ETHREAD, and two predictable values
	// in its CrossThreadFlags: we know that the thread has neither the Terminated nor the ThreadHideFromDebugger bit set.

	End = ALIGN_UP_BY(Thread, PAGE_SIZE) - (ULONG_PTR)Thread;
	for (ULONG_PTR i = PS_THREAD_SEARCH_START; i < End; i += sizeof(ULONG))
	{
		const ULONG Candidate = *(ULONG*)((PUCHAR)Thread + i);
		if ((Candidate & PS_CROSS_THREAD_FLAGS_TERMINATED) == 0 &&
			(Candidate & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) == 0)
		{
			CandidateOffsets[i] = Candidate;
		}
	}

	// Set the flag we are looking for
	Status = ZwSetInformationThread(ThreadHandle, ThreadHideFromDebugger, nullptr, 0);
	if (!NT_SUCCESS(Status))
		goto Exit;

	// Go over the offsets again and see if we can find any values that have not changed except for the addition of this flag
	for (ULONG_PTR i = PS_THREAD_SEARCH_START; i < End; i += sizeof(ULONG))
	{
		if (CandidateOffsets[i] == (ULONG)-1)
			continue;

		const ULONG Candidate = *(ULONG*)((PUCHAR)Thread + i);
		if (Candidate == (CandidateOffsets[i] | PS_CROSS_THREAD_FLAGS_HIDEFROMDBG))
		{
			LastMatchFound = (ULONG)i;
			MatchesFound++;
		}
	}

	if (MatchesFound != 1)
	{
		Status = STATUS_NOT_FOUND;
		goto Exit;
	}

	*Offset = LastMatchFound;

Exit:
	if (Thread != nullptr)
		ObDereferenceObject(Thread);
	if (ThreadHandle != nullptr)
	{
		Undocumented::ZwTerminateThread(ThreadHandle, STATUS_SUCCESS);
		ObCloseHandle(ThreadHandle, ExGetPreviousMode());
	}
	if (Attached)
		KeUnstackDetachProcess(&ApcState);
	if (Process != nullptr)
		ObDereferenceObject(Process);
	ExFreePoolWithTag(CandidateOffsets, 'drhT');
	return Status;
}

BOOLEAN GetOffsets() 
{	
	if (g_HyperHide.CurrentWindowsBuildNumber >= WINDOWS_11)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0x74;
		ULONG CrossFlagsOffset = 0;
		if (NT_SUCCESS(FindCrossThreadFlagsOffset(&CrossFlagsOffset))) {

			NtapiOffsets.ThreadHideFromDebuggerFlagOffset = CrossFlagsOffset;
			NtapiOffsets.ThreadBreakOnTerminationFlagOffset = CrossFlagsOffset;
		}else{

			NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x560;
			NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x560;
		}
		NtapiOffsets.PicoContextOffset = 0x630;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x460;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x5c0;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_22H2 ||
		g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_21H1 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_21H2 ||
		g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_20H2 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_20H1)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0x74;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x510;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x510;
		NtapiOffsets.PicoContextOffset = 0x5e0;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x460;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x5c0;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_19H2 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_19H1)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0x74;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6e0;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6e0;
		NtapiOffsets.PicoContextOffset = 0x7a8;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x308;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE5)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6d0;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6d0;
		NtapiOffsets.PicoContextOffset = 0x798;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x300;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE4)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6d0;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6d0;
		NtapiOffsets.PicoContextOffset = 0x7a0;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x300;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE3)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6d0;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6d0;
		NtapiOffsets.PicoContextOffset = 0x7a0;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x300;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE2)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6c8;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6c8;
		NtapiOffsets.PicoContextOffset = 0x798;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x810;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE1)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6c0;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6c0;
		NtapiOffsets.PicoContextOffset = 0x790;
		NtapiOffsets.RestrictSetThreadContextOffset = 0;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_THRESHOLD2)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6bc;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6bc;
		NtapiOffsets.PicoContextOffset = 0x788;
		NtapiOffsets.RestrictSetThreadContextOffset = 0;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_THRESHOLD1)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6bc;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6bc;
		NtapiOffsets.PicoContextOffset = 0x788;
		NtapiOffsets.RestrictSetThreadContextOffset = 0;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x460;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_8_1)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6b4;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6b4;
		NtapiOffsets.PicoContextOffset = 0x770;
		NtapiOffsets.RestrictSetThreadContextOffset = 0;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x450;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_8)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x42c;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x42c;
		NtapiOffsets.PicoContextOffset = 0x770;
		NtapiOffsets.RestrictSetThreadContextOffset = 0;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x450;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_7_SP1 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_7)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x448;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x448;
		NtapiOffsets.PicoContextOffset = 0;
		NtapiOffsets.RestrictSetThreadContextOffset = 0;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x390;
	}

	else
	{
		return FALSE;
	}

	return TRUE;
}