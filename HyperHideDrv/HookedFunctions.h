#pragma once
#include <ntifs.h>

#define ObjectTypesInformation 3
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x40
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x4
#define PROCESS_DEBUG_INHERIT 0x00000001 // default for a non-debugged process
#define PROCESS_NO_DEBUG_INHERIT 0x00000002 // default for a debugged process
#define PROCESS_QUERY_INFORMATION   0x0400
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

#define BACKUP_RETURNLENGTH() \
    ULONG TempReturnLength = 0; \
    if(ARGUMENT_PRESENT(ReturnLength)) \
        TempReturnLength = *ReturnLength

#define RESTORE_RETURNLENGTH() \
    if(ARGUMENT_PRESENT(ReturnLength)) \
        (*ReturnLength) = TempReturnLength

BOOLEAN HookSyscalls();




#ifndef _UNDOCUMENTED_H
#define _UNDOCUMENTED_H


#include <ntifs.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <ntstrsafe.h>
#include <ntimage.h>


// This is in ntifs.h, but some say Alan Turing died trying to parse that file
extern "C"
NTKERNELAPI
NTSTATUS
ObQueryObjectAuditingByHandle(
    _In_ HANDLE Handle,
    _Out_ PBOOLEAN GenerateOnClose
);



extern "C"
NTKERNELAPI
PVOID
PsGetProcessDebugPort(
    _In_ PEPROCESS Process
);

extern "C"
NTKERNELAPI
PEPROCESS
PsGetThreadProcess(
    _In_ PETHREAD Thread
);

extern "C"
NTKERNELAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    _In_ PVOID Base
);

extern "C"
NTKERNELAPI
ULONG
NtBuildNumber;

class Undocumented
{
public:
    static NTSTATUS NTAPI ZwQueryInformationProcess(
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID ProcessInformation,
        IN ULONG ProcessInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI NtQueryInformationThread(
        IN HANDLE ThreadHandle,
        IN THREADINFOCLASS ThreadInformationClass,
        IN OUT PVOID ThreadInformation,
        IN ULONG ThreadInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI NtQueryObject(
        IN HANDLE Handle OPTIONAL,
        IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
        OUT PVOID ObjectInformation OPTIONAL,
        IN ULONG ObjectInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI ZwQuerySystemInformation(
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI NtQuerySystemInformation(
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI NtClose(
        IN HANDLE Handle);

    static NTSTATUS NTAPI NtGetContextThread(
        IN HANDLE ThreadHandle,
        IN OUT PCONTEXT Context);

    static NTSTATUS NTAPI NtSetContextThread(
        IN HANDLE ThreadHandle,
        IN PCONTEXT Context);

    static NTSTATUS NTAPI NtContinue(
        IN PCONTEXT Context,
        BOOLEAN RaiseAlert);

    static NTSTATUS NTAPI NtDuplicateObject(
        IN HANDLE SourceProcessHandle,
        IN HANDLE SourceHandle,
        IN HANDLE TargetProcessHandle,
        OUT PHANDLE TargetHandle,
        IN ACCESS_MASK DesiredAccess OPTIONAL,
        IN ULONG HandleAttributes,
        IN ULONG Options);

    static NTSTATUS NTAPI KeRaiseUserException(
        IN NTSTATUS ExceptionCode);

    static NTSTATUS NTAPI ZwSetInformationThread(
        IN HANDLE ThreadHandle,
        IN THREADINFOCLASS ThreadInformationClass,
        IN PVOID ThreadInformation,
        IN ULONG ThreadInformationLength);

    static NTSTATUS NTAPI NtSetInformationThread(
        IN HANDLE ThreadHandle,
        IN THREADINFOCLASS ThreadInformationClass,
        IN PVOID ThreadInformation,
        IN ULONG ThreadInformationLength);

    static NTSTATUS NTAPI NtSetInformationProcess(
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        IN PVOID ProcessInformation,
        IN ULONG ProcessInformationLength);

    static NTSTATUS NTAPI NtQueryInformationProcess(
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID ProcessInformation,
        IN ULONG ProcessInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI NtSystemDebugControl(
        IN SYSDBG_COMMAND Command,
        IN PVOID InputBuffer OPTIONAL,
        IN ULONG InputBufferLength OPTIONAL,
        OUT PVOID OutputBuffer,
        IN ULONG OutputBufferLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI ZwTerminateThread(
        IN HANDLE ThreadHandle OPTIONAL,
        IN NTSTATUS ExitStatus);

    static NTSTATUS NTAPI NtTerminateThread(
        IN HANDLE ThreadHandle OPTIONAL,
        IN NTSTATUS ExitStatus);

    static NTSTATUS NTAPI ZwCreateThreadEx(
        OUT PHANDLE ThreadHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN HANDLE ProcessHandle,
        IN PUSER_THREAD_START_ROUTINE StartRoutine,
        IN PVOID Argument OPTIONAL,
        IN ULONG CreateFlags,
        IN SIZE_T ZeroBits OPTIONAL,
        IN SIZE_T StackSize OPTIONAL,
        IN SIZE_T MaximumStackSize OPTIONAL,
        IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

    static NTSTATUS NTAPI NtCreateThreadEx(
        OUT PHANDLE ThreadHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN HANDLE ProcessHandle,
        IN PUSER_THREAD_START_ROUTINE StartRoutine,
        IN PVOID Argument OPTIONAL,
        IN ULONG CreateFlags,
        IN SIZE_T ZeroBits OPTIONAL,
        IN SIZE_T StackSize OPTIONAL,
        IN SIZE_T MaximumStackSize OPTIONAL,
        IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

    static bool UndocumentedInit();
};

#endif
