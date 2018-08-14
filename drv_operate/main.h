#pragma once
#pragma warning(disable:4200)
#pragma comment(lib, "ntoskrnl.lib")
#include <ntdef.h>
#include <ntifs.h>
#include <ntimage.h>

typedef unsigned char BYTE;
typedef BYTE* PBYTE;
typedef unsigned long long uint64_t;

UNICODE_STRING device, dos_device, drv_name;
PDEVICE_OBJECT device_obj = { NULL };

typedef  struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
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
	SystemModuleInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

EXTERN_C NTSTATUS NTKERNELAPI IoCreateDriver(PUNICODE_STRING, PDRIVER_INITIALIZE);
EXTERN_C NTSTATUS NTKERNELAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

BOOLEAN compare_data(const BYTE* data, const BYTE* mask, const char* sz_mask) {
	for (; *sz_mask; ++sz_mask, ++data, ++mask)
		if (*sz_mask == 'x' && *data != *mask)
			return NULL;

	return *sz_mask == NULL;
}

uint64_t get_sig(uint64_t addr, uint64_t length, BYTE * mask, const char * sz_mask) {
	for (uint64_t i = NULL; i < length; i++)
		if (compare_data((BYTE*)(addr + i), mask, sz_mask))
			return (uint64_t)(addr + i);
	
	return NULL;
}