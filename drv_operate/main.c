#include "main.h"

NTSTATUS ctchCreate( PDEVICE_OBJECT dev_obj, PIRP irp ) { return STATUS_SUCCESS; }
NTSTATUS ctchClose( PDEVICE_OBJECT dev_obj, PIRP irp ) { return STATUS_SUCCESS; }
NTSTATUS ctchCtrl( PDEVICE_OBJECT dev_obj, PIRP irp ) { return STATUS_SUCCESS; }

BOOLEAN clean_entry( ) {
	ULONG bytes = NULL;
	NTSTATUS status = ZwQuerySystemInformation( SystemModuleInformation, NULL, bytes, &bytes );
	DbgPrint( "clean_entry(): Initializing\n" );

	if ( !bytes ) {
		DbgPrint( "clean_entry(): ZwQuerySystemInformation (1) failed, status code: 0x%X\n", status );
		return FALSE;
	}

	PRTL_PROCESS_MODULES modules = ( PRTL_PROCESS_MODULES )ExAllocatePoolWithTag( NonPagedPool, bytes, 0x454E4F45 );

	status = ZwQuerySystemInformation( SystemModuleInformation, modules, bytes, &bytes );

	if ( !NT_SUCCESS( status ) ) {
		DbgPrint( "clean_entry(): ZwQuerySystemInformation (2) failed, status code: 0x%X\n", status );
		return FALSE;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules; uint64_t ntoskrnl = NULL, ntoskrnl_sz = NULL;

	DbgPrint( "clean_entry(): Number of modules: %i\n", modules->NumberOfModules );
	for ( ULONG i = NULL; i < modules->NumberOfModules; i++ ) {
		DbgPrint( "clean_entry(): Module (%i) Path: %s\n", i, module[i].FullPathName );

		if ( !strcmp( (char*)module[i].FullPathName, "\\SystemRoot\\system32\\ntoskrnl.exe" ) ) {
			ntoskrnl = (uint64_t)module[i].ImageBase;
			ntoskrnl_sz = (uint64_t)module[i].ImageSize;
			break;
		}
	}

	if ( modules )
		ExFreePoolWithTag( modules, NULL );

	if ( ntoskrnl <= NULL ) {
		DbgPrint( "clean_entry(): Could not get ntoskrnl.exe base\n" );
		return FALSE;
	}

	uint64_t mm_unloaded_ptr = get_sig( ntoskrnl, ntoskrnl_sz, (PBYTE)"\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x" );

	DbgPrint( "clean_entry(): MmUnloadedDrivers Ptr found at: 0x%X", mm_unloaded_ptr );

	if ( !mm_unloaded_ptr ) {
		DbgPrint( "clean_entry(): Could not get MmUnloadedDrivers pointer\n" );
		return FALSE;
	}

	uint64_t mm_unloaded_drvs = (uint64_t)( (PUCHAR)mm_unloaded_ptr + *(PULONG)((PUCHAR)mm_unloaded_ptr + 3 ) + 7 );
	uint64_t buffer_ptr = *(uint64_t*)mm_unloaded_drvs;

	void * new_buffer = ExAllocatePoolWithTag( NonPagedPoolNx, 0x7D0, 0x54446D4D );

	if ( !new_buffer )
		return FALSE;

	memset( new_buffer, 0, 0x7D0 );

	*(uint64_t*)mm_unloaded_drvs = (uint64_t)new_buffer;

	ExFreePoolWithTag( (PVOID)buffer_ptr, 0x54446D4D );

	DbgPrint( "clean_entry(): Success\n" );

	return TRUE;
}

NTSTATUS drv_init( PDRIVER_OBJECT drv_obj, PUNICODE_STRING rgstry_path ) {
	DbgPrint( "drv_init(.., ..): Real Entry Loading\n" );

	RtlInitUnicodeString( &device, L"\\Device\\DrvOperate" );
	RtlInitUnicodeString( &dos_device, L"\\DosDevices\\DrvOperate" );
	
	NTSTATUS cr_status;

	cr_status = IoCreateDevice( drv_obj, NULL, &device, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_obj );
	cr_status = IoCreateSymbolicLink( &dos_device, &device );

	DbgPrint( "drv_init(.., ..): Device Object: 0x%X\n", device_obj );
	DbgPrint( "drv_init(.., ..): Driver Object: 0x%X\n", drv_obj );

	drv_obj -> MajorFunction[IRP_MJ_CREATE] = ctchCreate;
	drv_obj -> MajorFunction[IRP_MJ_CLOSE] = ctchClose;
	drv_obj -> MajorFunction[IRP_MJ_DEVICE_CONTROL] = ctchCtrl;

	drv_obj -> DriverUnload = NULL;

	device_obj -> Flags |= DO_DIRECT_IO;
	device_obj -> Flags &= ~DO_DEVICE_INITIALIZING;

	clean_entry( );
	
	DbgPrint( "drv_init(.., ..): Success\n" );
	return cr_status;
}

NTSTATUS drv_entry( PDRIVER_OBJECT drv_obj, PUNICODE_STRING rgstry_path ) {
	DbgPrint( "drv_entry(.., ..): False Entry Loading\n" );
	RtlInitUnicodeString( &drv_name, L"\\Driver\\DrvOperate" );
	NTSTATUS status = IoCreateDriver( &drv_name, &drv_init );

	if (!NT_SUCCESS(status))
		DbgPrint( "drv_entry(.., ..): Failed, status: 0x%X\n", status );
	else
		DbgPrint( "drv_entry(.., ..): Success\n" );

	return status;
}
