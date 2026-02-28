#include "pch.h"
#include <ntddstor.h>
#include <ntddscsi.h>
//#include <storport.h>
//#include <srb.h>
//#include <scsi.h> 
#include <nvme.h>
#include <srbhelper.h>
//#include <nvme.h>
#include "DriverMon.h"
#include "CyclicBuffer.h"
#include "SpinLock.h"


//
// prototypes
//

void DriverMonUnload(PDRIVER_OBJECT);
NTSTATUS DriverMonCreateClose(PDEVICE_OBJECT, PIRP);
NTSTATUS DriverMonDeviceControl(PDEVICE_OBJECT, PIRP);
NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR Information = 0);
NTSTATUS AddDriver(PCWSTR driverName, PVOID* driverObject);
NTSTATUS RemoveDriver(PVOID DriverObject);
NTSTATUS RemoveDriver(int index);

//NTSTATUS DriverMonGenericDispatch(PDEVICE_OBJECT, PIRP);

NTSTATUS HookDeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS HookInternalDeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS OnIrpCompleted(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID context);
NTSTATUS GetDataFromIrp(PDEVICE_OBJECT Deviceobject, PIRP Irp, PIO_STACK_LOCATION stack, IrpMajorCode code, PVOID buffer, ULONG size, bool output = false);
void GenericDriverUnload(PDRIVER_OBJECT DriverObject);

void RemoveAllDrivers();

DriverMonGlobals globals;

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING /* RegistryPath */) {
	DriverObject->DriverUnload = DriverMonUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverMonCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverMonDeviceControl;

	UNICODE_STRING name, symLink;
	RtlInitUnicodeString(&name, DeviceName);
	RtlInitUnicodeString(&symLink, DeviceSymLink);

	auto status = STATUS_SUCCESS;

	do {
		globals.DataBuffer = new (NonPagedPool) CyclicBuffer<SpinLock>;
		if (globals.DataBuffer == nullptr) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		globals.IrpCompletionTable = new (NonPagedPool) SimpleTable<PVOID, PVOID, 128>;
		if (globals.IrpCompletionTable == nullptr) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		status = globals.DataBuffer->Init(1 << 20, NonPagedPool, DRIVER_TAG);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		PDEVICE_OBJECT DeviceObject;
		status = IoCreateDevice(DriverObject, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRIVER_PREFIX "Error creating device object (0x%08X)\n", status));
			break;
		}

		status = IoCreateSymbolicLink(&symLink, &name);
		if (!NT_SUCCESS(status)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRIVER_PREFIX "Error creating symbolic link (0x%08X)\n", status));
			IoDeleteDevice(DeviceObject);
			break;
		}
	} while (false);

	if (!NT_SUCCESS(status)) {
		if (globals.DataBuffer)
			delete globals.DataBuffer;
		if (globals.IrpCompletionTable)
			delete globals.IrpCompletionTable;

		return status;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, DRIVER_PREFIX "DriverEntry completed successfully\n"));

	return status;
}

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR Information) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = Information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverMonCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	return CompleteRequest(Irp);
}

void DriverMonUnload(PDRIVER_OBJECT DriverObject) {
	RemoveAllDrivers();

	auto event = InterlockedExchangePointer((PVOID*)&globals.NotifyEvent, nullptr);
	if (event) {
		ObDereferenceObject(event);
	}

	delete globals.DataBuffer;
	delete globals.IrpCompletionTable;

	UNICODE_STRING symLink;
	RtlInitUnicodeString(&symLink, DeviceSymLink);
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverMonDeviceControl(PDEVICE_OBJECT, PIRP Irp) {
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;
	ULONG_PTR information = 0;
	auto inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
	auto outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (static_cast<DriverMonIoctls>(stack->Parameters.DeviceIoControl.IoControlCode)) {
		case DriverMonIoctls::StartMonitoring:
			globals.IsMonitoring = true;
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, DRIVER_PREFIX "Monitoring started\n"));
			break;

		case DriverMonIoctls::StopMonitoring:
			globals.IsMonitoring = false;
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, DRIVER_PREFIX "Monitoring stopped\n"));
			break;

		case DriverMonIoctls::SetEventHandle: {
			if (inputLen < sizeof(HANDLE)) {
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			PKEVENT event;
			status = ObReferenceObjectByHandle(*(HANDLE*)Irp->AssociatedIrp.SystemBuffer, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&event, nullptr);
			if (!NT_SUCCESS(status))
				break;

			auto oldEvent = InterlockedExchangePointer((PVOID*)&globals.NotifyEvent, event);

			if (oldEvent)
				ObDereferenceObject(oldEvent);
			break;
		}

		case DriverMonIoctls::AddDriver: {
			if (globals.Count >= MaxMonitoredDrivers) {
				status = STATUS_TOO_MANY_ADDRESSES;
				break;
			}

			if (inputLen < 1 || inputLen > 64 || outputLen < sizeof(PVOID)) {
				status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			PCWSTR driverName = static_cast<PCWSTR>(Irp->AssociatedIrp.SystemBuffer);
			if (driverName[inputLen / sizeof(WCHAR) - 1] != L'\0') {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			// BDFを渡すようにする
			status = AddDriver(driverName, (PVOID*)Irp->AssociatedIrp.SystemBuffer);
			if (NT_SUCCESS(status)) {
				information = sizeof(PVOID);
			}
			break;
		}

		case DriverMonIoctls::RemoveDriver:
			if (inputLen < sizeof(PVOID)) {
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			// BDFを渡すようにする
			status = RemoveDriver(*(PVOID*)Irp->AssociatedIrp.SystemBuffer);
			break;

		case DriverMonIoctls::RemoveAll:
			RemoveAllDrivers();
			break;

		case DriverMonIoctls::GetData: {
			if (outputLen < sizeof(CommonInfoHeader)) {
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			auto buffer = static_cast<PUCHAR>(MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority));
			if (buffer == nullptr) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			information = globals.DataBuffer->Read(buffer, outputLen);
			break;
		}

		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	return CompleteRequest(Irp, status, information);
}

NTSTATUS AddDriver(PCWSTR driverName, PVOID* driverObject) {
	int index = -1;

	//
	// find first available slot, make sure driver is not already monitored
	//

	for (int i = 0; i < MaxMonitoredDrivers; ++i) {
		if (globals.Drivers[i].DriverObject == nullptr) {
			if (index < 0) {
				index = i;
			}
		}
		else {
			// existing driver, check if not already being monitored

			if (_wcsicmp(globals.Drivers[i].DriverName, driverName) == 0) {
				*driverObject = globals.Drivers[i].DriverObject;
				return STATUS_SUCCESS;
			}
		}
	}


	//  ここでドライバーオブジェクトを探している。
#if 0
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, driverName);
	PDRIVER_OBJECT driver;
	auto status = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE, nullptr, 0, 
		*IoDriverObjectType, KernelMode, nullptr, (PVOID*)&driver);
	if (!NT_SUCCESS(status))
		return status;
#else 
	const WCHAR DriverName[] = L"\\driver\\pci";

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, DriverName);

	PDRIVER_OBJECT pciDriver;
	ULONG actualCount;
	PDEVICE_OBJECT* m_ppDevices = nullptr;

	ULONG propertyAddress, BusNumber;
	USHORT FunctionNumber, DeviceNumber;
	ULONG  length;


	PDEVICE_OBJECT TargetDevice = NULL;
	PDRIVER_OBJECT TargetDriver = NULL;

	bool bRet = false;

	auto status = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE , nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&pciDriver);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Failure  ObReferenceObjectByName\n");
		return status;
	}
	else {
		DbgPrint("Success   ObReferenceObjectByName\n");
	}

	if ((STATUS_BUFFER_TOO_SMALL == (status = IoEnumerateDeviceObjectList(pciDriver, NULL, 0, &actualCount)) && actualCount)) {
		DbgPrint("Success IoEnumerateDeviceObjectList :%d \n", actualCount);

		m_ppDevices = (PDEVICE_OBJECT*)ExAllocatePool(NonPagedPool, sizeof(PDEVICE_OBJECT) * actualCount);

		if (m_ppDevices) {
			status = IoEnumerateDeviceObjectList(pciDriver, m_ppDevices, actualCount * sizeof(PDEVICE_OBJECT), &actualCount);

			if (NT_SUCCESS(status)) {
				DbgPrint("Success IoEnumerateDeviceObjectList \n");

				for (size_t i = 0; i < actualCount; ++i) {
					//pdo = IoGetAttachedDeviceReference(m_ppDevices[i]);

					status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyBusNumber, sizeof(ULONG), (PVOID)&BusNumber, &length);
					if (NT_SUCCESS(status)) {
						DbgPrint("BusNumber:%x\n", BusNumber);

						status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyAddress, sizeof(ULONG), (PVOID)&propertyAddress, &length);
						if (NT_SUCCESS(status)) {
							DeviceNumber = (USHORT)(((propertyAddress) >> 16) & 0x0000FFFF);
							FunctionNumber = (USHORT)((propertyAddress) & 0x0000FFFF);
							DbgPrint("DeviceNumber:%x\n", DeviceNumber);
							DbgPrint("FunctionNumber:%x\n", FunctionNumber);

							if (BusNumber == 0x5 && DeviceNumber == 0x0 && FunctionNumber == 0x0) {

								PDEVICE_OBJECT  topDevice = IoGetAttachedDeviceReference(m_ppDevices[i]);

								UNICODE_STRING target;

								RtlInitUnicodeString(&target, L"\\Driver\\stornvme");

								for (PDEVICE_OBJECT d = topDevice; d; d = d->AttachedDevice) {
									if (RtlCompareUnicodeString(&d->DriverObject->DriverName, &target, TRUE) == 0)
									{
										TargetDevice = d;
										TargetDriver = d->DriverObject;
										DbgPrint("This is stornvme!\n");
										bRet = true;
									}
								}

								ObDereferenceObject(topDevice); 

								break;
							}
						}
						else {
							DbgPrint("Failure IoGetDeviceProperty\n");
						}
					}
					else {
						DbgPrint("Failure IoGetDeviceProperty\n");
					}

				} // for (i = 0; i < actualCount; i++)

				for (size_t i = 0; i < actualCount; ++i) ObDereferenceObject(m_ppDevices[i]);

				ExFreePool(m_ppDevices);

				if (bRet == false) {
					DbgPrint("stornvme not found\n");
					ObDereferenceObject(pciDriver);
					return STATUS_NO_SUCH_DEVICE;
				}

			}
			else {
				ExFreePool(m_ppDevices);
				ObDereferenceObject(pciDriver);
				return status;
			}

		}
		else {
			DbgPrint("Failure allocation device object list\n");
			ObDereferenceObject(pciDriver);
			return STATUS_INSUFFICIENT_RESOURCES;

		}
	}
	else {
		DbgPrint("Failure IoEnumerateDeviceObjectList, cannot get size\n");
		ObDereferenceObject(pciDriver);
		return status;
	}

	ObDereferenceObject(pciDriver);

#endif

	::wcscpy_s(globals.Drivers[index].DriverName, L"\\Driver\\stornvme");

	//for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
	//	globals.Drivers[index].MajorFunction[i] = static_cast<PDRIVER_DISPATCH>(
	//		InterlockedExchangePointer((PVOID*)&TargetDriver->MajorFunction[i], DriverMonGenericDispatch));
	//}

	globals.IsMonitoring = TRUE;

	globals.Drivers[index].MajorFunction[IRP_MJ_DEVICE_CONTROL] = static_cast<PDRIVER_DISPATCH>(
		InterlockedExchangePointer((PVOID*)&TargetDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL], HookDeviceIoControl));

	globals.Drivers[index].MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = static_cast<PDRIVER_DISPATCH>(
		InterlockedExchangePointer((PVOID*)&TargetDriver->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL], HookInternalDeviceIoControl));

	globals.Drivers[index].DriverUnload = static_cast<PDRIVER_UNLOAD>(InterlockedExchangePointer((PVOID*)&TargetDriver->DriverUnload, GenericDriverUnload));
	globals.Drivers[index].DriverObject = TargetDriver;
	globals.Drivers[index].DeviceObject = TargetDevice;

	++globals.Count;
	*driverObject = TargetDriver;

	globals.ReferenceCount = 1;

	KeInitializeEvent(
		&globals.StopEvent,
		NotificationEvent, 
		FALSE              
	);

	DbgPrint("Success add stornvme\n");

	return STATUS_SUCCESS;
}

NTSTATUS RemoveDriver(PVOID DriverObject) {
	for (int i = 0; i < MaxMonitoredDrivers; ++i) {
		auto& driver = globals.Drivers[i];
		if (driver.DriverObject == DriverObject) {
			return RemoveDriver(i);
		}
	}
	return STATUS_INVALID_PARAMETER;
}

NTSTATUS RemoveDriver(int i) {
	auto& driver = globals.Drivers[i];
	//for (int j = 0; j <= IRP_MJ_MAXIMUM_FUNCTION; j++) {
		//InterlockedExchangePointer((PVOID*)&driver.DriverObject->MajorFunction[j], driver.MajorFunction[j]);
	//}

	//LARGE_INTEGER timeout;
	//timeout.QuadPart = -10 * 1000 * 1000;
	
	globals.IsMonitoring = FALSE;

	if (InterlockedDecrement(&globals.ReferenceCount) > 0) {
		KeWaitForSingleObject(&globals.StopEvent, Executive, KernelMode, FALSE, nullptr);
	}

	InterlockedExchangePointer((PVOID*)&driver.DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], driver.MajorFunction[IRP_MJ_DEVICE_CONTROL]);
	InterlockedExchangePointer((PVOID*)&driver.DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL], driver.MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL]);

	InterlockedExchangePointer((PVOID*)&driver.DriverUnload, driver.DriverUnload);

	globals.Count--;
	//ObDereferenceObject(driver.DriverObject);
	driver.DriverObject = nullptr;

	return STATUS_SUCCESS;
}


NTSTATUS HookDeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	if (globals.IsMonitoring == FALSE) {
		KeSetEvent(&globals.StopEvent, IO_NO_INCREMENT, FALSE);
		return  STATUS_DEVICE_REMOVED;
	}

	InterlockedIncrement(&globals.ReferenceCount);

	auto driver = DeviceObject->DriverObject;
	auto stack = IoGetCurrentIrpStackLocation(Irp);

	if (globals.Drivers[0].DeviceObject != DeviceObject) {
		auto status =  globals.Drivers[0].MajorFunction[stack->MajorFunction](DeviceObject, Irp);
		if (InterlockedDecrement(&globals.ReferenceCount) == 0) {
			KeSetEvent(&globals.StopEvent, IO_NO_INCREMENT, FALSE);
		}

		return status;
	}

	if (globals.Drivers[0].DriverObject != driver) {
		NT_ASSERT(false);
		if (InterlockedDecrement(&globals.ReferenceCount) == 0) {
			KeSetEvent(&globals.StopEvent, IO_NO_INCREMENT, FALSE);
		}
		return  STATUS_SUCCESS;
	}

	ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;

	if (ioctl == IOCTL_SCSI_PASS_THROUGH) {
		DbgPrint("IOCTL_SCSI_PASS_THROUGH\n");
	}else if (ioctl == IOCTL_SCSI_PASS_THROUGH_DIRECT) {
		DbgPrint("IOCTL_SCSI_PASS_THROUGH_DIRECT\n");
	}
	else if (ioctl == IOCTL_STORAGE_PROTOCOL_COMMAND) {
		DbgPrint("IOCTL_STORAGE_PROTOCOL_COMMAND\n");
	}
	else if (ioctl == IOCTL_STORAGE_QUERY_PROPERTY) {
		DbgPrint("IOCTL_STORAGE_QUERY_PROPERTY\n");

		PSTORAGE_PROPERTY_QUERY query = (PSTORAGE_PROPERTY_QUERY)Irp->AssociatedIrp.SystemBuffer;
		ULONG inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (query != nullptr && inputBufferLength >= sizeof(STORAGE_PROPERTY_QUERY)) {
			if (query->PropertyId == StorageAdapterProtocolSpecificProperty && query->QueryType == PropertyStandardQuery) {
				PSTORAGE_PROTOCOL_SPECIFIC_DATA protocolData = (PSTORAGE_PROTOCOL_SPECIFIC_DATA)query->AdditionalParameters;
				if (protocolData->ProtocolType == ProtocolTypeNvme) {
					switch (protocolData->DataType) {
					case NVMeDataTypeIdentify:
						DbgPrint("NVMeDataTypeIdentify\n");

						break;

					case NVMeDataTypeLogPage:
						DbgPrint("NVMeDataTypeLogPage\n");

						break;

					case NVMeDataTypeLogPageEx:
						DbgPrint("NVMeDataTypeLogPageEx\n");

						break;

					case NVMeDataTypeFeature:
						DbgPrint("NVMeDataTypeFeature\n");

						break;

					case NVMeDataTypeUnknown:
						DbgPrint("NVMeDataTypeUnknown\n");
						break;

					default:
						DbgPrint("NVMeDataTypeUnknown\n");
						break;
					}
					
				}

			}
		}
	}
	else {
		DbgPrint("OTHER_IOCTL\n");

	}

	auto status =  globals.Drivers[0].MajorFunction[stack->MajorFunction](DeviceObject, Irp);

	if (InterlockedDecrement(&globals.ReferenceCount) == 0) {
		KeSetEvent(&globals.StopEvent, IO_NO_INCREMENT, FALSE);
	}

	return status;
}


NTSTATUS HookInternalDeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	if (globals.IsMonitoring == FALSE) {
		KeSetEvent(&globals.StopEvent, IO_NO_INCREMENT, FALSE);
		return  STATUS_DEVICE_REMOVED;
	}

	InterlockedIncrement(&globals.ReferenceCount);

	auto driver = DeviceObject->DriverObject;
	auto stack = IoGetCurrentIrpStackLocation(Irp);

	if (globals.Drivers[0].DeviceObject != DeviceObject) {
		auto status = globals.Drivers[0].MajorFunction[stack->MajorFunction](DeviceObject, Irp);
		if (InterlockedDecrement(&globals.ReferenceCount) == 0) {
			KeSetEvent(&globals.StopEvent, IO_NO_INCREMENT, FALSE);
		}

		return status;
	}

	if (globals.Drivers[0].DriverObject != driver) {
		NT_ASSERT(false);
		if (InterlockedDecrement(&globals.ReferenceCount) == 0) {
			KeSetEvent(&globals.StopEvent, IO_NO_INCREMENT, FALSE);
		}
		return  STATUS_SUCCESS;
	}

	PVOID   pAnySrb = stack->Parameters.Scsi.Srb;
	if (pAnySrb != nullptr)
	{
		UCHAR func = SrbGetSrbFunction(pAnySrb);
		if (func == SRB_FUNCTION_STORAGE_REQUEST_BLOCK)
		{
			DbgPrint("SRB_FUNCTION_STORAGE_REQUEST_BLOCK\n");
		}
		else if (func == SRB_FUNCTION_EXECUTE_SCSI) {
			DbgPrint("SRB_FUNCTION_STORAGE_REQUEST_BLOCK\n");
		}
		else {
			DbgPrint("OTHER_SRB_FUNCTION\n");

		}
	}

	auto status = globals.Drivers[0].MajorFunction[stack->MajorFunction](DeviceObject, Irp);

	if (InterlockedDecrement(&globals.ReferenceCount) == 0) {
		KeSetEvent(&globals.StopEvent, IO_NO_INCREMENT, FALSE);
	}

	return status;
}

#if 0

NTSTATUS DriverMonGenericDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	auto driver = DeviceObject->DriverObject;
	auto stack = IoGetCurrentIrpStackLocation(Irp);

	IrpArrivedInfo* info = nullptr;

	for (int i = 0; i < MaxMonitoredDrivers; ++i) {
		if (globals.Drivers[i].DriverObject != driver) {
			continue;
		}
		if (globals.IsMonitoring && globals.NotifyEvent) {
			NT_ASSERT(driver == DeviceObject->DriverObject);

			// report operation
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, DRIVER_PREFIX "Driver 0x%p intercepted!\n", driver));

			info = static_cast<IrpArrivedInfo*>(ExAllocatePoolWithTag(NonPagedPool, MaxDataSize + sizeof(IrpArrivedInfo), DRIVER_TAG));

			// ここで共通の情報を入れる
			if (info) {
				info->Type = DataItemType::IrpArrived;
				KeQuerySystemTime((PLARGE_INTEGER)&info->Time);
				info->Size = sizeof(IrpArrivedInfo);
				info->DeviceObject = DeviceObject;
				info->Irp = Irp;
				info->DriverObject = driver;
				info->MajorFunction = static_cast<IrpMajorCode>(stack->MajorFunction);
				info->MinorFunction = static_cast<IrpMinorCode>(stack->MinorFunction);
				info->ProcessId = HandleToULong(PsGetCurrentProcessId());
				info->ThreadId = HandleToULong(PsGetCurrentThreadId());
				info->Irql = KeGetCurrentIrql();
				info->DataSize = 0;
				info->scsi_opcode = 0;
				info->nvme_opcode = 0;

				switch (info->MajorFunction) {
					ULONG ioctl;
					case IrpMajorCode::DEVICE_CONTROL:						// 0xe 

						ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
						if (ioctl == IOCTL_SCSI_PASS_THROUGH || ioctl == IOCTL_SCSI_PASS_THROUGH_DIRECT) {
							PSCSI_PASS_THROUGH pSpt = (PSCSI_PASS_THROUGH)Irp->AssociatedIrp.SystemBuffer;
							ULONG inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
							if (pSpt != nullptr && inputBufferLength >= sizeof(SCSI_PASS_THROUGH)) {

								PCDB pCdb = (PCDB)pSpt->Cdb;
								info->scsi_opcode = pCdb->CDB6GENERIC.OperationCode;

							}
						}
						else if (ioctl == IOCTL_STORAGE_PROTOCOL_COMMAND) {
							PSTORAGE_PROTOCOL_COMMAND protocolCommand = (PSTORAGE_PROTOCOL_COMMAND)Irp->AssociatedIrp.SystemBuffer;
							ULONG inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
							if (protocolCommand != nullptr && inputBufferLength >= sizeof(STORAGE_PROTOCOL_COMMAND)) {
								if (protocolCommand->ProtocolType == ProtocolTypeNvme) {
									auto command = (PNVME_COMMAND)protocolCommand->Command;

									info->nvme_opcode = command->CDW0.OPC;
								}
							}
						}
						else if (ioctl == IOCTL_STORAGE_QUERY_PROPERTY) {
							PSTORAGE_PROPERTY_QUERY query = (PSTORAGE_PROPERTY_QUERY)Irp->AssociatedIrp.SystemBuffer;
							ULONG inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
							if (query != nullptr && inputBufferLength >= sizeof(STORAGE_PROPERTY_QUERY)) {
								if (query->PropertyId == StorageAdapterProtocolSpecificProperty && query->QueryType == PropertyStandardQuery) {
									PSTORAGE_PROTOCOL_SPECIFIC_DATA protocolData = (PSTORAGE_PROTOCOL_SPECIFIC_DATA)((PUCHAR)query + sizeof(STORAGE_PROPERTY_QUERY));
									if (protocolData->ProtocolType == ProtocolTypeNvme) {
										switch (protocolData->DataType) {
										case NVMeDataTypeIdentify:

											break;

										case NVMeDataTypeLogPage:

											break;

										case NVMeDataTypeLogPageEx:

											break;
										}
									}

								}
							}
						}

						break;

					case IrpMajorCode::INTERNAL_DEVICE_CONTROL:	// 0xf  
						PVOID   pAnySrb = stack->Parameters.Scsi.Srb;
						if (pAnySrb != nullptr )
						{
							UCHAR func = SrbGetSrbFunction(pAnySrb);
							if ( func == SRB_FUNCTION_STORAGE_REQUEST_BLOCK)
							{
								PSTORAGE_REQUEST_BLOCK pSrb = (PSTORAGE_REQUEST_BLOCK)pAnySrb;

								if (pSrb->Length >= sizeof(STORAGE_REQUEST_BLOCK)) {
									PSTORAGE_PROTOCOL_COMMAND protocolCommand = (PSTORAGE_PROTOCOL_COMMAND)pSrb->DataBuffer;
									if (protocolCommand != NULL && pSrb->DataTransferLength >= sizeof(STORAGE_PROTOCOL_COMMAND)) {
	

									}
								}

							}
							else if (func == SRB_FUNCTION_EXECUTE_SCSI) {
								PSCSI_REQUEST_BLOCK pSrb = (PSCSI_REQUEST_BLOCK)pAnySrb;
								PCDB pcdb = SrbGetCdb(pSrb);
								UCHAR  cdbLen = SrbGetCdbLength(pSrb);
								if (pcdb != nullptr && cdbLen)
								{
									//info->scsi_opcode = pcdb->CDB6GENERIC.OperationCode;
									info->scsi_opcode = pcdb->AsByte[0];
								}
							
							}
						}
			
						break;				
				}

				switch (info->MajorFunction) {
#if 1
					case IrpMajorCode::WRITE:
						info->Write.Length = stack->Parameters.Write.Length;
						info->Write.Offset = stack->Parameters.Write.ByteOffset.QuadPart;
						if (info->Write.Length > 0) {
							auto dataSize = min(MaxDataSize, info->Write.Length);
							if (NT_SUCCESS(GetDataFromIrp(DeviceObject, Irp, stack, info->MajorFunction, (PUCHAR)info + sizeof(IrpArrivedInfo), dataSize))) {
								info->DataSize = dataSize;
								info->Size += (USHORT)dataSize;
							}
						}
						break;
#endif
					case IrpMajorCode::DEVICE_CONTROL:						// 0xe 
					case IrpMajorCode::INTERNAL_DEVICE_CONTROL:	// 0xf  

						info->DeviceIoControl.IoControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
						info->DeviceIoControl.InputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
						info->DeviceIoControl.OutputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
						if (info->DeviceIoControl.InputBufferLength > 0) {
							auto dataSize = min(MaxDataSize, info->DeviceIoControl.InputBufferLength);
							if (NT_SUCCESS(GetDataFromIrp(DeviceObject, Irp, stack, info->MajorFunction, (PUCHAR)info + sizeof(IrpArrivedInfo), dataSize))) {
								info->DataSize = dataSize;
								info->Size += (USHORT)dataSize;
							}

						}
						break;
				}

				globals.DataBuffer->Write(info, info->Size);

			}
			//
			// replace completion routine and save old one 
			//          
			/*
			auto oldCompletion = InterlockedExchangePointer((PVOID*)&stack->CompletionRoutine, OnIrpCompleted);
			auto index = globals.IrpCompletionTable->Insert(Irp, oldCompletion);
			if (index < 0) {
				// no more space in table, revert completion
				InterlockedExchangePointer((PVOID*)&stack->CompletionRoutine, oldCompletion);
			}
			*/
		}

		auto userBuffer = Irp->UserBuffer;
		auto status = globals.Drivers[i].MajorFunction[stack->MajorFunction](DeviceObject, Irp);
		if (info) {
			// IRP completed synchronously 
			// build completion message

			int size = sizeof(IrpCompletedInfo);
			int extraSize = 0;

			if (status != STATUS_PENDING && NT_SUCCESS(status)) {
				switch (info->MajorFunction) {
					case IrpMajorCode::READ:
						extraSize = info->Read.Length;
						break;
					case IrpMajorCode::DEVICE_CONTROL:
					case IrpMajorCode::INTERNAL_DEVICE_CONTROL:
						extraSize = info->DeviceIoControl.OutputBufferLength;
						break;
				}
			}
			extraSize = min(MaxDataSize, extraSize);
			size += extraSize;
			auto completeInfo = static_cast<IrpCompletedInfo*>(ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG));
			if (completeInfo) {
				KeQuerySystemTime((PLARGE_INTEGER)&completeInfo->Time);
				completeInfo->Type = DataItemType::IrpCompleted;
				if (status != STATUS_PENDING && NT_SUCCESS(status)) {
					if (userBuffer && KeGetCurrentIrql() < DISPATCH_LEVEL) {
						::memcpy((PUCHAR)completeInfo + sizeof(IrpCompletedInfo), userBuffer, extraSize);
					}
					else {
						size -= extraSize;
						extraSize = 0;
					}
				}
				completeInfo->DataSize = extraSize;
				completeInfo->ProcessId = HandleToULong(PsGetCurrentProcessId());
				completeInfo->ThreadId = HandleToULong(PsGetCurrentThreadId());
				completeInfo->Irp = Irp;
				completeInfo->Status = status;
				completeInfo->Information = extraSize;
				completeInfo->Size = (USHORT)size;

				globals.DataBuffer->Write(completeInfo, completeInfo->Size);
				ExFreePool(completeInfo);
			}
		}
		if (info)
			ExFreePool(info);

		if (info && globals.NotifyEvent)
			KeSetEvent(globals.NotifyEvent, 2, FALSE);
		return status;
	}

	NT_ASSERT(false);
	return STATUS_SUCCESS;
}

#endif

NTSTATUS OnIrpCompleted(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID context) {
	int index;
	auto originalCompletion = static_cast<PIO_COMPLETION_ROUTINE>(globals.IrpCompletionTable->Find(Irp, &index));

	auto status = Irp->IoStatus.Status;

	// capture IRP parameters

	auto info = static_cast<IrpCompletedInfo*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(IrpCompletedInfo) + MaxDataSize, DRIVER_TAG));
	if (info) {
		KeQuerySystemTime((PLARGE_INTEGER)&info->Time);
		info->Irp = Irp;
		info->Information = Irp->IoStatus.Information;
		info->Status = status;
		info->Type = DataItemType::IrpCompleted;
		info->Size = sizeof(IrpCompletedInfo);
		info->DataSize = 0;
	}

	auto stack = IoGetCurrentIrpStackLocation(Irp);
	if (Irp->PendingReturned && Irp->CurrentLocation < Irp->StackCount) {
		IoMarkIrpPending(Irp);
	}

	if (originalCompletion) {
		if ((NT_SUCCESS(status) && (stack->Control & SL_INVOKE_ON_SUCCESS)) ||
			(Irp->Cancel && (stack->Control & SL_INVOKE_ON_CANCEL)) ||
			(!NT_SUCCESS(status) && (stack->Control & SL_INVOKE_ON_ERROR))) {
			status = originalCompletion(DeviceObject, Irp, context);
		}
	}

	// report completion
	KdPrint((DRIVER_PREFIX "IRP 0x%p completed with status 0x%08X\n", Irp, status));

	if (index >= 0)
		globals.IrpCompletionTable->RemoveAt(index);

	if (info && globals.IsMonitoring) {
		if (NT_SUCCESS(status)) {
			switch (stack->MajorFunction) {
#if 1
				case IRP_MJ_READ:
					if (info->Information > 0) {
						auto dataSize = min(MaxDataSize, (ULONG)info->Information);
						if (NT_SUCCESS(GetDataFromIrp(DeviceObject, Irp, stack, IrpMajorCode::READ,
							(PUCHAR)info + sizeof(IrpCompletedInfo), dataSize))) {
							info->DataSize = dataSize;
							info->Size += (USHORT)dataSize;
						}
					}
					break;
#endif

				case IRP_MJ_DEVICE_CONTROL:
				case IRP_MJ_INTERNAL_DEVICE_CONTROL:   // same to IRP_MJ_SCSI
					auto len = stack->Parameters.DeviceIoControl.OutputBufferLength;
					if (len > 0) {
						auto dataSize = min(MaxDataSize, len);
						if (NT_SUCCESS(GetDataFromIrp(DeviceObject, Irp, stack, static_cast<IrpMajorCode>(stack->MajorFunction, true),
							(PUCHAR)info + sizeof(IrpCompletedInfo), dataSize))) {
							info->DataSize = dataSize;
							info->Size += (USHORT)dataSize;
						}
					}
					break;
			}
		}
		globals.DataBuffer->Write(info, info->Size);

		if (globals.NotifyEvent) {
			KeSetEvent(globals.NotifyEvent, 2, FALSE);
		}
	}
	if (info) {
		ExFreePool(info);
	}
	return status;
}

void RemoveAllDrivers() {

	for (int i = 0; i < MaxMonitoredDrivers; ++i) {
		if (globals.Drivers[i].DriverObject)
			RemoveDriver(i);
	}
	NT_ASSERT(globals.Count == 0);
}

NTSTATUS GetDataFromIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION stack, IrpMajorCode code, PVOID buffer, ULONG size, bool output) {
	__try {
		switch (code) {
		case IrpMajorCode::WRITE:
		case IrpMajorCode::READ:
			if (Irp->MdlAddress) {
				auto p = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
				if (p) {
					::memcpy(buffer, p, size);
					return STATUS_SUCCESS;
				}
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			if (DeviceObject->Flags & DO_BUFFERED_IO) {
				if (!Irp->AssociatedIrp.SystemBuffer) {
					return STATUS_INVALID_PARAMETER;
				}
				::memcpy(buffer, Irp->AssociatedIrp.SystemBuffer, size);
				return STATUS_SUCCESS;
			}
			if (!Irp->UserBuffer) {
				return STATUS_INVALID_PARAMETER;
			}
			::memcpy(buffer, Irp->UserBuffer, size);
			return STATUS_SUCCESS;

		case IrpMajorCode::DEVICE_CONTROL:
		case IrpMajorCode::INTERNAL_DEVICE_CONTROL:
			auto controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
			if (METHOD_FROM_CTL_CODE(controlCode) == METHOD_NEITHER) {
				if (stack->Parameters.DeviceIoControl.Type3InputBuffer < (PVOID)(1 << 16)) {
					::memcpy(buffer, stack->Parameters.DeviceIoControl.Type3InputBuffer, size);
				}
				else {
					return STATUS_UNSUCCESSFUL;
				}
			}
			else {
				if (!output || METHOD_FROM_CTL_CODE(controlCode) == METHOD_BUFFERED) {
					if (!Irp->AssociatedIrp.SystemBuffer) {
						return STATUS_INVALID_PARAMETER;
					}
					::memcpy(buffer, Irp->AssociatedIrp.SystemBuffer, size);
				}
				else {
					if (!Irp->MdlAddress) {
						return STATUS_INVALID_PARAMETER;
					}
					auto data = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
					if (data) {
						::memcpy(buffer, data, size);
					}
					else {
						return STATUS_UNSUCCESSFUL;
					}
				}
			}
			return STATUS_SUCCESS;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
	}
	return STATUS_UNSUCCESSFUL;
}

void GenericDriverUnload(PDRIVER_OBJECT DriverObject) {
	for (int i = 0; i < MaxMonitoredDrivers; ++i) {
		if (globals.Drivers[i].DriverObject == DriverObject) {
			if (globals.Drivers[i].DriverUnload)
				globals.Drivers[i].DriverUnload(DriverObject);
			RemoveDriver(i);
		}
	}
	NT_ASSERT(false);
}
