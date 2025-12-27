#include "includes.h"
#include "detections/dpc.h"
#include "integrity/hvci.h"
#include "integrity/usermode threads.h"
#include "integrity/vulnerable_drivers.h"
#include "detections/dma.h"
#include "detections/kdmapper.h"
#include "integrity/integrity.h"
#include "detections/mouse.h"
#include "detections/efi.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    
    /* no need to unreference drvobj as we dont call it anywhere anyway */

    DPC::perform_dpc_scan();

    return STATUS_SUCCESS;
}
