#include "dpc.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    
    /* no need to unreference drvobj as we dont call it anywhere anyway */

    DPC::perform_dpc_scan();

    return STATUS_SUCCESS;
}
