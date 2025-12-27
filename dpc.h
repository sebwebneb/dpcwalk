#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#define MAX_STACK_DEPTH 128
#define DUMP_SIZE 0x100
#define POOL_TAG_DPC 'besw'

typedef struct _DPC_REPORT_PACKET {
    ULONG64 detection_timestamp;
    ULONG processor_id;
    ULONG64 suspicious_rip;
    ULONG64 stack_frame_index;
    CHAR module_name[256];
    CHAR detection_reason[128];
    UCHAR memory_dump[DUMP_SIZE];
} DPC_REPORT_PACKET, * PDPC_REPORT_PACKET;

typedef struct _DPC_CONTEXT {
    KDPC dpc;
    KEVENT event;
    DPC_REPORT_PACKET report;
    BOOLEAN has_detection;
    ULONG processor;
} DPC_CONTEXT, * PDPC_CONTEXT;

MODULE_CACHE g_moduleCache = { 0 };

namespace DPC { /* all love namespaces */

    VOID QueuePacketToUser(PDPC_REPORT_PACKET packet) {
        // DbgPrint("[SEBWEBNEB] QUEUED PACKET: RIP 0x%llx | Reason: %s | Module: %s\n", packet->suspicious_rip, packet->detection_reason, packet->module_name);

        /* in here you'd obviously replace it with your data collecton and actually send it over to usermode, */
        /* however this is just a poc. */
    }

    VOID safe_strcpy(PCHAR dest, const CHAR* src, SIZE_T destSize) {
        SIZE_T i;
        for (i = 0; i < destSize - 1 && src[i] != '\0'; i++) {
            dest[i] = src[i];
        }
        dest[i] = '\0';
    }

    BOOLEAN str_starts_with_i(const CHAR* str, const CHAR* prefix) {
        while (*prefix) {
            CHAR c1 = *str;
            CHAR c2 = *prefix;
            if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
            if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
            if (c1 != c2) return FALSE;
            str++;
            prefix++;
        }
        return TRUE;
    }

    BOOLEAN validate_section_perms(PVOID moduleBase, PVOID address) {
        if (!MmIsAddressValid(moduleBase)) return TRUE;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
        if (dos->e_magic != 0x5A4D) return TRUE;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((ULONG64)moduleBase + dos->e_lfanew);
        if (!MmIsAddressValid(nt) || nt->Signature != 0x4550) return TRUE;

        PIMAGE_SECTION_HEADER_LOCAL section = (PIMAGE_SECTION_HEADER_LOCAL)((ULONG64)nt + sizeof(IMAGE_NT_HEADERS64));
        ULONG64 target = (ULONG64)address;
        ULONG64 modStart = (ULONG64)moduleBase;

        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (!MmIsAddressValid(&section[i])) break;

            ULONG64 start = modStart + section[i].VirtualAddress;
            ULONG64 end = start + section[i].Misc.VirtualSize;

            if (target >= start && target < end) {
                ULONG chars = section[i].Characteristics;

                if (!(chars & IMAGE_SCN_MEM_EXECUTE)) return FALSE;
                if (chars & IMAGE_SCN_MEM_DISCARDABLE) return FALSE;
                if ((chars & IMAGE_SCN_MEM_EXECUTE) && (chars & IMAGE_SCN_MEM_WRITE)) return FALSE;

                return TRUE;
            }
        }
        return FALSE;
    }

    BOOLEAN is_address_valid_code(PVOID address, PCHAR moduleNameOut, SIZE_T moduleNameSize, PCHAR reasonOut, SIZE_T reasonSize) {
        KIRQL oldIrql;
        ULONG64 addr = (ULONG64)address;

        if (addr < 0xFFFF800000000000) return TRUE;
        if (addr >= 0xFFFFF90000000000) return TRUE;

        KeAcquireSpinLock(&g_moduleCache.lock, &oldIrql);

        for (ULONG i = 0; i < g_moduleCache.count; i++) {
            PMODULE_ENTRY entry = &g_moduleCache.entries[i];
            ULONG64 base = (ULONG64)entry->base;

            if (addr >= base && addr < (base + entry->size)) {
                if (str_starts_with_i(entry->name, "dump_")) { /* this catches ghostmapper, dump drivers shouldnt ever be executing */
                    safe_strcpy(moduleNameOut, entry->name, moduleNameSize);
                    safe_strcpy(reasonOut, "Blacklisted Driver", reasonSize);
                    KeReleaseSpinLock(&g_moduleCache.lock, oldIrql);
                    return FALSE;
                }

                if (!validate_section_perms(entry->base, address)) { /* self explanatory */
                    safe_strcpy(moduleNameOut, entry->name, moduleNameSize);
                    safe_strcpy(reasonOut, "Invalid Section (RWX/NoExec/Init)", reasonSize);
                    KeReleaseSpinLock(&g_moduleCache.lock, oldIrql);
                    return FALSE;
                }

                safe_strcpy(moduleNameOut, entry->name, moduleNameSize);
                safe_strcpy(reasonOut, "Valid", reasonSize);
                KeReleaseSpinLock(&g_moduleCache.lock, oldIrql);
                return TRUE;
            }
        }

        safe_strcpy(moduleNameOut, "UNBACKED", moduleNameSize);
        safe_strcpy(reasonOut, "Unbacked Code", reasonSize);
        KeReleaseSpinLock(&g_moduleCache.lock, oldIrql);
        return FALSE;
    }

    NTSTATUS refresh_module_cache() {
        NTSTATUS status;
        ULONG bufferSize = 0;
        PVOID buffer = NULL;
        PRTL_PROCESS_MODULES modules;

        status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
        if (status != STATUS_INFO_LENGTH_MISMATCH) return status;

        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, POOL_TAG_DPC);
        if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;

        status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(buffer, POOL_TAG_DPC);
            return status;
        }

        modules = (PRTL_PROCESS_MODULES)buffer;
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_moduleCache.lock, &oldIrql);

        if (modules->NumberOfModules > g_moduleCache.capacity) {
            if (g_moduleCache.entries) ExFreePoolWithTag(g_moduleCache.entries, POOL_TAG_DPC);
            g_moduleCache.capacity = modules->NumberOfModules + 64;
            g_moduleCache.entries = (PMODULE_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, g_moduleCache.capacity * sizeof(MODULE_ENTRY), POOL_TAG_DPC);
        }

        if (g_moduleCache.entries) {
            g_moduleCache.count = modules->NumberOfModules;
            for (ULONG i = 0; i < modules->NumberOfModules; i++) {
                PRTL_PROCESS_MODULE_INFORMATION mod = &modules->Modules[i];
                g_moduleCache.entries[i].base = mod->ImageBase;
                g_moduleCache.entries[i].size = mod->ImageSize;
                PCHAR name = (PCHAR)mod->FullPathName + mod->OffsetToFileName;
                safe_strcpy(g_moduleCache.entries[i].name, name, sizeof(g_moduleCache.entries[i].name));
            }
        }

        KeReleaseSpinLock(&g_moduleCache.lock, oldIrql);
        ExFreePoolWithTag(buffer, POOL_TAG_DPC);
        return STATUS_SUCCESS;
    }

    NTSTATUS init_module_cache() {
        KeInitializeSpinLock(&g_moduleCache.lock);
        g_moduleCache.entries = NULL;
        g_moduleCache.count = 0;
        g_moduleCache.capacity = 0;
        return refresh_module_cache();
    }

    VOID cleanup_module_cache() {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_moduleCache.lock, &oldIrql);
        if (g_moduleCache.entries) ExFreePoolWithTag(g_moduleCache.entries, POOL_TAG_DPC);
        g_moduleCache.entries = NULL;
        g_moduleCache.count = 0;
        KeReleaseSpinLock(&g_moduleCache.lock, oldIrql);
    }

    VOID dpc_routine(PKDPC dpc, PVOID deferredContext, PVOID systemArg1, PVOID systemArg2) {
        UNREFERENCED_PARAMETER(dpc);
        UNREFERENCED_PARAMETER(systemArg1);
        UNREFERENCED_PARAMETER(systemArg2);

        PDPC_CONTEXT ctx = (PDPC_CONTEXT)deferredContext;
        PVOID callers[MAX_STACK_DEPTH] = { 0 };
        USHORT framesCaptured = 0;
        LARGE_INTEGER startTime, endTime, frequency;

        KeQueryPerformanceCounter(&frequency);
        startTime = KeQueryPerformanceCounter(NULL);

        framesCaptured = RtlCaptureStackBackTrace(0, MAX_STACK_DEPTH, callers, NULL);

        for (ULONG i = 0; i < framesCaptured; i++) {
            PVOID returnAddress = callers[i];

            if ((ULONG64)returnAddress < 0xFFFF800000000000) continue;
            if (!MmIsAddressValid(returnAddress)) continue;

            CHAR moduleName[256] = { 0 };
            CHAR reason[128] = { 0 };

            if (!is_address_valid_code(returnAddress, moduleName, sizeof(moduleName), reason, sizeof(reason))) {
                ctx->has_detection = TRUE;
                ctx->report.detection_timestamp = startTime.QuadPart;
                ctx->report.processor_id = ctx->processor;
                ctx->report.suspicious_rip = (ULONG64)returnAddress;
                ctx->report.stack_frame_index = i;
                safe_strcpy(ctx->report.module_name, moduleName, sizeof(ctx->report.module_name));
                safe_strcpy(ctx->report.detection_reason, reason, sizeof(ctx->report.detection_reason));

                if (MmIsAddressValid(returnAddress)) {
                    __try {
                        RtlCopyMemory(ctx->report.memory_dump, (PVOID)((ULONG64)returnAddress), DUMP_SIZE);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        RtlZeroMemory(ctx->report.memory_dump, DUMP_SIZE);
                    }
                }
                break;
            }
        }

        endTime = KeQueryPerformanceCounter(NULL);
        ULONG64 elapsed = endTime.QuadPart - startTime.QuadPart;
        ULONG64 microseconds = (elapsed * 1000000) / frequency.QuadPart;

        if (ctx->processor == 0) {
           // DbgPrint("[SEBWEBNEB] CPU 0 Scan: %u frames, %llu us\n", framesCaptured, microseconds); 
           // this dbgprint is for debug, remove if you want
        }

        KeSetEvent(&ctx->event, IO_NO_INCREMENT, FALSE);
    }

    NTSTATUS perform_dpc_scan() {
        ULONG cpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        PDPC_CONTEXT contexts = NULL;
        NTSTATUS status = STATUS_SUCCESS;

        status = refresh_module_cache();
        if (!NT_SUCCESS(status)) return status;

        contexts = (PDPC_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, cpuCount * sizeof(DPC_CONTEXT), POOL_TAG_DPC);
        if (!contexts) return STATUS_INSUFFICIENT_RESOURCES;

        RtlZeroMemory(contexts, cpuCount * sizeof(DPC_CONTEXT));

        for (ULONG i = 0; i < cpuCount; i++) {
            PDPC_CONTEXT ctx = &contexts[i];
            ctx->processor = i;
            ctx->has_detection = FALSE;
            KeInitializeEvent(&ctx->event, NotificationEvent, FALSE);
            KeInitializeDpc(&ctx->dpc, dpc_routine, ctx);
            KeSetTargetProcessorDpc(&ctx->dpc, (CCHAR)i);
            KeSetImportanceDpc(&ctx->dpc, HighImportance);
            KeInsertQueueDpc(&ctx->dpc, NULL, NULL);
        }

        for (ULONG i = 0; i < cpuCount; i++) {
            KeWaitForSingleObject(&contexts[i].event, Executive, KernelMode, FALSE, NULL);

            if (contexts[i].has_detection) {
                QueuePacketToUser(&contexts[i].report);
            }
        }

        ExFreePoolWithTag(contexts, POOL_TAG_DPC);
        return STATUS_SUCCESS;
    }
}
