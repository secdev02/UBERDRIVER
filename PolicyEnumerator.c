//
// PolicyEnumerator.c - Kernel driver to enumerate approved WDAC policy signers
// For testing and verification purposes only
//

#include <ntddk.h>
#include <wdm.h>

#define POLICY_TAG 'PLCY'

// Structure to hold policy file information
typedef struct _POLICY_FILE_INFO {
    UNICODE_STRING FilePath;
    LARGE_INTEGER FileSize;
    BOOLEAN Exists;
} POLICY_FILE_INFO, *PPOLICY_FILE_INFO;

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

NTSTATUS ReadPolicyFile(
    _In_ PUNICODE_STRING FilePath,
    _Out_ PVOID* Buffer,
    _Out_ PULONG BufferSize
);

VOID ParsePolicySigners(
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize
);

VOID EnumeratePolicyFiles(VOID);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, ReadPolicyFile)
#pragma alloc_text(PAGE, ParsePolicySigners)
#pragma alloc_text(PAGE, EnumeratePolicyFiles)
#endif

//
// Driver Entry Point
//
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[PolicyEnum] Driver loading...\n");
    
    // Set unload routine
    DriverObject->DriverUnload = DriverUnload;
    
    // Enumerate all policy files
    EnumeratePolicyFiles();
    
    DbgPrint("[PolicyEnum] Driver loaded successfully\n");
    
    return STATUS_SUCCESS;
}

//
// Driver Unload
//
VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();
    
    DbgPrint("[PolicyEnum] Driver unloading\n");
}

//
// Read a policy file from disk
//
NTSTATUS
ReadPolicyFile(
    _In_ PUNICODE_STRING FilePath,
    _Out_ PVOID* Buffer,
    _Out_ PULONG BufferSize
)
{
    NTSTATUS status;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    FILE_STANDARD_INFORMATION fileInfo;
    PVOID buffer = NULL;
    
    PAGED_CODE();
    
    *Buffer = NULL;
    *BufferSize = 0;
    
    // Initialize object attributes
    InitializeObjectAttributes(
        &objAttr,
        FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );
    
    // Open the file
    status = ZwCreateFile(
        &fileHandle,
        GENERIC_READ,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[PolicyEnum] Failed to open file: %wZ (Status: 0x%08X)\n", FilePath, status);
        return status;
    }
    
    // Get file size
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatus,
        &fileInfo,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[PolicyEnum] Failed to query file info (Status: 0x%08X)\n", status);
        ZwClose(fileHandle);
        return status;
    }
    
    // Allocate buffer
    buffer = ExAllocatePoolWithTag(
        NonPagedPool,
        (SIZE_T)fileInfo.EndOfFile.QuadPart,
        POLICY_TAG
    );
    
    if (buffer == NULL) {
        DbgPrint("[PolicyEnum] Failed to allocate memory\n");
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Read file
    status = ZwReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        buffer,
        (ULONG)fileInfo.EndOfFile.QuadPart,
        NULL,
        NULL
    );
    
    ZwClose(fileHandle);
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[PolicyEnum] Failed to read file (Status: 0x%08X)\n", status);
        ExFreePoolWithTag(buffer, POLICY_TAG);
        return status;
    }
    
    *Buffer = buffer;
    *BufferSize = (ULONG)fileInfo.EndOfFile.QuadPart;
    
    return STATUS_SUCCESS;
}

//
// Parse policy file to extract signer information
// Note: This is a basic parser that looks for certificate patterns
//
VOID
ParsePolicySigners(
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize
)
{
    PUCHAR data = (PUCHAR)Buffer;
    ULONG i;
    ULONG certCount = 0;
    
    PAGED_CODE();
    
    DbgPrint("[PolicyEnum] Parsing policy buffer (Size: %u bytes)\n", BufferSize);
    
    // Look for X.509 certificate signatures (ASN.1 SEQUENCE tag 0x30 0x82)
    // This is a simplified parser - real certificates need full ASN.1 parsing
    for (i = 0; i < BufferSize - 4; i++) {
        // Look for certificate header pattern
        if (data[i] == 0x30 && data[i + 1] == 0x82) {
            USHORT certSize = (data[i + 2] << 8) | data[i + 3];
            
            DbgPrint("[PolicyEnum]   Found potential certificate at offset 0x%X (Size: %u bytes)\n", 
                     i, certSize);
            
            // Try to find subject/issuer information
            // Look for OID patterns (0x06 followed by length)
            for (ULONG j = i; j < i + 200 && j < BufferSize - 10; j++) {
                if (data[j] == 0x06 && data[j + 1] >= 3 && data[j + 1] <= 16) {
                    // Found an OID, print it
                    DbgPrint("[PolicyEnum]     OID at +0x%X: ", j - i);
                    for (ULONG k = 0; k < data[j + 1] && k < 16; k++) {
                        DbgPrint("%02X ", data[j + 2 + k]);
                    }
                    DbgPrint("\n");
                }
                
                // Look for printable strings (certificate names)
                if (data[j] == 0x13 || data[j] == 0x0C) { // PrintableString or UTF8String
                    UCHAR strLen = data[j + 1];
                    if (strLen > 0 && strLen < 128 && j + 2 + strLen < BufferSize) {
                        DbgPrint("[PolicyEnum]     Name at +0x%X: ", j - i);
                        for (ULONG k = 0; k < strLen && k < 64; k++) {
                            if (data[j + 2 + k] >= 0x20 && data[j + 2 + k] <= 0x7E) {
                                DbgPrint("%c", data[j + 2 + k]);
                            }
                        }
                        DbgPrint("\n");
                    }
                }
            }
            
            certCount++;
            i += certSize + 4; // Skip past this certificate
        }
    }
    
    if (certCount == 0) {
        DbgPrint("[PolicyEnum] No certificate patterns found - may be encrypted or different format\n");
        
        // Print first 256 bytes as hex for manual inspection
        DbgPrint("[PolicyEnum] First 256 bytes (hex):\n");
        for (i = 0; i < 256 && i < BufferSize; i++) {
            if (i % 16 == 0) {
                DbgPrint("[PolicyEnum] %04X: ", i);
            }
            DbgPrint("%02X ", data[i]);
            if (i % 16 == 15) {
                DbgPrint("\n");
            }
        }
        DbgPrint("\n");
    }
    
    DbgPrint("[PolicyEnum] Total potential certificates found: %u\n", certCount);
}

//
// Enumerate all WDAC policy files
//
VOID
EnumeratePolicyFiles(VOID)
{
    NTSTATUS status;
    UNICODE_STRING policyPath;
    PVOID buffer;
    ULONG bufferSize;
    
    PAGED_CODE();
    
    DbgPrint("[PolicyEnum] ========================================\n");
    DbgPrint("[PolicyEnum] Enumerating WDAC Policy Files\n");
    DbgPrint("[PolicyEnum] ========================================\n\n");
    
    // Check SiPolicy.p7b (legacy single policy format)
    RtlInitUnicodeString(&policyPath, L"\\SystemRoot\\System32\\CodeIntegrity\\SiPolicy.p7b");
    DbgPrint("[PolicyEnum] Checking: %wZ\n", &policyPath);
    
    status = ReadPolicyFile(&policyPath, &buffer, &bufferSize);
    if (NT_SUCCESS(status)) {
        DbgPrint("[PolicyEnum] SUCCESS - File size: %u bytes\n", bufferSize);
        ParsePolicySigners(buffer, bufferSize);
        ExFreePoolWithTag(buffer, POLICY_TAG);
    }
    DbgPrint("\n");
    
    // Check driversipolicy.p7b (Microsoft recommended blocks)
    RtlInitUnicodeString(&policyPath, L"\\SystemRoot\\System32\\CodeIntegrity\\driversipolicy.p7b");
    DbgPrint("[PolicyEnum] Checking: %wZ\n", &policyPath);
    
    status = ReadPolicyFile(&policyPath, &buffer, &bufferSize);
    if (NT_SUCCESS(status)) {
        DbgPrint("[PolicyEnum] SUCCESS - File size: %u bytes\n", bufferSize);
        ParsePolicySigners(buffer, bufferSize);
        ExFreePoolWithTag(buffer, POLICY_TAG);
    }
    DbgPrint("\n");
    
    // Note: Multiple policy format files would be in CiPolicies\Active\{GUID}.cip
    // Enumerating those would require directory enumeration
    DbgPrint("[PolicyEnum] Note: Multiple policy format files (.cip) are located in:\n");
    DbgPrint("[PolicyEnum]   \\SystemRoot\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip\n");
    DbgPrint("[PolicyEnum]   Use tools like 'CiTool.exe -lp' to list them from user mode\n\n");
    
    DbgPrint("[PolicyEnum] ========================================\n");
    DbgPrint("[PolicyEnum] Enumeration Complete\n");
    DbgPrint("[PolicyEnum] ========================================\n");
    DbgPrint("[PolicyEnum] IMPORTANT: For full policy parsing, use PowerShell:\n");
    DbgPrint("[PolicyEnum]   Get-CIPolicy or ConfigCI module cmdlets\n");
    DbgPrint("[PolicyEnum]   CiTool.exe -lp (Windows 11 2022+)\n");
}

