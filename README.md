# UBERDRIVER
Kernel Signed Driver Validation Research 

CLAUDE AI Created README.

## Driver Validation Happens in **Kernel Mode**

The driver signature validation is performed entirely in kernel mode through the **CI.dll** (Code Integrity) module. Here's the breakdown:

### Key Components

1. **CI.dll** - CI.dll is a kernel-mode library that allows drivers to validate Authenticode signatures in kernel mode. When the Windows kernel verifies drivers as they are loaded, this must be done in kernel mode.

2. **CiValidateImageHeader()** - This function is used by ntoskernel.exe when a driver is being loaded to verify its signature. It maps the file in kernel space and extracts its signature, and also calculates the file digest.

3. **g_CiOptions** - DSE (Driver Signature Enforcement) is implemented using the kernel mode library CI.dll. The CI.dll module defines the variable g_CiOptions, which controls whether Windows enforces driver signature verification.

### With HVCI/VBS Enabled

When Hypervisor-protected Code Integrity is active, there's an additional layer:

Upon loading a new driver, the secure kernel is also triggered and uses its own instance of the code integrity library, SKCI.dll (Secure Kernel Code Integrity). The digital signature is validated and checked to be authorized within the current policy in the Secure World (VTL1). Only then are executable and non-writable permissions applied.

### Custom Kernel Signers Specifics

Custom Kernel Signers (CKS) allows users to decide what certificates are trusted or denied in kernel. It requires the CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners policy to be enabled.

The SIPolicy.bin file (which defines trusted signers) is loaded during the early boot process and enforced by CI.dll in kernel mode. The validation never touches user mode—CI.DLL is not callable outside the kernel, ensuring that signature checks cannot be bypassed from user-mode code.

Approach 

I'll search for information about the kernel structures that handle driver signature verification and custom kernel signers.Based on the research, here's what I found about kernel structures that hold approved kernel driver signers:

## Key Kernel Structures and Components

### **CI.dll Global Variables**

The Code Integrity module (CI.dll) contains several critical global variables that control driver signature enforcement:

- **`CI!g_CiOptions`** - A configuration variable with flags that control Driver Signature Enforcement (DSE), typically set to 0 to completely disable DSE
- **`nt!SeCiCallbacks`** (or `nt!g_CiCallbacks`) - A callback structure filled by CiInitialize() containing function pointers like CiValidateImageHeader() and CiValidateImageData()

### **Certificate Validation Structures**

During signature validation, CI.dll uses specific structures to hold certificate information:

**PolicyInfo Structure:**
```c
typedef struct _PolicyInfo {
    int structSize;
    NTSTATUS verificationStatus;
    int flags;
    PVOID certChainInfo;  // Pointer to certificate chain data
    FILETIME revocationTime;
    FILETIME notBeforeTime;
    FILETIME notAfterTime;
} PolicyInfo;
```

The certChainInfo buffer contains data about the entire certificate chain in both parsed format (organized sub-structures) and raw format (ASN.1 certificate blobs, keys, EKUs), making it easy to check the subject, issuer, certificate chain, and hash algorithms.

## Custom Kernel Signers (WDAC Policies)

Yes, **custom kernel signers are supported through Windows Defender Application Control (WDAC)** policies:

### **Policy Storage Locations**

WDAC policies containing custom signer information are stored at:

- **Single policy format**: 
  - `C:\Windows\System32\CodeIntegrity\SiPolicy.p7b`
  - `<EFI System Partition>\Microsoft\Boot\SiPolicy.p7b`
  
- **Multiple policy format** (Windows 10 1903+):
  - `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{PolicyGUID}.cip`
  - `<EFI System Partition>\Microsoft\Boot\CiPolicies\Active\{PolicyGUID}.cip`

- **Microsoft recommended driver blocks**:
  - `driversipolicy.p7b` in the `%windir%\system32\CodeIntegrity` directory, which contains blocks enforced by HVCI, Smart App Control, or S mode

### **How Policies Work**

When the operating system boots, either WINLOAD or the kernel CI driver loads the policy from disk into memory and begins enforcement based on the configured rules. The policy files contain:

- **Signer definitions** with certificate TBS (To-Be-Signed) hashes
- **Extended Key Usage (EKU)** requirements
- **Rule options** (like requiring EV certificates for kernel drivers)
- **UpdatePolicySigners** - certificates authorized to update the policy

## In-Memory Certificate Validation

Functions like CiCheckSignedFile() and CiValidateFileObject() are exported by CI.dll to validate signatures, and the ntoskrnl.exe uses CiValidateImageHeader() when loading drivers. These functions:

1. Extract certificates from the PE signature
2. Validate against the loaded WDAC policy rules
3. Check certificate chains and EKUs
4. Return validation results in the PolicyInfo structure

The actual certificate data from loaded policies resides in CI.dll's memory space, managed by internal functions like `MinCryptVerifyCertificateWithPolicy2()`.

**Note**: Custom kernel signers use a specific OID (1.3.6.1.4.1.311.79.1) when signing policy files to indicate the content is specifically a WDAC policy.



## References - Windows Custom Kernel Signers & Driver Validation

### Code Integrity (CI.dll) Documentation

- **Code Integrity in the Kernel: A Look Into ci.dll** (Cybereason)
  - https://www.cybereason.com/blog/code-integrity-in-the-kernel-a-look-into-cidll
  - https://medium.com/cybereason/code-integrity-in-the-kernel-66b3f5cce5f

- **CI.dll FIPS 140 Security Policy Documents** (NIST/Microsoft)
  - Windows 7: https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp1327.pdf
  - Windows Vista: https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp890.pdf

### Driver Signature Enforcement (DSE)

- **Driver Signature Enforcement** (BorderGate)
  - https://www.bordergate.co.uk/driver-signature-enforcement/

- **The Swan Song for Driver Signature Enforcement Tampering** (Fortinet)
  - https://www.fortinet.com/blog/threat-research/driver-signature-enforcement-tampering

- **A Quick Insight into the Driver Signature Enforcement** (j00ru)
  - https://j00ru.vexillium.org/2010/06/insight-into-the-driver-signature-enforcement/

- **Back Doors for Cross-Signed Drivers** (Geoff Chappell)
  - https://www.geoffchappell.com/notes/security/whqlsettings/index.htm

### Custom Kernel Signers (CKS)

- **Windows10-CustomKernelSigners** (HyperSine)
  - https://github.com/HyperSine/Windows10-CustomKernelSigners

- **SSDE - Secure Boot Self-Signed Driver Enrollment** (valinet)
  - https://github.com/valinet/ssde

### Microsoft Official Documentation

- **Kernel-Mode Code Signing Requirements**
  - https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-

- **Windows Driver Signing Tutorial**
  - https://learn.microsoft.com/en-us/windows-hardware/drivers/install/windows-driver-signing-tutorial

### WDAC / Device Guard Policy

- **WDAC Notes** (SpyNetGirl)
  - https://spynetgirl.github.io/WDAC/WDAC%20Notes/

- **Windows Device Guard Code Integrity Policy Reference**
  - https://exploit200.rssing.com/chan-4343295/all_p4.html
