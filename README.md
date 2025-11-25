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
