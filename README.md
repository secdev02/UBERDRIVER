
# UBERDRIVER
Kernel Signed Driver Validation Research 

CLAUDE AI Assisted / Guided Research - Claude created this README for example.

The aim, take a problem, question for research, and use Claude to augment, enrich, enhance.

Research Aim - Understand and Extend and exploit custom signed kernel drivers.

Check claims for accuracy, test, validate, challenge, learn.

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


# WDAC Policy Enumerator Driver

A kernel-mode driver for Windows that enumerates and displays information about currently active Windows Defender Application Control (WDAC) policies and their approved signers.

## Purpose

This driver helps security researchers and system administrators verify which kernel-mode code signing certificates are currently trusted on a Windows system. It's useful for:

- Auditing security configurations
- Verifying WDAC policy deployment
- Testing and debugging custom WDAC policies
- Ensuring no unexpected signers are trusted

## What It Does

The driver:
1. Enumerates WDAC policy files from standard locations
2. Reads policy files (SiPolicy.p7b, driversipolicy.p7b)
3. Attempts to extract certificate information from policies
4. Outputs findings to the kernel debugger (DebugView or WinDbg)

## Prerequisites

### Development Requirements

- Windows 10/11 SDK
- Windows Driver Kit (WDK) for Windows 10/11
- Visual Studio 2019 or later with C++ development tools
- Administrator privileges

### Runtime Requirements

- Windows 10 version 1607 or later / Windows 11
- Test Mode enabled OR properly signed driver
- Administrator privileges

## Compilation

### Method 1: Using Visual Studio with WDK

1. Open Visual Studio
2. Create a new "Empty WDM Driver" project
3. Add `PolicyEnumerator.c` to the project
4. Build the solution (x64 Debug or Release)

### Method 2: Using MSBuild and WDK Command Line

```cmd
REM Open "x64 Native Tools Command Prompt for VS"
cd /d <project_directory>
msbuild PolicyEnumerator.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Method 3: Using Legacy WDK Build

```cmd
REM Open WDK Build Environment
cd /d <project_directory>
build
```

## Test Signing (Required for Testing)

Since this driver is not Microsoft-signed, you must enable test mode:

### Enable Test Mode

```cmd
REM Run as Administrator
bcdedit /set testsigning on
shutdown /r /t 0
```

### Create a Test Certificate

```cmd
REM Create a self-signed certificate
makecert -r -pe -ss PrivateCertStore -n "CN=Test Driver Signing" TestDriverSign.cer

REM Sign the driver
signtool sign /s PrivateCertStore /n "Test Driver Signing" /t http://timestamp.digicert.com PolicyEnumerator.sys
```

### Install the Test Certificate

```cmd
REM Install to Trusted Root
certmgr /add TestDriverSign.cer /s /r localMachine root

REM Install to Trusted Publishers
certmgr /add TestDriverSign.cer /s /r localMachine trustedpublisher
```

## Installation and Usage

### Method 1: Using SC.EXE (Service Control)

```cmd
REM Run as Administrator

REM Copy driver to system directory
copy PolicyEnumerator.sys C:\Windows\System32\drivers\

REM Create the service
sc create PolicyEnumerator type= kernel binPath= C:\Windows\System32\drivers\PolicyEnumerator.sys

REM Start the driver
sc start PolicyEnumerator

REM View output in DebugView or WinDbg

REM Stop the driver
sc stop PolicyEnumerator

REM Delete the service
sc delete PolicyEnumerator
```

### Method 2: Using OSR Driver Loader

1. Download OSR Driver Loader from https://www.osronline.com/article.cfm%5Earticle=157.htm
2. Register the driver
3. Start the driver
4. View output in DebugView

### Method 3: Using DevCon (Device Console)

```cmd
devcon install PolicyEnumerator.inf Root\PolicyEnumerator
devcon enable Root\PolicyEnumerator
```

## Viewing Output

The driver outputs information to the kernel debug log. To view:

### Option 1: DebugView (Sysinternals)

1. Download DebugView from https://learn.microsoft.com/sysinternals/downloads/debugview
2. Run as Administrator
3. Enable "Capture Kernel" (Ctrl+K)
4. Enable "Enable Verbose Kernel Output"
5. Start the driver
6. View the output in DebugView

### Option 2: WinDbg (Windows Debugger)

```cmd
REM Attach kernel debugger
windbg -kl

REM View debug output
!dbgprint
```

## Expected Output

The driver will output information similar to:

```
[PolicyEnum] ========================================
[PolicyEnum] Enumerating WDAC Policy Files
[PolicyEnum] ========================================

[PolicyEnum] Checking: \SystemRoot\System32\CodeIntegrity\SiPolicy.p7b
[PolicyEnum] SUCCESS - File size: 12345 bytes
[PolicyEnum] Parsing policy buffer (Size: 12345 bytes)
[PolicyEnum]   Found potential certificate at offset 0x200 (Size: 1024 bytes)
[PolicyEnum]     OID at +0x10: 55 04 03 ...
[PolicyEnum]     Name at +0x50: Microsoft Windows Production CA
...
[PolicyEnum] Total potential certificates found: 3

[PolicyEnum] Checking: \SystemRoot\System32\CodeIntegrity\driversipolicy.p7b
...
```

## Advanced Usage: Full Policy Parsing

For complete policy analysis, use PowerShell tools after identifying policy files:

```powershell
# List all active policies (Windows 11 2022+)
CiTool.exe -lp

# Export policy to XML for analysis
# Note: Binary to XML conversion requires reverse engineering or tools
```

## Important Notes

### Limitations

1. **Binary Format**: WDAC policy files use an undocumented binary format. This driver provides basic parsing but may not extract all signer information.

2. **Encrypted Policies**: Some policies may be encrypted or signed, making direct parsing difficult.

3. **Multiple Policies**: Modern systems (Windows 10 1903+) support up to 32 active policies in `CiPolicies\Active\`. This driver shows legacy locations only.

4. **Certificate Extraction**: The parser looks for ASN.1 certificate patterns but full X.509 parsing is complex.

### Security Considerations

- **Test Environment Only**: This driver is for testing and research purposes.
- **No Production Use**: Do not deploy on production systems without thorough testing.
- **Test Signing**: Test-signed drivers reduce security; disable test mode after testing.

### Recommended Workflow

1. Run this driver to identify policy files
2. Copy policy files for offline analysis
3. Use Microsoft's ConfigCI PowerShell module for full parsing:
   ```powershell
   # If you have XML source
   Get-CIPolicy -FilePath .\policy.xml
   ```

## Troubleshooting

### Driver Won't Load

- Verify test mode is enabled: `bcdedit /enum`
- Check driver is signed: `signtool verify /pa PolicyEnumerator.sys`
- Review Event Viewer > Windows Logs > System for errors

### No Output in DebugView

- Ensure "Capture Kernel" is enabled
- Check driver is running: `sc query PolicyEnumerator`
- Verify DebugView is running as Administrator

### Access Denied Errors

- Ensure running as Administrator
- Check file permissions on policy files
- Some policies may be protected by HVCI/VBS

## Cleanup

```cmd
REM Stop and remove driver
sc stop PolicyEnumerator
sc delete PolicyEnumerator

REM Remove driver file
del C:\Windows\System32\drivers\PolicyEnumerator.sys

REM Disable test mode (optional)
bcdedit /set testsigning off
shutdown /r /t 0
```

## Alternative Tools

For production environments, consider these alternatives:

1. **CiTool.exe** (Windows 11 2022+)
   ```cmd
   CiTool.exe -lp
   ```

2. **PowerShell ConfigCI Module**
   ```powershell
   Get-Command -Module ConfigCI
   ```

3. **WDAC Wizard**
   - GUI tool for policy management
   - Available on GitHub

## References

- [Windows Defender Application Control](https://learn.microsoft.com/windows/security/threat-protection/windows-defender-application-control/)
- [Driver Signing Requirements](https://learn.microsoft.com/windows-hardware/drivers/install/driver-signing)
- [Code Integrity in the Kernel](https://www.cybereason.com/blog/code-integrity-in-the-kernel-a-look-into-cidll)

## License

This code is provided for educational and testing purposes. Use at your own risk.

## Disclaimer

This driver directly interacts with security-critical system components. Improper use could affect system stability or security. Always test in isolated environments first.



Inpsired by - Learn to pick up and think like an adversary and use their tools.


<img width="244" height="207" alt="image" src="https://github.com/user-attachments/assets/ceaa0146-6326-4e3e-a58e-4c852b292364" />
