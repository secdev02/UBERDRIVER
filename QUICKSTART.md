# Quick Start Guide - WDAC Policy Enumerator

This guide will get you running in 5 minutes.

## Prerequisites Check

1. **Administrator Command Prompt** - Right-click Command Prompt → "Run as administrator"
2. **Test Mode** - Check if enabled:
   ```cmd
   bcdedit /enum | findstr testsigning
   ```
   If it shows "testsigning No", you need to enable it (see below).

## Fast Track: Using the Helper Script

### Step 1: Enable Test Signing (First Time Only)

```cmd
REM Run build_and_test.bat as Administrator
build_and_test.bat

REM Choose option 5 to enable test signing
REM Reboot when prompted
```

### Step 2: Build (If you have WDK/Visual Studio)

```cmd
REM Option 1: Visual Studio
REM Open PolicyEnumerator.vcxproj in Visual Studio
REM Build → Build Solution (x64 Release)

REM Option 2: Command Line (from VS Native Tools prompt)
msbuild PolicyEnumerator.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Step 3: Sign the Driver

```cmd
build_and_test.bat
REM Choose option 2 to create test certificate and sign
```

### Step 4: Install and Run

```cmd
build_and_test.bat
REM Choose option 3 to install and start driver
```

### Step 5: View Output

```cmd
build_and_test.bat
REM Choose option 7 to launch DebugView
REM In DebugView: Capture → Capture Kernel (Ctrl+K)
```

You should see output like:
```
[PolicyEnum] Driver loading...
[PolicyEnum] ========================================
[PolicyEnum] Enumerating WDAC Policy Files
[PolicyEnum] ========================================
```

## Manual Method (No Helper Script)

### 1. Enable Test Signing

```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```

### 2. Create Test Certificate

```cmd
makecert -r -pe -ss PrivateCertStore -n "CN=PolicyTest" test.cer
certmgr /add test.cer /s /r localMachine root
certmgr /add test.cer /s /r localMachine trustedpublisher
```

### 3. Sign Driver

```cmd
signtool sign /s PrivateCertStore /n "PolicyTest" /t http://timestamp.digicert.com PolicyEnumerator.sys
```

### 4. Install Driver

```cmd
copy PolicyEnumerator.sys C:\Windows\System32\drivers\
sc create PolicyEnumerator type= kernel binPath= C:\Windows\System32\drivers\PolicyEnumerator.sys
sc start PolicyEnumerator
```

### 5. View Output in DebugView

- Download: https://learn.microsoft.com/sysinternals/downloads/debugview
- Run as Administrator
- Capture → Capture Kernel (Ctrl+K)

## What You'll See

The driver will display:

1. **Policy file locations** being checked
2. **File sizes** of found policies
3. **Certificate patterns** detected in policies
4. **OIDs and names** from embedded certificates

Example output:
```
[PolicyEnum] Checking: \SystemRoot\System32\CodeIntegrity\SiPolicy.p7b
[PolicyEnum] SUCCESS - File size: 8192 bytes
[PolicyEnum] Parsing policy buffer (Size: 8192 bytes)
[PolicyEnum]   Found potential certificate at offset 0x400 (Size: 1024 bytes)
[PolicyEnum]     Name at +0x50: Microsoft Windows Production PCA 2011
[PolicyEnum]     Name at +0xA0: Microsoft Code Signing PCA
[PolicyEnum] Total potential certificates found: 2
```

## Cleanup When Done

```cmd
sc stop PolicyEnumerator
sc delete PolicyEnumerator
del C:\Windows\System32\drivers\PolicyEnumerator.sys

REM Optional: Disable test signing
bcdedit /set testsigning off
shutdown /r /t 0
```

## Troubleshooting

### "Driver failed to load"
- Check test signing: `bcdedit /enum | findstr testsigning`
- Verify signature: `signtool verify /pa PolicyEnumerator.sys`

### "No output in DebugView"
- Enable "Capture Kernel" (Ctrl+K)
- Run DebugView as Administrator
- Check driver is running: `sc query PolicyEnumerator`

### "Access Denied"
- Run Command Prompt as Administrator
- Some policy files may be protected by VBS/HVCI

## Alternative: Check Policies Without Driver

```cmd
REM List active policies (Windows 11 2022+)
CiTool.exe -lp

REM Check policy files exist
dir C:\Windows\System32\CodeIntegrity\*.p7b
dir C:\Windows\System32\CodeIntegrity\CiPolicies\Active\*.cip
```

## Next Steps

Once you verify the driver works:

1. Review the full README.md for advanced options
2. Modify the code to extract specific certificate fields
3. Use PowerShell ConfigCI module for complete policy analysis:
   ```powershell
   Get-Command -Module ConfigCI
   ```

## Important Notes

⚠️ **Test Environment Only** - This is a research tool, not for production use.

⚠️ **Test Signing Reduces Security** - Disable test mode after testing.

⚠️ **Certificate Limitations** - The driver does basic parsing. For complete analysis, use Microsoft's ConfigCI PowerShell module.

## Need Help?

1. Check Event Viewer → Windows Logs → System for driver errors
2. Review full README.md for detailed troubleshooting
3. Verify WDK and Visual Studio are properly installed

