# WDAC Policy Enumerator - Project Summary

## What Was Created

A complete Windows kernel driver project to enumerate and display Windows Defender Application Control (WDAC) policy signers.

## Files Included

### Core Driver Files
1. **PolicyEnumerator.c** - Main driver source code
   - Enumerates WDAC policy files
   - Reads SiPolicy.p7b and driversipolicy.p7b
   - Parses certificate data from policies
   - Outputs to kernel debug log

2. **PolicyEnumerator.inf** - Driver installation file
   - Service configuration
   - Installation instructions for Windows

### Build System Files
3. **PolicyEnumerator.vcxproj** - Visual Studio project file
   - For building with VS 2019+
   - Configured for x64 WDM driver

4. **sources** - Legacy WDK build file
   - For older WDK build environments

5. **CMakeLists.txt** - CMake build configuration
   - For modern CMake-based builds

### Helper Scripts
6. **build_and_test.bat** - Interactive helper script
   - Automated build, sign, install workflow
   - Test mode management
   - DebugView launcher

### Documentation
7. **README.md** - Comprehensive documentation
   - Detailed compilation instructions
   - Usage examples
   - Troubleshooting guide
   - Security considerations

8. **QUICKSTART.md** - Fast-track guide
   - 5-minute setup
   - Step-by-step instructions
   - Common issues and solutions

## Key Features

### What the Driver Does

1. **Locates Active Policies**
   - Checks C:\Windows\System32\CodeIntegrity\SiPolicy.p7b
   - Checks C:\Windows\System32\CodeIntegrity\driversipolicy.p7b
   - Reports on multiple policy format locations

2. **Reads Policy Files**
   - Opens policy files from kernel mode
   - Reads entire file contents
   - Handles file I/O errors gracefully

3. **Parses Certificate Data**
   - Searches for ASN.1 certificate structures
   - Extracts OIDs (Object Identifiers)
   - Identifies certificate subject/issuer names
   - Displays hex dumps for manual analysis

4. **Debug Output**
   - Sends all findings to kernel debug log
   - Compatible with DebugView
   - Compatible with WinDbg
   - Formatted for easy reading

## How to Use

### Quick Start (5 Minutes)

1. Open QUICKSTART.md
2. Enable test signing
3. Build the driver
4. Sign with test certificate
5. Install and run
6. View output in DebugView

### Detailed Setup

See README.md for:
- Complete build instructions
- Multiple build methods
- Test signing procedures
- Installation options
- Advanced configuration

## Technical Details

### Driver Architecture

- **Type**: WDM (Windows Driver Model)
- **Load Type**: Demand start
- **Execution**: Runs once at start, then unloads
- **Memory**: Uses paged pool for file buffers
- **Safety**: All code pageable, proper cleanup

### Parsing Algorithm

The driver looks for:
1. **X.509 Certificate Headers** (0x30 0x82 sequence)
2. **OID Patterns** (0x06 tag + length)
3. **String Fields** (0x13 PrintableString, 0x0C UTF8String)
4. **Certificate Chains** (multiple cert sequences)

### Output Format

```
[PolicyEnum] Checking: <path>
[PolicyEnum] SUCCESS - File size: <bytes>
[PolicyEnum] Parsing policy buffer...
[PolicyEnum]   Found potential certificate at offset 0x<hex>
[PolicyEnum]     OID at +0x<offset>: <hex bytes>
[PolicyEnum]     Name at +0x<offset>: <string>
[PolicyEnum] Total potential certificates found: <count>
```

## Limitations

1. **Binary Format**: WDAC policies use an undocumented binary format. Full parsing requires reverse engineering or Microsoft's tools.

2. **Encrypted Policies**: Some policies may be encrypted/signed, limiting direct analysis.

3. **Multiple Policies**: The driver shows legacy single-policy locations. Modern systems may have multiple .cip files.

4. **Certificate Complexity**: Full X.509 parsing is complex. The driver does pattern matching only.

## Security Notes

### Test Signing Mode

- Required for unsigned drivers
- Reduces system security
- Should be disabled after testing
- Command: `bcdedit /set testsigning off`

### Production Use

⚠️ **NOT RECOMMENDED** - This driver is for:
- Security research
- Policy testing
- Development environments
- Educational purposes

### Proper Use Cases

✅ **Appropriate**:
- Auditing test systems
- Verifying WDAC deployment
- Security research
- Driver development learning

❌ **Not Appropriate**:
- Production servers
- Critical systems
- Systems without backups
- Compliance-required environments

## Recommended Workflow

### For Testing WDAC Policies

1. Deploy your WDAC policy to test system
2. Run this driver to verify policy files present
3. Check output for expected signers
4. Use Microsoft tools for complete analysis:
   ```powershell
   CiTool.exe -lp
   Get-CIPolicy (if you have XML source)
   ```

### For Security Auditing

1. Run driver on target system
2. Export debug log output
3. Identify all certificates in policies
4. Cross-reference with expected signers
5. Investigate any unexpected certificates

## Alternative Tools

If you need production-ready tools:

1. **CiTool.exe** (Built into Windows 11 2022+)
   ```cmd
   CiTool.exe -lp
   CiTool.exe -up -p <PolicyID>
   ```

2. **ConfigCI PowerShell Module**
   ```powershell
   Get-CIPolicy -FilePath policy.xml
   Get-SystemDriver
   ConvertFrom-CIPolicy
   ```

3. **WDAC Wizard** (GUI tool)
   - Available on GitHub
   - User-friendly interface
   - Policy creation and editing

## Troubleshooting Reference

### Build Issues

| Error | Solution |
|-------|----------|
| WDK not found | Install Windows Driver Kit |
| MSBuild failed | Open project in Visual Studio |
| Link errors | Verify WDK paths in project |

### Runtime Issues

| Error | Solution |
|-------|----------|
| Driver won't load | Enable test signing |
| Access denied | Run as Administrator |
| No output | Enable "Capture Kernel" in DebugView |
| File not found | Policy may not be deployed |

## Next Steps

### Extending the Driver

To add more functionality:

1. **Full ASN.1 Parser**: Implement complete X.509 parsing
2. **Multiple Policies**: Enumerate CiPolicies\Active directory
3. **CI.dll Integration**: Call CI.dll exported functions
4. **Policy Validation**: Verify policy signatures
5. **Real-time Monitoring**: Watch for policy changes

### Learning Resources

- [Windows Driver Development](https://learn.microsoft.com/windows-hardware/drivers/)
- [WDAC Documentation](https://learn.microsoft.com/windows/security/threat-protection/windows-defender-application-control/)
- [Code Integrity Research](https://www.cybereason.com/blog/code-integrity-in-the-kernel-a-look-into-cidll)

## Support and Contribution

This is a standalone educational tool. For issues:

1. Review README.md troubleshooting section
2. Check Event Viewer for driver errors
3. Verify WDK installation and configuration
4. Test on a clean VM first

## License and Disclaimer

**For educational and testing purposes only.**

- No warranty provided
- Use at your own risk
- Test in isolated environments
- Not for production use
- May affect system stability if misused

## Files Checklist

Before you start, ensure you have:

- [ ] PolicyEnumerator.c
- [ ] PolicyEnumerator.inf
- [ ] PolicyEnumerator.vcxproj
- [ ] sources (optional, for legacy builds)
- [ ] CMakeLists.txt (optional, for CMake)
- [ ] build_and_test.bat
- [ ] README.md
- [ ] QUICKSTART.md

All files are ready to use!

---

**Created**: November 25, 2025  
**Version**: 1.0  
**Purpose**: WDAC Policy Signer Enumeration for Testing

