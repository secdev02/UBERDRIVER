using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace CustomKernelSignerReader
{
    public class KernelSignerReader
    {
        // Native API declarations
        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(
            int SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            int BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength);

        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CryptQueryObject(
            int dwObjectType,
            IntPtr pvObject,
            int dwExpectedContentTypeFlags,
            int dwExpectedFormatTypeFlags,
            int dwFlags,
            out int pdwMsgAndCertEncodingType,
            out int pdwContentType,
            out int pdwFormatType,
            ref IntPtr phCertStore,
            ref IntPtr phMsg,
            ref IntPtr ppvContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertCloseStore(IntPtr hCertStore, int dwFlags);

        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern IntPtr CertEnumCertificatesInStore(IntPtr hCertStore, IntPtr pPrevCertContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertFreeCertificateContext(IntPtr pCertContext);

        // Constants
        private const int CERT_QUERY_OBJECT_FILE = 0x00000001;
        private const int CERT_QUERY_CONTENT_FLAG_ALL = 0x00003FFE;
        private const int CERT_QUERY_FORMAT_FLAG_ALL = 0x0000000E;
        
        private const int SystemCodeIntegrityInformation = 103;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        // Structures
        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_CODEINTEGRITY_INFORMATION
        {
            public int Length;
            public uint CodeIntegrityOptions;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CERT_CONTEXT
        {
            public uint dwCertEncodingType;
            public IntPtr pbCertEncoded;
            public uint cbCertEncoded;
            public IntPtr pCertInfo;
            public IntPtr hCertStore;
        }

        // Code Integrity Options flags
        private const uint CODEINTEGRITY_OPTION_ENABLED = 0x01;
        private const uint CODEINTEGRITY_OPTION_TESTSIGN = 0x02;
        private const uint CODEINTEGRITY_OPTION_UMCI_ENABLED = 0x04;
        private const uint CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED = 0x80;
        private const uint CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED = 0x400;

        public static bool IsRunningAsSystem()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }

        private static bool EnableDebugPrivilege()
        {
            IntPtr tokenHandle;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle))
            {
                return false;
            }

            LUID luid;
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
            {
                return false;
            }

            TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES
                {
                    Luid = luid,
                    Attributes = SE_PRIVILEGE_ENABLED
                }
            };

            return AdjustTokenPrivileges(tokenHandle, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
        }

        public static void QueryCodeIntegrityStatus()
        {
            Console.WriteLine("=== Code Integrity Status ===");
            Console.WriteLine();

            SYSTEM_CODEINTEGRITY_INFORMATION ciInfo = new SYSTEM_CODEINTEGRITY_INFORMATION
            {
                Length = Marshal.SizeOf(typeof(SYSTEM_CODEINTEGRITY_INFORMATION))
            };

            IntPtr ciInfoPtr = Marshal.AllocHGlobal(ciInfo.Length);
            Marshal.StructureToPtr(ciInfo, ciInfoPtr, false);

            int returnLength;
            int status = NtQuerySystemInformation(
                SystemCodeIntegrityInformation,
                ciInfoPtr,
                ciInfo.Length,
                out returnLength);

            if (status == 0)
            {
                ciInfo = Marshal.PtrToStructure<SYSTEM_CODEINTEGRITY_INFORMATION>(ciInfoPtr);
                
                Console.WriteLine(String.Format("Code Integrity Options: 0x{0:X8}", ciInfo.CodeIntegrityOptions));
                Console.WriteLine();
                Console.WriteLine("Active Options:");
                
                if ((ciInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) != 0)
                    Console.WriteLine("  - Code Integrity Enabled");
                if ((ciInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN) != 0)
                    Console.WriteLine("  - Test Signing Enabled (TESTSIGN)");
                if ((ciInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_UMCI_ENABLED) != 0)
                    Console.WriteLine("  - User Mode Code Integrity (UMCI) Enabled");
                if ((ciInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0)
                    Console.WriteLine("  - Hypervisor-Protected Code Integrity (HVCI) Enabled");
                if ((ciInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED) != 0)
                    Console.WriteLine("  - Debug Mode Enabled");
                
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine(String.Format("Failed to query Code Integrity status: 0x{0:X8}", status));
                Console.WriteLine();
            }

            Marshal.FreeHGlobal(ciInfoPtr);
        }

        public static void ReadCustomKernelSigners()
        {
            Console.WriteLine("=== Searching for Custom Kernel Signers ===");
            Console.WriteLine();

            // 1. Parse WDAC policy files for embedded certificates
            ParseWDACPolicyFiles();

            // 2. Check registry for policy information
            ReadDetailedPolicyRegistry();

            // 3. Check all certificate stores thoroughly
            ScanAllCertificateStores();

            // 4. Check for test-signed drivers
            CheckTestSignedDrivers();

            // 5. Check SiPolicy.p7b
            ParseSiPolicyFile();

            // 6. Check UEFI Secure Boot variables (if accessible)
            CheckSecureBootVariables();

            // 7. Scan driver store for custom signed drivers
            ScanDriverStore();
        }

        private static void ParseWDACPolicyFiles()
        {
            Console.WriteLine("--- Parsing WDAC Policy Files (.cip) ---");
            Console.WriteLine();

            string policyDir = @"C:\Windows\System32\CodeIntegrity\CiPolicies\Active";
            
            try
            {
                if (Directory.Exists(policyDir))
                {
                    string[] cipFiles = Directory.GetFiles(policyDir, "*.cip");
                    
                    if (cipFiles.Length > 0)
                    {
                        Console.WriteLine(String.Format("Found {0} policy file(s)", cipFiles.Length));
                        Console.WriteLine();

                        foreach (string cipFile in cipFiles)
                        {
                            Console.WriteLine(String.Format("Policy: {0}", Path.GetFileName(cipFile)));
                            ExtractCertificatesFromPolicy(cipFile);
                            Console.WriteLine();
                        }
                    }
                    else
                    {
                        Console.WriteLine("No .cip policy files found");
                        Console.WriteLine();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("Error: {0}", ex.Message));
                Console.WriteLine();
            }
        }

        private static void ExtractCertificatesFromPolicy(string policyFile)
        {
            try
            {
                // .cip files are PKCS#7 signed data structures
                IntPtr hCertStore = IntPtr.Zero;
                IntPtr hMsg = IntPtr.Zero;
                IntPtr pContext = IntPtr.Zero;
                
                IntPtr fileNamePtr = Marshal.StringToCoTaskMemUni(policyFile);
                
                int dwMsgAndCertEncodingType;
                int dwContentType;
                int dwFormatType;

                bool result = CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE,
                    fileNamePtr,
                    CERT_QUERY_CONTENT_FLAG_ALL,
                    CERT_QUERY_FORMAT_FLAG_ALL,
                    0,
                    out dwMsgAndCertEncodingType,
                    out dwContentType,
                    out dwFormatType,
                    ref hCertStore,
                    ref hMsg,
                    ref pContext);

                Marshal.FreeCoTaskMem(fileNamePtr);

                if (result && hCertStore != IntPtr.Zero)
                {
                    Console.WriteLine("  Certificates embedded in policy:");
                    
                    IntPtr pCertContext = IntPtr.Zero;
                    int certCount = 0;

                    while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != IntPtr.Zero)
                    {
                        CERT_CONTEXT certContext = Marshal.PtrToStructure<CERT_CONTEXT>(pCertContext);
                        
                        byte[] certData = new byte[certContext.cbCertEncoded];
                        Marshal.Copy(certContext.pbCertEncoded, certData, 0, (int)certContext.cbCertEncoded);
                        
                        X509Certificate2 cert = new X509Certificate2(certData);
                        
                        certCount++;
                        Console.WriteLine(String.Format("    Certificate {0}:", certCount));
                        Console.WriteLine(String.Format("      Subject: {0}", cert.Subject));
                        Console.WriteLine(String.Format("      Issuer: {0}", cert.Issuer));
                        Console.WriteLine(String.Format("      Thumbprint: {0}", cert.Thumbprint));
                        Console.WriteLine(String.Format("      Serial: {0}", cert.SerialNumber));
                        Console.WriteLine(String.Format("      Valid: {0} to {1}", cert.NotBefore, cert.NotAfter));
                        
                        // Check for signing capabilities
                        DisplayCertificateCapabilities(cert);
                        Console.WriteLine();
                    }

                    if (certCount == 0)
                    {
                        Console.WriteLine("    No certificates found in policy");
                    }

                    CertCloseStore(hCertStore, 0);
                }
                else
                {
                    Console.WriteLine(String.Format("  Unable to parse policy file (Error: {0})", Marshal.GetLastWin32Error()));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("  Error parsing policy: {0}", ex.Message));
            }
        }

        private static void ParseSiPolicyFile()
        {
            Console.WriteLine("--- Checking SiPolicy.p7b ---");
            Console.WriteLine();

            string siPolicyPath = @"C:\Windows\System32\CodeIntegrity\SiPolicy.p7b";
            
            if (File.Exists(siPolicyPath))
            {
                Console.WriteLine(String.Format("Found: {0}", siPolicyPath));
                FileInfo fi = new FileInfo(siPolicyPath);
                Console.WriteLine(String.Format("Size: {0} bytes, Modified: {1}", fi.Length, fi.LastWriteTime));
                Console.WriteLine();
                
                ExtractCertificatesFromPolicy(siPolicyPath);
            }
            else
            {
                Console.WriteLine("SiPolicy.p7b not found");
                Console.WriteLine();
            }
        }

        private static void DisplayCertificateCapabilities(X509Certificate2 cert)
        {
            foreach (X509Extension ext in cert.Extensions)
            {
                if (ext.Oid.Value == "2.5.29.37") // Enhanced Key Usage
                {
                    X509EnhancedKeyUsageExtension ekuExt = (X509EnhancedKeyUsageExtension)ext;
                    Console.WriteLine("      Enhanced Key Usage:");
                    foreach (System.Security.Cryptography.Oid oid in ekuExt.EnhancedKeyUsages)
                    {
                        string friendlyName = GetEKUFriendlyName(oid.Value);
                        Console.WriteLine(String.Format("        - {0} ({1})", friendlyName, oid.Value));
                    }
                }
            }
        }

        private static string GetEKUFriendlyName(string oid)
        {
            switch (oid)
            {
                case "1.3.6.1.4.1.311.61.1.1":
                    return "Kernel Mode Code Signing";
                case "1.3.6.1.4.1.311.10.3.6":
                    return "Windows System Component Verification";
                case "1.3.6.1.4.1.311.10.3.5":
                    return "Windows Hardware Driver Verification";
                case "1.3.6.1.4.1.311.76.6.1":
                    return "Windows TCB Component";
                case "1.3.6.1.5.5.7.3.3":
                    return "Code Signing";
                case "1.3.6.1.4.1.311.10.3.39":
                    return "Windows Store";
                default:
                    return oid;
            }
        }

        private static void ReadDetailedPolicyRegistry()
        {
            Console.WriteLine("--- Detailed Policy Registry Information ---");
            Console.WriteLine();

            string[] registryPaths = new string[]
            {
                @"SYSTEM\CurrentControlSet\Control\CI\Policy",
                @"SYSTEM\CurrentControlSet\Control\CI\PolicyInformation",
                @"SYSTEM\CurrentControlSet\Control\CI\TrustPointConfig",
                @"SYSTEM\CurrentControlSet\Control\CI\Protected",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CodeIntegrity/Operational"
            };

            foreach (string path in registryPaths)
            {
                ReadRegistryKeyRecursive(path, 0);
            }
        }

        private static void ReadRegistryKeyRecursive(string path, int depth)
        {
            if (depth > 3) return; // Limit recursion

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                {
                    if (key != null)
                    {
                        string indent = new string(' ', depth * 2);
                        Console.WriteLine(String.Format("{0}[HKLM\\{1}]", indent, path));

                        foreach (string valueName in key.GetValueNames())
                        {
                            object value = key.GetValue(valueName);
                            
                            if (value is byte[])
                            {
                                byte[] bytes = (byte[])value;
                                if (bytes.Length <= 64)
                                {
                                    Console.WriteLine(String.Format("{0}  {1} = {2}", 
                                        indent, valueName, BitConverter.ToString(bytes).Replace("-", " ")));
                                }
                                else
                                {
                                    Console.WriteLine(String.Format("{0}  {1} = [Binary: {2} bytes]", 
                                        indent, valueName, bytes.Length));
                                }
                            }
                            else
                            {
                                Console.WriteLine(String.Format("{0}  {1} = {2}", indent, valueName, value));
                            }
                        }

                        foreach (string subKeyName in key.GetSubKeyNames())
                        {
                            ReadRegistryKeyRecursive(path + "\\" + subKeyName, depth + 1);
                        }
                        
                        Console.WriteLine();
                    }
                }
            }
            catch (Exception ex)
            {
                // Silently skip inaccessible keys
            }
        }

        private static void ScanAllCertificateStores()
        {
            Console.WriteLine("--- Scanning All Certificate Stores ---");
            Console.WriteLine();

            StoreLocation[] locations = new StoreLocation[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser };
            StoreName[] storeNames = (StoreName[])Enum.GetValues(typeof(StoreName));

            int totalFound = 0;

            foreach (StoreLocation location in locations)
            {
                foreach (StoreName storeName in storeNames)
                {
                    try
                    {
                        X509Store store = new X509Store(storeName, location);
                        store.Open(OpenFlags.ReadOnly);

                        foreach (X509Certificate2 cert in store.Certificates)
                        {
                            if (IsInterestingCert(cert))
                            {
                                if (totalFound == 0)
                                {
                                    Console.WriteLine("Found interesting certificates:");
                                }
                                
                                Console.WriteLine(String.Format("  Store: {0}\\{1}", location, storeName));
                                Console.WriteLine(String.Format("  Subject: {0}", cert.Subject));
                                Console.WriteLine(String.Format("  Issuer: {0}", cert.Issuer));
                                Console.WriteLine(String.Format("  Thumbprint: {0}", cert.Thumbprint));
                                DisplayCertificateCapabilities(cert);
                                Console.WriteLine();
                                totalFound++;
                            }
                        }

                        store.Close();
                    }
                    catch { }
                }
            }

            if (totalFound == 0)
            {
                Console.WriteLine("No custom/interesting certificates found in standard stores");
                Console.WriteLine();
            }
        }

        private static bool IsInterestingCert(X509Certificate2 cert)
        {
            // Look for non-Microsoft root certificates or self-signed certs
            if (cert.Issuer == cert.Subject && !cert.Subject.Contains("Microsoft"))
            {
                return true;
            }

            // Look for kernel signing OIDs
            foreach (X509Extension ext in cert.Extensions)
            {
                if (ext.Oid.Value == "2.5.29.37")
                {
                    X509EnhancedKeyUsageExtension ekuExt = (X509EnhancedKeyUsageExtension)ext;
                    foreach (System.Security.Cryptography.Oid oid in ekuExt.EnhancedKeyUsages)
                    {
                        if (oid.Value == "1.3.6.1.4.1.311.61.1.1" || 
                            oid.Value == "1.3.6.1.4.1.311.10.3.6" ||
                            oid.Value == "1.3.6.1.4.1.311.10.3.5")
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private static void CheckTestSignedDrivers()
        {
            Console.WriteLine("--- Checking for Test-Signed Drivers ---");
            Console.WriteLine();

            string driverDir = @"C:\Windows\System32\drivers";
            
            try
            {
                if (Directory.Exists(driverDir))
                {
                    string[] driverFiles = Directory.GetFiles(driverDir, "*.sys");
                    int testSignedCount = 0;

                    foreach (string driverFile in driverFiles)
                    {
                        try
                        {
                            X509Certificate2 cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(driverFile));
                            
                            if (cert.Subject.Contains("Test") || cert.Issuer.Contains("Test") || 
                                !cert.Subject.Contains("Microsoft"))
                            {
                                testSignedCount++;
                                Console.WriteLine(String.Format("  Driver: {0}", Path.GetFileName(driverFile)));
                                Console.WriteLine(String.Format("    Signed by: {0}", cert.Subject));
                                Console.WriteLine(String.Format("    Issuer: {0}", cert.Issuer));
                                Console.WriteLine();
                            }
                        }
                        catch { }
                    }

                    if (testSignedCount == 0)
                    {
                        Console.WriteLine("No test-signed or non-Microsoft drivers found");
                        Console.WriteLine();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("Error: {0}", ex.Message));
                Console.WriteLine();
            }
        }

        private static void CheckSecureBootVariables()
        {
            Console.WriteLine("--- UEFI Secure Boot Variables ---");
            Console.WriteLine();
            Console.WriteLine("Note: UEFI variables require special access and may not be readable");
            Console.WriteLine();

            // Attempt to check if Secure Boot is enabled via registry
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State"))
                {
                    if (key != null)
                    {
                        object uefiSecureBootEnabled = key.GetValue("UEFISecureBootEnabled");
                        if (uefiSecureBootEnabled != null)
                        {
                            Console.WriteLine(String.Format("Secure Boot Enabled: {0}", uefiSecureBootEnabled));
                            Console.WriteLine();
                        }
                    }
                }
            }
            catch { }
        }

        private static void ScanDriverStore()
        {
            Console.WriteLine("--- Scanning Driver Store ---");
            Console.WriteLine();

            string driverStore = @"C:\Windows\System32\DriverStore\FileRepository";
            
            try
            {
                if (Directory.Exists(driverStore))
                {
                    string[] subDirs = Directory.GetDirectories(driverStore);
                    int customSignedCount = 0;

                    foreach (string dir in subDirs)
                    {
                        try
                        {
                            string[] sysFiles = Directory.GetFiles(dir, "*.sys", SearchOption.AllDirectories);
                            
                            foreach (string sysFile in sysFiles)
                            {
                                try
                                {
                                    X509Certificate2 cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(sysFile));
                                    
                                    if (!cert.Subject.Contains("Microsoft Corporation"))
                                    {
                                        customSignedCount++;
                                        Console.WriteLine(String.Format("  Custom-signed driver: {0}", Path.GetFileName(sysFile)));
                                        Console.WriteLine(String.Format("    Path: {0}", dir));
                                        Console.WriteLine(String.Format("    Signer: {0}", cert.Subject));
                                        Console.WriteLine();
                                    }
                                }
                                catch { }
                            }
                        }
                        catch { }
                    }

                    if (customSignedCount == 0)
                    {
                        Console.WriteLine("No custom-signed drivers found in driver store");
                        Console.WriteLine();
                    }
                    else
                    {
                        Console.WriteLine(String.Format("Total custom-signed drivers found: {0}", customSignedCount));
                        Console.WriteLine();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("Error: {0}", ex.Message));
                Console.WriteLine();
            }
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("Custom Kernel Signer Reader - Enhanced Edition");
            Console.WriteLine("================================================");
            Console.WriteLine();

            if (!IsRunningAsSystem())
            {
                Console.WriteLine("WARNING: Not running as SYSTEM.");
                Console.WriteLine("Some information may be inaccessible.");
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine("Running as SYSTEM - Full access granted.");
                Console.WriteLine();
            }

            if (EnableDebugPrivilege())
            {
                Console.WriteLine("Debug privilege enabled.");
                Console.WriteLine();
            }

            QueryCodeIntegrityStatus();
            ReadCustomKernelSigners();

            Console.WriteLine("=== Scan Complete ===");
            Console.WriteLine();
            
            if (!IsRunningAsSystem())
            {
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
            }
        }
    }
}
