using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.ComponentModel;
using System.Security.Principal;
using Microsoft.Win32;
using System.Collections.Generic;

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

        // Constants
        private const int SystemCodeIntegrityInformation = 103;
        private const int SystemCodeIntegrityPolicyInformation = 218;
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

        // Code Integrity Options flags
        private const uint CODEINTEGRITY_OPTION_ENABLED = 0x01;
        private const uint CODEINTEGRITY_OPTION_TESTSIGN = 0x02;
        private const uint CODEINTEGRITY_OPTION_UMCI_ENABLED = 0x04;
        private const uint CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED = 0x08;
        private const uint CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED = 0x10;
        private const uint CODEINTEGRITY_OPTION_TEST_BUILD = 0x20;
        private const uint CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD = 0x40;
        private const uint CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED = 0x80;
        private const uint CODEINTEGRITY_OPTION_FLIGHT_BUILD = 0x100;
        private const uint CODEINTEGRITY_OPTION_FLIGHTING_ENABLED = 0x200;
        private const uint CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED = 0x400;
        private const uint CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED = 0x800;
        private const uint CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED = 0x1000;

        // Check if running as SYSTEM
        public static bool IsRunningAsSystem()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }

        // Enable debug privilege
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

        // Query Code Integrity status
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
                    Console.WriteLine("  - Test Signing Enabled");
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

        // Read Custom Kernel Signers from registry and certificate stores
        public static void ReadCustomKernelSigners()
        {
            Console.WriteLine("=== Custom Kernel Signers ===");
            Console.WriteLine();

            // Check CI Policy registry locations
            ReadCIPolicyFromRegistry();

            // Check certificate stores
            ReadTrustedKernelSigners();

            // Check for supplemental policies
            ReadSupplementalPolicies();
        }

        private static void ReadCIPolicyFromRegistry()
        {
            Console.WriteLine("--- Code Integrity Policies (Registry) ---");
            
            string[] policyPaths = new string[]
            {
                @"SYSTEM\CurrentControlSet\Control\CI\Policy",
                @"SYSTEM\CurrentControlSet\Control\CI\PolicyInformation",
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard"
            };

            foreach (string path in policyPaths)
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            Console.WriteLine(String.Format("Policy Path: HKLM\\{0}", path));
                            
                            string[] valueNames = key.GetValueNames();
                            foreach (string valueName in valueNames)
                            {
                                object value = key.GetValue(valueName);
                                Console.WriteLine(String.Format("  {0} = {1}", valueName, value));
                            }
                            Console.WriteLine();
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(String.Format("Unable to read {0}: {1}", path, ex.Message));
                }
            }
        }

        private static void ReadTrustedKernelSigners()
        {
            Console.WriteLine("--- Trusted Kernel Mode Code Signing Certificates ---");
            Console.WriteLine();

            // Check Windows Component Store
            ReadCertificateStore(StoreName.TrustedPublisher, StoreLocation.LocalMachine, "Trusted Publisher (Kernel)");
            
            // Check Code Signing store
            ReadCertificateStore(StoreName.Root, StoreLocation.LocalMachine, "Trusted Root (Kernel)");

            // Check for EKU specific to kernel signing
            ReadKernelCodeSigningCertificates();
        }

        // Replace the ReadCertificateStore method with this corrected version:
private static void ReadCertificateStore(StoreName storeName, StoreLocation storeLocation, string description)
{
    try
    {
        X509Store store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadOnly);

        Console.WriteLine(String.Format("{0} ({1} certificates):", description, store.Certificates.Count));

        int relevantCount = 0;
        foreach (X509Certificate2 cert in store.Certificates)
        {
            // Check if certificate has kernel code signing capabilities
            if (IsKernelCodeSigningCert(cert))
            {
                relevantCount++;
                Console.WriteLine(String.Format("  Subject: {0}", cert.Subject));
                Console.WriteLine(String.Format("  Issuer: {0}", cert.Issuer));
                Console.WriteLine(String.Format("  Thumbprint: {0}", cert.Thumbprint));
                Console.WriteLine(String.Format("  Valid: {0} to {1}", cert.NotBefore, cert.NotAfter));
                
                // Display EKU
                foreach (X509Extension eku in cert.Extensions)  // Fixed: X509Extension not X509Enhancement
                {
                    if (eku.Oid.Value == "2.5.29.37") // Enhanced Key Usage
                    {
                        X509EnhancedKeyUsageExtension ekuExt = (X509EnhancedKeyUsageExtension)eku;
                        Console.WriteLine("  Enhanced Key Usage:");
                        foreach (System.Security.Cryptography.Oid oid in ekuExt.EnhancedKeyUsages)  // Fixed: Added full namespace
                        {
                            Console.WriteLine(String.Format("    - {0} ({1})", oid.FriendlyName, oid.Value));
                        }
                    }
                }
                Console.WriteLine();
            }
        }

        if (relevantCount == 0)
        {
            Console.WriteLine("  (No kernel code signing certificates found)");
        }

        store.Close();
        Console.WriteLine();
    }
    catch (Exception ex)
    {
        Console.WriteLine(String.Format("Error reading certificate store: {0}", ex.Message));
        Console.WriteLine();
    }
}

// Replace the IsKernelCodeSigningCert method with this corrected version:
private static bool IsKernelCodeSigningCert(X509Certificate2 cert)
{
    // Check for Windows System Component Verification EKU (1.3.6.1.4.1.311.10.3.6)
    // or Kernel Mode Code Signing (1.3.6.1.4.1.311.61.1.1)
    foreach (X509Extension ext in cert.Extensions)
    {
        if (ext.Oid.Value == "2.5.29.37")
        {
            X509EnhancedKeyUsageExtension ekuExt = (X509EnhancedKeyUsageExtension)ext;
            foreach (System.Security.Cryptography.Oid oid in ekuExt.EnhancedKeyUsages)  // Fixed: Added full namespace
            {
                if (oid.Value == "1.3.6.1.4.1.311.10.3.6" || // Windows System Component Verification
                    oid.Value == "1.3.6.1.4.1.311.61.1.1")   // Kernel Mode Code Signing
                {
                    return true;
                }
            }
        }
    }
    return false;
}

        private static void ReadKernelCodeSigningCertificates()
        {
            Console.WriteLine("--- Kernel Mode Code Signing Specific Certificates ---");
            
            try
            {
                X509Store store = new X509Store(StoreName.TrustedPublisher, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);

                X509Certificate2Collection kernelCerts = store.Certificates.Find(
                    X509FindType.FindByApplicationPolicy,
                    "1.3.6.1.4.1.311.61.1.1", // Kernel Mode Code Signing OID
                    false);

                Console.WriteLine(String.Format("Found {0} certificates with Kernel Mode Code Signing EKU:", kernelCerts.Count));
                Console.WriteLine();

                foreach (X509Certificate2 cert in kernelCerts)
                {
                    Console.WriteLine(String.Format("  Subject: {0}", cert.Subject));
                    Console.WriteLine(String.Format("  Issuer: {0}", cert.Issuer));
                    Console.WriteLine(String.Format("  Thumbprint: {0}", cert.Thumbprint));
                    Console.WriteLine(String.Format("  Serial: {0}", cert.SerialNumber));
                    Console.WriteLine(String.Format("  Valid: {0} to {1}", cert.NotBefore, cert.NotAfter));
                    Console.WriteLine();
                }

                store.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("Error: {0}", ex.Message));
            }
            Console.WriteLine();
        }

        private static void ReadSupplementalPolicies()
        {
            Console.WriteLine("--- Supplemental Code Integrity Policies ---");
            Console.WriteLine();

            string policyPath = @"C:\Windows\System32\CodeIntegrity\CiPolicies\Active";
            
            try
            {
                if (System.IO.Directory.Exists(policyPath))
                {
                    string[] policyFiles = System.IO.Directory.GetFiles(policyPath, "*.cip");
                    
                    Console.WriteLine(String.Format("Found {0} active policy files:", policyFiles.Length));
                    foreach (string file in policyFiles)
                    {
                        System.IO.FileInfo fileInfo = new System.IO.FileInfo(file);
                        Console.WriteLine(String.Format("  {0} ({1} bytes, modified: {2})", 
                            fileInfo.Name, 
                            fileInfo.Length, 
                            fileInfo.LastWriteTime));
                    }
                    Console.WriteLine();
                }
                else
                {
                    Console.WriteLine("Policy directory not found.");
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("Error reading policies: {0}", ex.Message));
                Console.WriteLine();
            }
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("Custom Kernel Signer Reader");
            Console.WriteLine("===========================");
            Console.WriteLine();

            // Check if running as SYSTEM
            if (!IsRunningAsSystem())
            {
                Console.WriteLine("WARNING: Not running as SYSTEM.");
                Console.WriteLine("This program requires SYSTEM privileges for full access.");
                Console.WriteLine("Current user: " + WindowsIdentity.GetCurrent().Name);
                Console.WriteLine();
                Console.WriteLine("To run as SYSTEM, use PsExec:");
                Console.WriteLine("  psexec -s -i YourProgram.exe");
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine("Running as SYSTEM - Full access granted.");
                Console.WriteLine();
            }

            // Enable debug privilege
            if (EnableDebugPrivilege())
            {
                Console.WriteLine("Debug privilege enabled.");
                Console.WriteLine();
            }

            // Query Code Integrity status
            QueryCodeIntegrityStatus();

            // Read Custom Kernel Signers
            ReadCustomKernelSigners();

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
