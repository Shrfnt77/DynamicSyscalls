using System;
using System.Runtime.InteropServices;

namespace ProcessHollowing
{
    internal class Native
    {
        public static uint Commit = 0x1000;
        public static uint Reserve = 0x2000;
        public static uint ExecuteReadWrite = 0x40;


        public static uint RTL_USER_PROCESS_PARAMETERS_NORMALIZED = 1;


        public static uint PS_ATTRIBUTE_IMAGE_NAME = 0x20005;
        public static uint PS_ATTRIBUTE_PARENT_PROCESS = 0x60000;
        public static uint PS_ATTRIBUTE_MITIGATION_OPTIONS = 0x20010;

        public static long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;
        public static uint THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x00000001;



        public static uint PROCESS_ALL_ACCESS = 0x1FFFFF;
        public static uint THREAD_ALL_ACCESS = 0x1FFFFF;
        [DllImport("ntdll.dll")]
        public static extern uint RtlCreateProcessParametersEx(ref IntPtr pProcessParameters, IntPtr ImagePathName, IntPtr DllPath, IntPtr CurrentDirectory, IntPtr CommandLine, IntPtr Environment, IntPtr WindowTitle, IntPtr DesktopInfo, IntPtr ShellInfo, IntPtr RuntimeData, uint Flags);
        public delegate uint NtCreateUserProcess(ref IntPtr ProcessHandle, ref IntPtr ThreadHandle, uint ProcessDesiredAccess, uint ThreadDesiredAccess, IntPtr ProcessObjectAttributes, IntPtr ThreadObjectAttributes, uint ProcessFlags, uint ThreadFlags, IntPtr ProcessParameters, ref PsCreateInfo CreateInfo, ref PsAttributeList AttributeList);
        public delegate uint NtGetContextThread(IntPtr hThread , ref Context Context);
        public delegate uint NtSetContextThread(IntPtr hThread, ref Context Context);
        public delegate uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);
        public delegate uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, ref uint NumberOfBytesWritten);
        public delegate uint NtReadVirtualMemory(IntPtr ProcessHandle, ulong BaseAddress, IntPtr Buffer, uint NumberOfBytesToRead, ref uint NumberOfBytesRead);
        public delegate uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, uint ZeroBits, ref uint RegionSize, uint AllocationType, uint Protect);
        public delegate uint NtResumeThread(IntPtr hThread,ref uint SuspendCount);
    }
}
