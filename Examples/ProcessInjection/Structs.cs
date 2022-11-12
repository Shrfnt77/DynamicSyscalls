using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcessInjection
{
    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID 
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
   public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)] public string Buffer;

        public UNICODE_STRING(string str)
        {
            Buffer = str;
            Length = (ushort)Encoding.Unicode.GetByteCount(str);
            MaximumLength = Length;
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x100)]
    struct SYSTEM_PROCESS_INFORMATION
    {
        [FieldOffset(0x00)]
        public UInt32 NextEntryOffset;
        [FieldOffset(0x04)]
        public UInt32 NumberOfThreads;
        [FieldOffset(0x38)]
        public UNICODE_STRING ImageName;
        [FieldOffset(0x50)]
        public IntPtr UniqueProcessId;
        [FieldOffset(0x60)]
        public UInt32 HandleCount;
        [FieldOffset(0x64)]
        public UInt32 SessionId;
        [FieldOffset(0xF8)]
        public UInt64 OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential, Size = 0x50)]
    public struct SYSTEM_THREAD_INFORMATION
    {
        public Int64 KernelTime;
        public Int64 UserTime;
        public Int64 CreateTime;
        public UInt32 WaitTime;
        public IntPtr StartAddress;
        public IntPtr ClientIdUniqueProcess;
        public IntPtr ClientIdUniqueThread;
        public Int32 Priority;
        public Int32 BasePriority;
        public UInt32 ContextSwitches;
        public UInt32 ThreadState;
        public UInt32 WaitReason;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    public class SystemProcess 
    {
        public uint NumberOfThreads;
        public UNICODE_STRING ImageName;
        public IntPtr UniqueProcessId;
        public List<SYSTEM_THREAD_INFORMATION> Threads;
    }

}
