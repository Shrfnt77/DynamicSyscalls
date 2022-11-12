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


    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    public struct IOStatusBlock
    {
        public uint status;
        public IntPtr information;
    }
    public enum FileInformationClass
    {
        FileDirectoryInformation = 1,     // 1
        FileFullDirectoryInformation,     // 2
        FileBothDirectoryInformation,     // 3
        FileBasicInformation,         // 4
        FileStandardInformation,      // 5
        FileInternalInformation,      // 6
        FileEaInformation,        // 7
        FileAccessInformation,        // 8
        FileNameInformation,          // 9
        FileRenameInformation,        // 10
        FileLinkInformation,          // 11
        FileNamesInformation,         // 12
        FileDispositionInformation,       // 13
        FilePositionInformation,      // 14
        FileFullEaInformation,        // 15
        FileModeInformation = 16,     // 16
        FileAlignmentInformation,     // 17
        FileAllInformation,           // 18
        FileAllocationInformation,    // 19
        FileEndOfFileInformation,     // 20
        FileAlternateNameInformation,     // 21
        FileStreamInformation,        // 22
        FilePipeInformation,          // 23
        FilePipeLocalInformation,     // 24
        FilePipeRemoteInformation,    // 25
        FileMailslotQueryInformation,     // 26
        FileMailslotSetInformation,       // 27
        FileCompressionInformation,       // 28
        FileObjectIdInformation,      // 29
        FileCompletionInformation,    // 30
        FileMoveClusterInformation,       // 31
        FileQuotaInformation,         // 32
        FileReparsePointInformation,      // 33
        FileNetworkOpenInformation,       // 34
        FileAttributeTagInformation,      // 35
        FileTrackingInformation,      // 36
        FileIdBothDirectoryInformation,   // 37
        FileIdFullDirectoryInformation,   // 38
        FileValidDataLengthInformation,   // 39
        FileShortNameInformation,     // 40
        FileHardLinkInformation = 46    // 46    
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
