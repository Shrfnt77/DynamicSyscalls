using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace DynamicSyscalls
{
    public static class DynamicInvoke
    {
        /// <summary>
        /// Global System Calls Entries
        /// </summary>
        private static List<SystemCallEntry> SystemCallsTabel = new List<SystemCallEntry>();

        /// <summary>
        /// Global Allocated PROCs 
        /// </summary>
        private static List<IntPtr> Allocated = new List<IntPtr>();
        

        /// <summary>
        /// Syscall gate 
        /// </summary>
        private static byte[] SystemcallBytes =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, 0x00 => SysCall Number 
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        /// <summary>
        /// Get Syscall asm instructions based on the function name or hash
        /// </summary>
        /// <param name="FunctionName"></param>
        /// <param name="IsHash"></param>
        /// <returns></returns>
        private static byte[] Resolve(string FunctionName, bool IsHash)
        {
            // query the global entries 
            SystemCallEntry systemCall = ((IsHash) ? SystemCallsTabel.Where(x => x.Hash == FunctionName) : SystemCallsTabel.Where(x => x.Name == FunctionName)).FirstOrDefault();
            if (systemCall == null)
            {
                throw new Exception($"Cannot Resolve {FunctionName}");
            }
            
            byte[] bytes = BitConverter.GetBytes(systemCall.Number);
            byte[] systemcall = SystemcallBytes;

            // need to overwrite 2 bytes only since we have around 470 nt syscall 
            systemcall[4] = bytes[0];
            systemcall[5] = bytes[1];
            return systemcall;
        }

        static DynamicInvoke() 
        {
            IntPtr hBase = Helper.GetModule("ntdll.dll");
            int PeHeader = Marshal.ReadInt32(hBase, 0x3c);
            int OptionalHeaders = PeHeader + 0x18;
            int ExportTableRva = Marshal.ReadInt32(hBase, OptionalHeaders + 0x70);
            int OrdinalBase = Marshal.ReadInt32(hBase, ExportTableRva + 0x10);
            int NumberOfFunctions = Marshal.ReadInt32(hBase, ExportTableRva + 0x14);
            int NumberOfNames = Marshal.ReadInt32(hBase, ExportTableRva + 0x18);
            int AddressOfFunctions = Marshal.ReadInt32(hBase, ExportTableRva + 0x1C);
            int AddressOfNames = Marshal.ReadInt32(hBase, ExportTableRva + 0x20);
            int AddressOfOrdinalsNames = Marshal.ReadInt32(hBase, ExportTableRva + 0x24);

            Dictionary<int, string> sysCallsFunctions = new Dictionary<int, string>();

            for (int i = 0; i < NumberOfNames; i++)
            {

                int functionNameRVA = Marshal.ReadInt32(hBase + AddressOfNames + i * 4);
                string functionName = Marshal.PtrToStringAnsi(new IntPtr(hBase.ToInt64() + functionNameRVA));


                if (functionName.StartsWith("Nt") && !functionName.StartsWith("Ntdll"))
                {
                    int functionOrdinal = Marshal.ReadInt16((IntPtr)(hBase.ToInt64() + AddressOfOrdinalsNames + i * 2)) + OrdinalBase;
                    int functionRva = Marshal.ReadInt32((IntPtr)(hBase.ToInt64() + AddressOfFunctions + 4 * (functionOrdinal - OrdinalBase)));
                    sysCallsFunctions.Add(functionRva, functionName);
                }
            }
            // sort based on function RVA 
            int count = 0;
            foreach (KeyValuePair<int, string> item in sysCallsFunctions.OrderBy(x => x.Key))
            {

                SystemCallsTabel.Add(new SystemCallEntry() {Name = item.Value , Hash = Helper.GetMd5(item.Value) , Number = count++ });
            }
        }

        /// <summary>
        /// Get NT call PROC based on the function name or md5(function_name) and store it in memory
        /// You will need to call FreeMemory function once u done
        /// </summary>
        /// <param name="FunctionName"></param>
        /// <param name="IsHash"></param>
        /// <returns></returns>
        public static T GetDelegate<T>(string FunctionName, bool IsHash) where T : Delegate
        {
            byte[] systemcallbytes = Resolve(FunctionName, IsHash);
            IntPtr hAllocated = Marshal.AllocHGlobal(systemcallbytes.Length);
            Allocated.Add(hAllocated);
            Marshal.Copy(systemcallbytes, 0, hAllocated, systemcallbytes.Length);

            // the only native call we have lol
            Native.VirtualProtect(hAllocated, ((uint)systemcallbytes.Length), Native.ExecuteReadWrite, out _);
            
            return Marshal.GetDelegateForFunctionPointer<T>(hAllocated);
        }

        /// <summary>
        /// Execute a syscall quickly, you don't need to call FreeMemory function after that one
        /// </summary>
        /// <param name="FunctionName"></param>
        /// <param name="Parameters"></param>
        /// <param name="IsHash"></param>
        /// <returns></returns>
        public static object Invoke<T>(string FunctionName, ref object[] Parameters, bool IsHash) where T : Delegate
        {
            byte[] systemcallbytes = Resolve(FunctionName, IsHash);
            IntPtr hAllocated = Marshal.AllocHGlobal(systemcallbytes.Length);
            Marshal.Copy(systemcallbytes, 0, hAllocated, systemcallbytes.Length);
            Native.VirtualProtect(hAllocated, ((uint)systemcallbytes.Length), Native.ExecuteReadWrite, out _);
            object ret = Marshal.GetDelegateForFunctionPointer(hAllocated, typeof(T)).DynamicInvoke(Parameters);
            Marshal.FreeHGlobal(hAllocated);
            return ret;
        }

        /// <summary>
        /// To be called once to free the allocated PROCs, or who cares lol
        /// </summary>
        public static void FreeMemory() 
        {
            foreach (IntPtr ptr in Allocated) 
            {
                if (ptr != IntPtr.Zero) 
                {
                    Marshal.FreeHGlobal(ptr);
                }
            }
        }


        /// <summary>
        /// SystemCallEntry that holds the function name and md5(function_name) and syscall number 
        /// </summary>
        private class SystemCallEntry
        {
            public string Name { get; set; }
            public string Hash { get; set; }
            public int Number { get; set; }

        }

    }

}
