using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ProcessHollowing
{
    internal static class Helper
    {
        private static List<IntPtr> Allocated = new List<IntPtr>();
        public static IntPtr ToPointer(this UnicodeString Data)
        {
            IntPtr pUnicodeString = Marshal.AllocHGlobal(16);
            Allocated.Add(pUnicodeString);
            Marshal.StructureToPtr(Data, pUnicodeString, true);
            return pUnicodeString;
        }
        public static UnicodeString ToUnicode(string data)
        {
            UnicodeString StringObject = new UnicodeString();
            StringObject.Length = (ushort)(data.Length * 2);
            StringObject.MaximumLength = (ushort)(StringObject.Length + 1);
            StringObject.Buffer = Marshal.StringToHGlobalUni(data);
            Allocated.Add(StringObject.Buffer);
            return StringObject;
        }


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
    }
}
