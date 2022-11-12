using System;
using System.Runtime.InteropServices;

namespace DynamicSyscalls
{
    internal class Native
    {
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
    }
}
