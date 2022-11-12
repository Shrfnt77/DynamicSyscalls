using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace DynamicSyscalls
{
    internal class Helper
    {
        /// <summary>
        /// Caluclate the MD5 hash
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string GetMd5(string str) 
        {
            byte[] in_string = new UTF8Encoding().GetBytes(str);

            // need MD5 to calculate the hash
            byte[] hash = ((HashAlgorithm)CryptoConfig.CreateFromName("MD5")).ComputeHash(in_string);

            // string representation (similar to UNIX format)
           return BitConverter.ToString(hash)
               // without dashes
               .Replace("-", string.Empty)
               // make lowercase
               .ToLower();
        }

        /// <summary>
        /// Return the module base
        /// </summary>
        /// <param name="Modulename"></param>
        /// <returns></returns>
        public static IntPtr GetModule(string Modulename)
        {
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (module.ModuleName.IndexOf(Modulename, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return module.BaseAddress;
                }
            }
            throw new Exception($"Cannot Find Module {Modulename}");
        }

    }
}
