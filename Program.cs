using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace UNIEL_Decrypt
{
    class Program
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptCreateHash(IntPtr hProv, uint algId, IntPtr hKey, uint dwFlags, ref IntPtr phHash);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptDeriveKey(IntPtr hProv, int Algid, IntPtr hBaseData, int flags, ref IntPtr phKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, int Final, uint dwFlags, byte[] pbData, ref uint pdwDataLen);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptHashData(IntPtr hHash, byte[] pbData, uint dataLen, uint flags);

        static void Main(string[] args)
        {
            Console.WriteLine("UNIEL_Decrypt by @dantarion v1.0");
            if(args.Length != 1)
            {
                Console.WriteLine("Usage UNIEL_Decrypt.exe <filename>");
                return;
            }
            var data = System.IO.File.ReadAllBytes(args[0]);

            IntPtr phProv = new IntPtr();
            IntPtr phHash = new IntPtr();
            IntPtr phKey = new IntPtr();

            if (CryptAcquireContext(ref phProv, null, "Microsoft Enhanced Cryptographic Provider v1.0", 1, 0))
            {
                if(CryptCreateHash(phProv,0x8004,new IntPtr(0),0,ref phHash))
                {
                    var magic = new byte[] { 173, 196, 215, 236, 56, 154, 157, 225, 116, 82, 12, 108, 235, 152, 82, 226, 59, 20, 150, 116 };
                    CryptHashData(phHash, magic, (uint)magic.Length, 0);
                    if(CryptDeriveKey(phProv, 0x6801, phHash, 0x800000,ref phKey))
                    {
                        uint pdwDataLen = (uint)data.Length;
                        CryptDecrypt(phKey, new IntPtr(0), 1, 0, data,ref pdwDataLen);
                        System.IO.File.WriteAllBytes(args[0]+".decrypted", data);
                    }
                }
            }

        }
    }
}
