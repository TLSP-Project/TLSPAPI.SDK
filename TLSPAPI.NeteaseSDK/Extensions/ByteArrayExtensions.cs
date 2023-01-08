using System;
using System.Collections.Generic;
using System.Text;

namespace TLSPAPI.NeteaseSDK.Extensions
{
    public static class ByteArrayExtensions
    {
        public static byte[] Xor(this byte[] buffer, byte[] bytes)
        {
            byte[] result = new byte[buffer.Length];

            for (int i = 0; i < buffer.Length && i < bytes.Length; i++)
                result[i] = (byte)(bytes[i] ^ buffer[i]);

            return result;
        }
    }
}
