
using System;
using System.IO;

namespace X509.EnduranceTest.Shared
{
    public class TestDataGenerator
    {
        public static byte[] GenerateJunk(int kiloBytes)
        {
            int maxBytes = kiloBytes * 1024;

            using var buffer = new MemoryStream(maxBytes);
            var bytesWritten = 0;

            while (bytesWritten < maxBytes)
            {
                var more = Guid.NewGuid().ToByteArray();
                buffer.Write(more, 0, more.Length);
                bytesWritten += more.Length;
            }
            buffer.Flush();
            return buffer.ToArray();
        }
    }
}
