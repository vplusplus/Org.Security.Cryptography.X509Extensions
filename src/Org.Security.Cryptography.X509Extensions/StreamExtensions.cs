
using System;
using System.IO;

namespace Org.Security.Cryptography
{
    internal static class StreamExtensions
    {
        //...............................................................................
        #region Utils: WriteLengthAndBytes(), ReadLengthAndBytes()
        //...............................................................................
        internal static void WriteLengthAndBytes(this Stream outputStream, byte[] bytes)
        {
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == bytes) throw new ArgumentNullException(nameof(bytes));

            // Int32 length to exactly-four-bytes array.
            var length = BitConverter.GetBytes((Int32)bytes.Length);

            // Write the four-byte-length followed by the data.
            outputStream.Write(length, 0, length.Length);
            outputStream.Write(bytes, 0, bytes.Length);
        }

        internal static byte[] ReadLengthAndBytes(this Stream inputStream, int maxBytes)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));

            // Read an Int32, exactly four bytes.
            var arrLength = new byte[4];
            var bytesRead = inputStream.Read(arrLength, 0, 4);
            if (bytesRead != 4) throw new Exception("Unexpected end of InputStream. Expecting 4 bytes.");

            // Length of data to read.
            var length = BitConverter.ToInt32(arrLength, 0);
            if (length > maxBytes) throw new Exception($"Unexpected data size {length:#,0} bytes. Expecting NOT more than {maxBytes:#,0} bytes.");

            // Read suggested no of bytes...
            var bytes = new byte[length];
            bytesRead = inputStream.Read(bytes, 0, bytes.Length);
            if (bytesRead != bytes.Length) throw new Exception($"Unexpected end of input stream. Expecting {bytes.Length:#,0} bytes.");

            return bytes;
        }

        #endregion
    }
}
