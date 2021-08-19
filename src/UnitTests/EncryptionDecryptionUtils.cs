using System.IO;
using System.Security.Cryptography.X509Certificates;

using Org.Security.Cryptography;

namespace UnitTests
{
    class EncryptionDecryptionUtils
    {
        //TODO: Move this to separate class
        internal static byte[] EncryptBytes(X509Certificate2 x509Cert, byte[] inputData)
        {
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                x509Cert.EncryptStream(input, output);
                output.Flush();
                return output.ToArray();
            }
        }
        //TODO: Move this to separate class
        internal static byte[] DecryptBytes(X509Certificate2 x509Cert, byte[] inputData)
        {
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                x509Cert.DecryptStream(input, output);
                output.Flush();
                return output.ToArray();
            }
        }
    }
}

