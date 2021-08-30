using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

using Org.Security.Cryptography;

namespace UnitTests
{
    public class EncryptionDecryptionUtils
    {
        public  static byte[] EncryptBytesWithTimestampUsingX509CertificateBasedEncryptor(X509Certificate2 x509Cert, byte[] inputData)
        {
            var encryptor = new X509CertificateBasedEncryptor();
            using var input = new MemoryStream(inputData);
            using var output = new MemoryStream(inputData.Length);
            encryptor.EncryptStreamWithTimestamp(x509Cert, input, output);
            output.Flush();
            return output.ToArray();
        }
        public  static byte[] DecryptBytesWithTimestampValidationUsingX509CertificateBasedDecryptor(
            byte[] inputData,
            Func<string, X509Certificate2> certificateSelector,
            TimeSpan? lifeSpan = null)
        {
            var decryptor = new X509CertificateBasedDecryptor();
            using var input = new MemoryStream(inputData);
            using var output = new MemoryStream(inputData.Length);
            if (lifeSpan.HasValue)
            {
                decryptor.DecryptStreamWithTimestampValidation(input, output, certificateSelector, lifeSpan.Value);
            }
            else
            {
                decryptor.DecryptStreamWithTimestampValidation(input, output, certificateSelector);
            }
            output.Flush();
            return output.ToArray();
        }
        public  static byte[] EncryptBytesUsingX509CertificateBasedEncryptor(X509Certificate2 x509Cert, byte[] inputData)
        {
            var encryptor = new X509CertificateBasedEncryptor();
            using var input = new MemoryStream(inputData);
            using var output = new MemoryStream(inputData.Length);
            encryptor.EncryptStream(x509Cert, input, output);
            output.Flush();
            return output.ToArray();
        }
        public  static byte[] DecryptBytesUsingX509CertificateBasedDecryptor(byte[] inputData, Func<string, X509Certificate2> certificateSelector)
        {
            var decryptor = new X509CertificateBasedDecryptor();
            using var input = new MemoryStream(inputData);
            using var output = new MemoryStream(inputData.Length);
            decryptor.DecryptStream(input, output, certificateSelector);
            output.Flush();
            return output.ToArray();
        }
        public  static byte[] EncryptBytesUsingExtensionMethod(X509Certificate2 x509Cert, byte[] inputData)
        {
            using var input = new MemoryStream(inputData);
            using var output = new MemoryStream(inputData.Length);
            x509Cert.EncryptStream(input, output);
            output.Flush();
            return output.ToArray();
        }
        public  static byte[] DecryptBytesUsingExtensionMethod(X509Certificate2 x509Cert, byte[] inputData)
        {
            using var input = new MemoryStream(inputData);
            using var output = new MemoryStream(inputData.Length);
            x509Cert.DecryptStream(input, output);
            output.Flush();
            return output.ToArray();
        }
    }
}