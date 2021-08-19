using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Org.Security.Cryptography
{
    public class X509CertificateBasedEncryptor
    {
        #region public
        /// <summary>
        /// Encrypt input stream using the symmetric algorithm provided. 
        /// The key of symmetric algorithm is encrypted using the Asymmetric algorithm available on the given certificate.
        /// It writes the UTC timestamp of encryption. This can be used to validate during decryption to avoid replay attacks in client server scenarios.
        /// </summary>
        /// <param name="x509Cert"></param>
        /// <param name="inputStream"></param>
        /// <param name="outputStream"></param>
        /// <param name="dataEncryptionAlgorithmName"></param>
        /// <param name="keySize"></param>
        /// <param name="blockSize"></param>
        public void EncryptStreamWithTimestamp(
            X509Certificate2 x509Cert,
            MemoryStream inputStream,
            MemoryStream outputStream,
            string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName,
                                int keySize = Defaults.DEF_KeySize,
                                int blockSize = Defaults.DEF_BlockSize)
        {
            var thumbprintArray = Encoding.UTF8.GetBytes(x509Cert.Thumbprint);
            outputStream.WriteLengthAndBytes(thumbprintArray);
            x509Cert.EncryptStream(inputStream, outputStream, true, dataEncryptionAlgorithmName, keySize, blockSize);
        }
        #endregion
        /// <summary>
        /// Encrypt input stream using the symmetric algorithm provided. 
        /// The key of symmetric algorithm is encrypted using the Asymmetric algorithm available on the given certificate.
        /// </summary>
        /// <param name="x509Cert"></param>
        /// <param name="inputStream"></param>
        /// <param name="outputStream"></param>
        /// <param name="dataEncryptionAlgorithmName"></param>
        /// <param name="keySize"></param>
        /// <param name="blockSize"></param>
        /// <remarks>The thumbprint of the certificate is attached as first thing in the encrypted data. 
        /// Use this if decryptor doesn't know what certificate encryptor used. Mainly in internet/web/distributed systems scenarios where the certificate rotated out of sync.
        /// </remarks>
        //TODO: Add the timestamp of encryption to avoid replay attacks if its used to transmit authentication details between client and server.
        public void EncryptStream(X509Certificate2 x509Cert,
                                Stream inputStream,
                                Stream outputStream,
                                string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName,
                                int keySize = Defaults.DEF_KeySize,
                                int blockSize = Defaults.DEF_BlockSize)
        {
            var thumbprintArray = Encoding.UTF8.GetBytes(x509Cert.Thumbprint);
            outputStream.WriteLengthAndBytes(thumbprintArray);
            x509Cert.EncryptStream(inputStream, outputStream, false, dataEncryptionAlgorithmName, keySize, blockSize);
        }
        /// <summary>
        /// Encrypt input string using the symmetric algorithm provided. 
        /// The key of symmetric algorithm is encrypted using the Asymmetric algorithm available on the given <paramref name="x509Cert"/>.
        /// </summary>
        /// <param name="x509Cert"></param>
        /// <param name="valueToEncode"></param>
        /// <param name="dataEncryptionAlgorithmName"></param>
        /// <param name="keySize"></param>
        /// <param name="blockSize"></param>
        /// <returns> The encrypted content in base64 format.</returns>
        /// <remarks>
        /// The thumbprint of the certificate is attached as first thing in the encrypted data.
        /// Use this if decryptor doesn't know what certificate encryptor used. Mainly in internet/web/distributed systems scenarios where the certificate rotated out of sync.</remarks>
        /// </remarks>
        public string EncryptStringToBase64EncodedString(X509Certificate2 x509Cert,
            string valueToEncode,
            string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName,
                                int keySize = Defaults.DEF_KeySize,
                                int blockSize = Defaults.DEF_BlockSize)
        {
            var inputData = Encoding.UTF8.GetBytes(valueToEncode);
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                this.EncryptStream(x509Cert, input, output, dataEncryptionAlgorithmName, keySize, blockSize);
                output.Flush();
                var outputArray = output.ToArray();
                return Convert.ToBase64String(outputArray);
            }
        }
    }
}