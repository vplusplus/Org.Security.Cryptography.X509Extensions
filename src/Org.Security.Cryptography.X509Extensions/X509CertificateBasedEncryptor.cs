using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Org.Security.Cryptography
{
    public class X509CertificateBasedEncryptor
    {
        #region Defaults
        const string DEF_DataEncryptionAlgorithmName = "Aes";
        const int DEF_KeySize = 256;
        const int DEF_BlockSize = 128;
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
        /// <remarks>The thumbprint of the certificate is attached as first thing in the encrypted data</remarks>
        //TODO: Add the timestamp of encryption to avoid replay attacks if its used to transmit authentication details between client and server.
        public void EncryptStream(X509Certificate2 x509Cert,
                                Stream inputStream,
                                Stream outputStream,
                                string dataEncryptionAlgorithmName = DEF_DataEncryptionAlgorithmName,
                                int keySize = DEF_KeySize,
                                int blockSize = DEF_BlockSize)
        {
            var thumbprintArray = Encoding.UTF8.GetBytes(x509Cert.Thumbprint);
            outputStream.WriteLengthAndBytes(thumbprintArray);
            x509Cert.EncryptStream(inputStream, outputStream, dataEncryptionAlgorithmName, keySize, blockSize);
        }
        /// <summary>
        /// Encrypt input string using the symmetric algorithm provided. 
        /// The key of symmetric algorithm is encrypted using the Asymmetric algorithm available on the given certificate.
        /// </summary>
        /// <param name="x509Cert"></param>
        /// <param name="valueToEncode"></param>
        /// <param name="dataEncryptionAlgorithmName"></param>
        /// <param name="keySize"></param>
        /// <param name="blockSize"></param>
        /// <returns> The encrypted content in base64 format</returns>
        public string EncryptStringToBase64EncodedString(X509Certificate2 x509Cert,
            string valueToEncode,
            string dataEncryptionAlgorithmName = DEF_DataEncryptionAlgorithmName,
                                int keySize = DEF_KeySize,
                                int blockSize = DEF_BlockSize)
        {
            var inputData = Encoding.UTF8.GetBytes(valueToEncode);
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                this.EncryptStream(x509Cert, input, output, dataEncryptionAlgorithmName, keySize,blockSize);
                output.Flush();
                var outputArray = output.ToArray();
                return Convert.ToBase64String(outputArray);
            }
        }
    }
}