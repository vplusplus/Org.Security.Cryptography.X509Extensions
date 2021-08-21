using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Org.Security.Cryptography
{
    /// <summary>
    /// Provides capabilities to encrypt data using X509 certificate.
    /// </summary>
    public class X509CertificateBasedEncryptor
    {
        #region public
        /// <summary>
        /// Encrypt input stream using the symmetric algorithm provided in <paramref name="dataEncryptionAlgorithmName"/> 
        /// The key of symmetric algorithm is encrypted using the Asymmetric algorithm available on the given <paramref name="x509Cert".
        /// It writes the UTC timestamp of encryption. This can be used to validate during decryption to avoid replay attacks in client server scenarios.
        /// </summary>
        /// <param name="x509Cert">Certificate to encrypt</param>
        /// <param name="inputStream"></param>
        /// <param name="outputStream"></param>
        /// <param name="dataEncryptionAlgorithmName">Name of symmetric algorithm. Defaults to 'Aes'</param>
        /// <param name="keySize"></param>
        /// <param name="blockSize"></param>
        /// <remarks>The thumbprint of the certificate is attached as first thing in the encrypted data. 
        /// Use this if decryptor doesn't know what certificate encryptor used. Mainly in internet/web/distributed systems scenarios where the certificate rotated out of sync.
        /// </remarks>
        public void EncryptStreamWithTimestamp(
            X509Certificate2 x509Cert,
            Stream inputStream,
            Stream outputStream,
            string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName,
                                int keySize = Defaults.DEF_KeySize,
                                int blockSize = Defaults.DEF_BlockSize)
        {
            ValidateAndWritePlainThumprintToOutputStream(x509Cert, outputStream);
            x509Cert.EncryptStream(inputStream, outputStream, true, dataEncryptionAlgorithmName, keySize, blockSize);
        }

        /// <summary>
        /// Encrypt input stream using the symmetric algorithm provided in <paramref name="dataEncryptionAlgorithmName"/>. 
        /// The key of symmetric algorithm is encrypted using the Asymmetric algorithm available on the given <paramref name="x509Cert".
        /// </summary>
        /// <param name="x509Cert">Certificate to encrypt</param>
        /// <param name="inputStream"></param>
        /// <param name="outputStream"></param>
        /// <param name="dataEncryptionAlgorithmName">Name of symmetric algorithm. Defaults to 'Aes'</param>
        /// <param name="keySize"></param>
        /// <param name="blockSize"></param>
        /// <remarks>The thumbprint of the certificate is attached as first thing in the encrypted data. 
        /// Use this if decryptor doesn't know what certificate encryptor used. Mainly in internet/web/distributed systems scenarios where the certificate rotated out of sync.
        /// </remarks>
        public void EncryptStream(X509Certificate2 x509Cert,
                                Stream inputStream,
                                Stream outputStream,
                                string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName,
                                int keySize = Defaults.DEF_KeySize,
                                int blockSize = Defaults.DEF_BlockSize)
        {
            ValidateAndWritePlainThumprintToOutputStream(x509Cert, outputStream);
            x509Cert.EncryptStream(inputStream, outputStream, false, dataEncryptionAlgorithmName, keySize, blockSize);
        }
        /// <summary>
        /// Encrypt <paramref name="valueToEncode"/> using the symmetric algorithm provided in <paramref name="dataEncryptionAlgorithmName"/>. 
        /// The key of symmetric algorithm is encrypted using the Asymmetric algorithm available on the given <paramref name="x509Cert"/>.
        /// </summary>
        /// <param name="x509Cert">Certificate to encrypt</param>
        /// <param name="valueToEncode">The input string to encode</param>
        /// <param name="dataEncryptionAlgorithmName">Name of symmetric algorithm. Defaults to 'Aes'</param>
        /// <param name="keySize"></param>
        /// <param name="blockSize"></param>
        /// <returns>The encrypted content in base64 format.</returns>
        /// <remarks>
        /// The thumbprint of the certificate is attached as first thing in the encrypted data.
        /// Use this if decryptor doesn't know what certificate encryptor used. Mainly in internet/web/distributed systems scenarios where the certificate rotated out of sync.
        /// </remarks>
        public string EncryptStringToBase64(X509Certificate2 x509Cert,
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
                //TODO: Consider using CryptoStream to convert into base64 https://stackoverflow.com/questions/19134062/encode-a-filestream-to-base64-with-c-sharp
                return Convert.ToBase64String(outputArray);
            }
        }
        /// <summary>
        /// Encrypt <paramref name="valueToEncode"/> using the symmetric algorithm provided including the timestamp of emcryption. 
        /// The key of symmetric algorithm is encrypted using the Asymmetric algorithm available on the given <paramref name="x509Cert"/>.
        /// </summary>
        /// <param name="x509Cert">Certificate to encrypt</param>
        /// <param name="valueToEncode">The input string to encode</param>
        /// <param name="dataEncryptionAlgorithmName">Name of symmetric algorithm. Defaults to 'Aes'</param>
        /// <param name="keySize"></param>
        /// <param name="blockSize"></param>
        /// <returns>The encrypted content in base64 format.</returns>
        /// <remarks>The thumbprint of the certificate is attached as first thing in the encrypted data. 
        /// Use this if decryptor doesn't know what certificate encryptor used. Mainly in internet/web/distributed systems scenarios where the certificate rotated out of sync.
        /// The timestamped encrypted payload is good in client-server or internet scenarios to avoid re-play attacks.
        /// </remarks>
        public string EncryptStringToBase64WithTimestamp(X509Certificate2 x509Cert,
            string valueToEncode,
            string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName,
                                int keySize = Defaults.DEF_KeySize,
                                int blockSize = Defaults.DEF_BlockSize)
        {
            var inputData = Encoding.UTF8.GetBytes(valueToEncode);
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                this.EncryptStreamWithTimestamp(x509Cert, input, output, dataEncryptionAlgorithmName, keySize, blockSize);
                output.Flush();
                var outputArray = output.ToArray();
                return Convert.ToBase64String(outputArray);
            }
        }

        #endregion

        #region Private helpers
        private static void ValidateAndWritePlainThumprintToOutputStream(X509Certificate2 x509Cert, Stream outputStream)
        {
            if (null == x509Cert) throw new ArgumentNullException(nameof(x509Cert));
            var thumbprintArray = Encoding.UTF8.GetBytes(x509Cert.Thumbprint);
            outputStream.WriteLengthAndBytes(thumbprintArray);
        }
        #endregion
    }
}