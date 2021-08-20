
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Org.Security.Cryptography
{
    /// <summary>
    /// Extensions to encrypt/decrypt Streams using X509 Certificates.
    /// DEFAULT: AES-256/128 for Data encryption.
    /// </summary>
    public static class X509Certificate2StreamEncryptionExtensions
    {
        #region Public 
        /// <summary>
        /// The X509 Certificate public key serves as KeyEncryptionKey (KEK).
        /// Data is encrypted using a randomly generated DataEncryptionKey and IV.
        /// Writes encrypted DataEncryptionKey, encrypted IV and encrypted data to the output stream.
        /// NOTE: The OutputStream will be disposed at the end of this call.
        /// </summary>
        public static void EncryptStream(this X509Certificate2 x509Cert,
                                Stream inputStream,
                                Stream outputStream,
                                bool includeUTCTimeStamp = false,
                                string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName,
                                int keySize = Defaults.DEF_KeySize,
                                int blockSize = Defaults.DEF_BlockSize)
        {
            if (null == x509Cert) throw new ArgumentNullException(nameof(x509Cert));
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == dataEncryptionAlgorithmName) throw new ArgumentNullException(nameof(dataEncryptionAlgorithmName));

            // Encrypt using Public key.
            // DO NOT Dispose this; Doing so will render the X509Certificate use-less, if the caller had cached the cert.
            // We didn't acquire the X509 Certificate; Caller is responsible for disposing X509Certificate2. 
            // Did endurance test of 1 mil cycles, found NO HANDLE leak.
            var keyEncryption = x509Cert.GetPublicKeyAsymmetricAlgorithm();

            using (var dataEncryption = SymmetricAlgorithm.Create(dataEncryptionAlgorithmName))
            {
                if (null == dataEncryption) throw new Exception($"SymmetricAlgorithm.Create('{dataEncryptionAlgorithmName}') returned null.");

                // Select suggested keySize/blockSize.
                dataEncryption.KeySize = keySize;
                dataEncryption.BlockSize = blockSize;
                EncryptStream(inputStream, outputStream, includeUTCTimeStamp, keyEncryption, dataEncryption);
            }
        }
        #endregion

        #region Private Helpers
        //...............................................................................
        //Encrypt/Decrypt the Key (Asymmetric) and the Data (Symmetric)
        //...............................................................................
        static void EncryptStream(
            Stream inputStream,
            Stream outputStream,
            bool includeUTCTimeStamp,
            AsymmetricAlgorithm keyEncryption,
            SymmetricAlgorithm dataEncryption)
        {
            if (null == keyEncryption) throw new ArgumentNullException(nameof(keyEncryption));
            if (null == dataEncryption) throw new ArgumentNullException(nameof(dataEncryption));

            // About...
            // Trace.WriteLine($"Encrypting. KEK: {keyEncryption.GetType().Name} / {keyEncryption.KeySize} bits");
            // Trace.WriteLine($"Encrypting. DEK: {dataEncryption.GetType().Name} / {dataEncryption.KeySize} bits / BlockSize: {dataEncryption.BlockSize} bits");

            var keyFormatter = new RSAPKCS1KeyExchangeFormatter(keyEncryption);
            if (true == includeUTCTimeStamp)
            {
                var currentUTCTimeTicks = DateTime.UtcNow.Ticks;
                var currentUTCTimeBytes = BitConverter.GetBytes(currentUTCTimeTicks);
                var encryptedUTCTimeBytes = keyFormatter.CreateKeyExchange(currentUTCTimeBytes);
                outputStream.WriteLengthAndBytes(encryptedUTCTimeBytes);
            }
            // The DataEncryptionKey and the IV.
            var DEK = dataEncryption.Key ?? throw new Exception("SymmetricAlgorithm.Key was NULL");
            var IV = dataEncryption.IV ?? throw new Exception("SymmetricAlgorithm.IV was NULL");

            // Encrypt the DataEncryptionKey and the IV
            var encryptedDEK = keyFormatter.CreateKeyExchange(DEK);
            var encryptedIV = keyFormatter.CreateKeyExchange(IV);

            // Write the Encrypted DEK and IV
            outputStream.WriteLengthAndBytes(encryptedDEK);
            outputStream.WriteLengthAndBytes(encryptedIV);

            // Write the encrypted data.
            // Note: Disposing the CryptoStream also disposes the outputStream. There is no keepOpen option.
            using (var transform = dataEncryption.CreateEncryptor())
            using (var cryptoStream = new CryptoStream(outputStream, transform, CryptoStreamMode.Write))
            {
                inputStream.CopyTo(cryptoStream, bufferSize: dataEncryption.BlockSize * 4);
            }
        }
        #endregion
    }
}
