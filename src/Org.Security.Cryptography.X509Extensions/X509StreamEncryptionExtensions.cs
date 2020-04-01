
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Org.Security.Cryptography
{
    /// <summary>
    /// Extensions to encrypt/decrypt Streams using X509 Certificates.
    /// DEFAULT: AES-256/128 for Data encryption.
    /// </summary>
    public static class X509StreamEncryptionExtensions
    {
        // Defaults
        const string    DEF_DataEncryptionAlgorithmName = "Aes";
        const int       DEF_KeySize = 256;
        const int       DEF_BlockSize = 128;

        /// <summary>
        /// X509Certificate public key serves as KeyEncryptionKey (KEK).
        /// Data is encrypted using a randomly generated DataEncryptionKey and IV.
        /// Writes encrypted DataEncryptionKey (using KEK), encrypted IV (using KEK) and encrypted data (using DEK) to the output stream.
        /// </summary>
        public static void EncryptStream(this X509Certificate2 x509Cert, Stream inputStream, Stream outputStream, string dataEncryptionAlgorithmName = DEF_DataEncryptionAlgorithmName, int keySize = DEF_KeySize, int blockSize = DEF_BlockSize)
        {
            if (null == x509Cert) throw new ArgumentNullException(nameof(x509Cert));
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == dataEncryptionAlgorithmName) throw new ArgumentNullException(nameof(dataEncryptionAlgorithmName));

            // Encrypt using Public key.
            // DO NOT Dispose this; Doing so will render the X509Certificate in the cache use-less.
            // Did endurance test of 1 mil cycles, found NO HANDLE leak.
            var keyEncryption = x509Cert.GetRsaPublicKeyAsymmetricAlgorithm();

            using (var dataEncryption = SymmetricAlgorithm.Create(dataEncryptionAlgorithmName))
            {
                if (null == dataEncryption) throw new Exception($"SymmetricAlgorithm.Create('{dataEncryptionAlgorithmName}') returned null.");

                // Select suggested keySize/blockSize.
                dataEncryption.KeySize = keySize;
                dataEncryption.BlockSize = blockSize;
                EncryptStream(inputStream, outputStream, keyEncryption,  dataEncryption);
            }
        }

        /// <summary>
        /// X509Certificate private key serves as KeyEncryptionKey (KEK).
        /// Reads and decrypts the Encrypted DataEncryptionKey and Encrypted IV using the KEK.
        /// Decrypts the data using the DataEncryptionKey and IV. 
        /// </summary>
        public static void DecryptStream(this X509Certificate2 x509Cert, Stream inputStream, Stream outputStream, string dataEncryptionAlgorithmName = DEF_DataEncryptionAlgorithmName)
        {
            if (null == x509Cert) throw new ArgumentNullException(nameof(x509Cert));
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == dataEncryptionAlgorithmName) throw new ArgumentNullException(nameof(dataEncryptionAlgorithmName));

            // Decrypt using Private key.
            // DO NOT Dispose this; Doing so will render the X509Certificate in cache use-less.
            // Did endurance test of 1 mil cycles, found NO HANDLE leak.
            var keyEncryption = x509Cert.GetRsaPrivateKeyAsymmetricAlgorithm();

            using (var dataEncryption = SymmetricAlgorithm.Create(dataEncryptionAlgorithmName))
            {
                if (null == dataEncryption) throw new Exception($"SymmetricAlgorithm.Create('{dataEncryptionAlgorithmName}') returned null.");

                // KeySize/blockSize will be selected when we assign key/IV later.
                DecryptStream(inputStream, outputStream, keyEncryption, dataEncryption);
            }
        }

        //...............................................................................
        #region Encrypt/Decrypt the Key (Asymmetric) and the Data (Symmetric)
        //...............................................................................

        static void EncryptStream(Stream inputStream, Stream outputStream, AsymmetricAlgorithm keyEncryption, SymmetricAlgorithm dataEncryption)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == keyEncryption) throw new ArgumentNullException(nameof(keyEncryption));
            if (null == dataEncryption) throw new ArgumentNullException(nameof(dataEncryption));

            // About...
            // Trace.WriteLine($"Encrypting. KEK: {keyEncryption.GetType().Name} / {keyEncryption.KeySize} bits");
            // Trace.WriteLine($"Encrypting. DEK: {dataEncryption.GetType().Name} / {dataEncryption.KeySize} bits / BlockSize: {dataEncryption.BlockSize} bits");

            // The DataEncryptionKey and the IV.
            var DEK = dataEncryption.Key ?? throw new Exception("SymmetricAlgorithm.Key was NULL");
            var IV = dataEncryption.IV ?? throw new Exception("SymmetricAlgorithm.IV was NULL");

            // Encrypt the DataEncryptionKey and the IV
            var keyFormatter = new RSAPKCS1KeyExchangeFormatter(keyEncryption);
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

        static void DecryptStream(Stream inputStream, Stream outputStream, AsymmetricAlgorithm keyEncryption, SymmetricAlgorithm dataEncryption)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == keyEncryption) throw new ArgumentNullException(nameof(keyEncryption));
            if (null == dataEncryption) throw new ArgumentNullException(nameof(dataEncryption));

            var encryptedDEK = inputStream.ReadLengthAndBytes(maxBytes: 2048);
            var encryptedIV = inputStream.ReadLengthAndBytes(maxBytes: 2048);

            var keyDeformatter = new RSAPKCS1KeyExchangeDeformatter(keyEncryption);
            dataEncryption.Key = keyDeformatter.DecryptKeyExchange(encryptedDEK);
            dataEncryption.IV = keyDeformatter.DecryptKeyExchange(encryptedIV);

            // About...
            // Trace.WriteLine($"Decrypting. KEK: {keyEncryption.GetType().Name} / {keyEncryption.KeySize} bits");
            // Trace.WriteLine($"Decrypting. DEK: {dataEncryption.GetType().Name} / {dataEncryption.KeySize} bits / BlockSize: {dataEncryption.BlockSize} bits");

            // Read the encrypted data.
            // Note: Disposing the CryptoStream also disposes the inputStream. There is no keepOpen option.
            using (var transform = dataEncryption.CreateDecryptor())
            using (var cryptoStream = new CryptoStream(inputStream, transform, CryptoStreamMode.Read))
            {
                cryptoStream.CopyTo(outputStream, bufferSize: dataEncryption.BlockSize * 4);
            }
        }

        #endregion

        //...............................................................................
        #region Utils: WriteLengthAndBytes(), ReadLengthAndBytes()
        //...............................................................................
        static void WriteLengthAndBytes(this Stream outputStream, byte[] bytes)
        {
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == bytes) throw new ArgumentNullException(nameof(bytes));

            // Int32 length to exactly-four-bytes array.
            var length = BitConverter.GetBytes((Int32)bytes.Length);

            // Write the four-byte-length followed by the data.
            outputStream.Write(length, 0, length.Length);
            outputStream.Write(bytes, 0, bytes.Length);
        }

        static byte[] ReadLengthAndBytes(this Stream inputStream, int maxBytes)
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
