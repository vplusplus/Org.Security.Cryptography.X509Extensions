
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Org.Security.Cryptography.X509RsaAes
{
    /// <summary>
    /// Extensions to encrypt/decrypt Streams using X509 Certificates.
    /// Expects X509 RSA Certificate. 
    /// Uses AES-256 with 128bit blockSize for Data encryption.
    /// </summary>
    public static class X509RsaAesStreamEncryptionExtensions
    {
        // Not confgurable, to avoid provider/consumer mis-configuration
        const int AesKeySize = 256;
        const int AesBlockSize = 128;

        // Random prefix, for a private slice of X509 Cache.
        static readonly string X509CachePrefix = Guid.NewGuid().ToString();

        /// <summary>
        /// X509Certificate public key serves as KeyEncryptionKey (KEK).
        /// Data is encrypted using a randomly generated DataEncryptionKey and IV.
        /// Writes encrypted DataEncryptionKey (using KEK), encrypted IV (using KEK) and encrypted data (using DEK) to the output stream.
        /// </summary>
        public static void Encrypt(this Stream inputStream, Stream outputStream, string thumbPrint, StoreName storeName, StoreLocation storeLocation)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == thumbPrint) throw new ArgumentNullException(nameof(thumbPrint));

            var cert = X509CertificateCache.GetCertificate(thumbPrint, storeName, storeLocation, X509CachePrefix);

            inputStream.Encrypt(outputStream, cert);
        }

        /// <summary>
        /// X509Certificate private key serves as KeyEncryptionKey (KEK).
        /// Reads and decrypts the Encrypted DataEncryptionKey and Encrypted IV using the KEK.
        /// Decrypts the data using the DataEncryptionKey and IV. 
        /// </summary>
        public static void Decrypt(this Stream inputStream, Stream outputStream, string thumbPrint, StoreName storeName, StoreLocation storeLocation)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == thumbPrint) throw new ArgumentNullException(nameof(thumbPrint));

            var cert = X509CertificateCache.GetCertificate(thumbPrint, storeName, storeLocation, X509CachePrefix);

            inputStream.Decrypt(outputStream, cert);
        }

        /// <summary>
        /// X509Certificate public key serves as KeyEncryptionKey (KEK).
        /// Data is encrypted using a randomly generated DataEncryptionKey and IV.
        /// Writes encrypted DataEncryptionKey (using KEK), encrypted IV (using KEK) and encrypted data (using DEK) to the output stream.
        /// </summary>
        public static void Encrypt(this Stream inputStream, Stream outputStream, X509Certificate2 cert)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == cert) throw new ArgumentNullException(nameof(cert));

            // Ensure PublicKey exists and supports RSA
            if (null == cert.PublicKey) throw new ArgumentNullException($"X509Certificate2.PublicKey was NULL: {cert.Thumbprint}");
            if (null == cert.PublicKey.Key) throw new ArgumentNullException($"X509Certificate2.PublicKey.Key was NULL: {cert.Thumbprint}");
            if (null == cert.PublicKey.Key as RSA) throw new ArgumentNullException($"X509Certificate2 is NOT a RSA Certificate: {cert.Thumbprint}");

            // DO NOT Dispose this.
            RSA keyEncryption = (RSA)cert.PublicKey.Key;

            using (Aes dataEncryption = Aes.Create())
            {
                dataEncryption.KeySize = AesKeySize;
                dataEncryption.BlockSize = AesBlockSize;

                Encrypt(keyEncryption, dataEncryption, inputStream, outputStream);
            }
        }

        /// <summary>
        /// X509Certificate private key serves as KeyEncryptionKey (KEK).
        /// Reads and decrypts the Encrypted DataEncryptionKey and Encrypted IV using the KEK.
        /// Decrypts the data using the DataEncryptionKey and IV. 
        /// </summary>
        public static void Decrypt(this Stream inputStream, Stream outputStream, X509Certificate2 cert)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == cert) throw new ArgumentNullException(nameof(cert));

            // Ensure PrivateKey exists and supports RSA
            if (null == cert.PrivateKey) throw new ArgumentNullException($"X509Certificate2.PrivateKey was NULL: {cert.Thumbprint}");
            if (null == cert.PrivateKey as RSA) throw new ArgumentNullException($"X509Certificate2 is NOT a RSA Certificate: {cert.Thumbprint}");

            // DO NOT Dispose this.
            RSA keyEncryption = (RSA)cert.PrivateKey;

            using (Aes dataEncryption = Aes.Create())
            {
                Decrypt(keyEncryption, dataEncryption, inputStream, outputStream);
            }
        }

        static void Encrypt(AsymmetricAlgorithm keyEncryption, SymmetricAlgorithm dataEncryption, Stream inputStream, Stream outputStream)
        {
            if (null == keyEncryption) throw new ArgumentNullException(nameof(keyEncryption));
            if (null == dataEncryption) throw new ArgumentNullException(nameof(dataEncryption));
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));

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
            using (var transform = dataEncryption.CreateEncryptor())
            using (var cryptoStream = new CryptoStream(outputStream, transform, CryptoStreamMode.Write))
            {
                inputStream.CopyTo(cryptoStream, dataEncryption.BlockSize);
            }
        }

        static void Decrypt(AsymmetricAlgorithm keyEncryption, SymmetricAlgorithm dataEncryption, Stream inputStream, Stream outputStream)
        {
            if (null == keyEncryption) throw new ArgumentNullException(nameof(keyEncryption));
            if (null == dataEncryption) throw new ArgumentNullException(nameof(dataEncryption));
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));

            var encryptedDEK = inputStream.ReadLengthAndBytes();
            var encryptedIV = inputStream.ReadLengthAndBytes();

            var keyDeformatter = new RSAPKCS1KeyExchangeDeformatter(keyEncryption);
            dataEncryption.Key = keyDeformatter.DecryptKeyExchange(encryptedDEK);
            dataEncryption.IV = keyDeformatter.DecryptKeyExchange(encryptedIV);

            using (var transform = dataEncryption.CreateDecryptor())
            using (var cryptoStream = new CryptoStream(inputStream, transform, CryptoStreamMode.Read))
            {
                cryptoStream.CopyTo(outputStream, dataEncryption.BlockSize);
            }
        }

        static void WriteLengthAndBytes(this Stream outputStream, byte[] bytes)
        {
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == bytes) throw new ArgumentNullException(nameof(bytes));

            var length = BitConverter.GetBytes((Int32)bytes.Length);

            outputStream.Write(length, 0, length.Length);
            outputStream.Write(bytes, 0, bytes.Length);
        }

        static byte[] ReadLengthAndBytes(this Stream outputStream)
        {
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));

            // Read an Int32, exactly four bytes.
            var arrLength = new byte[4];
            var bytesRead = outputStream.Read(arrLength, 0, 4);
            if (bytesRead != 4) throw new Exception("Unexpected end of InputStream. Expecting 4 bytes.");

            // Read suggested no of bytes...
            var length = BitConverter.ToInt32(arrLength, 0);
            var bytes = new byte[length];
            bytesRead = outputStream.Read(bytes, 0, bytes.Length);
            if (bytesRead != bytes.Length) throw new Exception($"Unexpected end of input stream. Expecting {bytes.Length:#,0} bytes.");

            return bytes;
        }

        static void CopyTo(this Stream inputStream, Stream outputStream, int bufferSize)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (bufferSize <= 0) throw new ArgumentException("Invalid buffer size. Must be > 0");

            byte[] buffer = new byte[bufferSize];
            int bytesRead = 0;

            do {
                bytesRead = inputStream.Read(buffer, 0, buffer.Length);
                if (bytesRead > 0) outputStream.Write(buffer, 0, bytesRead);
            }
            while (bytesRead > 0);
        }

    }
}
