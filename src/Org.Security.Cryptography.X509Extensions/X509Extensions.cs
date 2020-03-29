
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Org.Security.Cryptography
{
    /// <summary>
    /// Encryption/Decryption helpers, that uses KeyEncryptionKey (KEK) and DataEncryptionKey (DEK) to encrypt/decrypt data streams.
    /// The X509Certificate public/private key pair is used as Key Encryption Key (KEK).
    /// Data Encruption Key (DEK) is generated and unique for each call.
    /// The encrypted version of DataEncryptionKey and the IV are written as header to output stream.
    /// </summary>
    public static class X509Extensions
    {
        const string DefaultDataEncryptionAlgorithm = "Aes";
        const int DefaultDataEncryptionKeySize = 256;
        const int DefaultDataEncryptionBlockSize = 128;

        /// <summary>
        /// Writes encrypted version of the data to the output stream.
        /// The randomly generated key and IV of the suggedted SymmetricAlgorithm is used as DataEncryptionKey (DEK).
        /// The PublicKey of the X509 certificate is used as KeyEncryptionKey (KEK) to encrypt the DEK.
        /// Writes the encrypted DEK and IV to the outputstream.
        /// </summary>
        public static void EncryptUsingPublicKey(this X509Certificate2 x509WithPublicKey, Stream inputStream, Stream outputStream, string dataEncryptionAlgorithmName = DefaultDataEncryptionAlgorithm, int keySize = DefaultDataEncryptionKeySize, int blockSize = DefaultDataEncryptionBlockSize)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == x509WithPublicKey) throw new ArgumentNullException(nameof(x509WithPublicKey));
            if (null == dataEncryptionAlgorithmName) throw new ArgumentNullException(nameof(dataEncryptionAlgorithmName));

            // IMP: We didn't create the Cert. DO NOT DISPOSE.
            // IMP: Disposing the AsymmetricAlgorithm will render the X509Certificate2 useless for subsequent use.
            AsymmetricAlgorithm keyEnryptionAlgorithm = x509WithPublicKey.PublicKey.Key ?? throw new Exception("X509Certificate2.PublicKey.Key was NULL.");

            using (SymmetricAlgorithm dataEncryptionAlgorithm = SymmetricAlgorithm.Create(dataEncryptionAlgorithmName))
            {
                if (null == dataEncryptionAlgorithm) throw new Exception($"SymmetricAlgorithm.Create('{dataEncryptionAlgorithmName}') returned NULL.");

                dataEncryptionAlgorithm.KeySize = keySize;
                dataEncryptionAlgorithm.BlockSize = blockSize;

                //Console.WriteLine($"KEK-Algorithm: {keyEnryptionAlgorithm.GetType().FullName}");
                //Console.WriteLine($"KEK-KeySize: {keyEnryptionAlgorithm.KeySize} bits");
                //Console.WriteLine($"DEK-Algorithm: {dataEncryptionAlgorithm.GetType().FullName}");
                //Console.WriteLine($"DEK-KeySize: {dataEncryptionAlgorithm.KeySize} bits");
                //Console.WriteLine($"DEK-BlockSize: {dataEncryptionAlgorithm.BlockSize} bits");

                // DEK is the randomly generated on-time-use Symmetric key and IV.
                byte[] dataEncryptionKey = dataEncryptionAlgorithm.Key;
                byte[] dataEncryptionIV = dataEncryptionAlgorithm.IV;

                // Encrypt the DEK using the public key (KEK).
                var keyFormatter = new RSAPKCS1KeyExchangeFormatter(keyEnryptionAlgorithm);
                byte[] encryptedDataEncryptionKey = keyFormatter.CreateKeyExchange(dataEncryptionKey);

                // Write the length & bytes of encrypted DEK and IV
                outputStream.WriteLengthAndBytes(encryptedDataEncryptionKey);
                outputStream.WriteLengthAndBytes(dataEncryptionIV);

                // Write Data
                using (var transform = dataEncryptionAlgorithm.CreateEncryptor())
                using (var encryptedOutputStream = new CryptoStream(outputStream, transform, CryptoStreamMode.Write))
                {
                    int bufferSize = dataEncryptionAlgorithm.BlockSize;
                    inputStream.CopyTo(encryptedOutputStream, bufferSize);
                }
            }
        }

        /// <summary>
        /// Writes decrypted version of the data to the output stream.
        /// Reads the encrypted DataEncryptionKey (DEK) and the IV from the input stream.
        /// The PrivateKey of the X509 certificate is used to decrypt the DataEncryptionKey (DEK).
        /// </summary>
        public static void DecryptUsingPrivateKey(this X509Certificate2 x509WithPrivateKey, Stream inputStream, Stream outputStream, string dataEncryptionAlgorithmName = DefaultDataEncryptionAlgorithm)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == x509WithPrivateKey) throw new ArgumentNullException(nameof(x509WithPrivateKey));
            if (null == x509WithPrivateKey.PrivateKey) throw new ArgumentException("X509Certificate2.PrivateKey was NULL.");
            if (null == dataEncryptionAlgorithmName) throw new ArgumentNullException(nameof(dataEncryptionAlgorithmName));

            // We didn't create the Cert. DO NOT DISPOSE.
            AsymmetricAlgorithm keyEnryptionAlgorithm = x509WithPrivateKey.PrivateKey;

            // Data Encryption key (DEK) is read from the stream.
            // DEK itself comes encrypted using the Key encryption key (KEK)
            // Use X509 cert private key to decrypt the DEK
            // Use the DEK to decrypt the data

            byte[] encryptedDataEncryptionKey = ReadLengthAndBytes(inputStream);
            byte[] dataEncryptionIV = ReadLengthAndBytes(inputStream);

            using (SymmetricAlgorithm dataEncryptionAlgorithm = SymmetricAlgorithm.Create(dataEncryptionAlgorithmName))
            {
                if (null == dataEncryptionAlgorithm) throw new Exception($"SymmetricAlgorithm.Create('{dataEncryptionAlgorithmName}') returned NULL.");

                RSAPKCS1KeyExchangeDeformatter keyDeFormatter = new RSAPKCS1KeyExchangeDeformatter(keyEnryptionAlgorithm);
                byte[] dataEncryptionKey = keyDeFormatter.DecryptKeyExchange(encryptedDataEncryptionKey);

                using (var transform = dataEncryptionAlgorithm.CreateDecryptor(dataEncryptionKey, dataEncryptionIV))
                using (CryptoStream decryptedInputStream = new CryptoStream(inputStream, transform, CryptoStreamMode.Read))
                {
                    int bufferSize = dataEncryptionAlgorithm.BlockSize;
                    decryptedInputStream.CopyTo(outputStream, bufferSize);
                }
            }
        }

        /// <summary>
        /// Copies content of input stream to the output stream.
        /// Using a single buffer of suggested buffer size.
        /// </summary>
        static void CopyTo(this Stream inputStream, Stream outputStream, int bufferSize)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));

            byte[] buffer = new byte[bufferSize];
            int bytesRead = 0;
            do
            {
                bytesRead = inputStream.Read(buffer, 0, buffer.Length);
                if (bytesRead > 0) outputStream.Write(buffer, 0, bytesRead);
            }
            while (bytesRead > 0);
        }

        /// <summary>
        /// Writes four-byte-header that represents length of data, followed by the data itself.
        /// </summary>
        static void WriteLengthAndBytes(this Stream outputStream, byte[] bytes)
        {
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (null == bytes) throw new ArgumentNullException(nameof(bytes));

            outputStream.WriteInt32(bytes.Length);
            outputStream.Write(bytes, 0, bytes.Length);
        }

        /// <summary>
        /// Reads four-byte-header which represents length of data, and reads the data.
        /// </summary>
        static byte[] ReadLengthAndBytes(this Stream inputStream)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));

            // Read the length of data to read.
            int dataLength = inputStream.ReadInt32();

            // Read the data
            byte[] data = new byte[dataLength];
            var bytesRead = inputStream.Read(data, 0, data.Length);
            if (bytesRead != data.Length) throw new Exception($"Unexpected end of stream. Expecting {data.Length} bytes. Found {bytesRead} bytes.");

            return data;
        }

        /// <summary>
        /// Writes given Int32 value to the stream.
        /// </summary>
        static void WriteInt32(this Stream outputStream, Int32 value)
        {
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));

            byte[] fourBytes = BitConverter.GetBytes(value);
            outputStream.Write(fourBytes, 0, 4);
        }

        /// <summary>
        /// Reads an Int32 value from the stream.
        /// </summary>
        static Int32 ReadInt32(this Stream inputStream)
        {
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));

            byte[] fourBytes = new byte[4];
            int bytesRead = inputStream.Read(fourBytes, 0, 4);
            if (bytesRead != 4) throw new Exception($"Unexpected end of stream. Expecting 4 bytes. Found {bytesRead} bytes.");

            return BitConverter.ToInt32(fourBytes, startIndex: 0);
        }
    }
}
