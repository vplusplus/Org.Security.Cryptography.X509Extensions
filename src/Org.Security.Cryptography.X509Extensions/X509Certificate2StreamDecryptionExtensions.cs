
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Org.Security.Cryptography
{
    public static class X509Certificate2StreamDecryptionExtensions
    {
        #region Public
        /// <summary>
        /// The X509 Certificate private key serves as KeyEncryptionKey (KEK).
        /// Reads and decrypts the Encrypted DataEncryptionKey and Encrypted IV using the KEK.
        /// Decrypts the data using the DataEncryptionKey and IV. 
        /// NOTE: The InputStream will be disposed at the end of this call.
        /// </summary>
        public static void DecryptStream(this X509Certificate2 x509Cert,
            Stream inputStream,
            Stream outputStream,
            string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName)
        {
            x509Cert.DecryptStreamWithTimestampValidation(inputStream, outputStream, false, dataEncryptionAlgorithmName);
        }
            public static void DecryptStreamWithTimestampValidation(this X509Certificate2 x509Cert,
            Stream inputStream,
            Stream outputStream,
            bool validateTimestamp,
            string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName)
        {
            Validator.ValidateParametersAndThrowException(x509Cert, inputStream, outputStream, dataEncryptionAlgorithmName);
            // Decrypt using Private key.
            // DO NOT Dispose this; Doing so will render the X509Certificate use-less, if the caller had cached the cert.
            // We didn't acquire the X509 Certificate; Caller is responsible for disposing X509Certificate2. 
            // Did endurance test of 1 mil cycles, found NO HANDLE leak.
            var keyEncryption = x509Cert.GetPrivateKeyAsymmetricAlgorithm();

            using (var dataEncryption = SymmetricAlgorithm.Create(dataEncryptionAlgorithmName))
            {
                if (null == dataEncryption) throw new Exception($"SymmetricAlgorithm.Create('{dataEncryptionAlgorithmName}') returned null.");
                // KeySize/blockSize will be selected when we assign key/IV later.
                DecryptStream(inputStream, outputStream, validateTimestamp, Defaults.EncyptedPayloadTimeSpan, keyEncryption, dataEncryption);
            }
        }
        public static void DecryptStreamWithTimestampValidation(this X509Certificate2 x509Cert,
        Stream inputStream,
        Stream outputStream,
        TimeSpan lifeSpan,
        string dataEncryptionAlgorithmName = Defaults.DEF_DataEncryptionAlgorithmName)
        {
            Validator.ValidateParametersAndThrowException(x509Cert, inputStream, outputStream, dataEncryptionAlgorithmName);
            // Decrypt using Private key.
            // DO NOT Dispose this; Doing so will render the X509Certificate use-less, if the caller had cached the cert.
            // We didn't acquire the X509 Certificate; Caller is responsible for disposing X509Certificate2. 
            // Did endurance test of 1 mil cycles, found NO HANDLE leak.
            var keyEncryption = x509Cert.GetPrivateKeyAsymmetricAlgorithm();

            using (var dataEncryption = SymmetricAlgorithm.Create(dataEncryptionAlgorithmName))
            {
                if (null == dataEncryption) throw new Exception($"SymmetricAlgorithm.Create('{dataEncryptionAlgorithmName}') returned null.");
                // KeySize/blockSize will be selected when we assign key/IV later.
                DecryptStream(inputStream, outputStream, true, lifeSpan, keyEncryption, dataEncryption);
            }
        }
        #endregion

        #region Private helpers
        static void DecryptStream(Stream inputStream, Stream outputStream, bool validateTimestamp, TimeSpan lifeSpanOfInput, AsymmetricAlgorithm keyEncryption, SymmetricAlgorithm dataEncryption)
        {
            //Some validations are done by callers and this is not public.
            if (null == keyEncryption) throw new ArgumentNullException(nameof(keyEncryption));

            var keyDeformatter = new RSAPKCS1KeyExchangeDeformatter(keyEncryption);
            if (true == validateTimestamp)
            {
                var encryptionUTCTimestampbytes = inputStream.ReadLengthAndBytes(maxBytes: 2048);
                var decryptionUTCTimestampBytes = keyDeformatter.DecryptKeyExchange(encryptionUTCTimestampbytes);
                var encryptionUTCTimeStampTicks = BitConverter.ToInt64(decryptionUTCTimestampBytes, 0);
                var encryptionDataTime = new DateTime(encryptionUTCTimeStampTicks);
                if ((DateTime.UtcNow - encryptionDataTime) > lifeSpanOfInput) throw new TimeoutException($"The encrypted message timed out as it was created {lifeSpanOfInput} ago");
            }
            var encryptedDEK = inputStream.ReadLengthAndBytes(maxBytes: 2048);
            var encryptedIV = inputStream.ReadLengthAndBytes(maxBytes: 2048);

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
    }
}
