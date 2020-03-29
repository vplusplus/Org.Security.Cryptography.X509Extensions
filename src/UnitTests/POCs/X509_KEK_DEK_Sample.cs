
using Org.Security.Cryptography;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace UnitTests
{
    static class X509_RSA_AES
    {
        public static void Encrypt(this Stream inputStream, Stream outputStream, string thumbPrint, StoreName storeName, StoreLocation storeLocation)
        {
            var cert = X509CertificateCache.GetCertificate(thumbPrint, storeName, storeLocation);

            inputStream.Encrypt(outputStream, cert);
        }

        public static void Decrypt(this Stream inputStream, Stream outputStream, string thumbPrint, StoreName storeName, StoreLocation storeLocation)
        {
            var cert = X509CertificateCache.GetCertificate(thumbPrint, storeName, storeLocation);

            inputStream.Decrypt(outputStream, cert);
        }

        public static void Encrypt(this Stream inputStream, Stream outputStream, X509Certificate2 cert)
        {
            RSA keyEncryption = (RSA)cert.PublicKey.Key;

            using (Aes dataEncryption = Aes.Create())
            {
                dataEncryption.KeySize = 256;
                dataEncryption.BlockSize = 128;

                Encrypt(keyEncryption, dataEncryption, inputStream, outputStream);
            }
        }

        public static void Decrypt(this Stream inputStream, Stream outputStream, X509Certificate2 cert)
        {
            RSA keyEncryption = (RSA)cert.PrivateKey;

            using(Aes dataEncryption = Aes.Create())
            {
                Decrypt(keyEncryption, dataEncryption, inputStream, outputStream);
            }
        }

        static void Encrypt(AsymmetricAlgorithm keyEncryption, SymmetricAlgorithm dataEncryption, Stream inputStream, Stream outputStream)
        {
            var DEK = dataEncryption.Key;
            var IV = dataEncryption.IV;

            var keyFormatter = new RSAPKCS1KeyExchangeFormatter(keyEncryption);
            var encryptedDEK = keyFormatter.CreateKeyExchange(DEK);
            var encryptedIV = keyFormatter.CreateKeyExchange(IV);

            outputStream.WriteLengthAndBytes(encryptedDEK);
            outputStream.WriteLengthAndBytes(encryptedIV);

            using (var transform = dataEncryption.CreateEncryptor())
            using (var cryptoStream = new CryptoStream(outputStream, transform, CryptoStreamMode.Write))
            {
                inputStream.CopyTo(cryptoStream);
            }
        }

        static void Decrypt(AsymmetricAlgorithm keyEncryption, SymmetricAlgorithm dataEncryption, Stream inputStream, Stream outputStream)
        {
            var encryptedDEK = inputStream.ReadLengthAndBytes();
            var encryptedIV = inputStream.ReadLengthAndBytes();

            var keyDeformatter = new RSAPKCS1KeyExchangeDeformatter(keyEncryption);
            dataEncryption.Key = keyDeformatter.DecryptKeyExchange(encryptedDEK);
            dataEncryption.IV = keyDeformatter.DecryptKeyExchange(encryptedIV);

            using (var transform = dataEncryption.CreateDecryptor())
            using (var cryptoStream = new CryptoStream(inputStream, transform, CryptoStreamMode.Read))
            {
                cryptoStream.CopyTo(outputStream);
            }
        }

        static void WriteLengthAndBytes(this Stream stream, byte[] bytes)
        {
            byte[] length = BitConverter.GetBytes((Int32)bytes.Length);
            stream.Write(length, 0, length.Length);
            stream.Write(bytes, 0, bytes.Length);
        }

        static byte[] ReadLengthAndBytes(this Stream stream)
        {
            byte[] fourBytes = new byte[4];
            stream.Read(fourBytes, 0, 4);
            var length = BitConverter.ToInt32(fourBytes, 0);

            byte[] bytes = new byte[length];
            stream.Read(bytes, 0, bytes.Length);

            return bytes;
        }

    }
}


// AsymmetricAlgorithm
// SymmetricAlgorithm

// RSAPKCS1KeyExchangeFormatter
// RSAPKCS1SignatureFormatter

