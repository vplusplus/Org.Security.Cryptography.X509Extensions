

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTests.POCs
{
    [TestClass]
    public class SymmetricAlgorithmSamples
    {
        [TestMethod]
        public void AES_GenerateKeyAndIv()
        {
            using (var aes = new AesManaged())
            {
                aes.GenerateIV();
                aes.GenerateKey();

                var key = aes.Key;
                var iv = aes.IV;
                Console.WriteLine($"Key: {key.Length * 8} bits. IV: {iv.Length * 8} bits");
            }
        }

        [TestMethod]
        public void CreateSymmetricProviderUsingAlgorithmName()
        {
            string[] names = new[]
            {
                "Aes", "AesManaged",
                "Rijndael", "RijndaelManaged",
                "DES", "TripleDES", "TripleDESManaged"
            };

            foreach (var name in names)
            {
                Console.WriteLine($"Creating {name}");
                var alg = SymmetricAlgorithm.Create(name);
                if (null == alg)
                {
                    Console.WriteLine("SymmetricAlgorithm.Create(name) returned NULL.");
                }
                else
                {
                    Console.WriteLine(alg.GetType().FullName);
                    Console.WriteLine($"Default KeySize: {alg.KeySize} bits");
                    Console.WriteLine($"Default BlockSize: {alg.BlockSize} bits");

                    Console.WriteLine("Legal key sizes:");
                    foreach (var size in alg.LegalKeySizes) Console.WriteLine($"MinSize: {size.MinSize} MaxSize: {size.MaxSize} bits");
                    Console.WriteLine("Legal block sizes:");
                    foreach (var size in alg.LegalBlockSizes) Console.WriteLine($"MinSize: {size.MinSize} MaxSize: {size.MaxSize} bits");

                }
                Console.WriteLine();
            }
        }

        [TestMethod]
        public void HelloSymmetric_AesManaged()
        {
            var key = GiveMe256Bits();
            var iv = GiveMe128Bits();

            EncryptAndDecryptTest(() => new AesManaged(), key, iv);
        }

        [TestMethod]
        public void HelloSymmetric_RijndaelManaged()
        {
            var key = GiveMe256Bits();
            var iv = GiveMe128Bits();

            EncryptAndDecryptTest(() => new RijndaelManaged(), key, iv);
        }

        static void EncryptAndDecryptTest(Func<SymmetricAlgorithm> fxSymmetricAlgorithm, byte[] key, byte[] iv)
        {
            Console.WriteLine($"Key: {key.Length * 8} bits. IV: {iv.Length * 8} bits.");

            var input = "Hello World!";

            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] encryptedBytes = null;
            byte[] decryptedBytes = null;

            using (var outputStream = new MemoryStream(1024))
            {
                using (var cryptoProvider = fxSymmetricAlgorithm())
                using (var encryptor = cryptoProvider.CreateEncryptor(key, iv))
                using (var cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
                using (var inputStream = new MemoryStream(inputBytes))
                {
                    Console.WriteLine($"Provider: {cryptoProvider.GetType().FullName}");
                    Console.WriteLine($"KeySize: {cryptoProvider.KeySize:#,0} bits");
                    Console.WriteLine($"BlockSize: {cryptoProvider.BlockSize:#,0} bits");

                    inputStream.CopyTo(cryptoStream);
                }
                encryptedBytes = outputStream.ToArray();
            }

            using (var outputStream = new MemoryStream(1024))
            {
                using (var cryptoProvider = fxSymmetricAlgorithm())
                using (var decryptor = cryptoProvider.CreateDecryptor(key, iv))
                using (var inputStream = new MemoryStream(encryptedBytes))
                using (var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(outputStream);
                }
                decryptedBytes = outputStream.ToArray();
            }

            Console.WriteLine($"Input Data: {inputBytes.Length:#,0} bytes");
            Console.WriteLine($"Encrypted Data: {encryptedBytes.Length:#,0} bytes");
            Console.WriteLine($"Decrypted Data: {encryptedBytes.Length:#,0} bytes");

            var final = Encoding.UTF8.GetString(decryptedBytes);

            Console.WriteLine($"Original: {input}");
            Console.WriteLine($"Final: {final}");
        }

        static byte[] GiveMe256Bits()
        {
            // DO NOT USE for generating random keys in PRD
            var something = Guid.NewGuid().ToByteArray();
            using (var sha = SHA256.Create()) return sha.ComputeHash(something);
        }

        static byte[] GiveMe128Bits()
        {
            // DO NOT USE for generating random keys in PRD
            return Guid.NewGuid().ToByteArray();
        }
    }
}
