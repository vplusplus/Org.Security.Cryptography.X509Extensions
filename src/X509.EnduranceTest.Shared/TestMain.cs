
using System;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using EasyConsole;
using Org.Security.Cryptography;
using UnitTests;

namespace X509.EnduranceTest.Shared
{
    public static class TestMain
    {
        async public static Task Run()
        {
            try
            {
                await PrintOptionsAndRunTestAsync();
            }
            catch (Exception err)
            {
                ConsoleWriter.WriteRecursively(err);
            }
            Console.WriteLine("Press ENTER to quit...");
            Console.ReadLine();
        }
        async static Task PrintOptionsAndRunTestAsync()
        {
            bool canContinue= true;
            while (canContinue)
            {
                var menu = new Menu()
                    .AddSync("Print AsymmetricAlgorithm provider.", () => ConsoleWriter.PrintCSP(MyConfig.DecryptionCertificate))
                    .AddSync("Validate Encryption/Decryption, ONCE.", () => ValidateEncryptionAndDecryptionOnce(MyConfig.DecryptionCertificate))
                    .AddSync("X509Certificate2.EncryptStream - 8KB random data 100,000 times", () => X509Certificate2ExtensionsEnduranceTests.Encryption(MyConfig.DecryptionCertificate,8, 100000))
                    .AddSync("X509Certificate2.DecryptStream - 8KB random data 100,000 times", () => X509Certificate2ExtensionsEnduranceTests.Decryption(MyConfig.DecryptionCertificate,8, 100000))

                    .AddSync("X509CertificateBasedEncryptor.EncryptStringToBase64WithTimestamp - Random 256 bytes, 100,000", () => X509CertificateBasedEncryptorEnduranceTests.EncryptStringToBase64WithTimestamp(.25, 100000))
                    .AddSync("X509CertificateBasedDecryptor.DecryptBase64EncodedStringWithTimestampValidation - Random 256 bytes, 100,000", () => X509CertificateBasedDecryptorEnduranceTests.DecryptStringToBase64WithTimestamp(.25, 100000))
                    .AddSync("X509CertificateBasedEncryptor.EncryptStringToBase64WithTimestamp - Random 1 KB, 100,000", () => X509CertificateBasedEncryptorEnduranceTests.EncryptStringToBase64WithTimestamp(1, 100000))
                    .AddSync("X509CertificateBasedDecryptor.DecryptBase64EncodedStringWithTimestampValidation - Random 1 KB, 100,000", () => X509CertificateBasedDecryptorEnduranceTests.DecryptStringToBase64WithTimestamp(1, 100000))
                    .AddSync("X509CertificateBasedEncryptor.EncryptStringToBase64WithTimestamp - Random 8KB, 100,000", () => X509CertificateBasedEncryptorEnduranceTests.EncryptStringToBase64WithTimestamp(8, 100000))
                    .AddSync("X509CertificateBasedDecryptor.DecryptBase64EncodedStringWithTimestampValidation - Random 8KB, 100,000", () => X509CertificateBasedDecryptorEnduranceTests.DecryptStringToBase64WithTimestamp(8,100000))
                    .AddSync("Exit",()=> canContinue = false);
                await menu.Display(CancellationToken.None);
            }
            
        }
        public static void ValidateEncryptionAndDecryptionOnce(X509Certificate2 cert)
        {
            var sampleData = TestDataGenerator.GenerateJunk(MyConfigForEnduranceTests.SampleDataSizeKB);
            Console.WriteLine($"Generated {sampleData.Length / 1024} KB random binary data.");

            // Encrypt/Decrypt ONCE...
            var encryptedBytes = EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(cert, sampleData);
            var decryptedBytes = EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(cert, encryptedBytes);
            Console.WriteLine($"SampleData: {sampleData.Length:#,0} bytes");
            Console.WriteLine($"Encrypted:  {encryptedBytes.Length:#,0} bytes");
            Console.WriteLine($"Decrypted:  {decryptedBytes.Length:#,0} bytes");

            // Vallidate
            var good = sampleData.SequenceEqual(decryptedBytes);
            if (!good) throw new Exception("Decrypted result doesn't match original data.");
        }
    }
}