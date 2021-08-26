
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
        #region AppSettings

        static int SampleDataSizeKB => Convert.ToInt32(AppSetting("SampleDataSizeKB"));
        static int LoopCount => Convert.ToInt32(AppSetting("LoopCount"));

        static string AppSetting(string name) => ConfigurationManager.AppSettings[name] ?? throw new Exception($"AppSetting 'name' not defined.");

        #endregion

        async public static Task Run()
        {
            try
            {
                await PrintOptionsAndRunTestAsync();
            }
            catch (Exception err)
            {
                var topError = err;
                while (null != err)
                {
                    Console.WriteLine($"[{err.GetType().FullName}]");
                    Console.WriteLine(err.Message);
                    err = err.InnerException;
                }
                Console.WriteLine(topError.StackTrace);
            }
        }
        async static Task PrintOptionsAndRunTestAsync()
        {
            var menu = new Menu()
                .AddSync("Print AsymmetricAlgorithm provider.", () => ConsoleWriter.PrintCSP(MyConfig.DecryptionCertificate))
                .AddSync("Validate Encryption/Decryption, ONCE.", () => ValidateEncryptionAndDecryptionOnce(MyConfig.DecryptionCertificate))
                .AddSync("Start ENcryption loop", () => BeginEncryptionLoop(MyConfig.DecryptionCertificate, LoopCount))
                .AddSync("Start DEcryption loop", () => BeginDecryptionLoop(MyConfig.DecryptionCertificate, LoopCount));

            await menu.Display(CancellationToken.None);
        }
        public static void ValidateEncryptionAndDecryptionOnce(X509Certificate2 cert)
        {
            var sampleData = TestDataGenerator.GenerateJunk(SampleDataSizeKB);
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
        static void BeginEncryptionLoop(X509Certificate2 cert, int maxIterations)
        {
            var sampleData = TestDataGenerator.GenerateJunk(SampleDataSizeKB);
            Console.WriteLine($"Generated {sampleData.Length / 1024} KB random binary data.");
            var encryptedBytes = EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(cert, sampleData);
            var decryptedBytes = EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(cert, encryptedBytes);

            var result= EnduranceTestRunner.BeginLoop( maxIterations, () => EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(cert, decryptedBytes));
        }

        static void BeginDecryptionLoop(X509Certificate2 cert, int maxIterations)
        {
            var sampleData = TestDataGenerator.GenerateJunk(SampleDataSizeKB);
            Console.WriteLine($"Generated {sampleData.Length / 1024} KB random binary data.");
            var encryptedBytes = EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(cert, sampleData);
            EnduranceTestRunner.BeginLoop( maxIterations, () => EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(cert, encryptedBytes));
        }

        
    }
   
}
