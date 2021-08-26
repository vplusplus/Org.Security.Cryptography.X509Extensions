
using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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

        public static void Run()
        {
            try
            {
                PrintOptionsAndRunTest();
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

        static void PrintOptionsAndRunTest()
        {
            while (true)
            {
                Console.WriteLine("-------------------------------------------");
                Console.WriteLine("[P] Print AsymmetricAlgorithm provider.");
                Console.WriteLine("[V] Validate Encryption/Decryption, ONCE.");
                Console.WriteLine("[E] Start ENcryption loop.");
                Console.WriteLine("[D] Start DEcryption loop.");
                Console.WriteLine("[Q] or Ctrl-C to quit");
                Console.WriteLine("-------------------------------------------");

                var input = (Console.ReadLine() ?? string.Empty).Trim().ToUpper();

                var cert = MyConfig.DecryptionCertificate;

                switch (input)
                {
                    case "V":
                        ValidateEncryptionAndDecryptionOnce(cert);
                        break;

                    case "E":
                        BeginEncryptionLoop(cert, LoopCount);
                        break;

                    case "D":
                        BeginDecryptionLoop(cert, LoopCount);
                        break;

                    case "P":
                        ConsoleWriter.PrintCSP(cert);
                        break;

                    case "Q":
                        return;

                    default:
                        ValidateEncryptionAndDecryptionOnce(cert);
                        break;
                }

                Console.WriteLine();
            }
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
            BeginLoop(cert, maxIterations, encrypt: true);
        }

        static void BeginDecryptionLoop(X509Certificate2 cert, int maxIterations)
        {
            BeginLoop(cert, maxIterations, decrypt: true);
        }

        static void BeginLoop(X509Certificate2 cert, int maxIterations, bool encrypt = false, bool decrypt = false)
        {
            var sampleData = TestDataGenerator.GenerateJunk(SampleDataSizeKB);

            Console.WriteLine($"MaxIterations: {maxIterations:#,0}");
            Console.WriteLine($"Generated {sampleData.Length / 1024} KB random binary data.");

            var encryptedBytes = EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(cert, sampleData);
            var decryptedBytes = EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(cert, encryptedBytes);

            var counter = 0;
            var elapsed = Stopwatch.StartNew();
            var statusUpdateInterval = TimeSpan.FromSeconds(2);
            var nextStatusUpdate = DateTime.Now.Add(statusUpdateInterval);

            var rate = 0.0;

            while (counter++ <= maxIterations)
            {
                if (encrypt) EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(cert, decryptedBytes);
                if (decrypt) EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(cert, encryptedBytes);

                if (nextStatusUpdate < DateTime.Now)
                {
                    rate = counter / elapsed.Elapsed.TotalSeconds;
                    Console.WriteLine($"{elapsed.Elapsed:hh\\:mm\\:ss} @ {rate:#,0} per-sec. Iterations: {counter:#,0} (Use Ctrl-C to quit...)");
                    nextStatusUpdate = DateTime.Now.Add(statusUpdateInterval);
                }
            }
            rate = counter / elapsed.Elapsed.TotalSeconds;
            Console.WriteLine("Finished.");
            Console.WriteLine($"{elapsed.Elapsed:hh\\:mm\\:ss} @ {rate:#,0} per-sec. Iterations: {counter:#,0} (Use Ctrl-C to quit...)");
        }
    }
    public class EnduranceTestResult {
    }
}
