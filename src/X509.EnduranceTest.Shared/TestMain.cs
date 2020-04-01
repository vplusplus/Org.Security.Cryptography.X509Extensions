
using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Org.Security.Cryptography;

namespace X509.EnduranceTest.Shared
{
    public static class TestMain
    {
        #region AppSettings

        static string   X509Thumbprint      => AppSetting("X509.Thumbprint");
        static int      SampleDataSizeKB    => Convert.ToInt32(AppSetting("SampleDataSizeKB"));
        static int      LoopCount           => Convert.ToInt32(AppSetting("LoopCount"));

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
                Console.WriteLine("----------------------------------");
                Console.WriteLine("[P] Print AsymmetricAlgorithm provider.");
                Console.WriteLine("[V] Validate Encryption/Decryption once.");
                Console.WriteLine("[E] Start ENcryption loop.");
                Console.WriteLine("[D] Start DEcryption loop.");
                Console.WriteLine("[Q] or Ctrl-C anytime to quit");
                Console.WriteLine("----------------------------------");

                var input = (Console.ReadLine() ?? string.Empty).Trim().ToUpper();

                var cert = X509CertificateCache.GetCertificate(X509Thumbprint);

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
                        PrintCSP(cert);
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
            var sampleData = GenerateJunk(SampleDataSizeKB);
            Console.WriteLine($"Generated {sampleData.Length / 1024} KB random binary data.");

            // Encrypt/Decrypt ONCE...
            var encryptedBytes = EncryptBytes(sampleData, cert);
            var decryptedBytes = DecryptBytes(encryptedBytes, cert);
            Console.WriteLine($"SampleData: {sampleData.Length} bytes");
            Console.WriteLine($"Encrypted: {encryptedBytes.Length} bytes");
            Console.WriteLine($"Decrypted: {decryptedBytes.Length} bytes");

            // Vallidate
            var good = sampleData.SequenceEqual(decryptedBytes);
            if (!good) throw new Exception("Decrypted result doesn't match original data.");
        }

        static void PrintCSP(X509Certificate2 cert)
        {
            AsymmetricAlgorithm alg = null;

            try
            {
                Console.WriteLine("cert.GetRSAPublicKey()");
                alg = cert.GetRSAPublicKey();
                Console.WriteLine(alg.GetType().FullName);
            }
            catch (Exception err)
            {
                PrintTopErrorInfo(err);
            }

            try
            {
                Console.WriteLine("cert.GetRSAPrivateKey()");
                alg = cert.GetRSAPrivateKey();
                Console.WriteLine(alg.GetType().FullName);
            }
            catch (Exception err)
            {
                PrintTopErrorInfo(err);
            }

            try
            {
                Console.WriteLine("cert.PublicKey.Key");
                alg = cert.PublicKey.Key;
                Console.WriteLine(alg.GetType().FullName);
            }
            catch(Exception err)
            {
                PrintTopErrorInfo(err);
            }

            try
            {
                Console.WriteLine("cert.PrivateKey");
                alg = cert.PrivateKey;
                Console.WriteLine(alg.GetType().FullName);
            }
            catch (Exception err)
            {
                PrintTopErrorInfo(err);
            }

            void PrintTopErrorInfo(Exception ex)
            {
                Console.WriteLine($"[{ex.GetType().FullName}]");
                Console.WriteLine(ex.Message);
            }
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
            var sampleData = GenerateJunk(SampleDataSizeKB);

            Console.WriteLine($"MaxIterations: {maxIterations:#,0}");
            Console.WriteLine($"Generated {sampleData.Length / 1024} KB random binary data.");

            var encryptedBytes = EncryptBytes(sampleData, cert);
            var decryptedBytes = DecryptBytes(encryptedBytes, cert);

            var counter = 0;
            var elapsed = Stopwatch.StartNew();
            var statusUpdateInterval = TimeSpan.FromSeconds(2);
            var nextStatusUpdate = DateTime.Now.Add(statusUpdateInterval);

            var rate = 0.0;

            while (counter++ <= maxIterations)
            {
                if (encrypt) EncryptBytes(decryptedBytes, cert);
                if (decrypt) DecryptBytes(encryptedBytes, cert);

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

        static byte[] EncryptBytes(byte[] inputData, X509Certificate2 cert)
        {
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream())
            {
                cert.EncryptStream(input, output);
                output.Flush();
                return output.ToArray();
            }
        }

        static byte[] DecryptBytes(byte[] inputData, X509Certificate2 cert)
        {
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                cert.DecryptStream(input, output);
                output.Flush();
                return output.ToArray();
            }
        }

        static byte[] GenerateJunk(int kiloBytes)
        {
            int maxBytes = kiloBytes * 1024;

            using (var buffer = new MemoryStream(maxBytes))
            {
                var bytesWritten = 0;

                while (bytesWritten < maxBytes)
                {
                    var more = Guid.NewGuid().ToByteArray();
                    buffer.Write(more, 0, more.Length);
                    bytesWritten += more.Length;
                }

                buffer.Flush();
                return buffer.ToArray();
            }
        }
    }
}
