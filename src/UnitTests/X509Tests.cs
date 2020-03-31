
using System;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Org.Security.Cryptography;

namespace UnitTests
{
    [TestClass]
    public class X509Tests
    {
        static string TestCertThumbPrint => 
            System.Configuration.ConfigurationManager.AppSettings["X509.ThumbPrint"] ??
              throw new Exception($"AppSetting 'X509.ThumbPrint' not defined.");

        [TestMethod]
        public void X509_LookupSpeed()
        {
            //......................................................................
            // OpenStore-Lookup-CloseStore:  apprx 5 milliSec per lookup
            // KeepStoreOpen-Lookup:         apprx 14 microSec per lookup
            //......................................................................

            const int loopCount = 10000;
            const StoreName storeName = StoreName.My;
            const StoreLocation storeLocation = StoreLocation.CurrentUser;

            var thumb = TestCertThumbPrint;
            Console.WriteLine(thumb);

            // Dry run
            OpenStoreAndLookupCert();

            // Scenario #1: OpenStore/Lookup/CloseStore
            Stopwatch timer = Stopwatch.StartNew();
            for (int i=0; i<loopCount; i++)
            {
                OpenStoreAndLookupCert();
            }
            timer.Stop();
            PrintStats("OPEN-CLOSE-STORE", timer.Elapsed, loopCount);

            // Scenario #2: OpenStore ONCE. LookupCert.
            timer = Stopwatch.StartNew();
            using (X509Store store = new X509Store(storeName, storeLocation))
            {
                // Open an existing store.
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                for (int i = 0; i < loopCount; i++)
                {
                    UseMyStoreLookupCert(store);
                }
            }
            timer.Stop();
            PrintStats("KEEP-STORE-OPEN", timer.Elapsed, loopCount);

            void PrintStats(string scenario, TimeSpan elapsed, int iterations)
            {
                var ratePerSec = (long)iterations / elapsed.TotalSeconds;
                var avgMs = elapsed.TotalMilliseconds / iterations;
                Console.WriteLine($"{scenario}: {iterations:#,0} iterations @ {ratePerSec:#,0.00} per-Sec. Avg: {avgMs:#,0.000} millSec");
            }

            void OpenStoreAndLookupCert()
            {
                using (X509Store store = new X509Store(storeName, storeLocation))
                {
                    // Open an existing store.
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                    // Look for the certificate by thumbPrint.
                    var certs = store
                        .Certificates
                        .Cast<X509Certificate2>()
                        .Where(x => null != x?.Thumbprint)
                        .Where(x => x.Thumbprint.Equals(thumb, StringComparison.OrdinalIgnoreCase))
                        .ToArray();

                    if (1 != certs.Length) throw new Exception("Cert not found.");
                }
            }

            void UseMyStoreLookupCert(X509Store storeThatIsAlreadyOpen)
            {
                var certs = storeThatIsAlreadyOpen
                    .Certificates
                    .Cast<X509Certificate2>()
                    .Where(x => null != x?.Thumbprint)
                    .Where(x => x.Thumbprint.Equals(thumb, StringComparison.OrdinalIgnoreCase))
                    .ToArray();

                if (1 != certs.Length) throw new Exception("Cert not found.");
            }
        }

        [TestMethod]
        public void X509_CacheLookup()
        {
            var cert = X509CertificateCache.GetCertificate(TestCertThumbPrint, StoreName.My, StoreLocation.CurrentUser);

            Console.WriteLine($"Thumbprint: {cert.Thumbprint}");
            Console.WriteLine($"Subject: {cert.Subject}");
            Console.WriteLine($"SubjectName: {cert.SubjectName?.Name}");
            Console.WriteLine($"IssuerName: {cert.IssuerName?.Name}");
            Console.WriteLine($"EffectiveDate: {cert.GetEffectiveDateString()}");
            Console.WriteLine($"ExpiryeDate: {cert.GetExpirationDateString()}");
        }

        [TestMethod]
        public void X509_TripleRoundTripTest()
        {
            const string TEST = "Hello World!";

            byte[] input   = Encoding.UTF8.GetBytes(TEST);
            byte[] output1 = DecryptBytes(EncryptBytes(input, TestCertThumbPrint), TestCertThumbPrint);
            byte[] output2 = DecryptBytes(EncryptBytes(output1, TestCertThumbPrint), TestCertThumbPrint);
            byte[] output3 = DecryptBytes(EncryptBytes(output2, TestCertThumbPrint), TestCertThumbPrint);

            Assert.IsTrue(input.SequenceEqual(output1));
            Assert.IsTrue(input.SequenceEqual(output2));
            Assert.IsTrue(input.SequenceEqual(output3));

            // Seeing is believing...
            Console.WriteLine($"Original: {TEST}");
            Console.WriteLine($"#1 {Encoding.UTF8.GetString(output1)}");
            Console.WriteLine($"#2 {Encoding.UTF8.GetString(output2)}");
            Console.WriteLine($"#3 {Encoding.UTF8.GetString(output3)}");
        }

        [TestMethod]
        public void X509_Benchmark_EncryptionAndDecryption()
        {
            const int SampleDataSizeInKB = 8;
            const int BenchmarkLoopCount = 1000;

            // Generate some random data and dryrun
            var SampleData = GenerateJunk(SampleDataSizeInKB);
            var encryptedBytes = EncryptBytes(SampleData, TestCertThumbPrint);
            var decryptedBytes = DecryptBytes(encryptedBytes, TestCertThumbPrint);

            Assert.IsTrue(decryptedBytes.SequenceEqual(SampleData), "Decrypted bytes doesn't match original data.");

            var timer = Stopwatch.StartNew();
            for (int i=0; i< BenchmarkLoopCount; i++)
            {
                EncryptBytes(SampleData, TestCertThumbPrint);
            }
            timer.Stop();

            var totalMs = timer.Elapsed.TotalMilliseconds;
            var totalSec = timer.Elapsed.TotalSeconds;
            var avgMs = totalMs / BenchmarkLoopCount;
            var ratePerSec = BenchmarkLoopCount / totalSec;

            Console.WriteLine("Encryption Benchmark:");
            Console.WriteLine($"SampleDataSize: {SampleData.Length / 1024:#,0} KB");
            Console.WriteLine($"Elapsed: {timer.Elapsed}");
            Console.WriteLine($"{BenchmarkLoopCount:#,0} iterations @ {ratePerSec:#,0.0} per Sec. / Average: {avgMs:#,0.00} milliSec");
            

            timer = Stopwatch.StartNew();
            for (int i = 0; i < BenchmarkLoopCount; i++)
            {
                DecryptBytes(encryptedBytes, TestCertThumbPrint);
            }
            timer.Stop();

            totalMs = timer.Elapsed.TotalMilliseconds;
            totalSec = timer.Elapsed.TotalSeconds;
            avgMs = totalMs / BenchmarkLoopCount;
            ratePerSec = BenchmarkLoopCount / totalSec;

            Console.WriteLine("Decryption Benchmark:");
            Console.WriteLine($"SampleDataSize: {SampleData.Length / 1024:#,0} KB");
            Console.WriteLine($"Elapsed: {timer.Elapsed}");
            Console.WriteLine($"{BenchmarkLoopCount:#,0} iterations @ {ratePerSec:#,0.0} per Sec. / Average: {avgMs:#,0.00} milliSec");

        }

        byte[] EncryptBytes(byte[] inputData, string thumbprint, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                input.Encrypt(output, thumbprint, storeName, storeLocation);
                output.Flush();
                return output.ToArray();
            }
        }

        byte[] DecryptBytes(byte[] inputData, string thumbprint, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                input.Decrypt(output, thumbprint, storeName, storeLocation);
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

