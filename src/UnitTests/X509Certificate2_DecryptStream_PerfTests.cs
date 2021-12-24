
using System;
using System.Linq;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using X509.EnduranceTest.Shared;

namespace UnitTests.Decryption
{
    [TestClass]
    public class X509Certificate2_DecryptStream_PerfTests
    {
        [TestMethod]
        public void X509_Benchmark_Decryption()
        {
            const int SampleDataSizeInKB = 8;
            const int BenchmarkLoopCount = 1000;

            // Generate some random data
            // Perform a dry run
            // Capture Encrypted and Decrypted version
            var SampleData = TestDataGenerator.GenerateJunk(SampleDataSizeInKB);
            var encryptedBytes = EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(MyConfig.EncryptionCertificate, SampleData);
            var decryptedBytes = EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(MyConfig.DecryptionCertificate, encryptedBytes);

            Assert.IsTrue(decryptedBytes.SequenceEqual(SampleData), "Decrypted bytes doesn't match original data.");

            //Act
            var timer = Stopwatch.StartNew();

            for (int i = 0; i < BenchmarkLoopCount; i++)
            {
                EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(MyConfig.DecryptionCertificate, encryptedBytes);
            }
            timer.Stop();
            //Assert
            var totalMs = timer.Elapsed.TotalMilliseconds;
            var totalSec = timer.Elapsed.TotalSeconds;
            var avgMs = totalMs / BenchmarkLoopCount;
            var ratePerSec = BenchmarkLoopCount / totalSec;

            Console.WriteLine("Decryption Benchmark:");
            Console.WriteLine($"SampleDataSize: {SampleData.Length / 1024:#,0} KB");
            Console.WriteLine($"Elapsed: {timer.Elapsed}");
            Console.WriteLine($"{BenchmarkLoopCount:#,0} iterations @ {ratePerSec:#,0.0} per Sec. / Average: {avgMs:#,0.00} milliSec");

        }

    }
}

