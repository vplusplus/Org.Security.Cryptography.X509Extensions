
using System;
using System.Linq;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using X509.EnduranceTest.Shared;

namespace UnitTests
{
    [TestClass]
    public class X509Certificate2_EncryptStream_PerfTests
    {
        [TestMethod]
        public void X509_Benchmark_1000TimesEncryption_ShouldBeCompletedWithin1Second()
        {
            //Arrange
            const int SampleDataSizeInKB = 8;
            const int BenchmarkLoopCount = 1000;

            // Generate some random data
            // Perform a dry run to warm up.
            // Capture Encrypted and Decrypted version
            var SampleData = TestDataGenerator.GenerateJunk(SampleDataSizeInKB);
            var encryptedBytes = EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(MyConfig.EncryptionCertificate, SampleData);
            var decryptedBytes = EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(MyConfig.DecryptionCertificate, encryptedBytes);

            Assert.IsTrue(decryptedBytes.SequenceEqual(SampleData), "Decrypted bytes doesn't match original data.");

            //Act
            var timer = Stopwatch.StartNew();
            for (int i = 0; i < BenchmarkLoopCount; i++)
            {
                EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(MyConfig.EncryptionCertificate, decryptedBytes);
            }
            timer.Stop();
            
            //Assert
            var totalMs = timer.Elapsed.TotalMilliseconds;
            var totalSec = timer.Elapsed.TotalSeconds;
            var avgMs = totalMs / BenchmarkLoopCount;
            var ratePerSec = BenchmarkLoopCount / totalSec;

            Console.WriteLine("Encryption Benchmark:");
            Console.WriteLine($"SampleDataSize: {SampleData.Length / 1024:#,0} KB");
            Console.WriteLine($"Elapsed: {timer.Elapsed}");
            Console.WriteLine($"{BenchmarkLoopCount:#,0} iterations @ {ratePerSec:#,0.0} per Sec. / Average: {avgMs:#,0.00} milliSec");
            
            Assert.IsTrue(
                1 > timer.Elapsed.TotalSeconds,
                $"Encrypting {BenchmarkLoopCount} times took more than 1 second. Consider optimizing or check machine configuration");
        }

    }
}

