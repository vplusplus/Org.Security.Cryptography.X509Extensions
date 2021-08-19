
using System;
using System.Linq;
using System.Diagnostics;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Org.Security.Cryptography;
using X509.EnduranceTest.Shared;

namespace UnitTests
{
    [TestClass]
    public class X509EncryptionTests
    {

        [TestMethod]
        public void WhenEncryptAndDecryptAreCalledWithCertsLoadedFromFiles_ShouldWork()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509EncryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
            var x509DecryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.pfx",MyConfig.TestCertficatePassword);
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            byte[] output1 = EncryptionDecryptionUtils.DecryptBytes(x509DecryptionCert, EncryptionDecryptionUtils.EncryptBytes(x509EncryptionCert, input));
            //Assert
            Assert.IsTrue(input.SequenceEqual(output1));
        }

        [TestMethod]
        [ExpectedException(typeof(Exception))]
        public void WhenDecryptStreamIsCalledWithCertThatDontHavePrivateKey_ThrowException()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509CertWithoutPrivateKey = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            byte[] output1 = EncryptionDecryptionUtils.DecryptBytes(x509CertWithoutPrivateKey, EncryptionDecryptionUtils.EncryptBytes(x509CertWithoutPrivateKey, input));
            //Assert
            Assert.IsTrue(input.SequenceEqual(output1));
        }
        //TODO: Below tests kept as is to test for now. Change later to have the tests run independently.
        // Ideally, it doesn't matter where from the certificate loaded as long as the X509Certificate2 object is available to tests.
        [TestMethod]
        public void X509_TripleRoundTripTest()
        {
            const string TEST = "Hello World!";

            var x509Cert = X509CertificateCache.GetCertificate(MyConfig.TestCertThumbPrint);

            byte[] input   = Encoding.UTF8.GetBytes(TEST);
            byte[] output1 = EncryptionDecryptionUtils.DecryptBytes(x509Cert, EncryptionDecryptionUtils.EncryptBytes(x509Cert, input));
            byte[] output2 = EncryptionDecryptionUtils.DecryptBytes(x509Cert, EncryptionDecryptionUtils.EncryptBytes(x509Cert, input));
            byte[] output3 = EncryptionDecryptionUtils.DecryptBytes(x509Cert, EncryptionDecryptionUtils.EncryptBytes(x509Cert, input));

            Assert.IsTrue(input.SequenceEqual(output1));
            Assert.IsTrue(input.SequenceEqual(output2));
            Assert.IsTrue(input.SequenceEqual(output3));

            // Seeing is believing...
            Console.WriteLine($"Original: {TEST}");
            Console.WriteLine($"#1 {Encoding.UTF8.GetString(output1)}");
            Console.WriteLine($"#2 {Encoding.UTF8.GetString(output2)}");
            Console.WriteLine($"#3 {Encoding.UTF8.GetString(output3)}");
        }
        //TODO: Move this benchmark to separate Test class
        [TestMethod]
        public void X509_Benchmark_EncryptionAndDecryption()
        {
            const int SampleDataSizeInKB = 8;
            const int BenchmarkLoopCount = 1000;

            var x509Cert = X509CertificateCache.GetCertificate(MyConfig.TestCertThumbPrint);

            // Generate some random data
            // Perform a dry run
            // Capture Encrypted and Decrypted version
            var SampleData = TestDataGenerator.GenerateJunk(SampleDataSizeInKB);
            var encryptedBytes = EncryptionDecryptionUtils.EncryptBytes(x509Cert, SampleData);
            var decryptedBytes = EncryptionDecryptionUtils.DecryptBytes(x509Cert, encryptedBytes);

            Assert.IsTrue(decryptedBytes.SequenceEqual(SampleData), "Decrypted bytes doesn't match original data.");

            var timer = Stopwatch.StartNew();
            for (int i=0; i< BenchmarkLoopCount; i++)
            {
                EncryptionDecryptionUtils.EncryptBytes(x509Cert, decryptedBytes);
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
                EncryptionDecryptionUtils.DecryptBytes(x509Cert, encryptedBytes);
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
    }
}

