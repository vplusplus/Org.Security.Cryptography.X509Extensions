
using System;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Org.Security.Cryptography.X509RsaAes;

namespace UnitTests
{

    [TestClass]
    public class X509Tests
    {
        // 2E3257EE8FC8A72DB3778DFB3F9EDC7D0A9D66C7
        // 4DB3C870B8D766AD895B8F7537CF58E22D4E0256

        const string CertThumbPrint = "2E3257EE8FC8A72DB3778DFB3F9EDC7D0A9D66C7";

        [TestMethod]
        public void FindCertificateTest()
        {
            var cert = Org.Security.Cryptography.X509CertificateCache.GetCertificate(CertThumbPrint, StoreName.My, StoreLocation.CurrentUser);

            Console.WriteLine($"Thumbprint: {cert.Thumbprint}");
            Console.WriteLine($"Subject: {cert.Subject}");
            Console.WriteLine($"SubjectName: {cert.SubjectName?.Name}");
            Console.WriteLine($"IssuerName: {cert.IssuerName?.Name}");
            Console.WriteLine($"EffectiveDate: {cert.GetEffectiveDateString()}");
            Console.WriteLine($"ExpiryeDate: {cert.GetExpirationDateString()}");
        }

        [TestMethod]
        public void X509RsaAes_TripleRoundTripTest()
        {
            const string TEST = "Hello World!";

            byte[] input   = Encoding.UTF8.GetBytes(TEST);
            byte[] output1 = DecryptBytes(EncryptBytes(input, CertThumbPrint), CertThumbPrint);
            byte[] output2 = DecryptBytes(EncryptBytes(output1, CertThumbPrint), CertThumbPrint);
            byte[] output3 = DecryptBytes(EncryptBytes(output2, CertThumbPrint), CertThumbPrint);

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
        public void X509RsaAes_BenchmarkEncryptionAndDecryption()
        {
            const int SampleDataSizeInKB = 2;

            // Generate some random data
            var SampleData = GenerateJunk(SampleDataSizeInKB);

            // Dryrun
            var encryptedBytes = EncryptBytes(SampleData, CertThumbPrint);
            var decryptedBytes = DecryptBytes(encryptedBytes, CertThumbPrint);

            var same = decryptedBytes.SequenceEqual(SampleData);
            if (!same) throw new Exception("Decrypted data doesn't match original data");

            Console.WriteLine($"Sample data length:    {SampleData.Length:#,0} bytes");
            Console.WriteLine($"Encrypted data length: {encryptedBytes.Length:#,0} bytes");
            Console.WriteLine($"Decrypted data length: {decryptedBytes.Length:#,0} bytes");

            const int LOOP_COUNT = 1000;

            var timer = Stopwatch.StartNew();
            for (int i=0; i<LOOP_COUNT; i++)
            {
                encryptedBytes = EncryptBytes(SampleData, CertThumbPrint);
                //decryptedBytes = DecryptBytes(encryptedBytes, CertThumbPrint);

            }
            timer.Stop();

            var elapsed = timer.Elapsed;
            Console.WriteLine($"LoopCount: {LOOP_COUNT:#,0}");
            Console.WriteLine($"Elapsed: {elapsed.TotalMilliseconds:#,0} millSec");
            Console.WriteLine($"Average: {elapsed.TotalMilliseconds / (long)LOOP_COUNT:#,0.000} millSec");
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
