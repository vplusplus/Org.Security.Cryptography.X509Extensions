
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
        // 2E3257EE8FC8A72DB3778DFB3F9EDC7D0A9D66C7
        // 4DB3C870B8D766AD895B8F7537CF58E22D4E0256

        const string CertThumbPrint = "2E3257EE8FC8A72DB3778DFB3F9EDC7D0A9D66C7";


        [TestMethod]
        public void FindCertificateTest()
        {
            var cert = X509CertificateCache.GetCertificate(CertThumbPrint, StoreName.My, StoreLocation.CurrentUser);

            Console.WriteLine($"Thumbprint: {cert.Thumbprint}");
            Console.WriteLine($"Subject: {cert.Subject}");
            Console.WriteLine($"SubjectName: {cert.SubjectName?.Name}");
            Console.WriteLine($"IssuerName: {cert.IssuerName?.Name}");
            Console.WriteLine($"EffectiveDate: {cert.GetEffectiveDateString()}");
            Console.WriteLine($"ExpiryeDate: {cert.GetExpirationDateString()}");
        }

        [TestMethod]
        public void X509_KEK_DEK_EncryptDecryptTest()
        {
            var cert = X509CertificateCache.GetCertificate(CertThumbPrint, StoreName.My, StoreLocation.CurrentUser);

            const string TEST = "Hello World!";

            byte[] inputBytes = Encoding.UTF8.GetBytes(TEST);
            byte[] encryptedBytes = null;
            byte[] decryptedBytes = null;

            using (var inputStream = new MemoryStream(inputBytes))
            using (var outputStream = new MemoryStream(1024))
            {
                cert.EncryptUsingPublicKey(inputStream, outputStream);
                outputStream.Flush();
                encryptedBytes = outputStream.ToArray();
            }

            using (var inputStream = new MemoryStream(encryptedBytes))
            using (var outputStream = new MemoryStream(1024))
            {
                cert.DecryptUsingPrivateKey(inputStream, outputStream);
                outputStream.Flush();
                decryptedBytes = outputStream.ToArray();
            }

            var firstResult = Encoding.UTF8.GetString(decryptedBytes);

            inputBytes = Encoding.UTF8.GetBytes(firstResult);

            using (var inputStream = new MemoryStream(inputBytes))
            using (var outputStream = new MemoryStream(1024))
            {
                cert.EncryptUsingPublicKey(inputStream, outputStream);
                outputStream.Flush();
                encryptedBytes = outputStream.ToArray();
            }

            using (var inputStream = new MemoryStream(encryptedBytes))
            using (var outputStream = new MemoryStream(1024))
            {
                cert.DecryptUsingPrivateKey(inputStream, outputStream);
                outputStream.Flush();
                decryptedBytes = outputStream.ToArray();
            }

            // Byte by byte comparison.
            Assert.IsTrue(inputBytes.SequenceEqual(decryptedBytes));

            // Recover original string
            var secondResult = Encoding.UTF8.GetString(decryptedBytes);

            // Seeing is believing...
            Console.WriteLine($"Original: {TEST}");
            Console.WriteLine($"First Result:  {firstResult}");
            Console.WriteLine($"Second Result: {secondResult}");
        }

        [TestMethod]
        public void BenchmarkX509CertLookup()
        {
            // Dry run
            X509CertificateCache.GetCertificate(CertThumbPrint);

            int loopCount = 10000;
            var timer = Stopwatch.StartNew();

            for (int i = 0; i < loopCount; i++)
            {
                // var ignoreMe = GetCert(CertThumbPrint);
                X509CertificateCache.GetCertificate(CertThumbPrint);
            }

            timer.Stop();
            var elapsed = timer.Elapsed;
            Console.WriteLine($"LoopCount: {loopCount:#,0}");
            Console.WriteLine($"Elapsed: {elapsed.TotalMilliseconds:#,0} millSec");
            Console.WriteLine($"Average: {elapsed.TotalMilliseconds*1000.0/(float)loopCount:#,0.000} microSec");
        }

        [TestMethod]
        public void BenchmarkX509EncryptionAndDecryption()
        {
            const int SampleDataSizeInKB = 2;

            // Generate some random data
            var SampleData = GenerateJunk(SampleDataSizeInKB);

            // Grab the cert
            var cert = X509CertificateCache.GetCertificate(CertThumbPrint);

            // Dryrun
            var encryptedBytes = EncryptBytes(cert, SampleData);
            var decryptedBytes = DecryptBytes(cert, encryptedBytes);

            var same = decryptedBytes.SequenceEqual(SampleData);
            if (!same) throw new Exception("Decrypted data doesn't match original data");

            Console.WriteLine($"Sample data length:    {SampleData.Length:#,0} bytes");
            Console.WriteLine($"Encrypted data length: {encryptedBytes.Length:#,0} bytes");
            Console.WriteLine($"Decrypted data length: {decryptedBytes.Length:#,0} bytes");

            const int LOOP_COUNT = 1000;

            var timer = Stopwatch.StartNew();
            for (int i=0; i<LOOP_COUNT; i++)
            {
                encryptedBytes = EncryptBytes(cert, SampleData);
                //decryptedBytes = DecryptBytes(cert, encryptedBytes);

            }
            timer.Stop();

            var elapsed = timer.Elapsed;
            Console.WriteLine($"LoopCount: {LOOP_COUNT:#,0}");
            Console.WriteLine($"Elapsed: {elapsed.TotalMilliseconds:#,0} millSec");
            Console.WriteLine($"Average: {elapsed.TotalMilliseconds / (long)LOOP_COUNT:#,0.000} millSec");
        }

        byte[] EncryptBytes(X509Certificate2 cert, byte[] inputData)
        {
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                cert.EncryptUsingPublicKey(input, output);
                output.Flush();
                return output.ToArray();
            }
        }

        byte[] DecryptBytes(X509Certificate2 cert, byte[] inputData)
        {
            using (var input = new MemoryStream(inputData))
            using (var output = new MemoryStream(inputData.Length))
            {
                cert.DecryptUsingPrivateKey(input, output);
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
