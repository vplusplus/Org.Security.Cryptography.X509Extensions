
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

        static X509Certificate2 GetCert(string thumbprint, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            using (X509Store store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                var certs = store
                    .Certificates
                    .Cast<X509Certificate2>()
                    .Where(x => x.Thumbprint.Equals(CertThumbPrint, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                //var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

                if (1 == certs.Count) return certs[0];
                else if (0 == certs.Count) throw new Exception($"X509Certificate not found: {storeLocation}/{storeName}/{thumbprint}");
                else throw new Exception($"More than ONE X509Certificate found: {storeLocation}/{storeName}/{thumbprint}");
            }
        }

        [TestMethod]
        public void FindCertificateTest()
        {
            // Verified that finding by thumbprints is case-IN-sensitive

            var cert1 = GetCert(CertThumbPrint.ToLower(), StoreName.My, StoreLocation.CurrentUser);
            var cert2 = GetCert(CertThumbPrint.ToUpper(), StoreName.My, StoreLocation.CurrentUser);

            var cert = GetCert(CertThumbPrint);

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
            X509Certificate2 cert = GetCert(CertThumbPrint) ?? throw new Exception("X509Certificate2 was NULL.");

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

            var secondResult = Encoding.UTF8.GetString(decryptedBytes);

            Console.WriteLine($"Original: {TEST}");
            Console.WriteLine($"First Result:  {firstResult}");
            Console.WriteLine($"Second Result: {secondResult}");
        }

        [TestMethod]
        public void BenchmarkX509CertLookup()
        {
            // Dry run
            X509Cache.GetCertificate(CertThumbPrint);

            int loopCount = 1000;
            var timer = Stopwatch.StartNew();

            for (int i = 0; i < loopCount; i++)
            {
                // var ignoreMe = GetCert(CertThumbPrint);
                X509Cache.GetCertificate(CertThumbPrint);
            }

            timer.Stop();
            var elapsed = timer.Elapsed;
            Console.WriteLine($"LoopCount: {loopCount:#,0}");
            Console.WriteLine($"Elapsed: {elapsed.TotalMilliseconds:#,0} millSec");
            Console.WriteLine($"Average: {elapsed.TotalMilliseconds/loopCount:#,0} millSec");
        }

        [TestMethod]
        public void BenchmarkX509EncryptionAndDecryption()
        {
            const int SampleDataSizeInKB = 2;

            // Generate some random data
            var SampleData = GenerateSampleData(SampleDataSizeInKB);

            // Grab the cert
            var cert = X509Cache.GetCertificate(CertThumbPrint);

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

        static byte[] GenerateSampleData(int kbs)
        {
            using (var buffer = new MemoryStream(kbs * 1024))
            {
                int maxBytes = kbs * 1024;
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
