using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.Security.Cryptography;
using UnitTests;

namespace X509.EnduranceTest.Shared
{
    internal class X509Certificate2_SignAndVerifyEnduranceTests
    {
        internal static void Run( double dataSizeInKB, int maxIterations)
        {
            var hashName = "SHA256";
            X509Certificate2 cert = MyConfig.SigningCertificate;
            var payload = TestDataGenerator.GenerateJunk((int)(dataSizeInKB * 1024));
            Console.WriteLine($"Generated {payload.Length / 1024} KB random binary data.");
            using var hashAlgorithm = HashAlgorithm.Create(hashName);
            // Digest
            var hash = hashAlgorithm.ComputeHash(payload);
            Console.WriteLine($"Hash: {hashName} {hash.Length * 8} bits / {hash.Length} BYTES");
            // Act
            EnduranceTestRunner.Run(maxIterations, () => cert.CreateSignature(hash));
        }
        internal static void RunVerify(double dataSizeInKB, int maxIterations)
        {
            var payload = TestDataGenerator.GenerateJunk((int)(dataSizeInKB * 1024));
            using var hashAlgorithm = HashAlgorithm.Create("SHA256");
            var hash = hashAlgorithm.ComputeHash(payload);
            var signature = MyConfig.SigningCertificate.CreateSignature(hash);
            X509Certificate2 verifyCertificate = MyConfig.VerifyCertificate;
            // Act
            EnduranceTestRunner.Run(maxIterations,()=> verifyCertificate.VerifySignature(hash, signature));
        }
    }
}