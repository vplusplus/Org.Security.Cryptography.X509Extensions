
using System;
using System.Security.Cryptography.X509Certificates;
using UnitTests;

namespace X509.EnduranceTest.Shared
{
    internal class X509Certificate2ExtensionsEnduranceTests
    {
        internal static void Encryption(X509Certificate2 cert, int dataSizeInKB, int maxIterations)
        {
            var sampleData = TestDataGenerator.GenerateJunk(dataSizeInKB);
            Console.WriteLine($"Generated {sampleData.Length / 1024} KB random binary data.");
            var encryptedBytes = EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(cert, sampleData);
            var decryptedBytes = EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(cert, encryptedBytes);

            var result = EnduranceTestRunner.Run(maxIterations, () => EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(cert, decryptedBytes));
        }

        internal static void Decryption(X509Certificate2 cert, int dataSizeInKB, int maxIterations)
        {
            var sampleData = TestDataGenerator.GenerateJunk(dataSizeInKB);
            Console.WriteLine($"Generated {sampleData.Length / 1024} KB random binary data.");
            var encryptedBytes = EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(cert, sampleData);
            EnduranceTestRunner.Run(maxIterations, () => EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(cert, encryptedBytes));
        }
    }
}
