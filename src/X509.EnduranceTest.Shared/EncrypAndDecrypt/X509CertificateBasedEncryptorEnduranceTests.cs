using Bogus.DataSets;
using Org.Security.Cryptography;
using System;
using UnitTests;

namespace X509.EnduranceTest.Shared
{
    internal class X509CertificateBasedEncryptorEnduranceTests
    {
        internal static void EncryptStringToBase64WithTimestamp(double dataSizeInKB, int loopCount)
        {
            var sampleData = new Lorem().Random.String2((int)(dataSizeInKB * 1024));
            Console.WriteLine($"Generated {sampleData.Length:#,0} bytes random text data.");
            var encryptor = new X509CertificateBasedEncryptor();
            var encryptionCertificate = MyConfig.EncryptionCertificate;
            var result = EnduranceTestRunner.Run(loopCount,
                () => encryptor.EncryptStringToBase64WithTimestamp(encryptionCertificate, sampleData));
        }
    }
}