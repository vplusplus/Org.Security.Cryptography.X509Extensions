using Bogus.DataSets;
using Org.Security.Cryptography;
using System;
using UnitTests;

namespace X509.EnduranceTest.Shared
{
    internal class X509CertificateBasedDecryptorEnduranceTests
    {
        internal static void DecryptStringToBase64WithTimestamp(double dataSizeInKB,int loopCount)
        {
            var sampleData = new Lorem().Random.String2((int)(dataSizeInKB * 1024));
            Console.WriteLine($"Generated {sampleData.Length:0,#} bytes random text data.");
            var encryptor = new X509CertificateBasedEncryptor();
            var encryptonCertificate = MyConfig.EncryptionCertificate;
            var decryptonCertificate = MyConfig.DecryptionCertificate;

            var encryptedValue = encryptor.EncryptStringToBase64WithTimestamp(encryptonCertificate, sampleData);
            var decryptor = new X509CertificateBasedDecryptor();

            var result = EnduranceTestRunner.Run(loopCount,
                () => decryptor.DecryptBase64EncodedStringWithTimestampValidation(encryptedValue,(thumprint)=> decryptonCertificate, TimeSpan.FromMinutes(5)));
        }
    }
}