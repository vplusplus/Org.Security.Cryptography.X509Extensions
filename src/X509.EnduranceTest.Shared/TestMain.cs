
using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using EasyConsole;
using Org.Security.Cryptography;
using UnitTests;

namespace X509.EnduranceTest.Shared
{

    public static class TestMain
    {
        async public static Task Run()
        {
            try
            {
                await PrintOptionsAndRunTestAsync();
            }
            catch (Exception err)
            {
                ConsoleWriter.WriteRecursively(err);
            }
            Console.WriteLine("Press ENTER to quit...");
            Console.ReadLine();
        }
        async static Task PrintOptionsAndRunTestAsync()
        {
            bool canContinue= true;
            while (canContinue)
            {
                var menu = new Menu()
                    .AddSync("Print AsymmetricAlgorithm provider.", () => ConsoleWriter.PrintCSP(MyConfig.DecryptionCertificate))
                    //.AddSync("Validate Encryption/Decryption, ONCE.", () => ValidateEncryptionAndDecryptionOnce(MyConfig.DecryptionCertificate))
                    .AddSync("X509Certificate2.EncryptStream - 8KB random data 100,000 times", () => X509Certificate2ExtensionsEnduranceTests.Encryption(MyConfig.DecryptionCertificate,8, 100000))
                    .AddSync("X509Certificate2.DecryptStream - 8KB random data 100,000 times", () => X509Certificate2ExtensionsEnduranceTests.Decryption(MyConfig.DecryptionCertificate,8, 100000))
                    .AddSync("X509CertificateBasedEncryptor.EncryptStringToBase64WithTimestamp - Random 256 bytes, 100,000", () => X509CertificateBasedEncryptorEnduranceTests.EncryptStringToBase64WithTimestamp(.25, 100000))
                    .AddSync("X509CertificateBasedDecryptor.DecryptBase64EncodedStringWithTimestampValidation - Random 256 bytes, 100,000", () => X509CertificateBasedDecryptorEnduranceTests.DecryptStringToBase64WithTimestamp(.25, 100000))
                    .AddSync("X509CertificateBasedEncryptor.EncryptStringToBase64WithTimestamp - Random 1 KB, 100,000", () => X509CertificateBasedEncryptorEnduranceTests.EncryptStringToBase64WithTimestamp(1, 100000))
                    .AddSync("X509CertificateBasedDecryptor.DecryptBase64EncodedStringWithTimestampValidation - Random 1 KB, 100,000", () => X509CertificateBasedDecryptorEnduranceTests.DecryptStringToBase64WithTimestamp(1, 100000))
                    .AddSync("X509CertificateBasedEncryptor.EncryptStringToBase64WithTimestamp - Random 8KB, 100,000", () => X509CertificateBasedEncryptorEnduranceTests.EncryptStringToBase64WithTimestamp(8, 100000))
                    .AddSync("X509CertificateBasedDecryptor.DecryptBase64EncodedStringWithTimestampValidation - Random 8KB, 100,000", () => X509CertificateBasedDecryptorEnduranceTests.DecryptStringToBase64WithTimestamp(8,100000))
                    .AddSync("Exit",()=> canContinue = false);
                await menu.Display(CancellationToken.None);
            }
            
        }
           }
}