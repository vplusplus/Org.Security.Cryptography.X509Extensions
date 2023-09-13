
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using EasyConsole;
using UnitTests;

namespace X509.EnduranceTest.Shared
{
    internal class EncryptionDecryptionMenuPage:MenuPage
    {
        public EncryptionDecryptionMenuPage(TestProgram program) : base("EncryptionDecryption", program)
        {
            this.Menu.AddSync("Print AsymmetricAlgorithm provider.", () => ConsoleWriter.PrintCSP(MyConfig.DecryptionCertificate));
            this.Menu.AddSync("Validate Encryption/Decryption, ONCE.", () => ValidateEncryptionAndDecryptionOnce(MyConfig.DecryptionCertificate));
            this.Menu.AddSync("X509Certificate2.EncryptStream - 8KB random data 100,000 times", () => X509Certificate2ExtensionsEnduranceTests.Encryption(MyConfig.DecryptionCertificate, 8, 100000));
            this.Menu.AddSync("X509Certificate2.DecryptStream - 8KB random data 100,000 times", () => X509Certificate2ExtensionsEnduranceTests.Decryption(MyConfig.DecryptionCertificate, 8, 100000));
            this.Menu.AddSync("X509CertificateBasedEncryptor.EncryptStringToBase64WithTimestamp - Random 256 bytes, 100,000", () => X509CertificateBasedEncryptorEnduranceTests.EncryptStringToBase64WithTimestamp(.25, 100000));
            this.Menu.AddSync("X509CertificateBasedDecryptor.DecryptBase64EncodedStringWithTimestampValidation - Random 256 bytes, 100,000", () => X509CertificateBasedDecryptorEnduranceTests.DecryptStringToBase64WithTimestamp(.25, 100000));
            this.Menu.AddSync("X509CertificateBasedEncryptor.EncryptStringToBase64WithTimestamp - Random 1 KB, 100,000", () => X509CertificateBasedEncryptorEnduranceTests.EncryptStringToBase64WithTimestamp(1, 100000));
            this.Menu.AddSync("X509CertificateBasedDecryptor.DecryptBase64EncodedStringWithTimestampValidation - Random 1 KB, 100,000", () => X509CertificateBasedDecryptorEnduranceTests.DecryptStringToBase64WithTimestamp(1, 100000));
            this.Menu.AddSync("X509CertificateBasedEncryptor.EncryptStringToBase64WithTimestamp - Random 8KB, 100,000", () => X509CertificateBasedEncryptorEnduranceTests.EncryptStringToBase64WithTimestamp(8, 100000));
            this.Menu.AddSync("X509CertificateBasedDecryptor.DecryptBase64EncodedStringWithTimestampValidation - Random 8KB, 100,000", () => X509CertificateBasedDecryptorEnduranceTests.DecryptStringToBase64WithTimestamp(8, 100000));
        }
        public async  override Task Display(CancellationToken cancellationToken)
        {
            await base.Display(cancellationToken);
            Input.ReadString("Press any key to continue");
            await this.Program.NavigateTo<EncryptionDecryptionMenuPage>(cancellationToken);
        }
        internal static void ValidateEncryptionAndDecryptionOnce(X509Certificate2 cert)
        {
            var sampleData = TestDataGenerator.GenerateJunk(MyConfigForEnduranceTests.SampleDataSizeKB);
            Console.WriteLine($"Generated {sampleData.Length / 1024} KB random binary data.");

            // Encrypt/Decrypt ONCE...
            var encryptedBytes = EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(cert, sampleData);
            var decryptedBytes = EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(cert, encryptedBytes);
            Console.WriteLine($"SampleData: {sampleData.Length:#,0} bytes");
            Console.WriteLine($"Encrypted:  {encryptedBytes.Length:#,0} bytes");
            Console.WriteLine($"Decrypted:  {decryptedBytes.Length:#,0} bytes");

            // Vallidate
            var good = sampleData.SequenceEqual(decryptedBytes);
            if (!good) throw new Exception("Decrypted result doesn't match original data.");
        }

    }
}