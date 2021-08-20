using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.Security.Cryptography;
using X509.EnduranceTest.Shared;

namespace UnitTests.Decryption
{
    [TestClass]
    public class X509CertificateBasedDecryptor_DecryptBase64EncodedStringWithTimestampValidation
    {
        [TestMethod]
        public void WhenItIsCalledWithProperParameters_ShouldEncrypt()
        {
            //Arrange
            const string input = "Hello World!";
            var x509EncryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
            var x509DecryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.pfx", MyConfig.TestCertficatePassword);
            //Act
            var encryptedBase64 = new X509CertificateBasedEncryptor().EncryptStringToBase64WithTimestamp(x509EncryptionCert, input);
            var decryptedOutput = new X509CertificateBasedDecryptor().DecryptBase64EncodedStringWithTimestampValidation(
                encryptedBase64,
                thumbprint => x509DecryptionCert);
            //Assert
            Assert.IsTrue(input.Equals(decryptedOutput));
        }
    }
}

