using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.Security.Cryptography;
using X509.EnduranceTest.Shared;

namespace UnitTests.Encryption
{
    [TestClass]
    public class X509CertificateBasedEncryptor_EncryptStringToBase64WithTimestamp
    {
        [TestMethod]
        public void WhenItIsCalledWithProperParameters_ShouldEncrypt()
        {
            //Arrange
            const string input = "Hello World!";
            var x509EncryptionCert = MyConfig.EncryptionCertificate;
            var x509DecryptionCert = MyConfig.DecryptionCertificate;
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

