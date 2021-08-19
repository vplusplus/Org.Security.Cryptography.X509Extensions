using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.Security.Cryptography;
using X509.EnduranceTest.Shared;

namespace UnitTests
{
    [TestClass]
    public class X509CertificateBasedEncryptor_EncryptStringToBase64EncodedString
    {
        [TestMethod]
        public void WhenItIsCalledWithProperParameters_ShouldEncrypt()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509EncryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
            var x509DecryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.pfx", MyConfig.TestCertficatePassword);
            //Act
           var encryptedBase64 = new X509CertificateBasedEncryptor().EncryptStringToBase64EncodedString(x509EncryptionCert, TEST);
            var decryptedOutput = new X509CertificateBasedDecryptor().DecryptBase64EncodedString(
                encryptedBase64,
                thumbprint => x509DecryptionCert);
            //Assert
            Assert.IsTrue(TEST.Equals(decryptedOutput));
        }
    }
}

