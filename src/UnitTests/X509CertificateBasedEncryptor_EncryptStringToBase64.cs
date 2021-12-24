using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.Security.Cryptography;
using X509.EnduranceTest.Shared;

namespace UnitTests.Encryption
{
    [TestClass]
    public class X509CertificateBasedEncryptor_EncryptStringToBase64
    {
        [TestMethod]
        public void WhenItIsCalledWithProperParameters_ShouldEncrypt()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509EncryptionCert = MyConfig.EncryptionCertificate;
            var x509DecryptionCert = MyConfig.DecryptionCertificate;
            //Act
            var encryptedBase64 = new X509CertificateBasedEncryptor().EncryptStringToBase64(x509EncryptionCert, TEST);
            var decryptedOutput = new X509CertificateBasedDecryptor().DecryptBase64EncodedString(
                encryptedBase64,
                thumbprint => x509DecryptionCert);
            //Assert
            Assert.IsTrue(TEST.Equals(decryptedOutput));
        }
        #region Encrypted contentSize tests
        [TestMethod]
        public void WhenSigleLetterAIsEncrypted_ResultSizeWillBe536()
        {
            //Arrange
            const string TEST = "A";
            var x509EncryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
            //Act
            var encryptedBase64 = new X509CertificateBasedEncryptor().EncryptStringToBase64(x509EncryptionCert, TEST);
            //Assert
            int expectedEncryptedArraySize = 776;
            Assert.AreEqual(expectedEncryptedArraySize, encryptedBase64.Length, $"Expected encrypted size for letter A is {expectedEncryptedArraySize}, but actual {encryptedBase64.Length}");
        }
        [TestMethod]
        public void WhenPersonFullNameJoyGeorgeKunjikkuruIsEncrypted_ResultSizeWillBe552()
        {
            //Arrange
            const string input = "JoyGeorgeKunjikkuru";
            var x509EncryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
            //Act
            var encryptedBase64 = new X509CertificateBasedEncryptor().EncryptStringToBase64(x509EncryptionCert, input);
            //Assert
            int expectedEncryptedArraySize = 796;
            Assert.AreEqual(expectedEncryptedArraySize, encryptedBase64.Length, $"Expected encrypted size for letter A is {expectedEncryptedArraySize}, but actual {encryptedBase64.Length}");

        }
        #endregion

    }
}

