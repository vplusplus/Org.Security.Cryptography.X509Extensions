using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.Security.Cryptography;
using System;
using System.Security.Cryptography;
using X509.EnduranceTest.Shared;

namespace UnitTests.Decryption
{
    [TestClass]
    public class X509CertificateBasedDecryptor_DecryptBase64EncodedStringWithTimestampValidation
    {

        #region Validations

        #endregion

        #region Happy scenarios
        [TestMethod]
        public void WhenItIsCalledWithProperParameters_ShouldWork()
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
        [TestMethod]
        public void WhenDESAlgorithmIsUsed_ShouldWork()
        {
            //Arrange
            const string input = "Hello World!";
            var x509EncryptionCert = MyConfig.EncryptionCertificate;
            var x509DecryptionCert = MyConfig.DecryptionCertificate;
            //Act
            var encryptedBase64 = new X509CertificateBasedEncryptor().EncryptStringToBase64WithTimestamp(x509EncryptionCert, input, "DES", 64, 64);
            var decryptedOutput = new X509CertificateBasedDecryptor().DecryptBase64EncodedStringWithTimestampValidation(
                encryptedBase64,
                thumbprint => x509DecryptionCert, TimeSpan.FromMinutes(1), "DES");
            //Assert
            Assert.IsTrue(input.Equals(decryptedOutput));
        }
        [TestMethod]
        public void WhenRijndaelAlgorithmIsUsedWithDefaultKeyAndBlockSizes_ShouldEncryptAndDecryt()
        {
            //Arrange
            string DataEncryptionAlgorithmName = "Rijndael";
            var encryptedBase64 = new X509CertificateBasedEncryptor().EncryptStringToBase64WithTimestamp(MyConfig.EncryptionCertificate, "Hello World!", DataEncryptionAlgorithmName);

            //Act
            var decryptedOutput = new X509CertificateBasedDecryptor().DecryptBase64EncodedStringWithTimestampValidation(
                encryptedBase64,
                thumbprint => MyConfig.DecryptionCertificate, TimeSpan.FromMinutes(1), DataEncryptionAlgorithmName);
            //Assert
        }
        #endregion
    }
}

