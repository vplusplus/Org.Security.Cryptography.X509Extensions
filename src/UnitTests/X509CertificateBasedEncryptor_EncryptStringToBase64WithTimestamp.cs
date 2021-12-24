using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.Security.Cryptography;
using System;
using System.Security.Cryptography;
using X509.EnduranceTest.Shared;

namespace UnitTests.Encryption
{
    [TestClass]
    public class X509CertificateBasedEncryptor_EncryptStringToBase64WithTimestamp
    {
        #region Validations
        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void WhenDESAlgorithmIsUsedWithDefaultKeyAndBlockSizes_ThrowCryptographicException()
        {
            //Arrange
            const string input = "Hello World!";
            var encryptedBase64 = new X509CertificateBasedEncryptor().EncryptStringToBase64WithTimestamp(MyConfig.EncryptionCertificate, input, "DES");
           
            //Assert
        }
        [TestMethod]
        public void WhenRC2AlgorithmIsUsedWithDefaultKeyAndBlockSizes_ThrowCryptographicException()
        {
            //Arrange
            //Act
            Action act =()=> new X509CertificateBasedEncryptor().EncryptStringToBase64WithTimestamp(MyConfig.EncryptionCertificate, "Hello World!", "RC2");
            act
                .Should()
                .Throw<CryptographicException>()
                .WithMessage("Specified key is not a valid size for this algorithm.");
            //Assert
        }
        [TestMethod]
        public void WhenTripleDESAlgorithmIsUsedWithDefaultKeyAndBlockSizes_ThrowCryptographicException()
        {
            //Arrange
            //Act
            Action act = () => new X509CertificateBasedEncryptor().EncryptStringToBase64WithTimestamp(MyConfig.EncryptionCertificate, "Hello World!", "TripleDES");
            act
                .Should()
                .Throw<CryptographicException>()
                .WithMessage("Specified key is not a valid size for this algorithm.");
            //Assert
        }
        #endregion

        #region Happy scenarios
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
        #endregion
    }
}

