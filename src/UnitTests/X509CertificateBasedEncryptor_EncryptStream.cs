
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.Security.Cryptography;
using X509.EnduranceTest.Shared;

namespace UnitTests.Encryption
{
    [TestClass]
    public class X509CertificateBasedEncryptor_EncryptStream
    {
        #region Validations
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenEncryptionCertificateParameterIsNull_ThrowArgumentNullException()
        {
            //Arrange
            //Act
            new X509CertificateBasedEncryptor().EncryptStream(null, new MemoryStream(), new MemoryStream());
            //Assert
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenTheInputStreamParameterIsNull_ThrowArgumentNullException()
        {
            //Arrange
            //Act
            new X509CertificateBasedEncryptor().EncryptStream(MyConfig.EncryptionCertificate, null, new MemoryStream());
            //Assert
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenTheOutputStreamParameterIsNull_ThrowArgumentNullException()
        {
            //Arrange
            //Act
            new X509CertificateBasedEncryptor().EncryptStream(MyConfig.EncryptionCertificate,  new MemoryStream(),null);
            //Assert
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenTheDataEncryptionAlgorithmNameIsNull_ThrowArgumentNullException()
        {
            //Arrange
            //Act
            new X509CertificateBasedEncryptor().EncryptStream(MyConfig.EncryptionCertificate, new MemoryStream(), new MemoryStream(),null);
            //Assert
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenTheDataEncryptionAlgorithmNameIsWhiteSpace_ThrowArgumentNullException()
        {
            //Arrange
            //Act
            new X509CertificateBasedEncryptor().EncryptStream(MyConfig.EncryptionCertificate, new MemoryStream(), new MemoryStream(), " ");
            //Assert
        }
        [TestMethod]
        public void WhenTheDataEncryptionAlgorithmNameIsUnknown_ThrowCryptographicException()
        {
            //Arrange
            Action act= () => new X509CertificateBasedEncryptor().EncryptStream(MyConfig.EncryptionCertificate, new MemoryStream(), new MemoryStream(), "MyAlgo");
            //Act
            act
                .Should()
                .Throw<CryptographicException>()
                .WithMessage("Not able to create Symmetric Data Encryption Algorithm using MyAlgo");
            //Assert
        }
        #endregion

        #region Positive / happy scenarios
        [TestMethod]
        public void WhenItIsCalledWithProperParameters_ShouldEncryptAndDecrypt()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509EncryptionCert = MyConfig.EncryptionCertificate;
            var x509DecryptionCert = MyConfig.DecryptionCertificate; byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            byte[] encryptedArray = EncryptionDecryptionUtils.EncryptBytesUsingX509CertificateBasedEncryptor(x509EncryptionCert, input);
            byte[] decryptedOutput = EncryptionDecryptionUtils.DecryptBytesUsingX509CertificateBasedDecryptor(
                encryptedArray,
                thumbprint => x509DecryptionCert);
            //Assert
            Assert.IsTrue(input.SequenceEqual(decryptedOutput));
        }
        #endregion
    }
}