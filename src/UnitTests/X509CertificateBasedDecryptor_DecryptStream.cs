
using System;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.Security.Cryptography;
using X509.EnduranceTest.Shared;

namespace UnitTests.Decryption
{
    [TestClass]
    public class X509CertificateBasedDecryptor_DecryptStream
    {
        #region Validation tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenTheInputStreamParameterIsNull_ThrowArgumentNullException()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509EncryptionCert = MyConfig.EncryptionCertificate;
            var x509DecryptionCert = MyConfig.DecryptionCertificate;
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            new X509CertificateBasedDecryptor().DecryptStream(null, new MemoryStream(),              
                thumbprint => MyConfig.DecryptionCertificate);
            //Assert
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenTheOutputStreamParameterIsNull_ThrowArgumentNullException()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509EncryptionCert = MyConfig.EncryptionCertificate;
            var x509DecryptionCert = MyConfig.DecryptionCertificate;
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            new X509CertificateBasedDecryptor().DecryptStream( new MemoryStream(), null,
                thumbprint => MyConfig.DecryptionCertificate);
            //Assert
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenTheDataEncryptionAlgorithmNameParameterIsNull_ThrowArgumentNullException()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509EncryptionCert = MyConfig.EncryptionCertificate;
            var x509DecryptionCert = MyConfig.DecryptionCertificate;
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            new X509CertificateBasedDecryptor().DecryptStream(
                new MemoryStream(), 
                new MemoryStream(),
                thumbprint => MyConfig.DecryptionCertificate,
                null);
            //Assert
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenTheCertificateSelectorParamIsNull_ThrowArgumentNullException()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509EncryptionCert = MyConfig.EncryptionCertificate;
            var x509DecryptionCert = MyConfig.DecryptionCertificate;
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            byte[] encryptedArray = EncryptionDecryptionUtils.EncryptBytesUsingX509CertificateBasedEncryptor(x509EncryptionCert, input);
            byte[] decryptedOutput = EncryptionDecryptionUtils.DecryptBytesUsingX509CertificateBasedDecryptor(
                encryptedArray,
                null);
            //Assert
            Assert.IsTrue(input.SequenceEqual(decryptedOutput));
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenTheDecryptionCertificateIsNull_ThrowArgumentNullException()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509EncryptionCert = MyConfig.EncryptionCertificate;
            var x509DecryptionCert = MyConfig.DecryptionCertificate;
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            byte[] encryptedArray = EncryptionDecryptionUtils.EncryptBytesUsingX509CertificateBasedEncryptor(x509EncryptionCert, input);
            byte[] decryptedOutput = EncryptionDecryptionUtils.DecryptBytesUsingX509CertificateBasedDecryptor(
                encryptedArray,
                thumbprint => null);
            //Assert
            Assert.IsTrue(input.SequenceEqual(decryptedOutput));
        }
        #endregion
    }
}