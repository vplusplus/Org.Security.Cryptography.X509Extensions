
using System;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.Security.Cryptography;
using X509.EnduranceTest.Shared;

namespace UnitTests
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
            const string TEST = "Hello World!";
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            new X509CertificateBasedEncryptor().EncryptStream(MyConfig.EncryptionCertificate, null, new MemoryStream());
            //Assert
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenTheOutputStreamParameterIsNull_ThrowArgumentNullException()
        {
            //Arrange
            const string TEST = "Hello World!";
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            new X509CertificateBasedEncryptor().EncryptStream(MyConfig.EncryptionCertificate,  new MemoryStream(),null);
            //Assert
        }
        #endregion

        #region Positive / happy scenarios
        [TestMethod]
        public void WhenItIsCalledWithProperParameters_ShouldEncrypt()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509EncryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
            var x509DecryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.pfx", MyConfig.TestCertficatePassword);
            byte[] input = Encoding.UTF8.GetBytes(TEST);
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