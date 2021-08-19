
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
    public class X509CertificateBasedDecryptor_DecryptStream
    {
        #region Validation tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenTheInputStreamParameterIsNull_ThrowArgumentNullException()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509EncryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
            var x509DecryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.pfx", MyConfig.TestCertficatePassword);
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            new X509CertificateBasedDecryptor().DecryptStream(null, new MemoryStream(),              
                thumbprint => null);
            //Assert
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenTheDecryptionCertificateIsNull_ThrowArgumentNullException()
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
                thumbprint => null);
            //Assert
            Assert.IsTrue(input.SequenceEqual(decryptedOutput));
        }
        #endregion
    }
}