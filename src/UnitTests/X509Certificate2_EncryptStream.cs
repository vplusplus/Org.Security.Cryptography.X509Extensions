using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using X509.EnduranceTest.Shared;
using Org.Security.Cryptography;
using System.IO;
using System;
using System.Security.Cryptography;

namespace UnitTests.Encryption
{
    [TestClass]
    public class X509Certificate2_EncryptStream
    {
        #region Validation tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenEncryptionCertificateIsNull_ThrowsArgumentNullException()
        {
            //Arrange
            X509Certificate2 certificate2 = null;
            //Act
            certificate2.EncryptStream(new MemoryStream(), new MemoryStream());
            //Assert
        }
        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void WhenEncryptionCertificateIsNotLoaded_ThrowsArgumentNullException()
        {
            //Arrange
            X509Certificate2 certificate2 = new X509Certificate2();
            //Act
            certificate2.EncryptStream(new MemoryStream(), new MemoryStream());
            //Assert
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenInputStreamIsNull_ThrowsArgumentNullException()
        {
            //Arrange
            //Act
            MyConfig.EncryptionCertificate.EncryptStream(null, new MemoryStream());
            //Assert
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenOutputStreamIsNull_ThrowsArgumentNullException()
        {
            //Arrange
            //Act
            MyConfig.EncryptionCertificate.EncryptStream( new MemoryStream(),null);
            //Assert
        }
        #endregion

        #region Encrypted contentSize tests
        [TestMethod]
        public void WhenSigleLetterAIsEncrypted_ResultSizeWillBe536()
        {
            //Arrange
            const string sampleData = "A";
            var x509EncryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
            byte[] input = Encoding.UTF8.GetBytes(sampleData);
            //Act
            byte[] output1 = EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(x509EncryptionCert, input);
            //Assert
            int expectedEncryptedArraySize = 536;
            Assert.AreEqual(expectedEncryptedArraySize, output1.Length, $"Expected encrypted size for letter A is {expectedEncryptedArraySize}, but actual {output1.Length}");
        }

        [TestMethod]
        public void WhenPersonFullNameJoyGeorgeKunjikkuruIsEncrypted_ResultSizeWillBe552()
        {
            //Arrange
            const string fullName = "JoyGeorgeKunjikkuru";
            var x509EncryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
            byte[] input = Encoding.UTF8.GetBytes(fullName);
            //Act
            byte[] output1 = EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(x509EncryptionCert, input);
            //Assert
            int expectedEncryptedArraySize = 552;
            Assert.AreEqual(expectedEncryptedArraySize, output1.Length, $"Expected encrypted size for letter A is {expectedEncryptedArraySize}, but actual {output1.Length}");
        }
        [TestMethod]
        public void When8KBIsEncrypted_ResultSizeWillBe8728()
        {
            //Arrange
            const int SampleDataSizeInKB = 8;
            var x509EncryptionCert = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
            var inputArray = TestDataGenerator.GenerateJunk(SampleDataSizeInKB);
            //Act
            byte[] output1 = EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(x509EncryptionCert, inputArray);
            //Assert
            int expectedEncryptedArraySize = 8728;
            Assert.AreEqual(expectedEncryptedArraySize, output1.Length, $"Expected encrypted size for letter A is {expectedEncryptedArraySize}, but actual {output1.Length}");
        }
        #endregion
    }
}

