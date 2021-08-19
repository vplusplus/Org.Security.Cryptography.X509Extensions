using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.Security.Cryptography;
using X509.EnduranceTest.Shared;

namespace UnitTests
{
    [TestClass]
    public class X509CertificateBasedEncryptor_EncryptStreamWithTimestamp
    {
       
        #region Encrypted contentSize tests
        [TestMethod]
        public void WhenSigleLetterAIsEncrypted_ResultSizeWillBe536()
        {
            //Arrange
            const string TEST = "A";
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            byte[] encryptedArray = EncryptionDecryptionUtils.EncryptBytesWithTimestampUsingX509CertificateBasedEncryptor(MyConfig.EncryptionCertificate, input);
            //Assert
            int expectedEncryptedArraySize = 840;
            Assert.AreEqual(expectedEncryptedArraySize, encryptedArray.Length, 
                $"Expected encrypted size for letter A is {expectedEncryptedArraySize}, but actual {encryptedArray.Length}");
        }
        [TestMethod]
        public void WhenPersonFullNameJoyGeorgeKunjikkuruIsEncrypted_ResultSizeWillBe552()
        {
            //Arrange
            const string TEST = "JoyGeorgeKunjikkuru";
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            byte[] encryptedArray = EncryptionDecryptionUtils.EncryptBytesWithTimestampUsingX509CertificateBasedEncryptor(MyConfig.EncryptionCertificate, input);
            //Assert
            int expectedEncryptedArraySize = 856;
            Assert.AreEqual(expectedEncryptedArraySize, encryptedArray.Length,
                $"Expected encrypted size for letter A is {expectedEncryptedArraySize}, but actual {encryptedArray.Length}");
        }
        #endregion
    }
}