
using System;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTests.Decryption
{
    [TestClass]
    public class X509CertificateBasedDecryptor_DecryptStreamWithTimestampValidation
    {
        #region Validation tests

        [TestMethod]
        [ExpectedException(typeof(Exception))]
        public void WhenDecryptionCertificateDontHavePrivateKey_ThrowException()
        {
            //Arrange
            const string inputString = "Hello World!";
            byte[] input = Encoding.UTF8.GetBytes(inputString);
            //Act
            byte[] encryptedArray = EncryptionDecryptionUtils.EncryptBytesWithTimestampUsingX509CertificateBasedEncryptor(MyConfig.EncryptionCertificate, input);
            byte[] decryptedOutput = EncryptionDecryptionUtils.DecryptBytesWithTimestampValidationUsingX509CertificateBasedDecryptor(
                encryptedArray,
                thumbprint => MyConfig.EncryptionCertificate);
            //Assert
            Assert.IsTrue(input.SequenceEqual(decryptedOutput));
        }
        #endregion

        #region Positive and happy scenarios

        [TestMethod]
        public void WhenDecryptionHappensWithinDefault1MinPeriod_ShouldDecrypt()
        {
            //Arrange
            const string TEST = "Hello World!";
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            byte[] encryptedArray = EncryptionDecryptionUtils.EncryptBytesWithTimestampUsingX509CertificateBasedEncryptor(MyConfig.EncryptionCertificate, input);
            byte[] decryptedOutput = EncryptionDecryptionUtils.DecryptBytesWithTimestampValidationUsingX509CertificateBasedDecryptor(
                encryptedArray,
                thumbprint => MyConfig.DecryptionCertificate);
            //Assert
            Assert.IsTrue(input.SequenceEqual(decryptedOutput));
        }
        
        [TestMethod]
        public void WhenDecryptionHappensBefore10SecsOfDefaultExpiry_ShouldDecrypt()
        {
            //Arrange
            const string inputString = "Hello World!";
            byte[] input = Encoding.UTF8.GetBytes(inputString);
            //Act
            byte[] encryptedArray = EncryptionDecryptionUtils.EncryptBytesWithTimestampUsingX509CertificateBasedEncryptor(MyConfig.EncryptionCertificate, input);
            Thread.Sleep(TimeSpan.FromSeconds(2));
            byte[] decryptedOutput = EncryptionDecryptionUtils.DecryptBytesWithTimestampValidationUsingX509CertificateBasedDecryptor(
                encryptedArray,
                thumbprint => MyConfig.DecryptionCertificate, TimeSpan.FromSeconds(10));
            //Assert
            Assert.IsTrue(input.SequenceEqual(decryptedOutput));
        }
        #endregion

        #region Negative and sad scenarios
        [TestMethod]
        [ExpectedException(typeof(TimeoutException))]
        public void WhenDecryptionHappensAfter1MinOfDefaultExpiry_ThrowException()
        {
            //Arrange
            const string inputString = "Hello World!";
            byte[] input = Encoding.UTF8.GetBytes(inputString);
            //Act
            byte[] encryptedArray = EncryptionDecryptionUtils.EncryptBytesWithTimestampUsingX509CertificateBasedEncryptor(MyConfig.EncryptionCertificate, input);
            Thread.Sleep(TimeSpan.FromSeconds(65));
            byte[] decryptedOutput = EncryptionDecryptionUtils.DecryptBytesWithTimestampValidationUsingX509CertificateBasedDecryptor(
                encryptedArray,
                thumbprint => MyConfig.DecryptionCertificate);
            //Assert
            Assert.IsTrue(input.SequenceEqual(decryptedOutput));
        }
        [TestMethod]
        [ExpectedException(typeof(TimeoutException))]
        public void WhenDecryptionHappensAfter10SecsOfDefaultExpiry_ThrowException()
        {
            //Arrange
            const string inputString = "Hello World!";
            byte[] input = Encoding.UTF8.GetBytes(inputString);
            //Act
            byte[] encryptedArray = EncryptionDecryptionUtils.EncryptBytesWithTimestampUsingX509CertificateBasedEncryptor(MyConfig.EncryptionCertificate, input);
            Thread.Sleep(TimeSpan.FromSeconds(12));
            byte[] decryptedOutput = EncryptionDecryptionUtils.DecryptBytesWithTimestampValidationUsingX509CertificateBasedDecryptor(
                encryptedArray,
                thumbprint => MyConfig.DecryptionCertificate,TimeSpan.FromSeconds(10));
            //Assert
            Assert.IsTrue(input.SequenceEqual(decryptedOutput));
        }
        [TestMethod]
        //[ExpectedException(typeof(TimeoutException))]
        public void WhenDecryptionPayloadDontHaveTimestamp_ThrowException()
        {
            //Arrange
            const string inputString = "Hello World!";
            byte[] input = Encoding.UTF8.GetBytes(inputString);
            bool exceptionThrown = false;
            //Act

            byte[] encryptedArray = EncryptionDecryptionUtils.EncryptBytesUsingX509CertificateBasedEncryptor(MyConfig.EncryptionCertificate, input);
            try
            {
                byte[] decryptedOutput = EncryptionDecryptionUtils.DecryptBytesWithTimestampValidationUsingX509CertificateBasedDecryptor(
                    encryptedArray,
                    thumbprint => MyConfig.DecryptionCertificate);
            }catch (ArgumentOutOfRangeException)
            {
                exceptionThrown = true;
            }
            catch(InvalidOperationException)
            {
                exceptionThrown = true;
            }
            //Assert
            Assert.IsTrue(exceptionThrown,$"Expected either {typeof(ArgumentOutOfRangeException)} or {typeof(InvalidOperationException)}");
        }
        #endregion
    }
}