
using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using X509.EnduranceTest.Shared;

namespace UnitTests.Decryption
{
    [TestClass]
    public class X509Certificate2_DecryptStream
    {
        [TestMethod]
        [ExpectedException(typeof(Exception))]
        public void WhenDecryptStreamIsCalledWithCertThatDontHavePrivateKey_ThrowException()
        {
            //Arrange
            const string TEST = "Hello World!";
            var x509CertWithoutPrivateKey = CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            byte[] output1 = EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(
                x509CertWithoutPrivateKey,
                EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(x509CertWithoutPrivateKey, input));
            //Assert
            Assert.IsTrue(input.SequenceEqual(output1));
        }

    }
}

