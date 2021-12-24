
using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Org.Security.Cryptography;

namespace UnitTests
{
    [TestClass]
    public class X509Certificate2_EncryptStream_DecryptStream
    {

        [TestMethod]
        public void WhenEncryptAndDecryptAreCalledWithCertsLoadedFromFiles_ShouldWork()
        {
            //Arrange
            const string TEST = "Hello World!";
            byte[] input = Encoding.UTF8.GetBytes(TEST);
            //Act
            byte[] output1 = EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(
                MyConfig.DecryptionCertificate,
                EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(MyConfig.EncryptionCertificate, input));
            //Assert
            Assert.IsTrue(input.SequenceEqual(output1));
        }
        // Ideally, it doesn't matter where from the certificate loaded as long as the X509Certificate2 object is available to tests.
        [TestMethod]
        public void X509_TripleRoundTripTest()
        {
            const string TEST = "Hello World!";

            byte[] input = Encoding.UTF8.GetBytes(TEST);
            byte[] output1 = EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(
                MyConfig.DecryptionCertificate,
                EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(MyConfig.EncryptionCertificate, input));
            byte[] output2 = EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(
                 MyConfig.DecryptionCertificate,
                 EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(MyConfig.EncryptionCertificate, input));
            byte[] output3 = EncryptionDecryptionUtils.DecryptBytesUsingExtensionMethod(
                            MyConfig.DecryptionCertificate,
                            EncryptionDecryptionUtils.EncryptBytesUsingExtensionMethod(MyConfig.EncryptionCertificate, input));

            Assert.IsTrue(input.SequenceEqual(output1));
            Assert.IsTrue(input.SequenceEqual(output2));
            Assert.IsTrue(input.SequenceEqual(output3));

            // Seeing is believing...
            Console.WriteLine($"Original: {TEST}");
            Console.WriteLine($"#1 {Encoding.UTF8.GetString(output1)}");
            Console.WriteLine($"#2 {Encoding.UTF8.GetString(output2)}");
            Console.WriteLine($"#3 {Encoding.UTF8.GetString(output3)}");
        }
    }
}

