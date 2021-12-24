
using System;
using Org.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography.X509Certificates;

namespace UnitTests.SignAndVerify
{
    [TestClass]
    public class X509Certificate2_VerifySignature
    {
        #region Validation tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenCertificateIsNull_ThrowArgumentNullException()
        {
            //Arrange
            const string TestData = "Hello world";
            var payload = Encoding.UTF8.GetBytes(TestData);
            using var hashAlgorithm = HashAlgorithm.Create("MD5");
            var hash = hashAlgorithm.ComputeHash(payload);
            var signature = MyConfig.SigningCertificate.CreateSignature(hash);
            X509Certificate2 certificate2 = null;
            // Act
            var good = certificate2.VerifySignature(hash, signature);
            Assert.IsTrue(good);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenSignatureIsNull_ThrowArgumentNullException()
        {
            //Arrange
            const string TestData = "Hello world";
            var payload = Encoding.UTF8.GetBytes(TestData);
            using var hashAlgorithm = HashAlgorithm.Create("MD5");
            var hash = hashAlgorithm.ComputeHash(payload);
            // Act
            var good = MyConfig.VerifyCertificate.VerifySignature(hash, null);
            Assert.IsTrue(good);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenHashIsNull_ThrowArgumentNullException()
        {
            //Arrange
            const string TestData = "Hello world";
            var payload = Encoding.UTF8.GetBytes(TestData);
            using var hashAlgorithm = HashAlgorithm.Create("MD5");
            var hash = hashAlgorithm.ComputeHash(payload);
            var signature = MyConfig.SigningCertificate.CreateSignature(hash);
            // Act
            var good = MyConfig.VerifyCertificate.VerifySignature(null, signature);
            Assert.IsTrue(good);
        }
        #endregion

        #region Happy scenarios
        [TestMethod]
        public void UsingMultipleHashAlgorithms_ShouldWork()
        {
            const string TestData = "Hello world";

            var payload = Encoding.UTF8.GetBytes(TestData);

            string[] HashAlgorithmNames = { "SHA256", "SHA384", "MD5", "SHA1", "SHA512" };

            foreach (var name in HashAlgorithmNames)
            {
                using var hashAlgorithm = HashAlgorithm.Create(name);
                // Digest
                var hash = hashAlgorithm.ComputeHash(payload);
                Console.WriteLine($"Hash: {name} {hash.Length * 8} bits / {hash.Length} BYTES");

                // Sign
                var signature = MyConfig.SigningCertificate.CreateSignature(hash);
                Console.WriteLine($"Signature: {signature.Length * 8} bits / {signature.Length} BYTES");

                // Verify
                var good = MyConfig.VerifyCertificate.VerifySignature(hash, signature);
                Assert.IsTrue(good);
            }
        }
        #endregion
    }
}