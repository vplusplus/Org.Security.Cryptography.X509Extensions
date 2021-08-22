
using System;
using Org.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography.X509Certificates;

namespace UnitTests.SignAndVerify
{
    [TestClass]
    public class X509Certificate2_CreateSignature
    {
        #region Validation tests
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenCertificateIsNull_ThrowArgumentNullException()
        {
            //arrange
            const string TestData = "Hello world";
            var payload = Encoding.UTF8.GetBytes(TestData);
            X509Certificate2 certificate2 = null;
            //Act
            using (var hashAlgorithm = HashAlgorithm.Create("MD5"))
            {
                var hash = hashAlgorithm.ComputeHash(payload);
                certificate2.CreateSignature(hash);
            }
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void WhenPayloadIsNull_ThrowArgumentNullException()
        {
            //arrange
            //Act
            using (var hashAlgorithm = HashAlgorithm.Create("MD5"))
            {
                MyConfig.SigningCertificate.CreateSignature(null);
            }
        }
        #endregion
    }
}