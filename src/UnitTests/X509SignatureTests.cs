
using System;
using Org.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTests.Signature
{
    [TestClass]
    public class X509SignatureTests
    {
        [TestMethod]
        public void TestSignature()
        {
            const string TestData = "Hello world";

            var payload = Encoding.UTF8.GetBytes(TestData);

            string[] HashAlgorithmNames = { "MD5", "SHA1", "SHA256", "SHA384", "SHA512" };

            foreach (var name in HashAlgorithmNames)
            {
                using (var hashAlgorithm = HashAlgorithm.Create(name))
                {
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
        }
    }
}