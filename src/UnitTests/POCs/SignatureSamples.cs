
using System;
using Org.Security.Cryptography;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTests.POCs
{
    // https://docs.microsoft.com/en-us/dotnet/standard/security/cryptographic-signatures

    // WIP WIP WIP 

    [TestClass]
    public class SignatureSamples
    {
        [TestMethod]
        public void TestSignature()
        {
            const string CertThumbPrint = "2E3257EE8FC8A72DB3778DFB3F9EDC7D0A9D66C7";
            const string TEST = "Hello world";

            var payload = Encoding.UTF8.GetBytes(TEST);

            var signature = X509RsaSha1Signature.Sign(payload, CertThumbPrint);
            var good = X509RsaSha1Signature.Verify(payload, signature, CertThumbPrint);
            Assert.IsTrue(good);

            signature = X509RsaSha1Signature.Sign(payload, CertThumbPrint);
            good = X509RsaSha1Signature.Verify(payload, signature, CertThumbPrint);
            Assert.IsTrue(good);

        }
    }

    static class X509RsaSha1Signature
    {
        const string SHA1 = "SHA1";

        public static byte[] Sign(byte[] payload, string thumbprint)
        {
            X509Certificate2 cert = X509CertificateCache.GetCertificate(thumbprint);

            var rsa = cert.PrivateKey;

            using (var sha = HashAlgorithm.Create(SHA1)) 
            {
                byte[] digest = sha.ComputeHash(payload);

                var signatureFormatter = new RSAPKCS1SignatureFormatter(rsa);
                signatureFormatter.SetHashAlgorithm(SHA1);

                byte[] signature = signatureFormatter.CreateSignature(digest);
                return signature;
            }
        }

        public static bool Verify(byte[] payload, byte[] signature, string thumbprint)
        {
            X509Certificate2 cert = X509CertificateCache.GetCertificate(thumbprint);

            var rsa = cert.PublicKey.Key;

            using (var sha = HashAlgorithm.Create(SHA1))
            {
                byte[] digest = sha.ComputeHash(payload);

                var signatureDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                signatureDeformatter.SetHashAlgorithm(SHA1);

                return signatureDeformatter.VerifySignature(digest, signature);
            }
        }
    }
}
