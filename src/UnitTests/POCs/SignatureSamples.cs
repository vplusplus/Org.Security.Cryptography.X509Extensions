using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using System.Text;

namespace UnitTests.POCs
{
    // https://docs.microsoft.com/en-us/dotnet/standard/security/cryptographic-signatures

    [TestClass]
    public class SignatureSamples
    {
        // Sender
        //  Message Or payload - The substance
        //  Message Digest - A compact representation of the message
        //  Encrypt the message digest with private key to create signature.
        // 
        // Receiver:
        //  Decrypt the signature using sender's public key
        //  Hash the message or payload to recreate the message digest
        //  Compare the hashses

        // To verify that data was signed by a particular party, you must have the following information:
        // a) The public key of the party that signed the data.
        // b) The digital signature.
        // c) The data that was signed.
        // d) The hash algorithm used by the signer.

        public void HelloSignature()
        {
            string something = "Hello World";

            //The hash value to sign.
            byte[] hashValue = SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(something));

            //Generate a public/private key pair.
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            //Create an RSAPKCS1SignatureFormatter object and pass it the
            //RSACryptoServiceProvider to transfer the private key.
            RSAPKCS1SignatureFormatter rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);

            //Set the hash algorithm to SHA1.
            rsaFormatter.SetHashAlgorithm("SHA1");

            //Create a signature for hashValue and assign it to
            //signedHashValue.
            byte[] signedHashValue = rsaFormatter.CreateSignature(hashValue);

        }

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
