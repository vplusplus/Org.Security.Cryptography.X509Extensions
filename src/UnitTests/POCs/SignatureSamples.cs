using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace UnitTests.POCs
{
    // https://docs.microsoft.com/en-us/dotnet/standard/security/cryptographic-signatures

    [TestClass]
    public class SignatureSamples
    {
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


    }
}
