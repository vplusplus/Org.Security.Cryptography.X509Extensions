using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace UnitTests.POCs
{
    // REF: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider?view=netframework-4.8
    // REF: https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-store-asymmetric-keys-in-a-key-container
    // REF: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/system-cryptography-use-fips-compliant-algorithms-for-encryption-hashing-and-signing

    [TestClass]
    public class AsymmetricAlgorithmSamples
    {
        static void GenerateKeyPair(int keySizeBits, out string xmlPrivateKey, out string xmlPublicKey)
        {
            using (var provider = new RSACryptoServiceProvider(keySizeBits))
            {
                xmlPrivateKey = provider.ToXmlString(includePrivateParameters: true);
                xmlPublicKey = provider.ToXmlString(includePrivateParameters: false);
            }
        }

        [TestMethod]
        public void GenerateKayPairAndSaveAsXml()
        {
            const int KeySizeInBits = 1024;

            using (var provider = new RSACryptoServiceProvider(KeySizeInBits))
            {
                var xmlPublicAndPrivateKeys = provider.ToXmlString(includePrivateParameters: true);
                var xmlPublicKeysOnly = provider.ToXmlString(includePrivateParameters: false);

                File.WriteAllText("../../../Junk/SampleKeys.bothkeys.xml", xmlPublicAndPrivateKeys);
                File.WriteAllText("../../../Junk/SampleKeys.pubkeys.xml", xmlPublicKeysOnly);
            }
        }

        [TestMethod]
        public void SaveKeyPairToKeyContainer()
        {
            // CpsParameters pointing to key container.
            var cp = new CspParameters();
            cp.KeyContainerName = "HelloCrypto";

            // Create RSACryptoServiceProvider
            // This generates the new key and also stores the key in contaner.
            var rsa = new RSACryptoServiceProvider(cp);

            // File.WriteAllText("../../../Junk/HelloCrypto.01.xml", rsa.ToXmlString(true));
        }

        [TestMethod]
        public void GetKeyPairFromKeyContainer()
        {
            // NOTE: This code is identical to SaveKeyPairToKeyContainer()

            // CpsParameters pointing to key container.
            var cp = new CspParameters();
            cp.KeyContainerName = "HelloCrypto";

            // Create RSACryptoServiceProvider
            // This generates the new key and also stores the key in contaner.
            var rsa = new RSACryptoServiceProvider(cp);

            // File.WriteAllText("../../../Junk/HelloCrypto.02.xml", rsa.ToXmlString(true));
        }

        [TestMethod]
        public void RemoveKeyPairFromKeyContainer()
        {
            // CpsParameters pointing to key container.
            var cp = new CspParameters();
            cp.KeyContainerName = "HelloCrypto";

            // Create RSACryptoServiceProvider
            // This generates the new key and also stores the key in contaner.
            var rsa = new RSACryptoServiceProvider(cp);

            // Delete the key entry in the container.
            rsa.PersistKeyInCsp = false;

            // Call Clear to release resources and delete the key from the container.  
            rsa.Clear();
        }

        [TestMethod]
        public void RSA_PublicPrivateKey_Encryption()
        {
            // Generate a key-pair.
            GenerateKeyPair(2048, out var xmlPrivateKey, out var xmlPublicKey);

            const string TEST = "Hello world!";

            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(TEST);
            byte[] encryptedData = null;
            byte[] decryptedData = null;    

            // Encrypt using public key
            using (var rsa = new RSACryptoServiceProvider())
            {
                // Import the PUBLIC key
                rsa.FromXmlString(xmlPublicKey);

                Console.WriteLine($"KeySize: {rsa.KeySize}");
                Console.WriteLine($"PublicOnly: {rsa.PublicOnly}");

                // Encrypt using public key
                encryptedData = rsa.Encrypt(dataToEncrypt, fOAEP: true);
            }

            // Decrypt using private key
            using (var rsa = new RSACryptoServiceProvider())
            {
                // Import the PRIVATE key
                rsa.FromXmlString(xmlPrivateKey);

                Console.WriteLine($"KeySize: {rsa.KeySize}");
                Console.WriteLine($"PublicOnly: {rsa.PublicOnly}");

                // Encrypt using public key
                decryptedData = rsa.Decrypt(encryptedData, fOAEP: true);
            }

            var result = Encoding.UTF8.GetString(decryptedData);

            Console.WriteLine($"Original: {TEST}");
            Console.WriteLine($"Final: {result}");
        }

    }
}
