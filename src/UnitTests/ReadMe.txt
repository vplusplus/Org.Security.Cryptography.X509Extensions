

//...............................................................................
// Creating a Cryptographic Scheme
// REF: https://docs.microsoft.com/en-us/dotnet/standard/security/creating-a-cryptographic-scheme
//...............................................................................
// A simple cryptographic scheme for encrypting and decrypting data might specify the following steps:
// 1) Each party generates a public/private key pair.
// 2) The parties exchange their public keys.
// 3) Each party generates a secret key for TripleDES encryption, for example, and encrypts the newly created key using the other's public key.
// 4) Each party sends the data to the other and combines the other's secret key with its own, in a particular order, to create a new secret key.
// 5) The parties then initiate a conversation using symmetric encryption.
//...............................................................................


// REF: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider?view=netframework-4.8
// REF: https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-store-asymmetric-keys-in-a-key-container
// REF: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/system-cryptography-use-fips-compliant-algorithms-for-encryption-hashing-and-signing

// REF: Useful info on X509 certs, cert stores and their locations.
// http://paulstovell.com/blog/x509certificate2

// REF: Comparison of Encryption algorithms
// https://symbiosisonlinepublishing.com/computer-science-technology/computerscience-information-technology32.php

Symmetric
Block Ciphers:	AES/RijndaelManaged, DES, 3DES
Stream Ciphers:	RC4, SEAL

Asymmetric			
RSA, DSA, Diffe-Hellman

AES algorithm can support any combination of data (128 bits) and key length of 128, 192, and 256 bits. 
The algorithm is referred to as AES-128, AES-192, or AES-256, depending on the key length.

