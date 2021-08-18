# Org.Security.Cryptography.X509Extensions
`X509Certificate2` Extensions for Encrypting and Signing using X509 certs.

# Getting started

- Clone or download the repo
- Compile Org.Security.Cryptography.X509Extensions.csproj to get the assembly.
- Refer the assembly in your project.

## Usage (Encryption)

 ```C#
     var x509Certificate = GetCertificateUsingYourWay(); // This certificate doesn't need to have private key.
     Stream yourStreamToEncrypt = GetYourStreamToEncrypt();
     var encryptedStream = new MemoryStream();
     x509Certificate.EncryptStream(yourStreamToEncrypt,encryptedStream);  
 ```
    
## Usage (Decryption)
 
 ```C#
     var x509Certificate = GetCertificateWithPrivateKeyUsingYourWay();
     Stream yourStreamToDecrypt = GetYourStreamToDecrypt();
     var decryptedStream = new MemoryStream();
     x509Certificate.DecryptStream(yourStreamToDecrypt, decryptedStream);  
 ```
