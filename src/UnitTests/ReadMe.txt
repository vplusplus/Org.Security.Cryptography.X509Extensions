
//.............................................................................
// IMP: CryptographicException "Invalid provider type specified” 
//.............................................................................
// Cert.PrivateKey throws CryptographicException in .Net Framework 4.7.1 if KeySpec is not specified.
// Alternative is to use cert.GetRSAPrivateKey()
// Or use -KeySpec KeyExchange when creating self-signed-cert
// Noticed AsymmetricAlgorithm using cert.GetRSAPrivateKey() is 4x slower compared to Cert.PrivateKey


// REF: Useful info on X509 certs, cert stores and their locations.
// http://paulstovell.com/blog/x509certificate2

// REF: Comparison of Encryption algorithms
// https://symbiosisonlinepublishing.com/computer-science-technology/computerscience-information-technology32.php

// System.Security.Cryptography
// https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography?view=netstandard-2.0

//.............................................................................
// AsymmetricAlgorithm
//.............................................................................
	RSA
		RSACng
		RSACryptoServiceProvider
		RSAOpenSsl
	DSA
		DSACng
		DSACryptoServiceProvider
		DSAOpenSsl
	ECDiffieHellman
		ECDiffieHellmanCng
		ECDiffieHellmanOpenSsl
	ECDsa
		ECDsaCng
		ECDsaOpenSsl

notes: 
* X509Certificate2.PublicKey.Key and X509Certificate2.PrivateKey returns RSACng
* The RSACng class is an implementation of the RSA algorithm using the Windows CNG libraries and isn't available on operating systems other than Windows

//.............................................................................
// SymmetricAlgorithm
//.............................................................................
	Aes
		AesCng
		AesCryptoServiceProvider
		AesManaged
	TripleDES
		TripleDESCng	
		TripleDESCryptoServiceProvider
	Rijndael
		RijndaelManaged
	DES
		DESCryptoServiceProvider
	RC2
		RC2CryptoServiceProvider
			
Notes: 
* AES algorithm can support any combination of data (128 bits) and key length of 128, 192, and 256 bits. 
* The algorithm is referred to as AES-128, AES-192, or AES-256, depending on the key length.
* The Rijndael class is the predecessor of the Aes algorithm. You should use the Aes algorithm instead of Rijndael






