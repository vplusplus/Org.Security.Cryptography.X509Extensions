
# About Federal Information Processing Standard

Is this package FIPS compliant? Depends. 

### .NET Core Federal Information Processing Standard (FIPS) compliance
* [.NET Core and FIPS](https://docs.microsoft.com/en-us/dotnet/standard/security/fips-compliance)
* Does not enforce the use of FIPS Approved algorithms or key sizes in .NET Core apps.
* The developer is responsible for ensuring that non-compliant FIPS algorithms aren't used.  

### Microsoft’s approach to FIPS 140-2 validation

* [Microsoft’s approach to FIPS 140-2 validation](https://docs.microsoft.com/en-us/windows/security/threat-protection/fips-140-validation)  
* [Using Windows in a FIPS 140-2 approved mode](https://docs.microsoft.com/en-us/windows/security/threat-protection/fips-140-validation#using-windows-in-a-fips-140-2-approved-mode-of-operation)  
* [Use FIPS compliant algorithms for encryption, hashing, and signing](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/system-cryptography-use-fips-compliant-algorithms-for-encryption-hashing-and-signing)  
* [Why We’re Not Recommending FIPS Mode Anymore](https://docs.microsoft.com/en-us/archive/blogs/secguide/why-were-not-recommending-fips-mode-anymore)  

### Windows FIPS Mode
> This policy setting determines whether the TLS/SSL security provider supports only the FIPS-compliant strong cipher suite known as TLS_RSA_WITH_3DES_EDE_CBC_SHA, which means that 
> * the provider only supports the TLS protocol as a client computer and as a server, if applicable. 
> * uses only the Triple Data Encryption Standard (3DES) encryption algorithm for the TLS traffic encryption, 
> * only the Rivest-Shamir-Adleman (RSA) public key algorithm for the TLS key exchange and authentication, 
> * and only the Secure Hash Algorithm version 1 (SHA-1) hashing algorithm for the TLS hashing requirements.

## More

Credit: [AesCryptoServiceProvider and FIPS mode](https://social.msdn.microsoft.com/Forums/vstudio/en-US/521b669d-09d8-46c9-812b-843b611f42e4/aescryptoserviceprovider-and-fips-mode)

Aes algorithm (as in "the algorithm") is FIPS 140-2 compliant.
Aes algorithm implementation by Microsoft (Enhanced Cryptographic Provider in rsaenh.dll) is also FIPS 140-2 compliant.
System.Security.Cryptography.AesCryptoServiceProvider uses rsaenh.dll CSP, hence is its also FIPS 140-2 compliant.

As an example, AesManaged DOESN'T use rsaenh.dll CSP.
AesManaged checks for FIPS mode and will throw an exception is FIPS compliance is turned on.
    
Strictly speaking it's not the AesCryptoServiceProvider or AesManaged that are FIPS 140-2 compliant.
Its the underlying libraries accessed through the CAPI (like the Enhanced Cryptographic Provider in rsaenh.dll).
All other .NET CSPs, e.g. AesManaged or MD5CryptoServiceProvider, that do not rely on this libraries are not compliant.

The security policy FIPS mode simply turns on a flag in the registry, nothing more  
REF: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\fipsalgorithmpolicy)
    
The AesManaged class for example checks the flag in its constructor and 
if it's set it simply throws an exception that tells the user that this is not a FIPS compliant algorithm,
because it doesn't call into the compliant libraries.

Turning the flag in the registry ON suggestes the use of FIPS compliant algorithms.
But does not trigger any other system-side processing. 
By enabling this flag, you'll get an exception every single time an application attempts to use a non-compliant algorithm. 

Since rsaenh.dll is FIPS compliant, the AesCryptoServiceProvider will not throw such an exception. 
After all, it is only a thin wrapper around the CAPI (advapi32.dll, crypt32.dll).


