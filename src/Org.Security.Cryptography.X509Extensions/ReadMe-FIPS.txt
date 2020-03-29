
// Microsoft’s approach to FIPS 140-2 validation
// Using Windows in a FIPS 140-2 approved mode of operation
// REF: https://docs.microsoft.com/en-us/windows/security/threat-protection/fips-140-validation

//.....................................................................................
// Credit:
// https://social.msdn.microsoft.com/Forums/vstudio/en-US/521b669d-09d8-46c9-812b-843b611f42e4/aescryptoserviceprovider-and-fips-mode
//.....................................................................................

Abstract: 

    Aes algorithm (the algorithm) is FIPS 140-2 compliant.
    Aes algorithm implementation by Microsoft (Enhanced Cryptographic Provider in rsaenh.dll) is also FIPS 140-2 compliant.
    System.Security.Cryptography.AesCryptoServiceProvider uses rsaenh.dll CSP, hence is its also FIPS 140-2 compliant.

    AesManaged DOESN'T use rsaenh.dll CSP.
    AesManaged checks for FIPS mode and will throw an exception is FIPS compliance is turned on.

More:

    Strictly speaking it's not the AesCryptoServiceProvider or AesManaged that are FIPS 140-2 compliant.
    Its the underlying libraries accessed through the CAPI (like the Enhanced Cryptographic Provider in rsaenh.dll).
    All other .NET CSPs, e.g. AesManaged or MD5CryptoServiceProvider, that do not rely on this libraries are not compliant.

    The security policy FIPS mode simply turns on a flag in the registry, nothing more
    REF: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\fipsalgorithmpolicy)
    
    It is the responsibility of CSPs to check this flag. 
    The AesManaged class for example checks the flag in its constructor and 
    if it's set it simply throws an exception that tells the user that this is not a FIPS compliant algorithm,
    because it doesn't call into the compliant libraries.

    Turning the flag in the registry ON suggestes the use of FIPS compliant algorithms.
    But does not trigger any other system-side processing. 
    By enabling this flag, you'll get an exception every single time an application attempts to use a non-compliant algorithm. 

    Since rsaenh.dll is FIPS compliant, the AesCryptoServiceProvider will not throw such an exception. 
    After all, it is only a thin wrapper around the CAPI (advapi32.dll, crypt32.dll).


