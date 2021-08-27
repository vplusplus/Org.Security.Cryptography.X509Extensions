using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Org.Security.Cryptography
{
    
    class Validator
    {
        internal static void ValidateParametersAndThrowException(X509Certificate2 x509Cert, Stream inputStream, Stream outputStream, string dataEncryptionAlgorithmName)
        {
            if (null == x509Cert) throw new ArgumentNullException(nameof(x509Cert));
            if (null == inputStream) throw new ArgumentNullException(nameof(inputStream));
            if (null == outputStream) throw new ArgumentNullException(nameof(outputStream));
            if (string.IsNullOrWhiteSpace(dataEncryptionAlgorithmName)) throw new ArgumentNullException(nameof(dataEncryptionAlgorithmName));
        }
       
    }
}