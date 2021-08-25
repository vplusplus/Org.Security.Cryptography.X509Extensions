using System;
using System.Security.Cryptography.X509Certificates;

namespace X509.EnduranceTest.Shared
{
    public class CertificateLoader
    {
        public static X509Certificate2 LoadFromFile(string filePath)
        {
            return new X509Certificate2(X509Certificate2.CreateFromCertFile(filePath));
        }
        public static X509Certificate2 LoadFromFile(string filePath,string password)
        {
            var cert = new X509Certificate2(filePath, password, X509KeyStorageFlags.PersistKeySet);
            if (null == cert) throw new NullReferenceException($"Certificate not found at {filePath}");
            return cert;
        }
    }
}
