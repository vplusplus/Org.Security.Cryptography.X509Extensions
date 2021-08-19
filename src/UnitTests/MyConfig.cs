
using System;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using X509.EnduranceTest.Shared;

namespace UnitTests
{
    internal static class MyConfig
    {
        internal static string TestCertThumbPrint => 
            ConfigurationManager.AppSettings["X509.ThumbPrint"] ?? 
                throw new Exception($"AppSetting 'X509.ThumbPrint' not defined.");
        /// <summary>
        /// Hardcoded password of test certificate files that are inside /TestCertificates folder 
        /// </summary>
        /// <remarks> Never hard code passwords in the code like this. This is just test</remarks>
        internal static string TestCertficatePassword => "MyP@ssw0rd";
        internal static X509Certificate2 EncryptionCertificate=> CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
        internal static X509Certificate2 DecryptionCertificate => CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.pfx", MyConfig.TestCertficatePassword);
        internal static X509Certificate2 VerifyCertificate => CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
        internal static X509Certificate2 SigningCertificate => CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.pfx", MyConfig.TestCertficatePassword);

    }
}
