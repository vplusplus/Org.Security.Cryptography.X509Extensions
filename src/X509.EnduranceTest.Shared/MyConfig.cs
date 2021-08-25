
using System;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using X509.EnduranceTest.Shared;

namespace UnitTests
{
    public static class MyConfig
    {
        internal static string TestCertThumbPrint => 
            ConfigurationManager.AppSettings["X509.ThumbPrint"] ?? 
                throw new Exception($"AppSetting 'X509.ThumbPrint' not defined.");
        /// <summary>
        /// Hardcoded password of test certificate files that are inside /TestCertificates folder 
        /// </summary>
        /// <remarks> Never hard code passwords in the code like this. This is just test</remarks>
        internal static string TestCertficatePassword => "MyP@ssw0rd";
        /// <summary>
        /// TODO: Below certificates expire on 2023-08-17. Need to recreate certificate then to continue using this test project
        /// </summary>
        public static X509Certificate2 EncryptionCertificate=> CertificateLoader.LoadFromFile(ConfigurationManager.AppSettings["EncryptionCertificatePath"]);
        public static X509Certificate2 DecryptionCertificate => CertificateLoader.LoadFromFile(ConfigurationManager.AppSettings["DecryptionCertificatePath"], MyConfig.TestCertficatePassword);
        public static X509Certificate2 VerifyCertificate => CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.cer");
        public static X509Certificate2 SigningCertificate => CertificateLoader.LoadFromFile("TestCertificates/hello.world.2048.net.pfx", MyConfig.TestCertficatePassword);

    }
}
