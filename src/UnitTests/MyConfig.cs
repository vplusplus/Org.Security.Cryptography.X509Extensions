
using System;
using System.Configuration;

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
    }
}
