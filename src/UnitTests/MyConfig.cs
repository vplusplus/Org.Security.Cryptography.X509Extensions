
using System;
using System.Configuration;

namespace UnitTests
{
    internal static class MyConfig
    {
        internal static string TestCertThumbPrint => 
            ConfigurationManager.AppSettings["X509.ThumbPrint"] ?? 
                throw new Exception($"AppSetting 'X509.ThumbPrint' not defined.");
    }
}
