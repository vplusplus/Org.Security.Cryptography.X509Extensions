
using System;
using System.Configuration;

namespace UnitTests
{
    internal static class MyConfigForEnduranceTests 
    {
        internal static int SampleDataSizeKB => Convert.ToInt32(AppSetting("SampleDataSizeKB"));

        static string AppSetting(string name) => ConfigurationManager.AppSettings[name] ?? throw new Exception($"AppSetting 'name' not defined.");

    }
}
