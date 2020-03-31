
using System;

namespace X509.EnduranceTest
{
    class Program
    {
        static void Main(string[] args)
        {
            X509.EnduranceTest.Shared.TestMain.Run();

            Console.WriteLine("Press ENTER to quit...");
            Console.ReadLine();
        }

        //static string X509Thumbprint => AppSetting("X509.Thumbprint");
        //static int SampleDataSizeKB => Convert.ToInt32(AppSetting("SampleDataSizeKB"));
        //static int LoopCount => Convert.ToInt32(AppSetting("LoopCount"));
        //static string AppSetting(string name) => ConfigurationManager.AppSettings[name] ?? throw new Exception($"AppSetting 'name' not defined.");
    }
}
