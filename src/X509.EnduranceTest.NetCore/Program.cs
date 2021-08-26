
using System;
using System.Threading.Tasks;

namespace X509.EnduranceTest
{
    class Program
    {
        async static Task Main(string[] args)
        {
            await X509.EnduranceTest.Shared.TestMain.Run();

            Console.WriteLine("Press ENTER to quit...");
            Console.ReadLine();
        }
    }
}