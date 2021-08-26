
using System;
using System.Threading.Tasks;

namespace X509.EnduranceTest
{
    class Program
    {
        static async Task Main(string[] args)
        {
            X509.EnduranceTest.Shared.TestMain.Run();

            Console.WriteLine("Press ENTER to quit...");
            Console.ReadLine();
        }
    }
}
