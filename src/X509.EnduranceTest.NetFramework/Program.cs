
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
    }
}
