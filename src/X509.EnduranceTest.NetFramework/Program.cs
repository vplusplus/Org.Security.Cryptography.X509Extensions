
using System;
using System.Threading.Tasks;

namespace X509.EnduranceTest
{
    class Program
    {
        static async Task Main(string[] args)
        {
            await X509.EnduranceTest.Shared.TestMain.Run();
        }
    }
}
