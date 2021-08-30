
using System;
using System.Threading;
using System.Threading.Tasks;
using X509.EnduranceTest.Shared;

namespace X509.EnduranceTest
{
    class Program
    {
        static async Task Main(string[] args)
        {
            await new TestProgram().Run(CancellationToken.None);
            //await X509.EnduranceTest.Shared.TestMain.Run();
        }
    }
}
