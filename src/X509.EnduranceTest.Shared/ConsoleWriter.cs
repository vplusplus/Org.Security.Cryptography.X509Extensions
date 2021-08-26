
using System;
using System.Security.Cryptography.X509Certificates;

namespace X509.EnduranceTest.Shared
{
    class ConsoleWriter
    {
        internal static void PrintCSP(X509Certificate2 cert)
        {
            Console.WriteLine($"Cert: {cert.Subject} / {cert.Thumbprint}");
            Console.WriteLine();

            try
            {
                Console.WriteLine("cert.PublicKey.Key");
                var alg = cert.PublicKey.Key;
                Console.WriteLine(alg.GetType().FullName);
                Console.WriteLine();
            }
            catch (Exception err)
            {
                PrintErrorSummary(err);
            }

            try
            {
                // Fails in .NET Framework if -KeySpec Signature not specified.
                // Works in .NET Core
                Console.WriteLine("cert.PrivateKey");
                var alg = cert.PrivateKey;
                Console.WriteLine(alg.GetType().FullName);
                Console.WriteLine();
            }
            catch (Exception err)
            {
                PrintErrorSummary(err);
            }

            try
            {
                Console.WriteLine("cert.GetRSAPublicKey()");
                var alg = cert.GetRSAPublicKey();
                Console.WriteLine(alg.GetType().FullName);
                Console.WriteLine();
            }
            catch (Exception err)
            {
                PrintErrorSummary(err);
            }

            try
            {
                Console.WriteLine("cert.GetRSAPrivateKey()");
                var alg = cert.GetRSAPrivateKey();
                Console.WriteLine(alg.GetType().FullName);
                Console.WriteLine();
            }
            catch (Exception err)
            {
                PrintErrorSummary(err);
            }

            void PrintErrorSummary(Exception ex)
            {
                Console.WriteLine("ERROR:");
                while (null != ex)
                {
                    Console.WriteLine($"[{ex.GetType().FullName}]");
                    Console.WriteLine(ex.Message);
                    ex = ex.InnerException;
                }
            }
        }

    }
}
