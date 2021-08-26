
using System;
using System.Diagnostics;

namespace X509.EnduranceTest.Shared
{
    internal class EnduranceTestRunner
    {
        internal static EnduranceTestResult BeginLoop( int maxIterations, Action actionToTest)
        {
            Console.WriteLine($"MaxIterations: {maxIterations:#,0}");

            var counter = 0;
            var elapsed = Stopwatch.StartNew();
            var statusUpdateInterval = TimeSpan.FromSeconds(2);
            var nextStatusUpdate = DateTime.Now.Add(statusUpdateInterval);

            var rate = 0.0;

            while (counter++ <= maxIterations)
            {
                actionToTest();
                if (nextStatusUpdate < DateTime.Now)
                {
                    rate = counter / elapsed.Elapsed.TotalSeconds;
                    Console.WriteLine($"{elapsed.Elapsed:hh\\:mm\\:ss} @ {rate:#,0} per-sec. Iterations: {counter:#,0} (Use Ctrl-C to quit...)");
                    nextStatusUpdate = DateTime.Now.Add(statusUpdateInterval);
                }
            }
            rate = counter / elapsed.Elapsed.TotalSeconds;
            Console.WriteLine("Finished.");
            Console.WriteLine($"{elapsed.Elapsed:hh\\:mm\\:ss} @ {rate:#,0} per-sec. Iterations: {counter:#,0} (Use Ctrl-C to quit...)");
            return new EnduranceTestResult(elapsed.Elapsed,rate,counter);
        }
    }
    public record EnduranceTestResult (TimeSpan Elapsed,double iteractionsPerSecond, int iterationsCompleted);
}

namespace System.Runtime.CompilerServices
{
}