
using System;
using System.Diagnostics;
using System.Text;

namespace Org.Security.Cryptography
{
    internal static class MyTrace
    {
        static readonly string ME = typeof(MyTrace).Namespace;

        [Conditional("DEBUG")]
        internal static void Info(Func<string> fxMessage) => Trace.WriteLine($"{ME}: {fxMessage()}");

        internal static void Error(Exception err)
        {
            // Error messages are always written to Trace output.
            // Trace switch is NOT consulted.
            if (null != err)
            {
                // Keep the top error, to print the stack trace at the end.
                var topError = err;

                var buffer = new StringBuilder();

                // The exception chain...
                buffer.AppendLine($"ERROR: {ME} / {DateTime.UtcNow} UTC");
                while (null != err)
                {
                    buffer.AppendLine(err.Message);
                    buffer.AppendLine(err.GetType().FullName);
                    err = err.InnerException;
                }

                // Stack trac of the top level error.
                buffer.AppendLine($"Stacktrace:");
                buffer.AppendLine(topError.StackTrace);

                // Print.
                Trace.WriteLine(buffer.ToString());
            }
        }
    }
}
