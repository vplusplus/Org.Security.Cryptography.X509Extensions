
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;

namespace Org.Security.Cryptography
{
    internal static class MyTrace
    {
        // Trace switch name: Org.Security.Cryptography
        static readonly string MyName = typeof(MyTrace).Namespace;

        // Making TraceSwitch update-able, because of the .Net core MESS (I meant, one of the .Net core messes)
        // .Net core applications WILL NOT honor TraceSwitch in config files.
        // Use X509Extensions.TraceLevel property
        internal static TraceSwitch MyTraceSwitch { get; set; } = new TraceSwitch(MyName, MyName, $"{TraceLevel.Warning}");

        [Conditional("DEBUG")]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Entering([CallerMemberName] string memberName = "") => WriteIf(MyTraceSwitch.TraceVerbose, () => $"--> {memberName}()");

        [Conditional("DEBUG")]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Verbose(Func<string> fxMessage) => WriteIf(MyTraceSwitch.TraceVerbose, fxMessage);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Info(Func<string> fxMessage) => WriteIf(MyTraceSwitch.TraceInfo, fxMessage);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Warn(Func<string> fxMessage) => WriteIf(MyTraceSwitch.TraceWarning, fxMessage);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Error(Func<string> fxMessage) => Write(fxMessage);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static void WriteIf(bool condition, Func<string> fxMessage)
        {
            if (condition) Trace.WriteLine($"{MyName}: {fxMessage()}");
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static void Write(Func<string> fxMessage)
        {
            Trace.WriteLine($"{MyName}: {fxMessage()}");
        }

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
                buffer.AppendLine($"{MyName}: An error occured at {DateTime.UtcNow} UTC");
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
