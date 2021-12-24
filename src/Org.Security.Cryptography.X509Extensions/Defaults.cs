using System;

namespace Org.Security.Cryptography
{
    internal static class Defaults
    {
        internal const string DEF_DataEncryptionAlgorithmName = "Aes";
        internal const int DEF_KeySize = 256;
        internal const int DEF_BlockSize = 128;
        internal static readonly TimeSpan EncyptedPayloadTimeSpan = TimeSpan.FromMinutes(1);
    }
}
