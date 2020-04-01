
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Org.Security.Cryptography
{
    public static class X509SignatureExtensions
    {
        public static byte[] CreateSignature(this X509Certificate2 x509Cert, byte[] hash)
        {
            if (null == x509Cert) throw new ArgumentNullException(nameof(x509Cert));
            if (null == hash) throw new ArgumentNullException(nameof(hash));

            var asymmetricAlgorithm = x509Cert.GetRsaPrivateKeyAsymmetricAlgorithm();
            var hashAlgorithmName = InferHashAlgorithm(hash);

            var formatter = new RSAPKCS1SignatureFormatter(asymmetricAlgorithm);
            formatter.SetHashAlgorithm(hashAlgorithmName);

            return formatter.CreateSignature(hash);
        }

        public static bool VerifySignature(this X509Certificate2 x509Cert, byte[] hash, byte[] signature)
        {
            if (null == x509Cert) throw new ArgumentNullException(nameof(x509Cert));
            if (null == hash) throw new ArgumentNullException(nameof(hash));
            if (null == signature) throw new ArgumentNullException(nameof(signature));

            var asymmetricAlgorithm = x509Cert.GetRsaPublicKeyAsymmetricAlgorithm();
            var hashAlgorithmName = InferHashAlgorithm(hash);

            var formatter = new RSAPKCS1SignatureDeformatter(asymmetricAlgorithm);
            formatter.SetHashAlgorithm(hashAlgorithmName);

            return formatter.VerifySignature(hash, signature);
        }

        static string InferHashAlgorithm(byte[] hash)
        {
            if (null == hash) throw new ArgumentNullException(nameof(hash));

            // MD5      128 bit / 16 bytes
            // SHA1     160 bit / 20 bytes
            // SHA224   224 bit / 28 bytes
            // SHA265   256 bit / 32 bytes
            // SHA384   384 bit / 48 bytes
            // SHA512   512 bit / 64 bytes

            switch (hash.Length)
            {
                case 16: return HashAlgorithmName.MD5.Name;
                case 20: return HashAlgorithmName.SHA1.Name;
                case 32: return HashAlgorithmName.SHA256.Name;
                case 48: return HashAlgorithmName.SHA384.Name;
                case 64: return HashAlgorithmName.SHA512.Name;
                default:
                    throw new Exception($"Can't infer Hash algorithm. Unexpected hash length {hash.Length:#,0} bytes. Expecting 16|20|32|48|64 bytes.");
            }
        }
    }
}
