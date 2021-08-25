
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Org.Security.Cryptography
{
    internal static class X509AsymmetricAlgorithmExtensions
    {
        /// <summary>
        /// Returns an AsymmetricAlgorithm, representing the PublicKey
        /// </summary>
        internal static AsymmetricAlgorithm GetPublicKeyAsymmetricAlgorithm(this X509Certificate2 x509Cert)
        {
            // Not sure what scenario the thumnprint will be null. If the cert is loaded it would have thumbprint
            if (null == x509Cert.Thumbprint) throw new ArgumentNullException("X509Certificate2.Thumbprint was NULL.");
            try
            {
                try
                {
                    // [FASTER] 
                    return x509Cert.PublicKey?.Key ?? throw new Exception($"X509Certificate2.PublicKey?.Key was NULL.");
                }
                catch (CryptographicException)
                {
                    // [SLOWER] - Seems rare scenario
                    return x509Cert.GetRSAPublicKey() ?? throw new Exception($"X509Certificate2.GetRSAPublicKey() returned NULL");
                }
            }
            catch (Exception err)
            {
                var msg = $"Error accessing PublicKey of the X509 Certificate. Cert: {x509Cert.Thumbprint}";
                throw new Exception(msg, err);
            }
        }

        /// <summary>
        /// Returns an AsymmetricAlgorithm, representing the PrivateKey
        /// </summary>
        internal static AsymmetricAlgorithm GetPrivateKeyAsymmetricAlgorithm(this X509Certificate2 x509Cert)
        {
            if (null == x509Cert.Thumbprint) throw new ArgumentNullException("X509Certificate2.Thumbprint was NULL.");
            try
            {
                try
                {
                    // [FASTER] 
                    return x509Cert.PrivateKey ?? throw new Exception($"X509Certificate2.PrivateKey was NULL.");
                }
                catch (CryptographicException)
                {
                    // [SLOWER] 
                    return x509Cert.GetRSAPrivateKey() ?? throw new Exception($"X509Certificate2.GetRSAPrivateKey() returned NULL.");
                }
            }
            catch (Exception err)
            {
                var msg = $"Error accessing PrivateKey of the X509 Certificate. Cert: {x509Cert.Thumbprint}";
                throw new Exception(msg, err);
            }
        }
    }
}
