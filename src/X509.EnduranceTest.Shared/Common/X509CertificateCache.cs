
//...................................................................................
#region About X509CertificateCache
//...................................................................................
// 
// It takes approx 5 milliSec to lookup and obtain the certificate from local certificate store,
// unless the Store itself is handled as singleton and never closed during process lifetime.
// X509CertificateCache can be used to cache and re-use the certs.
//
// Using the X509 certificate instance:
// Use the cache ONLY IF you absolutely know how you are using the X509Certificate2 instance.
// Disposing the certificate, or disposing the AsymmetricAlgorithm for example, 
// will leave a STALE and USELESS X509Certificate2 instance in the cache.
// Your code may not have control over other parts using/abusing the cache.
// If your use-case needs a private space that is not available to other callers, 
// use a unique-cache-prfix, that is not shared with others.
// Example: private static readonly string MyCachePrefix = Guid.NewGuid().ToString();
// 
// Is this thread-safe?
// The X509CertificateCache maintains per-thread-cache.
// Each thread has its own instance of the cache and corresponding cached versions of the X509 certificate.
// The cache is as thread-safe as the X509Certificate instance itself.
// The cache can't prevent you from passing the certificate instances in an async call, crossing thread boundary.
// If you are concerned about thread safety, do not pass the certifcates across async-call boundaries.
// For thread safety of X509Certificate2 related operations, refer Microsoft documentation.
// 
// How about server-restart on certificate changes?
// The ONLY option supported by the cache is lookup by thumbprint.
// The cache doesn't support lookup by other properties that may change, such as SubjectName.
// The thumbprint is a digital fingerprint for specific certificate instance.
// In addition, the certificates are cached based on StoreName and StoreLocation to avoid ambiguity.
// Certs identified by thumbprint can be treated immutable, as any change in certificate info would result in a new thumbprint.
// In general, you should not have to re-start the server after adding/updating certificate.
// DELETING a certificate might require a restart if the certificate is already cached.
//
// As with any other library, read-and-understand the code before using. 
//
#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace X509.EnduranceTest.Shared
{
    /// <summary>
    /// Per-thread-cache of X509Certificate2 instances, identified by StoreName, StoreLocation, Thumbprint and an optional cache name.
    /// Use the cache ONLY IF you absolutely know how you are using the X509Certificate2 instance.
    /// Disposing the certificate, for example, will leave a stale and useless X509Certificate2 instance in the cache.
    /// </summary>
    public static class X509CertificateCache
    {
        [ThreadStatic]
        static Dictionary<string, X509Certificate2> CertificateCache = null;

        /// <summary>
        /// Use the cache ONLY IF you absolutely know how you are using the X509Certificate2 instance.
        /// Disposing the certificate, for example, will leave a stale and useless X509Certificate2 instance in the cache.
        /// Throws an exception if requested certificate is NOT found. 
        /// </summary>
        public static X509Certificate2 GetCertificate(string x509Thumbprint, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser, string cacheKeyPrefix = null)
        {
            if (string.IsNullOrWhiteSpace(x509Thumbprint)) throw new ArgumentException("x509Thumbprint was NULL or EMPTY.");

            return TryGetCertificate(x509Thumbprint, storeName, storeLocation, cacheKeyPrefix) ?? 
                throw new Exception($"X509Certificate not found: {storeLocation}/{storeName}/{x509Thumbprint}");
        }

        /// <summary>
        /// Use the cache ONLY IF you absolutely know how you are using the X509Certificate2 instance.
        /// Disposing the certificate, for example, will leave a stale and useless X509Certificate2 instance in the cache.
        /// Returns the X509Certificate2 if found, else NULL.
        /// </summary>
        public static X509Certificate2 TryGetCertificate(string x509Thumbprint, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser, string cacheKeyPrefix = null)
        {
            if (string.IsNullOrWhiteSpace(x509Thumbprint)) throw new ArgumentException("x509Thumbprint was NULL or EMPTY.");

            // NOTE: Cache is ThreadStatic. It may not yet exist on this thread.
            CertificateCache = CertificateCache ?? new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);

            // Unique key based on prefix, location, store and thumbprint.
            cacheKeyPrefix = cacheKeyPrefix ?? "default";
            var cacheKey = $"{cacheKeyPrefix}/{storeLocation}/{storeName}/{x509Thumbprint}";

            // Lookup the cache.
            var found = CertificateCache.TryGetValue(cacheKey, out var certFromCache);
            if (found && null != certFromCache) return certFromCache;
            // Not in cache. Look in the store.
            using (X509Store store = new(storeName, storeLocation))
            {
                // Open an existing store.
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                // Look for the certificate by thumbPrint.
                var certs = store
                    .Certificates
                    .Cast<X509Certificate2>()
                    .Where(x => null != x?.Thumbprint)
                    .Where(x => x.Thumbprint.Equals(x509Thumbprint, StringComparison.OrdinalIgnoreCase))
                    .ToArray();

                if (1 == certs.Length)
                {
                    // Found ONE. Cache and return.
                    return (CertificateCache[cacheKey] = certs[0]);
                }
                else if (0 == certs.Length)
                {
                    // Not found. 
                    // Don't update the cache.
                    // This is a TryGet() call; Return NULL.
                    return null;
                }
                else
                {
                    // Found more than one cert with the thumbprint.
                    // We are looking-up by ThumbPrint. 
                    // This won't happen, just in case...
                    throw new Exception($"Found more than ONE X509Certificate: {storeLocation}/{storeName}/{x509Thumbprint}");
                }
            }
        }
    }
}
