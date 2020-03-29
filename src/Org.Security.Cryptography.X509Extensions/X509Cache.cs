
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Org.Security.Cryptography
{
    // Per-Thread-Cache of X590 Certificates identified by Thumbprint.
    // Certificates are cached based on StoreName and StoreLocation to avoid dis-ambuguity.
    // Given the call supports ONLY thumbprint, once located, it can't change for life-time.
    // If certificate is NOT found, cache is NOT updated with NULL.
    // As such, you should never encounter a situation where you need to re-start the server after adding/updating certificate.
    // DELETING a certificate might require a restart if the certificate is already cached.

    /// <summary>
    /// Per-thread-cache of X509Certificate2 instances, identified by StoreName, StoreLocation, Thumbprint and an optional cache name.
    /// Use the cache ONLY IF you absolutely know how you are using the X509Certificate2 instance.
    /// Disposing the certificate, for example, will leave a stale and useless X509Certificate2 instance in the cache.
    /// </summary>
    public static class X509Cache
    {
        [ThreadStatic]
        static Dictionary<string, X509Certificate2> CertificateCache = null;

        /// <summary>
        /// Use the cache ONLY IF you absolutely know how you are using the X509Certificate2 instance.
        /// Disposing the certificate, for example, will leave a stale and useless X509Certificate2 instance in the cache.
        /// Throws an exception if requested certificate is NOT found. 
        /// </summary>
        public static X509Certificate2 GetCertificate(string x509Thumbprint, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser, string cacheKeyPrefix = "/")
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
        public static X509Certificate2 TryGetCertificate(string x509Thumbprint, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser, string cacheKeyPrefix = "/")
        {
            if (string.IsNullOrWhiteSpace(x509Thumbprint)) throw new ArgumentException("x509Thumbprint was NULL or EMPTY.");

            // NOTE: Cache is ThreadStatic. It may not yet exist on this thread.
            CertificateCache = CertificateCache ?? new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);

            // Unique key based on store location, name and thumbprint.
            // Optional cacheKeyPrefix if given use-case do not want to share the instance with other callers.
            cacheKeyPrefix = cacheKeyPrefix ?? "default";
            var cacheKey = $"{cacheKeyPrefix}/{storeLocation}/{storeName}/{x509Thumbprint}";

            // Lookup the cache.
            var found = CertificateCache.TryGetValue(cacheKey, out var certFromCache);
            if (found && null != certFromCache) return certFromCache;

            // Not in cache. Look in the store.
            using (X509Store store = new X509Store(storeName, storeLocation))
            {
                // Open an existing store.
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                // Look for the certificate by thumbPrint.
                var certs = store
                    .Certificates
                    .Cast<X509Certificate2>()
                    .Where(x => x.Thumbprint.Equals(x509Thumbprint, StringComparison.OrdinalIgnoreCase))
                    .ToArray();

                if (1 == certs.Length)
                {
                    // Found ONE...
                    CertificateCache[cacheKey] = certs[0] ?? throw new Exception($"X509Store returned a NULL X509Certificate2 instance: {storeLocation}/{storeName}/{x509Thumbprint}");
                    return certs[0];
                }
                else if (certs.Length > 1)
                {
                    // We are looking-up by ThumbPrint. This won't happen, just in case...
                    throw new Exception($"Found more than ONE X509Certificate: {storeLocation}/{storeName}/{x509Thumbprint}");
                }
                else
                {
                    // Not found. Don't update the cache, yet.
                    // This TryGet() call. Return NULL.
                    return null;
                }
            }
        }

    }
}
