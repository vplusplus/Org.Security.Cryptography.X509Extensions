
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("UnitTests")]
namespace Org.Security.Cryptography
{
    internal static class CacheManager
    {
        static MemoryCache algorithmCache = new MemoryCache(new MemoryCacheOptions());

        //2021-08-27 - Joy George Kunjikkuru - Hack of the day - Just for unit testing exposing this ClearCache(); Should never be exposing in real scenario.
        internal static void ClearCache()
        {
            algorithmCache = new MemoryCache(new MemoryCacheOptions());
        }
        internal static TOut GetOrAdd<TOut>(object key, Func<object, TOut> valueFunction)
        {
            TOut outValue;
            algorithmCache.TryGetValue<TOut>(key, out outValue);
            if (null == outValue)
            {
                outValue = valueFunction(key);
                algorithmCache.Set<TOut>(key, outValue);

            }
            return outValue;
        }
    }
}
