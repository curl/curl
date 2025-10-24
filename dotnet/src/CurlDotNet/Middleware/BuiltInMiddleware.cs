/***************************************************************************
 * Built-in Middleware Implementations for CurlDotNet
 *
 * Common middleware for logging, retry, caching, etc.
 *
 * By Jacob Mellor
 * Sponsored by IronSoftware
 ***************************************************************************/

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Core;
using CurlDotNet.Exceptions;

namespace CurlDotNet.Middleware
{
    /// <summary>
    /// Middleware for logging curl operations.
    /// </summary>
    public class LoggingMiddleware : ICurlMiddleware
    {
        private readonly Action<string> _logger;

        public LoggingMiddleware(Action<string> logger = null)
        {
            _logger = logger ?? Console.WriteLine;
        }

        public async Task<CurlResult> ExecuteAsync(CurlContext context, Func<Task<CurlResult>> next)
        {
            _logger($"[CURL] Executing: {context.Command}");
            var startTime = DateTime.UtcNow;

            try
            {
                var result = await next();
                var elapsed = DateTime.UtcNow - startTime;
                _logger($"[CURL] Success: Status={result.StatusCode}, Time={elapsed.TotalMilliseconds}ms");
                return result;
            }
            catch (Exception ex)
            {
                var elapsed = DateTime.UtcNow - startTime;
                _logger($"[CURL] Failed: {ex.Message}, Time={elapsed.TotalMilliseconds}ms");
                throw;
            }
        }
    }

    /// <summary>
    /// Middleware for retry logic with exponential backoff.
    /// </summary>
    public class RetryMiddleware : ICurlMiddleware
    {
        private readonly int _maxRetries;
        private readonly TimeSpan _initialDelay;

        public RetryMiddleware(int maxRetries = 3, TimeSpan? initialDelay = null)
        {
            _maxRetries = maxRetries;
            _initialDelay = initialDelay ?? TimeSpan.FromSeconds(1);
        }

        public async Task<CurlResult> ExecuteAsync(CurlContext context, Func<Task<CurlResult>> next)
        {
            Exception lastException = null;

            for (int attempt = 0; attempt <= _maxRetries; attempt++)
            {
                try
                {
                    var result = await next();

                    // Check if HTTP error is retryable
                    if (result.StatusCode >= 500 || result.StatusCode == 429)
                    {
                        if (attempt < _maxRetries)
                        {
                            var delay = TimeSpan.FromMilliseconds(_initialDelay.TotalMilliseconds * Math.Pow(2, attempt));
                            await Task.Delay(delay, context.CancellationToken);
                            continue;
                        }
                    }

                    return result;
                }
                catch (CurlException ex) when (ex.IsRetryable() && attempt < _maxRetries)
                {
                    lastException = ex;
                    var delay = TimeSpan.FromMilliseconds(_initialDelay.TotalMilliseconds * Math.Pow(2, attempt));
                    await Task.Delay(delay, context.CancellationToken);
                }
                catch (Exception ex)
                {
                    lastException = ex;
                    if (attempt >= _maxRetries)
                        throw;
                }
            }

            throw new CurlRetryException($"Failed after {_maxRetries} retries", context.Command, _maxRetries, lastException);
        }
    }

    /// <summary>
    /// Middleware for timing curl operations.
    /// </summary>
    public class TimingMiddleware : ICurlMiddleware
    {
        public async Task<CurlResult> ExecuteAsync(CurlContext context, Func<Task<CurlResult>> next)
        {
            var startTime = DateTime.UtcNow;
            context.Properties["TimingStart"] = startTime;

            var result = await next();

            var endTime = DateTime.UtcNow;
            var duration = endTime - startTime;

            // Add timing to result
            if (result.Timings == null)
            {
                result.Timings = new CurlTimings();
            }
            result.Timings.Total = duration.TotalMilliseconds;

            // Add to context for other middleware
            context.Properties["TimingEnd"] = endTime;
            context.Properties["TimingDuration"] = duration;

            return result;
        }
    }

    /// <summary>
    /// Simple in-memory caching middleware.
    /// </summary>
    public class CachingMiddleware : ICurlMiddleware
    {
        private static readonly ConcurrentDictionary<string, CacheEntry> _cache = new ConcurrentDictionary<string, CacheEntry>();
        private readonly TimeSpan _ttl;

        public CachingMiddleware(TimeSpan? ttl = null)
        {
            _ttl = ttl ?? TimeSpan.FromMinutes(5);
        }

        public async Task<CurlResult> ExecuteAsync(CurlContext context, Func<Task<CurlResult>> next)
        {
            // Only cache GET requests
            if (context.Options?.Method != null && context.Options.Method != "GET")
            {
                return await next();
            }

            var cacheKey = GetCacheKey(context);

            // Check cache
            if (_cache.TryGetValue(cacheKey, out var entry) && entry.Expiry > DateTime.UtcNow)
            {
                // Clone the cached result
                return CloneResult(entry.Result);
            }

            // Execute and cache
            var result = await next();

            if (result.IsSuccess)
            {
                _cache[cacheKey] = new CacheEntry
                {
                    Result = result,
                    Expiry = DateTime.UtcNow.Add(_ttl)
                };

                // Clean expired entries periodically
                if (_cache.Count > 100)
                {
                    CleanExpiredEntries();
                }
            }

            return result;
        }

        private string GetCacheKey(CurlContext context)
        {
            // Simple cache key based on command
            // In production, parse URL and headers for better key
            return context.Command ?? context.Options?.Url ?? "";
        }

        private CurlResult CloneResult(CurlResult original)
        {
            // Simple clone - in production use proper cloning
            return new CurlResult
            {
                StatusCode = original.StatusCode,
                Body = original.Body,
                Headers = new Dictionary<string, string>(original.Headers),
                BinaryData = original.BinaryData,
                Command = original.Command,
                Timings = original.Timings
            };
        }

        private void CleanExpiredEntries()
        {
            var expired = _cache.Where(kvp => kvp.Value.Expiry < DateTime.UtcNow)
                                .Select(kvp => kvp.Key)
                                .ToList();

            foreach (var key in expired)
            {
                _cache.TryRemove(key, out _);
            }
        }

        private class CacheEntry
        {
            public CurlResult Result { get; set; }
            public DateTime Expiry { get; set; }
        }

        /// <summary>
        /// Clear the cache.
        /// </summary>
        public static void ClearCache()
        {
            _cache.Clear();
        }
    }

    /// <summary>
    /// Middleware for adding authentication headers.
    /// </summary>
    public class AuthenticationMiddleware : ICurlMiddleware
    {
        private readonly Func<CurlContext, Task<string>> _tokenProvider;

        public AuthenticationMiddleware(Func<CurlContext, Task<string>> tokenProvider)
        {
            _tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
        }

        public async Task<CurlResult> ExecuteAsync(CurlContext context, Func<Task<CurlResult>> next)
        {
            // Get token
            var token = await _tokenProvider(context);

            if (!string.IsNullOrEmpty(token))
            {
                // Add authorization header to options
                if (context.Options == null)
                {
                    context.Options = new CurlOptions();
                }

                if (context.Options.Headers == null)
                {
                    context.Options.Headers = new Dictionary<string, string>();
                }

                context.Options.Headers["Authorization"] = $"Bearer {token}";

                // Update command if needed
                if (!context.Command.Contains("Authorization"))
                {
                    context.Command = context.Command + $" -H 'Authorization: Bearer {token}'";
                }
            }

            return await next();
        }
    }

    /// <summary>
    /// Simple rate limiting middleware.
    /// </summary>
    public class RateLimitMiddleware : ICurlMiddleware
    {
        private readonly SemaphoreSlim _semaphore;
        private readonly int _requestsPerSecond;
        private readonly Queue<DateTime> _requestTimes = new Queue<DateTime>();
        private readonly object _lock = new object();

        public RateLimitMiddleware(int requestsPerSecond)
        {
            _requestsPerSecond = requestsPerSecond;
            _semaphore = new SemaphoreSlim(requestsPerSecond, requestsPerSecond);
        }

        public async Task<CurlResult> ExecuteAsync(CurlContext context, Func<Task<CurlResult>> next)
        {
            await WaitIfNeeded(context.CancellationToken);

            try
            {
                return await next();
            }
            finally
            {
                RecordRequest();
            }
        }

        private async Task WaitIfNeeded(CancellationToken cancellationToken)
        {
            lock (_lock)
            {
                // Remove old requests outside the window
                var cutoff = DateTime.UtcNow.AddSeconds(-1);
                while (_requestTimes.Count > 0 && _requestTimes.Peek() < cutoff)
                {
                    _requestTimes.Dequeue();
                }

                // If at limit, calculate wait time
                if (_requestTimes.Count >= _requestsPerSecond)
                {
                    var oldestRequest = _requestTimes.Peek();
                    var waitTime = oldestRequest.AddSeconds(1) - DateTime.UtcNow;
                    if (waitTime > TimeSpan.Zero)
                    {
                        Task.Delay(waitTime, cancellationToken).Wait(cancellationToken);
                    }
                }
            }
        }

        private void RecordRequest()
        {
            lock (_lock)
            {
                _requestTimes.Enqueue(DateTime.UtcNow);

                // Keep only requests in the last second
                var cutoff = DateTime.UtcNow.AddSeconds(-1);
                while (_requestTimes.Count > 0 && _requestTimes.Peek() < cutoff)
                {
                    _requestTimes.Dequeue();
                }
            }
        }
    }

    /// <summary>
    /// Middleware for modifying requests.
    /// </summary>
    public class RequestModifierMiddleware : ICurlMiddleware
    {
        private readonly Action<CurlContext> _modifier;

        public RequestModifierMiddleware(Action<CurlContext> modifier)
        {
            _modifier = modifier ?? throw new ArgumentNullException(nameof(modifier));
        }

        public async Task<CurlResult> ExecuteAsync(CurlContext context, Func<Task<CurlResult>> next)
        {
            _modifier(context);
            return await next();
        }
    }

    /// <summary>
    /// Middleware for modifying responses.
    /// </summary>
    public class ResponseModifierMiddleware : ICurlMiddleware
    {
        private readonly Func<CurlResult, Task<CurlResult>> _modifier;

        public ResponseModifierMiddleware(Func<CurlResult, Task<CurlResult>> modifier)
        {
            _modifier = modifier ?? throw new ArgumentNullException(nameof(modifier));
        }

        public async Task<CurlResult> ExecuteAsync(CurlContext context, Func<Task<CurlResult>> next)
        {
            var result = await next();
            return await _modifier(result);
        }
    }
}