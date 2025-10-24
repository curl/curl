/***************************************************************************
 * Middleware Pipeline for CurlDotNet
 *
 * Manages the chain of middleware components
 *
 * By Jacob Mellor
 * Sponsored by IronSoftware
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CurlDotNet.Core;

namespace CurlDotNet.Middleware
{
    /// <summary>
    /// Manages the middleware pipeline for curl operations.
    /// </summary>
    public class CurlMiddlewarePipeline
    {
        private readonly List<ICurlMiddleware> _middleware = new List<ICurlMiddleware>();
        private readonly Func<CurlContext, Task<CurlResult>> _finalHandler;

        /// <summary>
        /// Initialize a new middleware pipeline.
        /// </summary>
        /// <param name="finalHandler">The final handler that executes the curl command</param>
        public CurlMiddlewarePipeline(Func<CurlContext, Task<CurlResult>> finalHandler)
        {
            _finalHandler = finalHandler ?? throw new ArgumentNullException(nameof(finalHandler));
        }

        /// <summary>
        /// Add middleware to the pipeline (fluent).
        /// </summary>
        public CurlMiddlewarePipeline Use(ICurlMiddleware middleware)
        {
            _middleware.Add(middleware);
            return this;
        }

        /// <summary>
        /// Add middleware using a delegate (fluent).
        /// </summary>
        public CurlMiddlewarePipeline Use(Func<CurlContext, Func<Task<CurlResult>>, Task<CurlResult>> middleware)
        {
            _middleware.Add(new DelegateMiddleware(middleware));
            return this;
        }

        /// <summary>
        /// Execute the pipeline.
        /// </summary>
        public async Task<CurlResult> ExecuteAsync(CurlContext context)
        {
            // Build the pipeline from the end
            Func<Task<CurlResult>> pipeline = () => _finalHandler(context);

            // Wrap each middleware in reverse order
            for (int i = _middleware.Count - 1; i >= 0; i--)
            {
                var middleware = _middleware[i];
                var next = pipeline;
                pipeline = () => middleware.ExecuteAsync(context, next);
            }

            return await pipeline();
        }

        /// <summary>
        /// Clear all middleware from the pipeline.
        /// </summary>
        public void Clear()
        {
            _middleware.Clear();
        }

        /// <summary>
        /// Get the count of middleware in the pipeline.
        /// </summary>
        public int Count => _middleware.Count;

        /// <summary>
        /// Create a new pipeline builder.
        /// </summary>
        public static CurlMiddlewarePipelineBuilder CreateBuilder()
        {
            return new CurlMiddlewarePipelineBuilder();
        }

        /// <summary>
        /// Delegate-based middleware implementation.
        /// </summary>
        private class DelegateMiddleware : ICurlMiddleware
        {
            private readonly Func<CurlContext, Func<Task<CurlResult>>, Task<CurlResult>> _middleware;

            public DelegateMiddleware(Func<CurlContext, Func<Task<CurlResult>>, Task<CurlResult>> middleware)
            {
                _middleware = middleware;
            }

            public Task<CurlResult> ExecuteAsync(CurlContext context, Func<Task<CurlResult>> next)
            {
                return _middleware(context, next);
            }
        }
    }

    /// <summary>
    /// Fluent builder for creating middleware pipelines.
    /// </summary>
    public class CurlMiddlewarePipelineBuilder
    {
        private readonly List<ICurlMiddleware> _middleware = new List<ICurlMiddleware>();
        private Func<CurlContext, Task<CurlResult>> _finalHandler;

        /// <summary>
        /// Add middleware to the pipeline.
        /// </summary>
        public CurlMiddlewarePipelineBuilder Use(ICurlMiddleware middleware)
        {
            _middleware.Add(middleware);
            return this;
        }

        /// <summary>
        /// Add middleware using a delegate.
        /// </summary>
        public CurlMiddlewarePipelineBuilder Use(Func<CurlContext, Func<Task<CurlResult>>, Task<CurlResult>> middleware)
        {
            _middleware.Add(new DelegateMiddleware(middleware));
            return this;
        }

        /// <summary>
        /// Add logging middleware.
        /// </summary>
        public CurlMiddlewarePipelineBuilder UseLogging(Action<string> logger = null)
        {
            Use(new LoggingMiddleware(logger));
            return this;
        }

        /// <summary>
        /// Add retry middleware.
        /// </summary>
        public CurlMiddlewarePipelineBuilder UseRetry(int maxRetries = 3, TimeSpan? delay = null)
        {
            Use(new RetryMiddleware(maxRetries, delay));
            return this;
        }

        /// <summary>
        /// Add timing middleware.
        /// </summary>
        public CurlMiddlewarePipelineBuilder UseTiming()
        {
            Use(new TimingMiddleware());
            return this;
        }

        /// <summary>
        /// Add caching middleware.
        /// </summary>
        public CurlMiddlewarePipelineBuilder UseCaching(TimeSpan? ttl = null)
        {
            Use(new CachingMiddleware(ttl));
            return this;
        }

        /// <summary>
        /// Add authentication middleware.
        /// </summary>
        public CurlMiddlewarePipelineBuilder UseAuthentication(Func<CurlContext, Task<string>> tokenProvider)
        {
            Use(new AuthenticationMiddleware(tokenProvider));
            return this;
        }

        /// <summary>
        /// Add rate limiting middleware.
        /// </summary>
        public CurlMiddlewarePipelineBuilder UseRateLimit(int requestsPerSecond)
        {
            Use(new RateLimitMiddleware(requestsPerSecond));
            return this;
        }

        /// <summary>
        /// Set the final handler.
        /// </summary>
        public CurlMiddlewarePipelineBuilder WithHandler(Func<CurlContext, Task<CurlResult>> handler)
        {
            _finalHandler = handler;
            return this;
        }

        /// <summary>
        /// Build the pipeline.
        /// </summary>
        public CurlMiddlewarePipeline Build()
        {
            if (_finalHandler == null)
            {
                throw new InvalidOperationException("Final handler is required. Call WithHandler() before Build().");
            }

            var pipeline = new CurlMiddlewarePipeline(_finalHandler);
            foreach (var middleware in _middleware)
            {
                pipeline.Use(middleware);
            }

            return pipeline;
        }

        /// <summary>
        /// Delegate-based middleware implementation.
        /// </summary>
        private class DelegateMiddleware : ICurlMiddleware
        {
            private readonly Func<CurlContext, Func<Task<CurlResult>>, Task<CurlResult>> _middleware;

            public DelegateMiddleware(Func<CurlContext, Func<Task<CurlResult>>, Task<CurlResult>> middleware)
            {
                _middleware = middleware;
            }

            public Task<CurlResult> ExecuteAsync(CurlContext context, Func<Task<CurlResult>> next)
            {
                return _middleware(context, next);
            }
        }
    }
}