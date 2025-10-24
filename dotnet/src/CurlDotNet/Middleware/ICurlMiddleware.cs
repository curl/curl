/***************************************************************************
 * Middleware/Interceptor Pattern for CurlDotNet
 *
 * Allows intercepting and modifying requests and responses
 *
 * By Jacob Mellor
 * Sponsored by IronSoftware
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Core;

namespace CurlDotNet.Middleware
{
    /// <summary>
    /// Interface for curl middleware/interceptors.
    /// </summary>
    /// <remarks>
    /// <para>Middleware can modify requests before execution and responses after execution.</para>
    /// <para>Multiple middleware can be chained together in a pipeline.</para>
    /// <para>AI-Usage: Implement this interface to add cross-cutting concerns like logging, retry, caching, etc.</para>
    /// </remarks>
    /// <example>
    /// <code>
    /// public class LoggingMiddleware : ICurlMiddleware
    /// {
    ///     public async Task&lt;CurlResult&gt; ExecuteAsync(CurlContext context, Func&lt;Task&lt;CurlResult&gt;&gt; next)
    ///     {
    ///         Console.WriteLine($"Executing: {context.Command}");
    ///         var result = await next();
    ///         Console.WriteLine($"Status: {result.StatusCode}");
    ///         return result;
    ///     }
    /// }
    /// </code>
    /// </example>
    public interface ICurlMiddleware
    {
        /// <summary>
        /// Execute the middleware logic.
        /// </summary>
        /// <param name="context">The curl context containing request information</param>
        /// <param name="next">The next middleware in the pipeline</param>
        /// <returns>The curl result</returns>
        Task<CurlResult> ExecuteAsync(CurlContext context, Func<Task<CurlResult>> next);
    }

    /// <summary>
    /// Context object containing information about the curl request.
    /// </summary>
    public class CurlContext
    {
        /// <summary>
        /// The curl command being executed.
        /// </summary>
        public string Command { get; set; }

        /// <summary>
        /// The parsed curl options.
        /// </summary>
        public CurlOptions Options { get; set; }

        /// <summary>
        /// Custom properties for passing data between middleware.
        /// </summary>
        public Dictionary<string, object> Properties { get; set; } = new Dictionary<string, object>();

        /// <summary>
        /// The cancellation token for the request.
        /// </summary>
        public CancellationToken CancellationToken { get; set; }

        /// <summary>
        /// Request start time for timing.
        /// </summary>
        public DateTime StartTime { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Add a property to the context (fluent).
        /// </summary>
        public CurlContext WithProperty(string key, object value)
        {
            Properties[key] = value;
            return this;
        }

        /// <summary>
        /// Get a property from the context.
        /// </summary>
        public T GetProperty<T>(string key)
        {
            if (Properties.TryGetValue(key, out var value))
            {
                return (T)value;
            }
            return default(T);
        }
    }
}