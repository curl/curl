/***************************************************************************
 * Static API for CurlDotNet - Main Entry Point
 *
 * Primary API: Curl.Curl("https://example.com")
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 * Sponsored by Iron Software (ironsoftware.com)
 ***************************************************************************/

using System;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Exceptions;
using CurlDotNet.Progress;

namespace CurlDotNet
{
    /// <summary>
    /// Main static API for curl operations
    /// </summary>
    public static partial class Curl
    {
        private static readonly CurlExecutor _executor = new CurlExecutor();

        /// <summary>
        /// Execute a curl command - the primary API
        /// </summary>
        /// <param name="command">Curl command string (curl prefix optional)</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <param name="progress">Optional progress reporter for download/upload tracking</param>
        /// <returns>Fluent result object with full response data</returns>
        /// <example>
        /// // Simple GET request
        /// var result = await Curl.Curl("https://api.example.com/users");
        ///
        /// // With cancellation
        /// var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        /// var result = await Curl.Curl("https://slow-api.com/data", cts.Token);
        ///
        /// // With progress tracking
        /// var progress = new Progress&lt;CurlProgressInfo&gt;(p =&gt;
        ///     Console.WriteLine($"Downloaded: {p.PercentComplete:P0}"));
        /// var result = await Curl.Curl("https://example.com/large-file.zip", progress: progress);
        /// </example>
        public static async Task<CurlResult> Curl(
            string command,
            CancellationToken cancellationToken = default,
            IProgress<CurlProgressInfo> progress = null)
        {
            // Normalize command - make 'curl' prefix optional
            command = NormalizeCommand(command);

            try
            {
                return await _executor.ExecuteAsync(command, cancellationToken, progress);
            }
            catch (OperationCanceledException)
            {
                throw new CurlTimeoutException("Operation was cancelled", command);
            }
            catch (Exception ex)
            {
                throw new CurlExecutionException($"Failed to execute curl command: {ex.Message}", command, ex);
            }
        }

        /// <summary>
        /// Synchronous execution wrapper
        /// </summary>
        /// <param name="command">Curl command string</param>
        /// <returns>Fluent result object</returns>
        /// <example>
        /// var result = Curl.CurlSync("https://api.example.com/users");
        /// string json = result.Body;
        /// </example>
        public static CurlResult CurlSync(string command)
        {
            return Curl(command).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Execute with timeout
        /// </summary>
        /// <param name="command">Curl command string</param>
        /// <param name="timeout">Maximum time to wait</param>
        /// <param name="progress">Optional progress reporter</param>
        /// <returns>Fluent result object</returns>
        /// <example>
        /// var result = await Curl.CurlWithTimeout("https://slow-api.com", TimeSpan.FromSeconds(10));
        /// </example>
        public static async Task<CurlResult> CurlWithTimeout(
            string command,
            TimeSpan timeout,
            IProgress<CurlProgressInfo> progress = null)
        {
            using var cts = new CancellationTokenSource(timeout);
            return await Curl(command, cts.Token, progress);
        }

        /// <summary>
        /// Execute multiple curl commands in parallel
        /// </summary>
        /// <param name="commands">Array of curl commands</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Array of results in the same order as commands</returns>
        /// <example>
        /// var results = await Curl.CurlParallel(
        ///     "https://api1.example.com/data",
        ///     "https://api2.example.com/data",
        ///     "https://api3.example.com/data"
        /// );
        /// </example>
        public static async Task<CurlResult[]> CurlParallel(
            string[] commands,
            CancellationToken cancellationToken = default)
        {
            var tasks = new Task<CurlResult>[commands.Length];

            for (int i = 0; i < commands.Length; i++)
            {
                tasks[i] = Curl(commands[i], cancellationToken);
            }

            return await Task.WhenAll(tasks);
        }

        /// <summary>
        /// Execute with retry logic
        /// </summary>
        /// <param name="command">Curl command string</param>
        /// <param name="maxRetries">Maximum number of retry attempts</param>
        /// <param name="retryDelay">Delay between retries</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Fluent result object</returns>
        /// <example>
        /// var result = await Curl.CurlWithRetry(
        ///     "https://unreliable-api.com/data",
        ///     maxRetries: 3,
        ///     retryDelay: TimeSpan.FromSeconds(2)
        /// );
        /// </example>
        public static async Task<CurlResult> CurlWithRetry(
            string command,
            int maxRetries = 3,
            TimeSpan? retryDelay = null,
            CancellationToken cancellationToken = default)
        {
            var delay = retryDelay ?? TimeSpan.FromSeconds(1);
            Exception lastException = null;

            for (int attempt = 0; attempt <= maxRetries; attempt++)
            {
                try
                {
                    var result = await Curl(command, cancellationToken);
                    if (result.IsSuccess)
                        return result;

                    // If it's a client error (4xx), don't retry
                    if (result.StatusCode >= 400 && result.StatusCode < 500)
                        return result;

                    lastException = new CurlHttpException(
                        $"HTTP {result.StatusCode}: {result.StatusText}",
                        result.StatusCode);
                }
                catch (Exception ex)
                {
                    lastException = ex;
                }

                if (attempt < maxRetries)
                {
                    await Task.Delay(delay * (attempt + 1), cancellationToken);
                }
            }

            throw new CurlRetryException(
                $"Failed after {maxRetries + 1} attempts",
                command,
                maxRetries,
                lastException);
        }

        private static string NormalizeCommand(string command)
        {
            if (string.IsNullOrWhiteSpace(command))
                throw new CurlInvalidCommandException("Command cannot be empty");

            command = command.Trim();

            // If it's just a URL or starts with an option, add 'curl' prefix
            if (!command.StartsWith("curl", StringComparison.OrdinalIgnoreCase))
            {
                if (command.StartsWith("http", StringComparison.OrdinalIgnoreCase) ||
                    command.StartsWith("ftp", StringComparison.OrdinalIgnoreCase) ||
                    command.StartsWith("file://", StringComparison.OrdinalIgnoreCase) ||
                    command.StartsWith("-", StringComparison.OrdinalIgnoreCase))
                {
                    command = "curl " + command;
                }
            }

            return command;
        }
    }

    /// <summary>
    /// Alternative namespace for library-style access
    /// </summary>
    namespace Lib
    {
        /// <summary>
        /// Library-style curl access
        /// Usage: CurlDotNet.Lib.Curl.Execute("https://example.com")
        /// </summary>
        public static class Curl
        {
            /// <summary>
            /// Execute a curl command through the library namespace
            /// </summary>
            public static async Task<CurlResult> Execute(
                string command,
                CancellationToken cancellationToken = default,
                IProgress<CurlProgressInfo> progress = null)
            {
                return await CurlDotNet.Curl.Curl(command, cancellationToken, progress);
            }

            /// <summary>
            /// Synchronous execution
            /// </summary>
            public static CurlResult ExecuteSync(string command)
            {
                return Execute(command).GetAwaiter().GetResult();
            }
        }
    }
}