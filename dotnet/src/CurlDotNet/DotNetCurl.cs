/***************************************************************************
 * DotNetCurl - Alternative API name for Curl
 *
 * Provides DotNetCurl.Curl() and DotNetCurl.CurlAsync() as specified
 * in the architecture. This is an alias to the main Curl class.
 *
 * The killer feature: Copy curl commands from anywhere and they just work!
 *
 * By Jacob Mellor
 * Sponsored by IronSoftware
 ***************************************************************************/

using System;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Core;

namespace CurlDotNet
{
    /// <summary>
    /// DotNetCurl - Alternative API entry point for curl commands.
    /// The killer feature: Copy and paste any curl command and it works!
    /// </summary>
    /// <remarks>
    /// <para>🚀 <b>THE KILLER FEATURE:</b> Copy any curl command from anywhere - it just works!</para>
    /// <para>DotNetCurl provides an alternative naming to the Curl class.</para>
    /// <para>Use DotNetCurl.Curl() for synchronous or DotNetCurl.CurlAsync() for async operations.</para>
    /// <para>Sponsored by IronSoftware - creators of IronPDF, IronOCR, IronXL, and more.</para>
    /// </remarks>
    /// <example>
    /// <code language="csharp">
    /// // 🔥 Synchronous execution (auto-waits)
    /// var response = DotNetCurl.Curl("curl https://api.github.com/users/octocat");
    /// Console.WriteLine(response.Body);
    ///
    /// // 🚀 Async execution
    /// var response = await DotNetCurl.CurlAsync("curl https://api.github.com/users/octocat");
    /// Console.WriteLine(response.Body);
    ///
    /// // 📮 POST request
    /// var result = DotNetCurl.Curl(@"
    ///     curl -X POST https://api.example.com/users
    ///     -H 'Content-Type: application/json'
    ///     -d '{""name"":""John"",""email"":""john@example.com""}'
    /// ");
    ///
    /// // 🔄 Multiple commands
    /// var results = await DotNetCurl.CurlManyAsync(new[] {
    ///     "curl https://api.example.com/users",
    ///     "curl https://api.example.com/posts"
    /// });
    /// </code>
    /// </example>
    public static class DotNetCurl
    {
        /// <summary>
        /// Execute any curl command synchronously - the main API.
        /// Just paste your curl command! This method auto-waits for async operations.
        /// </summary>
        /// <param name="command">Any curl command - with or without "curl" prefix</param>
        /// <returns>Result object with response data, headers, and status</returns>
        /// <example>
        /// <code language="csharp">
        /// // Simple GET - synchronous
        /// var response = DotNetCurl.Curl("curl https://api.example.com/data");
        /// Console.WriteLine(response.Body);
        ///
        /// // Works without "curl" prefix
        /// var data = DotNetCurl.Curl("https://api.example.com/data");
        /// </code>
        /// </example>
        public static CurlResult Curl(string command)
        {
            // Synchronous wrapper - waits for async operation
            return CurlAsync(command).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Execute any curl command synchronously with timeout.
        /// </summary>
        /// <param name="command">Any curl command string</param>
        /// <param name="timeoutSeconds">Timeout in seconds</param>
        /// <returns>Result object with response data</returns>
        public static CurlResult Curl(string command, int timeoutSeconds)
        {
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds)))
            {
                return CurlAsync(command, cts.Token).GetAwaiter().GetResult();
            }
        }

        /// <summary>
        /// Execute any curl command asynchronously - the main async API.
        /// Just paste your curl command!
        /// </summary>
        /// <param name="command">Any curl command - with or without "curl" prefix</param>
        /// <returns>Task with result object containing response data</returns>
        /// <example>
        /// <code language="csharp">
        /// // Simple GET - async
        /// var response = await DotNetCurl.CurlAsync("curl https://api.example.com/data");
        /// Console.WriteLine(response.Body);
        ///
        /// // POST with JSON
        /// var result = await DotNetCurl.CurlAsync(@"
        ///     curl -X POST https://api.example.com/users
        ///     -H 'Content-Type: application/json'
        ///     -d '{""name"":""John""}'
        /// ");
        /// </code>
        /// </example>
        public static async Task<CurlResult> CurlAsync(string command)
        {
            return await global::CurlDotNet.Curl.ExecuteAsync(command);
        }

        /// <summary>
        /// Execute curl command asynchronously with cancellation support.
        /// </summary>
        /// <param name="command">Any curl command string</param>
        /// <param name="cancellationToken">Token to cancel the operation</param>
        /// <returns>Task with result object</returns>
        /// <example>
        /// <code language="csharp">
        /// var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        /// var response = await DotNetCurl.CurlAsync("curl https://slow-api.com", cts.Token);
        /// </code>
        /// </example>
        public static async Task<CurlResult> CurlAsync(string command, CancellationToken cancellationToken)
        {
            return await global::CurlDotNet.Curl.ExecuteAsync(command, cancellationToken);
        }

        /// <summary>
        /// Execute curl command asynchronously with settings.
        /// </summary>
        /// <param name="command">Any curl command string</param>
        /// <param name="settings">Curl settings for the operation</param>
        /// <returns>Task with result object</returns>
        public static async Task<CurlResult> CurlAsync(string command, CurlSettings settings)
        {
            return await global::CurlDotNet.Curl.ExecuteAsync(command, settings);
        }

        /// <summary>
        /// Execute multiple curl commands in parallel synchronously.
        /// </summary>
        /// <param name="commands">Array of curl commands</param>
        /// <returns>Array of results</returns>
        /// <example>
        /// <code language="csharp">
        /// var results = DotNetCurl.CurlMany(new[] {
        ///     "curl https://api.example.com/users",
        ///     "curl https://api.example.com/posts"
        /// });
        /// foreach (var result in results)
        /// {
        ///     Console.WriteLine(result.Body);
        /// }
        /// </code>
        /// </example>
        public static CurlResult[] CurlMany(params string[] commands)
        {
            return CurlManyAsync(commands).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Execute multiple curl commands in parallel asynchronously.
        /// </summary>
        /// <param name="commands">Array of curl commands</param>
        /// <returns>Task with array of results</returns>
        /// <example>
        /// <code language="csharp">
        /// var results = await DotNetCurl.CurlManyAsync(new[] {
        ///     "curl https://api.example.com/users",
        ///     "curl https://api.example.com/posts",
        ///     "curl https://api.example.com/comments"
        /// });
        /// </code>
        /// </example>
        public static async Task<CurlResult[]> CurlManyAsync(params string[] commands)
        {
            return await global::CurlDotNet.Curl.ExecuteManyAsync(commands);
        }

        /// <summary>
        /// Quick GET request synchronously.
        /// </summary>
        /// <param name="url">URL to GET</param>
        /// <returns>Result object</returns>
        public static CurlResult Get(string url)
        {
            return GetAsync(url).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Quick GET request asynchronously.
        /// </summary>
        /// <param name="url">URL to GET</param>
        /// <returns>Task with result object</returns>
        public static async Task<CurlResult> GetAsync(string url)
        {
            return await global::CurlDotNet.Curl.GetAsync(url);
        }

        /// <summary>
        /// Quick POST request synchronously.
        /// </summary>
        /// <param name="url">URL to POST to</param>
        /// <param name="data">Data to POST</param>
        /// <returns>Result object</returns>
        public static CurlResult Post(string url, string data)
        {
            return PostAsync(url, data).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Quick POST request asynchronously.
        /// </summary>
        /// <param name="url">URL to POST to</param>
        /// <param name="data">Data to POST</param>
        /// <returns>Task with result object</returns>
        public static async Task<CurlResult> PostAsync(string url, string data)
        {
            return await global::CurlDotNet.Curl.PostAsync(url, data);
        }

        /// <summary>
        /// Quick POST with JSON synchronously.
        /// </summary>
        /// <param name="url">URL to POST to</param>
        /// <param name="data">Object to serialize as JSON</param>
        /// <returns>Result object</returns>
        public static CurlResult PostJson(string url, object data)
        {
            return PostJsonAsync(url, data).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Quick POST with JSON asynchronously.
        /// </summary>
        /// <param name="url">URL to POST to</param>
        /// <param name="data">Object to serialize as JSON</param>
        /// <returns>Task with result object</returns>
        public static async Task<CurlResult> PostJsonAsync(string url, object data)
        {
            return await global::CurlDotNet.Curl.PostJsonAsync(url, data);
        }

        /// <summary>
        /// Download a file synchronously.
        /// </summary>
        /// <param name="url">URL to download from</param>
        /// <param name="outputPath">Path to save the file</param>
        /// <returns>Result object</returns>
        public static CurlResult Download(string url, string outputPath)
        {
            return DownloadAsync(url, outputPath).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Download a file asynchronously.
        /// </summary>
        /// <param name="url">URL to download from</param>
        /// <param name="outputPath">Path to save the file</param>
        /// <returns>Task with result object</returns>
        public static async Task<CurlResult> DownloadAsync(string url, string outputPath)
        {
            return await global::CurlDotNet.Curl.DownloadAsync(url, outputPath);
        }

        /// <summary>
        /// Validate a curl command without executing.
        /// </summary>
        /// <param name="command">Curl command to validate</param>
        /// <returns>Validation result</returns>
        public static ValidationResult Validate(string command)
        {
            return global::CurlDotNet.Curl.Validate(command);
        }

        /// <summary>
        /// Convert curl command to equivalent HttpClient C# code.
        /// </summary>
        /// <param name="command">Curl command to convert</param>
        /// <returns>C# HttpClient code</returns>
        public static string ToHttpClient(string command)
        {
            return global::CurlDotNet.Curl.ToHttpClient(command);
        }

        /// <summary>
        /// Convert curl command to JavaScript fetch code.
        /// </summary>
        /// <param name="command">Curl command to convert</param>
        /// <returns>JavaScript fetch code</returns>
        public static string ToFetch(string command)
        {
            return global::CurlDotNet.Curl.ToFetch(command);
        }

        /// <summary>
        /// Convert curl command to Python requests code.
        /// </summary>
        /// <param name="command">Curl command to convert</param>
        /// <returns>Python requests code</returns>
        public static string ToPython(string command)
        {
            return global::CurlDotNet.Curl.ToPythonRequests(command);
        }

        /// <summary>
        /// Get or set global maximum time for all curl operations (like --max-time).
        /// </summary>
        public static int DefaultMaxTimeSeconds
        {
            get => global::CurlDotNet.Curl.DefaultMaxTimeSeconds;
            set => global::CurlDotNet.Curl.DefaultMaxTimeSeconds = value;
        }

        /// <summary>
        /// Get or set global connection timeout (like --connect-timeout).
        /// </summary>
        public static int DefaultConnectTimeoutSeconds
        {
            get => global::CurlDotNet.Curl.DefaultConnectTimeoutSeconds;
            set => global::CurlDotNet.Curl.DefaultConnectTimeoutSeconds = value;
        }

        /// <summary>
        /// Get or set whether to follow redirects by default (like -L).
        /// </summary>
        public static bool DefaultFollowRedirects
        {
            get => global::CurlDotNet.Curl.DefaultFollowRedirects;
            set => global::CurlDotNet.Curl.DefaultFollowRedirects = value;
        }

        /// <summary>
        /// Get or set whether to ignore SSL errors by default (like -k).
        /// WARNING: Only use this for development/testing!
        /// </summary>
        public static bool DefaultInsecure
        {
            get => global::CurlDotNet.Curl.DefaultInsecure;
            set => global::CurlDotNet.Curl.DefaultInsecure = value;
        }
    }
}