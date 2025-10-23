/***************************************************************************
 * Curl - Static API for copy-paste curl commands
 *
 * The killer feature: Copy curl commands from anywhere and they just work!
 *
 * This could revolutionize how developers use HTTP in every language.
 * Imagine: Same curl commands working in C#, Rust, JavaScript, Python...
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Core;

namespace CurlDotNet
{
    /// <summary>
    /// Static curl API - Just paste your curl command!
    /// </summary>
    /// <remarks>
    /// <para>Copy curl commands from Stack Overflow, documentation, or AI responses.</para>
    /// <para>They just work. No translation needed.</para>
    /// <para>AI-Usage: This is how curl should work in every language.</para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // From Stack Overflow
    /// var result = await Curl.Execute("curl -X POST https://api.example.com/users -H 'Content-Type: application/json' -d '{\"name\":\"John\"}'");
    ///
    /// // From API documentation
    /// var data = await Curl.Execute("curl https://api.github.com/user -H 'Authorization: token OAUTH-TOKEN'");
    ///
    /// // From ChatGPT/Claude
    /// var response = await Curl.Execute("curl -L -o output.json https://example.com/data.json");
    /// </code>
    /// </example>
    public static class Curl
    {
        private static readonly CurlEngine _engine = new CurlEngine();

        // Global settings - thread-safe with volatile
        private static volatile int _defaultMaxTimeSeconds = 0; // 0 = no timeout
        private static volatile int _defaultConnectTimeoutSeconds = 0;
        private static volatile bool _defaultFollowRedirects = false;
        private static volatile bool _defaultInsecure = false;

        /// <summary>
        /// Set global maximum time for all curl operations (like --max-time).
        /// Thread-safe.
        /// </summary>
        public static int DefaultMaxTimeSeconds
        {
            get => _defaultMaxTimeSeconds;
            set => _defaultMaxTimeSeconds = value;
        }

        /// <summary>
        /// Set global connection timeout (like --connect-timeout).
        /// Thread-safe.
        /// </summary>
        public static int DefaultConnectTimeoutSeconds
        {
            get => _defaultConnectTimeoutSeconds;
            set => _defaultConnectTimeoutSeconds = value;
        }

        /// <summary>
        /// Set whether to follow redirects by default (like -L).
        /// Thread-safe.
        /// </summary>
        public static bool DefaultFollowRedirects
        {
            get => _defaultFollowRedirects;
            set => _defaultFollowRedirects = value;
        }

        /// <summary>
        /// Set whether to ignore SSL errors by default (like -k).
        /// Thread-safe.
        /// </summary>
        public static bool DefaultInsecure
        {
            get => _defaultInsecure;
            set => _defaultInsecure = value;
        }

        /// <summary>
        /// Execute any curl command - the main API.
        /// </summary>
        /// <param name="command">Copy-paste your curl command here</param>
        /// <returns>Fluent result object</returns>
        public static async Task<CurlResult> Execute(string command)
        {
            return await _engine.ExecuteAsync(command);
        }

        /// <summary>
        /// Execute with cancellation support.
        /// </summary>
        public static async Task<CurlResult> Execute(string command, CancellationToken cancellationToken)
        {
            return await _engine.ExecuteAsync(command, cancellationToken);
        }

        /// <summary>
        /// Execute with .NET-specific settings (cancellation, progress, etc).
        /// </summary>
        public static async Task<CurlResult> Execute(string command, CurlSettings settings)
        {
            return await _engine.ExecuteAsync(command, settings);
        }

        /// <summary>
        /// Quick GET request.
        /// </summary>
        public static async Task<CurlResult> Get(string url)
        {
            return await Execute($"curl {url}");
        }

        /// <summary>
        /// Quick POST request.
        /// </summary>
        public static async Task<CurlResult> Post(string url, string data)
        {
            return await Execute($"curl -X POST -d '{data}' {url}");
        }

        /// <summary>
        /// Quick POST with JSON.
        /// </summary>
        public static async Task<CurlResult> PostJson(string url, object data)
        {
            var json = SerializeJson(data);
            return await Execute($"curl -X POST -H 'Content-Type: application/json' -d '{json}' {url}");
        }

        /// <summary>
        /// Download a file.
        /// </summary>
        public static async Task<CurlResult> Download(string url, string outputPath)
        {
            return await Execute($"curl -o {outputPath} {url}");
        }

        /// <summary>
        /// Execute multiple curl commands in parallel.
        /// </summary>
        public static async Task<CurlResult[]> ExecuteMany(params string[] commands)
        {
            var tasks = commands.Select(cmd => Execute(cmd));
            return await Task.WhenAll(tasks);
        }

        /// <summary>
        /// Validate a curl command without executing.
        /// </summary>
        public static ValidationResult Validate(string command)
        {
            return _engine.Validate(command);
        }

        /// <summary>
        /// Convert curl command to equivalent HttpClient code.
        /// Great for learning and migration!
        /// </summary>
        public static string ToHttpClient(string command)
        {
            return _engine.ToHttpClientCode(command);
        }

        /// <summary>
        /// Convert curl command to equivalent JavaScript fetch.
        /// </summary>
        public static string ToFetch(string command)
        {
            return _engine.ToFetchCode(command);
        }

        /// <summary>
        /// Convert curl command to Python requests.
        /// </summary>
        public static string ToPythonRequests(string command)
        {
            return _engine.ToPythonCode(command);
        }

        private static string SerializeJson(object data)
        {
            #if NETSTANDARD2_0
            return Newtonsoft.Json.JsonConvert.SerializeObject(data);
            #else
            return System.Text.Json.JsonSerializer.Serialize(data);
            #endif
        }
    }
}