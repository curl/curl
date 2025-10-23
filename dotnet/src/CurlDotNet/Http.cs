/***************************************************************************
 * Simplified static API for CurlDotNet
 *
 * The simplest possible way to make HTTP requests with curl syntax
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 * Sponsored by Iron Software (ironsoftware.com)
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Text.Json;

namespace CurlDotNet
{
    /// <summary>
    /// Static helper class for the absolute simplest curl usage
    /// Just like using curl from the command line!
    /// </summary>
    public static class Http
    {
        private static readonly Curl _sharedInstance = new Curl();

        /// <summary>
        /// Execute any curl command - just paste it in!
        /// Usage: var html = await Http.Curl("curl https://example.com");
        /// </summary>
        public static async Task<CurlResult> Curl(string command, Action<CurlProgress> onProgress = null)
        {
            return await CurlExtensions.Execute(command, onProgress);
        }

        /// <summary>
        /// Simple GET request
        /// Usage: var data = await Http.Get("https://api.example.com/users");
        /// </summary>
        public static async Task<CurlResult> Get(string url, Dictionary<string, string> headers = null)
        {
            var command = BuildCommand("GET", url, headers);
            return await Curl(command);
        }

        /// <summary>
        /// POST JSON data
        /// Usage: var result = await Http.Post("https://api.example.com/users", new { name = "John" });
        /// </summary>
        public static async Task<CurlResult> Post<T>(string url, T data, Dictionary<string, string> headers = null)
        {
            var json = JsonSerializer.Serialize(data);
            var command = $"curl -X POST -H 'Content-Type: application/json' -d '{json}' {url}";

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    command = command.Replace(url, $"-H '{header.Key}: {header.Value}' {url}");
                }
            }

            return await Curl(command);
        }

        /// <summary>
        /// PUT JSON data
        /// </summary>
        public static async Task<CurlResult> Put<T>(string url, T data, Dictionary<string, string> headers = null)
        {
            var json = JsonSerializer.Serialize(data);
            var command = $"curl -X PUT -H 'Content-Type: application/json' -d '{json}' {url}";

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    command = command.Replace(url, $"-H '{header.Key}: {header.Value}' {url}");
                }
            }

            return await Curl(command);
        }

        /// <summary>
        /// DELETE request
        /// </summary>
        public static async Task<CurlResult> Delete(string url, Dictionary<string, string> headers = null)
        {
            var command = BuildCommand("DELETE", url, headers);
            return await Curl(command);
        }

        /// <summary>
        /// Download a file with progress callback
        /// Usage: await Http.Download("https://example.com/file.zip", @"C:\Downloads\file.zip", progress => Console.WriteLine($"{progress.PercentComplete}%"));
        /// </summary>
        public static async Task<CurlResult> Download(string url, string outputPath, Action<CurlProgress> onProgress = null)
        {
            var command = $"curl -o \"{outputPath}\" -L {url}";
            var result = await Curl(command, onProgress);
            return result;
        }

        /// <summary>
        /// Upload a file
        /// </summary>
        public static async Task<CurlResult> Upload(string url, string filePath, Dictionary<string, string> headers = null)
        {
            var command = $"curl -T \"{filePath}\" {url}";

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    command = command.Replace(url, $"-H '{header.Key}: {header.Value}' {url}");
                }
            }

            return await Curl(command);
        }

        /// <summary>
        /// Make authenticated request with Bearer token
        /// </summary>
        public static async Task<CurlResult> WithAuth(string url, string token, string method = "GET")
        {
            var command = $"curl -X {method} -H 'Authorization: Bearer {token}' {url}";
            return await Curl(command);
        }

        /// <summary>
        /// Make request with basic authentication
        /// </summary>
        public static async Task<CurlResult> WithBasicAuth(string url, string username, string password, string method = "GET")
        {
            var command = $"curl -X {method} -u {username}:{password} {url}";
            return await Curl(command);
        }

        /// <summary>
        /// Execute GraphQL query
        /// </summary>
        public static async Task<CurlResult> GraphQL(string url, string query, object variables = null)
        {
            var payload = new
            {
                query = query,
                variables = variables
            };

            return await Post(url, payload, new Dictionary<string, string>
            {
                ["Content-Type"] = "application/json",
                ["Accept"] = "application/json"
            });
        }

        /// <summary>
        /// Execute multiple requests in parallel
        /// </summary>
        public static async Task<Dictionary<string, CurlResult>> Parallel(params (string name, string command)[] requests)
        {
            var tasks = new Dictionary<string, Task<CurlResult>>();

            foreach (var (name, command) in requests)
            {
                tasks[name] = Curl(command);
            }

            await Task.WhenAll(tasks.Values);

            var results = new Dictionary<string, CurlResult>();
            foreach (var kvp in tasks)
            {
                results[kvp.Key] = await kvp.Value;
            }

            return results;
        }

        /// <summary>
        /// Create a webhook receiver (for testing webhooks)
        /// </summary>
        public static async Task<CurlResult> Webhook(string url, TimeSpan timeout)
        {
            var command = $"curl -X POST -m {(int)timeout.TotalSeconds} {url}";
            return await Curl(command);
        }

        /// <summary>
        /// Health check endpoint
        /// </summary>
        public static async Task<bool> IsHealthy(string url, int expectedStatus = 200)
        {
            try
            {
                var result = await Get(url);
                return result.StatusCode == expectedStatus;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Fetch and parse JSON in one call
        /// Usage: var users = await Http.GetJson<List<User>>("https://api.example.com/users");
        /// </summary>
        public static async Task<T> GetJson<T>(string url)
        {
            var result = await Get(url);
            return result.ThrowOnError().ToJson<T>();
        }

        /// <summary>
        /// Post and get typed response
        /// </summary>
        public static async Task<TResponse> PostJson<TRequest, TResponse>(string url, TRequest data)
        {
            var result = await Post(url, data);
            return result.ThrowOnError().ToJson<TResponse>();
        }

        private static string BuildCommand(string method, string url, Dictionary<string, string> headers)
        {
            var command = $"curl -X {method}";

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    command += $" -H '{header.Key}: {header.Value}'";
                }
            }

            command += $" {url}";
            return command;
        }
    }

    /// <summary>
    /// Namespace options for different use cases
    /// Developers can use whichever feels most natural
    /// </summary>
    namespace Simple
    {
        public static class Curl
        {
            /// <summary>
            /// The simplest possible API - just Curl()
            /// Usage: var result = await Curl("https://api.example.com");
            /// </summary>
            public static async Task<string> Go(string commandOrUrl)
            {
                // Auto-detect if it's a URL or full curl command
                if (!commandOrUrl.Contains(" ") && commandOrUrl.StartsWith("http"))
                {
                    commandOrUrl = "curl " + commandOrUrl;
                }
                else if (!commandOrUrl.StartsWith("curl"))
                {
                    commandOrUrl = "curl " + commandOrUrl;
                }

                var result = await Http.Curl(commandOrUrl);
                return result.Body;
            }
        }
    }
}