/***************************************************************************
 * CurlDotNet.Lib - Object-oriented libcurl for .NET
 *
 * Programmatic API similar to libcurl
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Core;

namespace CurlDotNet.Lib
{
    /// <summary>
    /// Object-oriented libcurl-style API for programmatic HTTP operations.
    /// </summary>
    /// <remarks>
    /// <para>This provides a libcurl-like experience with .NET idioms.</para>
    /// <para>AI-Usage: Use this for programmatic HTTP operations when you don't have curl strings.</para>
    /// </remarks>
    public class LibCurl : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly CurlEngine _engine;
        private readonly Dictionary<string, string> _defaultHeaders;

        public LibCurl()
        {
            _httpClient = new HttpClient();
            _engine = new CurlEngine(_httpClient);
            _defaultHeaders = new Dictionary<string, string>();
        }

        /// <summary>
        /// Perform a GET request.
        /// </summary>
        public async Task<CurlResult> GetAsync(string url, Action<CurlOptions> configure = null)
        {
            var options = new CurlOptions { Url = url, Method = "GET" };
            configure?.Invoke(options);
            return await PerformAsync(options);
        }

        /// <summary>
        /// Perform a POST request.
        /// </summary>
        public async Task<CurlResult> PostAsync(string url, object data, Action<CurlOptions> configure = null)
        {
            var options = new CurlOptions
            {
                Url = url,
                Method = "POST",
                Data = SerializeData(data)
            };
            configure?.Invoke(options);
            return await PerformAsync(options);
        }

        /// <summary>
        /// Perform a PUT request.
        /// </summary>
        public async Task<CurlResult> PutAsync(string url, object data, Action<CurlOptions> configure = null)
        {
            var options = new CurlOptions
            {
                Url = url,
                Method = "PUT",
                Data = SerializeData(data)
            };
            configure?.Invoke(options);
            return await PerformAsync(options);
        }

        /// <summary>
        /// Perform a DELETE request.
        /// </summary>
        public async Task<CurlResult> DeleteAsync(string url, Action<CurlOptions> configure = null)
        {
            var options = new CurlOptions { Url = url, Method = "DELETE" };
            configure?.Invoke(options);
            return await PerformAsync(options);
        }

        /// <summary>
        /// Perform a custom request with full control.
        /// </summary>
        public async Task<CurlResult> PerformAsync(CurlOptions options)
        {
            // Apply default headers
            foreach (var header in _defaultHeaders)
            {
#if NETSTANDARD2_0 || NET48
                if (!options.Headers.ContainsKey(header.Key))
                {
                    options.Headers[header.Key] = header.Value;
                }
#else
                options.Headers.TryAdd(header.Key, header.Value);
#endif
            }

            return await _engine.ExecuteAsync(options);
        }

        /// <summary>
        /// Set a default header for all requests.
        /// </summary>
        public LibCurl WithHeader(string key, string value)
        {
            _defaultHeaders[key] = value;
            return this;
        }

        /// <summary>
        /// Set bearer token authentication.
        /// </summary>
        public LibCurl WithBearerToken(string token)
        {
            return WithHeader("Authorization", $"Bearer {token}");
        }

        /// <summary>
        /// Set basic authentication.
        /// </summary>
        public LibCurl WithBasicAuth(string username, string password)
        {
            var auth = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{username}:{password}"));
            return WithHeader("Authorization", $"Basic {auth}");
        }

        private string SerializeData(object data)
        {
            if (data == null) return null;
            if (data is string s) return s;

            #if NETSTANDARD2_0
            // Use Newtonsoft.Json for older frameworks
            return Newtonsoft.Json.JsonConvert.SerializeObject(data);
            #else
            return System.Text.Json.JsonSerializer.Serialize(data);
            #endif
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}