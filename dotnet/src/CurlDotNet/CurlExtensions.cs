/***************************************************************************
 * Fluent API Extensions for CurlDotNet
 *
 * Maximum developer usability - just copy/paste curl commands!
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 * Sponsored by Iron Software (ironsoftware.com)
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using CurlDotNet.Output;

namespace CurlDotNet
{
    /// <summary>
    /// Fluent API extensions for curl responses
    /// </summary>
    public static class CurlExtensions
    {
        /// <summary>
        /// Execute a curl command with the simplest possible syntax
        /// Usage: var result = await Curl.Execute("curl https://api.example.com");
        /// </summary>
        public static async Task<CurlResult> Execute(string command, Action<CurlProgress> onProgress = null)
        {
            var curl = new Curl();

            // Make 'curl' prefix optional
            if (!command.TrimStart().StartsWith("curl", StringComparison.OrdinalIgnoreCase) &&
                (command.StartsWith("http", StringComparison.OrdinalIgnoreCase) ||
                 command.StartsWith("-", StringComparison.OrdinalIgnoreCase)))
            {
                command = "curl " + command;
            }

            var outputResult = await curl.ExecuteAsync(command);
            return new CurlResult(outputResult, onProgress);
        }

        /// <summary>
        /// Synchronous execution for simple scenarios
        /// </summary>
        public static CurlResult Get(string url)
        {
            return Execute($"curl {url}").GetAwaiter().GetResult();
        }

        /// <summary>
        /// POST with automatic JSON serialization
        /// </summary>
        public static async Task<CurlResult> Post<T>(string url, T data)
        {
            var json = JsonSerializer.Serialize(data);
            return await Execute($"curl -X POST -H 'Content-Type: application/json' -d '{json}' {url}");
        }
    }

    /// <summary>
    /// Fluent result object with method chaining support
    /// </summary>
    public class CurlResult
    {
        private readonly OutputResult _output;
        private readonly Action<CurlProgress> _progressCallback;

        public CurlResult(OutputResult output, Action<CurlProgress> progressCallback = null)
        {
            _output = output;
            _progressCallback = progressCallback;
        }

        // Implicit conversion to string for simplest usage
        public static implicit operator string(CurlResult result)
        {
            return result._output.ResponseBody ?? result._output.FormattedOutput;
        }

        // Direct property access
        public string Body => _output.ResponseBody;
        public int StatusCode => _output.StatusCode;
        public string Headers => _output.Headers;
        public bool IsSuccess => !_output.IsError && StatusCode >= 200 && StatusCode < 300;
        public bool IsError => _output.IsError;
        public string ErrorMessage => _output.ErrorMessage;

        /// <summary>
        /// Parse JSON response to strongly typed object
        /// </summary>
        public T ToJson<T>(JsonSerializerOptions options = null)
        {
            if (string.IsNullOrEmpty(Body))
                throw new InvalidOperationException("Response body is empty");

            return JsonSerializer.Deserialize<T>(Body, options ?? new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
        }

        /// <summary>
        /// Parse JSON response to dynamic object for exploration
        /// </summary>
        public dynamic ToDynamic()
        {
            if (string.IsNullOrEmpty(Body))
                throw new InvalidOperationException("Response body is empty");

            return JsonSerializer.Deserialize<dynamic>(Body);
        }

        /// <summary>
        /// Parse XML response
        /// </summary>
        public XDocument ToXml()
        {
            if (string.IsNullOrEmpty(Body))
                throw new InvalidOperationException("Response body is empty");

            return XDocument.Parse(Body);
        }

        /// <summary>
        /// Save response to file
        /// </summary>
        public async Task<CurlResult> SaveTo(string path, bool createDirectory = true)
        {
            if (createDirectory)
            {
                var directory = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(directory))
                    Directory.CreateDirectory(directory);
            }

            if (_output.BinaryData != null)
            {
                await File.WriteAllBytesAsync(path, _output.BinaryData);
            }
            else
            {
                await File.WriteAllTextAsync(path, Body ?? "");
            }

            return this;
        }

        /// <summary>
        /// Save to file synchronously
        /// </summary>
        public CurlResult SaveToSync(string path, bool createDirectory = true)
        {
            SaveTo(path, createDirectory).GetAwaiter().GetResult();
            return this;
        }

        /// <summary>
        /// Throw exception if request failed
        /// </summary>
        public CurlResult ThrowOnError()
        {
            if (IsError)
            {
                throw new CurlException($"Request failed with status {StatusCode}: {ErrorMessage}");
            }

            if (StatusCode >= 400)
            {
                throw new CurlException($"Request returned error status {StatusCode}");
            }

            return this;
        }

        /// <summary>
        /// Ensure specific status code
        /// </summary>
        public CurlResult EnsureStatus(int expectedStatus)
        {
            if (StatusCode != expectedStatus)
            {
                throw new CurlException($"Expected status {expectedStatus} but got {StatusCode}");
            }
            return this;
        }

        /// <summary>
        /// Ensure status code is in success range (2xx)
        /// </summary>
        public CurlResult EnsureSuccess()
        {
            if (!IsSuccess)
            {
                throw new CurlException($"Request failed with status {StatusCode}");
            }
            return this;
        }

        /// <summary>
        /// Log the response for debugging
        /// </summary>
        public CurlResult Log(Action<string> logger = null, bool includeHeaders = false)
        {
            var log = logger ?? Console.WriteLine;

            log($"[CURL] Status: {StatusCode}");

            if (includeHeaders && !string.IsNullOrEmpty(Headers))
            {
                log($"[CURL] Headers:\n{Headers}");
            }

            if (!string.IsNullOrEmpty(Body))
            {
                var preview = Body.Length > 500 ? Body.Substring(0, 500) + "..." : Body;
                log($"[CURL] Body: {preview}");
            }

            if (IsError)
            {
                log($"[CURL] ERROR: {ErrorMessage}");
            }

            return this;
        }

        /// <summary>
        /// Extract header value
        /// </summary>
        public string GetHeader(string name)
        {
            if (string.IsNullOrEmpty(Headers))
                return null;

            foreach (var line in Headers.Split('\n'))
            {
                var parts = line.Split(':', 2);
                if (parts.Length == 2 && parts[0].Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    return parts[1].Trim();
                }
            }

            return null;
        }

        /// <summary>
        /// Get response as stream
        /// </summary>
        public Stream ToStream()
        {
            return _output.GetStream();
        }

        /// <summary>
        /// Retry the request if it failed
        /// </summary>
        public async Task<CurlResult> RetryOnFailure(int maxRetries = 3, int delayMs = 1000)
        {
            if (IsSuccess)
                return this;

            // TODO: Store original command and retry
            await Task.Delay(delayMs);
            return this;
        }

        /// <summary>
        /// Transform the response body
        /// </summary>
        public CurlResult Transform(Func<string, string> transformer)
        {
            if (!string.IsNullOrEmpty(Body))
            {
                _output.ResponseBody = transformer(Body);
            }
            return this;
        }

        /// <summary>
        /// Chain another curl request using data from this response
        /// </summary>
        public async Task<CurlResult> Then(Func<CurlResult, string> nextCommand)
        {
            var command = nextCommand(this);
            return await CurlExtensions.Execute(command, _progressCallback);
        }

        /// <summary>
        /// Extract value using JSONPath-like syntax
        /// </summary>
        public string Extract(string path)
        {
            var json = ToJson<Dictionary<string, object>>();
            // Simple path extraction - could be enhanced with real JSONPath
            var parts = path.Split('.');
            object current = json;

            foreach (var part in parts)
            {
                if (current is Dictionary<string, object> dict && dict.ContainsKey(part))
                {
                    current = dict[part];
                }
                else
                {
                    return null;
                }
            }

            return current?.ToString();
        }
    }

    /// <summary>
    /// Progress information for downloads/uploads
    /// </summary>
    public class CurlProgress
    {
        public long TotalBytes { get; set; }
        public long BytesTransferred { get; set; }
        public double PercentComplete => TotalBytes > 0 ? (BytesTransferred * 100.0 / TotalBytes) : 0;
        public TimeSpan ElapsedTime { get; set; }
        public double BytesPerSecond { get; set; }
        public TimeSpan EstimatedTimeRemaining { get; set; }
        public string Operation { get; set; } // "download" or "upload"

        public override string ToString()
        {
            return $"{PercentComplete:F1}% ({BytesTransferred}/{TotalBytes} bytes) - {BytesPerSecond / 1024:F1} KB/s";
        }
    }
}