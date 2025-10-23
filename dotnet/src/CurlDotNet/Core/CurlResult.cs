/***************************************************************************
 * CurlResult - Fluent result object for curl operations
 *
 * Provides data extraction, chaining, transformation, and validation
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CurlDotNet.Core
{
    /// <summary>
    /// Fluent result object returned from curl operations.
    /// </summary>
    /// <remarks>
    /// <para>Provides chainable operations for data extraction, transformation, and validation.</para>
    /// <para>AI-Usage: This is the primary way to work with curl responses in .NET.</para>
    /// </remarks>
    public class CurlResult
    {
        /// <summary>
        /// The HTTP status code (200, 404, etc.)
        /// </summary>
        public int StatusCode { get; set; }

        /// <summary>
        /// The response body as string
        /// </summary>
        public string Body { get; set; }

        /// <summary>
        /// The response headers
        /// </summary>
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Binary data if response is not text
        /// </summary>
        public byte[] BinaryData { get; set; }

        /// <summary>
        /// The original curl command that was executed
        /// </summary>
        public string Command { get; set; }

        /// <summary>
        /// Timing information
        /// </summary>
        public CurlTimings Timings { get; set; }

        /// <summary>
        /// Files that were written (if using -o flag)
        /// </summary>
        public List<string> OutputFiles { get; set; } = new List<string>();

        #region Data Extraction

        /// <summary>
        /// Parse response as JSON and deserialize to type T.
        /// </summary>
        public T AsJson<T>()
        {
            #if NETSTANDARD2_0
            return Newtonsoft.Json.JsonConvert.DeserializeObject<T>(Body);
            #else
            return System.Text.Json.JsonSerializer.Deserialize<T>(Body);
            #endif
        }

        /// <summary>
        /// Parse response as dynamic JSON.
        /// </summary>
        public dynamic AsJson()
        {
            #if NETSTANDARD2_0
            return Newtonsoft.Json.JsonConvert.DeserializeObject(Body);
            #else
            return System.Text.Json.JsonDocument.Parse(Body);
            #endif
        }

        /// <summary>
        /// Get a specific header value.
        /// </summary>
        public string Header(string key)
        {
            return Headers.TryGetValue(key, out var value) ? value : null;
        }

        /// <summary>
        /// Save body to file.
        /// </summary>
        public CurlResult SaveTo(string path)
        {
            if (BinaryData != null)
            {
                File.WriteAllBytes(path, BinaryData);
            }
            else
            {
                File.WriteAllText(path, Body);
            }
            OutputFiles.Add(path);
            return this;
        }

        #endregion

        #region Chaining Requests

        /// <summary>
        /// Execute a follow-up curl command using data from this result.
        /// </summary>
        public async Task<CurlResult> FollowUp(string curlCommand)
        {
            // Can use data from current result in the new command
            var processedCommand = curlCommand
                .Replace("{body}", Body)
                .Replace("{status}", StatusCode.ToString());

            return await Curl.Execute(processedCommand);
        }

        /// <summary>
        /// Retry the same request.
        /// </summary>
        public async Task<CurlResult> Retry()
        {
            return await Curl.Execute(Command);
        }

        /// <summary>
        /// Retry with modifications.
        /// </summary>
        public async Task<CurlResult> RetryWith(Action<CurlSettings> configure)
        {
            var settings = new CurlSettings();
            configure(settings);
            return await Curl.Execute(Command, settings);
        }

        #endregion

        #region Transformation

        /// <summary>
        /// Transform the result using a function.
        /// </summary>
        public T Transform<T>(Func<CurlResult, T> transformer)
        {
            return transformer(this);
        }

        /// <summary>
        /// Map the body to a new value.
        /// </summary>
        public CurlResult Map(Func<string, string> mapper)
        {
            Body = mapper(Body);
            return this;
        }

        /// <summary>
        /// Filter lines in the body.
        /// </summary>
        public CurlResult FilterLines(Func<string, bool> predicate)
        {
            var lines = Body.Split('\n').Where(predicate);
            Body = string.Join("\n", lines);
            return this;
        }

        /// <summary>
        /// Apply jq-like JSON query.
        /// </summary>
        public string Query(string jsonPath)
        {
            var json = AsJson();
            // Simple JSON path implementation
            // In production, use a proper JSON path library
            return ExtractJsonPath(json, jsonPath);
        }

        #endregion

        #region Validation/Testing

        /// <summary>
        /// Assert the status code matches expected.
        /// </summary>
        public CurlResult AssertStatus(int expected)
        {
            if (StatusCode != expected)
            {
                throw new CurlAssertionException($"Expected status {expected} but got {StatusCode}");
            }
            return this;
        }

        /// <summary>
        /// Assert the body contains text.
        /// </summary>
        public CurlResult AssertContains(string text)
        {
            if (!Body.Contains(text))
            {
                throw new CurlAssertionException($"Body does not contain '{text}'");
            }
            return this;
        }

        /// <summary>
        /// Assert the body matches regex.
        /// </summary>
        public CurlResult AssertMatches(string pattern)
        {
            if (!System.Text.RegularExpressions.Regex.IsMatch(Body, pattern))
            {
                throw new CurlAssertionException($"Body does not match pattern '{pattern}'");
            }
            return this;
        }

        /// <summary>
        /// Assert a header exists with expected value.
        /// </summary>
        public CurlResult AssertHeader(string key, string expectedValue = null)
        {
            if (!Headers.ContainsKey(key))
            {
                throw new CurlAssertionException($"Header '{key}' not found");
            }

            if (expectedValue != null && Headers[key] != expectedValue)
            {
                throw new CurlAssertionException($"Header '{key}' expected '{expectedValue}' but was '{Headers[key]}'");
            }

            return this;
        }

        /// <summary>
        /// Check if request succeeded (2xx status).
        /// </summary>
        public bool IsSuccess => StatusCode >= 200 && StatusCode < 300;

        /// <summary>
        /// Throw if not successful.
        /// </summary>
        public CurlResult EnsureSuccess()
        {
            if (!IsSuccess)
            {
                throw new CurlHttpException($"Request failed with status {StatusCode}", StatusCode);
            }
            return this;
        }

        #endregion

        #region Output Operations (like curl command-line)

        /// <summary>
        /// Write to console like curl does.
        /// </summary>
        public CurlResult WriteToConsole()
        {
            Console.WriteLine(Body);
            return this;
        }

        /// <summary>
        /// Write to console with headers (like curl -i).
        /// </summary>
        public CurlResult WriteToConsoleWithHeaders()
        {
            Console.WriteLine($"HTTP/1.1 {StatusCode}");
            foreach (var header in Headers)
            {
                Console.WriteLine($"{header.Key}: {header.Value}");
            }
            Console.WriteLine();
            Console.WriteLine(Body);
            return this;
        }

        /// <summary>
        /// Write to directory respecting curl output flags.
        /// </summary>
        public CurlResult WriteToDirectory(string directory)
        {
            if (OutputFiles.Any())
            {
                foreach (var file in OutputFiles)
                {
                    var fileName = Path.GetFileName(file);
                    var destPath = Path.Combine(directory, fileName);
                    File.Copy(file, destPath, overwrite: true);
                }
            }
            return this;
        }

        /// <summary>
        /// Get verbose output like curl -v.
        /// </summary>
        public string GetVerboseOutput()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"> {Command}");
            sb.AppendLine($"< HTTP/1.1 {StatusCode}");
            foreach (var header in Headers)
            {
                sb.AppendLine($"< {header.Key}: {header.Value}");
            }
            sb.AppendLine();
            sb.AppendLine(Body);
            return sb.ToString();
        }

        #endregion

        #region Timing Operations

        /// <summary>
        /// Get timing information like curl -w.
        /// </summary>
        public string GetTimingInfo()
        {
            if (Timings == null) return "No timing information available";

            return $@"
time_namelookup:  {Timings.NameLookup}ms
time_connect:     {Timings.Connect}ms
time_appconnect:  {Timings.AppConnect}ms
time_pretransfer: {Timings.PreTransfer}ms
time_redirect:    {Timings.Redirect}ms
time_starttransfer: {Timings.StartTransfer}ms
time_total:       {Timings.Total}ms
";
        }

        #endregion

        private string ExtractJsonPath(dynamic json, string path)
        {
            // Simplified JSON path extraction
            // In production, use a proper library like Json.NET's SelectToken
            return json?.ToString() ?? "";
        }
    }

    /// <summary>
    /// Timing information for curl operations.
    /// </summary>
    public class CurlTimings
    {
        public double NameLookup { get; set; }
        public double Connect { get; set; }
        public double AppConnect { get; set; }
        public double PreTransfer { get; set; }
        public double Redirect { get; set; }
        public double StartTransfer { get; set; }
        public double Total { get; set; }
    }

    /// <summary>
    /// Exception thrown when an assertion fails.
    /// </summary>
    public class CurlAssertionException : Exception
    {
        public CurlAssertionException(string message) : base(message) { }
    }

    /// <summary>
    /// Exception thrown for HTTP errors.
    /// </summary>
    public class CurlHttpException : Exception
    {
        public int StatusCode { get; }

        public CurlHttpException(string message, int statusCode) : base(message)
        {
            StatusCode = statusCode;
        }
    }
}