/***************************************************************************
 * CurlDotNet - Pure .NET implementation of curl
 *
 * Based on curl by Daniel Stenberg, <daniel@haxx.se>, et al.
 * Original curl source: https://github.com/curl/curl
 *
 * .NET transpilation by Jacob Mellor
 * GitHub Repository: https://github.com/jacob-mellor/curl-dot-net
 * GitHub Profile: https://github.com/jacob-mellor
 *
 * This implementation transpiles curl's C source code to .NET/C#
 * maintaining compatibility with curl's command-line interface.
 *
 * Licensed under the curl license - see COPYING file
 * SPDX-License-Identifier: curl
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using CurlDotNet.Options;
using CurlDotNet.Handlers;
using CurlDotNet.Output;

namespace CurlDotNet
{
    /// <summary>
    /// Main curl implementation class. Provides a curl-like interface for making HTTP/HTTPS requests.
    /// This is a pure .NET implementation that mimics curl's command-line behavior.
    /// Transpiled from curl's tool_operate.c and related source files.
    /// </summary>
    public class CurlExecutor : DependencyInjection.ICurl
    {
        private readonly HttpClient _httpClient;
        private readonly CommandParser _parser;
        private readonly OutputFormatter _outputFormatter;

        public CurlExecutor() : this(new HttpClient())
        {
        }

        public CurlExecutor(HttpClient httpClient)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _parser = new CommandParser();
            _outputFormatter = new OutputFormatter();
        }

        /// <summary>
        /// Execute a curl command string, exactly as you would on the command line.
        /// Returns an OutputResult that can be used programmatically or written to disk.
        /// </summary>
        /// <param name="command">The curl command string (e.g., "curl https://example.com -H 'Accept: application/json'")</param>
        /// <returns>OutputResult containing response data, file paths, and formatted output</returns>
        public async Task<OutputResult> ExecuteAsync(string command)
        {
            if (string.IsNullOrWhiteSpace(command))
                throw new ArgumentException("Command cannot be empty", nameof(command));

            // Parse the command string into options
            var options = _parser.Parse(command);

            // Validate that we have at least a URL
            if (string.IsNullOrEmpty(options.Url))
            {
                throw new CurlException("No URL specified. Usage: curl [options...] <url>");
            }

            // Select the appropriate handler based on the URL scheme
            IProtocolHandler handler = SelectHandler(options.Url);

            // Execute the request
            var response = await handler.ExecuteAsync(options, _httpClient);

            // Handle output (to file or memory) and return result object
            return await _outputFormatter.HandleOutputAsync(response, options);
        }

        /// <summary>
        /// Synchronous wrapper for ExecuteAsync for compatibility.
        /// </summary>
        public OutputResult Execute(string command)
        {
            return ExecuteAsync(command).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Execute a curl command and write output directly to a stream.
        /// Useful for large responses or when piping output.
        /// </summary>
        public async Task ExecuteAsync(string command, Stream outputStream)
        {
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            var result = await ExecuteAsync(command);

            // Write appropriate data to stream
            if (result.BinaryData != null)
            {
                await outputStream.WriteAsync(result.BinaryData, 0, result.BinaryData.Length);
            }
            else if (!string.IsNullOrEmpty(result.FormattedOutput))
            {
                var bytes = Encoding.UTF8.GetBytes(result.FormattedOutput);
                await outputStream.WriteAsync(bytes, 0, bytes.Length);
            }
        }

        /// <summary>
        /// Execute multiple curl commands in parallel (similar to GNU parallel with curl).
        /// </summary>
        public async Task<Dictionary<string, OutputResult>> ExecuteMultipleAsync(params string[] commands)
        {
            var tasks = new Dictionary<string, Task<OutputResult>>();

            foreach (var command in commands)
            {
                tasks[command] = ExecuteAsync(command);
            }

            await Task.WhenAll(tasks.Values);

            var results = new Dictionary<string, OutputResult>();
            foreach (var kvp in tasks)
            {
                results[kvp.Key] = await kvp.Value;
            }

            return results;
        }

        private IProtocolHandler SelectHandler(string url)
        {
            var uri = new Uri(url);

            switch (uri.Scheme.ToLowerInvariant())
            {
                case "http":
                case "https":
                    return new HttpHandler();
                case "ftp":
                case "ftps":
                    return new FtpHandler();
                case "file":
                    return new FileHandler();
                default:
                    throw new CurlException($"Protocol '{uri.Scheme}' is not supported");
            }
        }
    }

    /// <summary>
    /// Exception thrown when curl operations fail.
    /// </summary>
    public class CurlException : Exception
    {
        public CurlException(string message) : base(message) { }
        public CurlException(string message, Exception innerException) : base(message, innerException) { }
    }
}