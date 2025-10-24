/***************************************************************************
 * CurlEngine - Core engine for executing curl commands
 *
 * Parses, validates, and executes curl commands using HttpClient
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Exceptions;

namespace CurlDotNet.Core
{
    /// <summary>
    /// Core engine that processes and executes curl commands.
    /// </summary>
    /// <remarks>
    /// <para>This is the heart of CurlDotNet - translates curl commands to HTTP operations.</para>
    /// <para>AI-Usage: This class handles the actual curl command execution.</para>
    /// </remarks>
    internal class CurlEngine : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly ICommandParser _parser;
        private readonly Dictionary<string, IProtocolHandler> _handlers;
        private bool _disposed;

        /// <summary>
        /// Create a new CurlEngine with default HttpClient.
        /// </summary>
        public CurlEngine() : this(new HttpClient())
        {
        }

        /// <summary>
        /// Create a new CurlEngine with custom HttpClient.
        /// </summary>
        public CurlEngine(HttpClient httpClient)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _parser = new CommandParser();
            _handlers = new Dictionary<string, IProtocolHandler>
            {
                ["http"] = new HttpHandler(_httpClient),
                ["https"] = new HttpHandler(_httpClient),
                ["ftp"] = new FtpHandler(),
                ["ftps"] = new FtpHandler(),
                ["file"] = new FileHandler()
            };
        }

        /// <summary>
        /// Execute a curl command string.
        /// </summary>
        /// <param name="command">The curl command to execute</param>
        /// <returns>Result of the curl operation</returns>
        public async Task<CurlResult> ExecuteAsync(string command)
        {
            return await ExecuteAsync(command, CancellationToken.None);
        }

        /// <summary>
        /// Execute a curl command with cancellation support.
        /// </summary>
        public async Task<CurlResult> ExecuteAsync(string command, CancellationToken cancellationToken)
        {
            var options = _parser.Parse(command);
            return await ExecuteAsync(options, cancellationToken);
        }

        /// <summary>
        /// Execute a curl command with custom settings.
        /// </summary>
        public async Task<CurlResult> ExecuteAsync(string command, CurlSettings settings)
        {
            var options = _parser.Parse(command);

            // Apply settings to options
            if (settings != null)
            {
                ApplySettings(options, settings);
            }

            return await ExecuteAsync(options, settings?.CancellationToken ?? CancellationToken.None);
        }

        /// <summary>
        /// Execute with parsed options.
        /// </summary>
        public async Task<CurlResult> ExecuteAsync(CurlOptions options)
        {
            return await ExecuteAsync(options, CancellationToken.None);
        }

        /// <summary>
        /// Execute with parsed options and cancellation.
        /// </summary>
        public async Task<CurlResult> ExecuteAsync(CurlOptions options, CancellationToken cancellationToken)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            if (string.IsNullOrEmpty(options.Url))
                throw new CurlException("No URL specified", 3);

            try
            {
                // Parse URL to determine protocol
                var uri = new Uri(options.Url);
                var protocol = uri.Scheme.ToLower();

                if (!_handlers.TryGetValue(protocol, out var handler))
                {
                    throw new CurlUnsupportedProtocolException($"Unsupported protocol: {protocol}");
                }

                // Execute with appropriate handler
                var result = await handler.ExecuteAsync(options, cancellationToken);
                result.Command = options.OriginalCommand;

                return result;
            }
            catch (UriFormatException ex)
            {
                throw new CurlMalformedUrlException($"Invalid URL: {options.Url}");
            }
            catch (TaskCanceledException ex)
            {
                throw new CurlOperationTimeoutException(options.MaxTime > 0 ? options.MaxTime : 30, options.OriginalCommand);
            }
            catch (HttpRequestException ex)
            {
                var uri = new Uri(options.Url);
                throw new CurlCouldntConnectException(uri.Host, uri.Port > 0 ? uri.Port : (uri.Scheme == "https" ? 443 : 80), options.OriginalCommand);
            }
        }

        /// <summary>
        /// Validate a curl command without executing it.
        /// </summary>
        public ValidationResult Validate(string command)
        {
            try
            {
                var options = _parser.Parse(command);

                if (string.IsNullOrEmpty(options.Url))
                {
                    return new ValidationResult
                    {
                        IsValid = false,
                        Error = "No URL specified"
                    };
                }

                try
                {
                    var uri = new Uri(options.Url);
                    if (!_handlers.ContainsKey(uri.Scheme.ToLower()))
                    {
                        return new ValidationResult
                        {
                            IsValid = false,
                            Error = $"Unsupported protocol: {uri.Scheme}"
                        };
                    }
                }
                catch (UriFormatException)
                {
                    return new ValidationResult
                    {
                        IsValid = false,
                        Error = $"Invalid URL: {options.Url}"
                    };
                }

                return new ValidationResult
                {
                    IsValid = true,
                    ParsedOptions = options
                };
            }
            catch (Exception ex)
            {
                return new ValidationResult
                {
                    IsValid = false,
                    Error = ex.Message
                };
            }
        }

        /// <summary>
        /// Convert curl command to HttpClient code.
        /// </summary>
        public string ToHttpClientCode(string command)
        {
            var options = _parser.Parse(command);
            var sb = new StringBuilder();

            sb.AppendLine("using var client = new HttpClient();");

            // Add headers
            foreach (var header in options.Headers)
            {
                sb.AppendLine($"client.DefaultRequestHeaders.Add(\"{header.Key}\", \"{header.Value}\");");
            }

            // Create request
            var method = options.Method ?? "GET";
            if (method == "GET")
            {
                sb.AppendLine($"var response = await client.GetAsync(\"{options.Url}\");");
            }
            else if (method == "POST" || method == "PUT")
            {
                var methodName = method == "POST" ? "PostAsync" : "PutAsync";
                if (!string.IsNullOrEmpty(options.Data))
                {
                    sb.AppendLine($"var content = new StringContent(\"{options.Data}\", Encoding.UTF8, \"application/json\");");
                    sb.AppendLine($"var response = await client.{methodName}(\"{options.Url}\", content);");
                }
                else
                {
                    sb.AppendLine($"var response = await client.{methodName}(\"{options.Url}\", null);");
                }
            }
            else if (method == "DELETE")
            {
                sb.AppendLine($"var response = await client.DeleteAsync(\"{options.Url}\");");
            }
            else
            {
                sb.AppendLine($"var request = new HttpRequestMessage(HttpMethod.{method}, \"{options.Url}\");");
                if (!string.IsNullOrEmpty(options.Data))
                {
                    sb.AppendLine($"request.Content = new StringContent(\"{options.Data}\", Encoding.UTF8);");
                }
                sb.AppendLine("var response = await client.SendAsync(request);");
            }

            sb.AppendLine("var body = await response.Content.ReadAsStringAsync();");

            return sb.ToString();
        }

        /// <summary>
        /// Convert curl command to JavaScript fetch.
        /// </summary>
        public string ToFetchCode(string command)
        {
            var options = _parser.Parse(command);
            var sb = new StringBuilder();

            sb.AppendLine($"const response = await fetch('{options.Url}', {{");

            if (!string.IsNullOrEmpty(options.Method) && options.Method != "GET")
            {
                sb.AppendLine($"  method: '{options.Method}',");
            }

            if (options.Headers.Any())
            {
                sb.AppendLine("  headers: {");
                foreach (var header in options.Headers)
                {
                    sb.AppendLine($"    '{header.Key}': '{header.Value}',");
                }
                sb.AppendLine("  },");
            }

            if (!string.IsNullOrEmpty(options.Data))
            {
                sb.AppendLine($"  body: JSON.stringify({options.Data}),");
            }

            sb.AppendLine("});");
            sb.AppendLine("const data = await response.json();");

            return sb.ToString();
        }

        /// <summary>
        /// Convert curl command to Python requests.
        /// </summary>
        public string ToPythonCode(string command)
        {
            var options = _parser.Parse(command);
            var sb = new StringBuilder();

            sb.AppendLine("import requests");
            sb.AppendLine();

            var method = (options.Method ?? "GET").ToLower();

            // Build headers dictionary if needed
            if (options.Headers.Any())
            {
                sb.AppendLine("headers = {");
                foreach (var header in options.Headers)
                {
                    sb.AppendLine($"    '{header.Key}': '{header.Value}',");
                }
                sb.AppendLine("}");
                sb.AppendLine();
            }

            // Build request
            sb.Append($"response = requests.{method}('{options.Url}'");

            if (options.Headers.Any())
            {
                sb.Append(", headers=headers");
            }

            if (!string.IsNullOrEmpty(options.Data))
            {
                if (options.Headers.ContainsKey("Content-Type") &&
                    options.Headers["Content-Type"].Contains("json"))
                {
                    sb.Append($", json={options.Data}");
                }
                else
                {
                    sb.Append($", data='{options.Data}'");
                }
            }

            sb.AppendLine(")");
            sb.AppendLine("data = response.json()");

            return sb.ToString();
        }

        private void ApplySettings(CurlOptions options, CurlSettings settings)
        {
            if (settings.MaxTimeSeconds.HasValue)
            {
                options.MaxTime = settings.MaxTimeSeconds.Value;
            }

            if (settings.ConnectTimeoutSeconds.HasValue)
            {
                options.ConnectTimeout = settings.ConnectTimeoutSeconds.Value;
            }

            if (settings.FollowRedirects.HasValue)
            {
                options.FollowLocation = settings.FollowRedirects.Value;
            }

            if (settings.Insecure.HasValue)
            {
                options.Insecure = settings.Insecure.Value;
            }

            if (settings.Headers != null)
            {
                foreach (var header in settings.Headers)
                {
                    options.Headers[header.Key] = header.Value;
                }
            }

            if (settings.OnProgress != null)
            {
                options.ProgressHandler = settings.OnProgress;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Don't dispose the HttpClient if it was provided externally
                    // Only dispose handlers
                    foreach (var handler in _handlers.Values)
                    {
                        if (handler is IDisposable disposable)
                        {
                            disposable.Dispose();
                        }
                    }
                }
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Result of command validation.
    /// </summary>
    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public string Error { get; set; }
        public CurlOptions ParsedOptions { get; set; }
    }
}