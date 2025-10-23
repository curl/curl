/***************************************************************************
 * HttpHandler - HTTP/HTTPS protocol handler
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Exceptions;

namespace CurlDotNet.Core
{
    /// <summary>
    /// Handler for HTTP and HTTPS protocols.
    /// </summary>
    public class HttpHandler : IProtocolHandler
    {
        private readonly HttpClient _httpClient;
        private readonly bool _ownsHttpClient;

        /// <summary>
        /// Create handler with default HttpClient.
        /// </summary>
        public HttpHandler() : this(CreateDefaultHttpClient(), true)
        {
        }

        /// <summary>
        /// Create handler with custom HttpClient.
        /// </summary>
        public HttpHandler(HttpClient httpClient, bool ownsHttpClient = false)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _ownsHttpClient = ownsHttpClient;
        }

        public async Task<CurlResult> ExecuteAsync(CurlOptions options, CancellationToken cancellationToken)
        {
            var request = CreateRequest(options);
            var startTime = DateTime.UtcNow;
            var timings = new CurlTimings();

            try
            {
                // Configure timeout
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                if (options.MaxTime > 0)
                {
                    cts.CancelAfter(TimeSpan.FromSeconds(options.MaxTime));
                }

                // Send request
                timings.PreTransfer = (DateTime.UtcNow - startTime).TotalMilliseconds;
                var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
                timings.StartTransfer = (DateTime.UtcNow - startTime).TotalMilliseconds;

                // Handle redirects manually if needed
                if (options.FollowLocation && IsRedirect(response.StatusCode))
                {
                    return await HandleRedirect(response, options, cts.Token, timings, startTime);
                }

                // Read response
                var result = await CreateResult(response, options, timings, startTime);

                // Handle output file
                if (!string.IsNullOrEmpty(options.OutputFile))
                {
                    await WriteOutputFile(result, options.OutputFile);
                }

                timings.Total = (DateTime.UtcNow - startTime).TotalMilliseconds;
                result.Timings = timings;

                return result;
            }
            catch (TaskCanceledException)
            {
                if (cancellationToken.IsCancellationRequested)
                    throw new CurlAbortedByCallbackException("Operation cancelled");
                throw new CurlOperationTimeoutException(options.MaxTime > 0 ? options.MaxTime : 30, options.OriginalCommand);
            }
            catch (HttpRequestException ex)
            {
                var uri = new Uri(options.Url);
                throw new CurlCouldntConnectException(uri.Host, uri.Port > 0 ? uri.Port : (uri.Scheme == "https" ? 443 : 80), options.OriginalCommand);
            }
        }

        public bool SupportsProtocol(string protocol)
        {
            return protocol == "http" || protocol == "https";
        }

        private HttpRequestMessage CreateRequest(CurlOptions options)
        {
            var method = GetHttpMethod(options);
            var request = new HttpRequestMessage(method, options.Url);

            // Add headers
            foreach (var header in options.Headers)
            {
                if (IsContentHeader(header.Key))
                {
                    // Will be added with content
                    continue;
                }

                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            // Set user agent
            if (!string.IsNullOrEmpty(options.UserAgent))
            {
                request.Headers.UserAgent.ParseAdd(options.UserAgent);
            }

            // Set referer
            if (!string.IsNullOrEmpty(options.Referer))
            {
                request.Headers.Referrer = new Uri(options.Referer);
            }

            // Set cookies
            if (!string.IsNullOrEmpty(options.Cookie))
            {
                request.Headers.Add("Cookie", options.Cookie);
            }

            // Set authorization
            if (options.Credentials != null)
            {
                var auth = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                    $"{options.Credentials.UserName}:{options.Credentials.Password}"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", auth);
            }

            // Set range
            if (!string.IsNullOrEmpty(options.Range))
            {
                request.Headers.Range = ParseRange(options.Range);
            }

            // Add content
            if (ShouldHaveContent(method, options))
            {
                request.Content = CreateContent(options);
            }

            return request;
        }

        private HttpMethod GetHttpMethod(CurlOptions options)
        {
            if (!string.IsNullOrEmpty(options.CustomMethod))
            {
                return new HttpMethod(options.CustomMethod);
            }

            return options.Method?.ToUpper() switch
            {
                "GET" => HttpMethod.Get,
                "POST" => HttpMethod.Post,
                "PUT" => HttpMethod.Put,
                "DELETE" => HttpMethod.Delete,
                "HEAD" => HttpMethod.Head,
                "OPTIONS" => HttpMethod.Options,
                "PATCH" => new HttpMethod("PATCH"),
                _ => HttpMethod.Get
            };
        }

        private bool ShouldHaveContent(HttpMethod method, CurlOptions options)
        {
            if (method == HttpMethod.Get || method == HttpMethod.Head)
                return false;

            return !string.IsNullOrEmpty(options.Data) ||
                   options.BinaryData != null ||
                   options.FormData.Any() ||
                   options.Files.Any();
        }

        private HttpContent CreateContent(CurlOptions options)
        {
            // Multipart form data
            if (options.Files.Any() || options.FormData.Any())
            {
                var content = new MultipartFormDataContent();

                foreach (var field in options.FormData)
                {
                    content.Add(new StringContent(field.Value), field.Key);
                }

                foreach (var file in options.Files)
                {
                    var fileContent = new ByteArrayContent(File.ReadAllBytes(file.Value));
                    fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
                    content.Add(fileContent, file.Key, Path.GetFileName(file.Value));
                }

                return content;
            }

            // Binary data
            if (options.BinaryData != null)
            {
                return new ByteArrayContent(options.BinaryData);
            }

            // Text data
            if (!string.IsNullOrEmpty(options.Data))
            {
                var content = new StringContent(options.Data, Encoding.UTF8);

                // Set content type from headers if specified
                if (options.Headers.TryGetValue("Content-Type", out var contentType))
                {
                    content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
                }
                else
                {
                    // Default to application/x-www-form-urlencoded for POST data
                    content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded");
                }

                return content;
            }

            return null;
        }

        private async Task<CurlResult> CreateResult(HttpResponseMessage response, CurlOptions options,
            CurlTimings timings, DateTime startTime)
        {
            var result = new CurlResult
            {
                StatusCode = (int)response.StatusCode,
                Headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value))
            };

            // Add content headers
            if (response.Content != null)
            {
                foreach (var header in response.Content.Headers)
                {
                    result.Headers[header.Key] = string.Join(", ", header.Value);
                }

                // Read body
                if (!options.HeadOnly)
                {
                    if (IsTextContent(response.Content))
                    {
                        result.Body = await response.Content.ReadAsStringAsync();
                    }
                    else
                    {
                        result.BinaryData = await response.Content.ReadAsByteArrayAsync();
                    }
                }
            }

            return result;
        }

        private async Task<CurlResult> HandleRedirect(HttpResponseMessage response, CurlOptions options,
            CancellationToken cancellationToken, CurlTimings timings, DateTime startTime)
        {
            var redirectCount = 0;
            var currentResponse = response;

            while (IsRedirect(currentResponse.StatusCode) && redirectCount < options.MaxRedirects)
            {
                var location = currentResponse.Headers.Location;
                if (location == null)
                {
                    throw new CurlException("Redirect response missing Location header");
                }

                var newUrl = location.IsAbsoluteUri
                    ? location.ToString()
                    : new Uri(new Uri(options.Url), location).ToString();

                options.Url = newUrl;
                redirectCount++;

                var newRequest = CreateRequest(options);
                currentResponse = await _httpClient.SendAsync(newRequest, cancellationToken);

                timings.Redirect = (DateTime.UtcNow - startTime).TotalMilliseconds;
            }

            if (redirectCount >= options.MaxRedirects)
            {
                throw new CurlTooManyRedirectsException(redirectCount);
            }

            return await CreateResult(currentResponse, options, timings, startTime);
        }

        private bool IsRedirect(HttpStatusCode statusCode)
        {
            return statusCode == HttpStatusCode.MovedPermanently ||
                   statusCode == HttpStatusCode.Found ||
                   statusCode == HttpStatusCode.SeeOther ||
                   statusCode == HttpStatusCode.TemporaryRedirect ||
                   statusCode == HttpStatusCode.PermanentRedirect;
        }

        private bool IsTextContent(HttpContent content)
        {
            var contentType = content.Headers.ContentType?.MediaType;
            if (contentType == null) return true;

            return contentType.StartsWith("text/") ||
                   contentType.Contains("json") ||
                   contentType.Contains("xml") ||
                   contentType.Contains("javascript");
        }

        private bool IsContentHeader(string headerName)
        {
            var contentHeaders = new[] { "Content-Type", "Content-Length", "Content-Encoding",
                "Content-Language", "Content-Location", "Content-Disposition" };
            return contentHeaders.Contains(headerName, StringComparer.OrdinalIgnoreCase);
        }

        private RangeHeaderValue ParseRange(string range)
        {
            // Parse range like "0-499" or "500-"
            var parts = range.Split('-');
            if (parts.Length == 2)
            {
                var from = string.IsNullOrEmpty(parts[0]) ? (long?)null : long.Parse(parts[0]);
                var to = string.IsNullOrEmpty(parts[1]) ? (long?)null : long.Parse(parts[1]);

                return new RangeHeaderValue(from, to);
            }
            return null;
        }

        private async Task WriteOutputFile(CurlResult result, string outputFile)
        {
            if (result.BinaryData != null)
            {
                await File.WriteAllBytesAsync(outputFile, result.BinaryData);
            }
            else if (!string.IsNullOrEmpty(result.Body))
            {
                await File.WriteAllTextAsync(outputFile, result.Body);
            }
            result.OutputFiles.Add(outputFile);
        }

        private static HttpClient CreateDefaultHttpClient()
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false, // We handle redirects manually
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            };

            return new HttpClient(handler);
        }
    }
}