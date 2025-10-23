using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Options;

namespace CurlDotNet.Handlers
{
    /// <summary>
    /// Handles HTTP and HTTPS protocol requests.
    /// Implements curl's HTTP functionality from lib/http.c
    /// </summary>
    public class HttpHandler : IProtocolHandler
    {
        public async Task<CurlResponse> ExecuteAsync(CurlOptions options, HttpClient httpClient)
        {
            var stopwatch = Stopwatch.StartNew();
            var response = new CurlResponse();

            try
            {
                // Configure HttpClient based on options
                ConfigureHttpClient(httpClient, options);

                // Create the request
                var request = CreateHttpRequest(options);

                // Set timeouts if specified
                if (options.ConnectTimeout.HasValue)
                {
                    httpClient.Timeout = TimeSpan.FromSeconds(options.ConnectTimeout.Value);
                }
                else if (options.MaxTime.HasValue)
                {
                    httpClient.Timeout = TimeSpan.FromSeconds(options.MaxTime.Value);
                }

                // Execute the request
                var httpResponse = await httpClient.SendAsync(request,
                    options.IncludeHeaders ? HttpCompletionOption.ResponseContentRead : HttpCompletionOption.ResponseContentRead);

                // Fill response object
                response.StatusCode = (int)httpResponse.StatusCode;
                response.StatusText = httpResponse.ReasonPhrase;
                response.EffectiveUrl = httpResponse.RequestMessage?.RequestUri?.ToString() ?? options.Url;
                response.HttpVersion = httpResponse.Version.ToString();
                response.Protocol = "HTTP";

                // Get response headers
                response.Headers = FormatHeaders(httpResponse.Headers, httpResponse.Content?.Headers);
                response.ContentType = httpResponse.Content?.Headers?.ContentType?.ToString();

                // Get response body
                if (httpResponse.Content != null)
                {
                    if (IsBinaryContent(httpResponse.Content.Headers))
                    {
                        response.BinaryData = await httpResponse.Content.ReadAsByteArrayAsync();
                        response.SizeDownload = response.BinaryData.Length;
                    }
                    else
                    {
                        response.Body = await httpResponse.Content.ReadAsStringAsync();
                        response.SizeDownload = Encoding.UTF8.GetByteCount(response.Body);
                    }
                }

                // Calculate timing information
                response.TotalTime = stopwatch.ElapsedMilliseconds;

                // Handle redirects
                if (options.FollowRedirects && IsRedirectStatus(httpResponse.StatusCode))
                {
                    if (httpResponse.Headers.Location != null)
                    {
                        response.RedirectUrl = httpResponse.Headers.Location.ToString();
                        // In a real implementation, we'd follow the redirect here
                        // For now, we'll just note it
                        response.NumRedirects = 1;
                    }
                }

                // Check for errors if fail on error is set
                if (options.FailOnError && (int)httpResponse.StatusCode >= 400)
                {
                    response.IsError = true;
                    response.ErrorCode = (int)httpResponse.StatusCode;
                    response.ErrorMessage = $"The requested URL returned error: {(int)httpResponse.StatusCode} {httpResponse.ReasonPhrase}";
                }
            }
            catch (TaskCanceledException ex)
            {
                response.IsError = true;
                response.ErrorCode = 28; // CURLE_OPERATION_TIMEDOUT
                response.ErrorMessage = "Operation timed out";
            }
            catch (HttpRequestException ex)
            {
                response.IsError = true;
                response.ErrorCode = 7; // CURLE_COULDNT_CONNECT
                response.ErrorMessage = ex.Message;
            }
            catch (Exception ex)
            {
                response.IsError = true;
                response.ErrorCode = 1; // CURLE_UNSUPPORTED_PROTOCOL or general error
                response.ErrorMessage = ex.Message;
            }
            finally
            {
                stopwatch.Stop();
                response.TotalTime = stopwatch.ElapsedMilliseconds;
            }

            return response;
        }

        private void ConfigureHttpClient(HttpClient httpClient, CurlOptions options)
        {
            // Clear default headers
            httpClient.DefaultRequestHeaders.Clear();

            // Set User-Agent
            if (!string.IsNullOrEmpty(options.UserAgent))
            {
                httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent);
            }
            else
            {
                httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"curl/{GetCurlVersion()}");
            }

            // Handle compression
            if (options.Compressed)
            {
                httpClient.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue("gzip"));
                httpClient.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue("deflate"));
                httpClient.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue("br"));
            }

            // Set proxy if specified
            if (!string.IsNullOrEmpty(options.Proxy))
            {
                // This would need more complex handling in a real implementation
                // as HttpClient's proxy needs to be set during construction
            }

            // Handle SSL certificate validation
            if (options.Insecure)
            {
                // This would need to be handled via HttpClientHandler during HttpClient construction
                // ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;
            }
        }

        private HttpRequestMessage CreateHttpRequest(CurlOptions options)
        {
            var method = GetHttpMethod(options.Method);
            var request = new HttpRequestMessage(method, options.Url);

            // Add custom headers
            foreach (var header in options.Headers)
            {
                var colonIndex = header.IndexOf(':');
                if (colonIndex > 0)
                {
                    var name = header.Substring(0, colonIndex).Trim();
                    var value = header.Substring(colonIndex + 1).Trim();

                    // Some headers need to be set on the content or have special handling
                    if (name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                    {
                        // Will be set with content
                        continue;
                    }
                    else if (name.Equals("Host", StringComparison.OrdinalIgnoreCase))
                    {
                        request.Headers.Host = value;
                    }
                    else
                    {
                        request.Headers.TryAddWithoutValidation(name, value);
                    }
                }
            }

            // Set Referer
            if (!string.IsNullOrEmpty(options.Referer))
            {
                request.Headers.Referrer = new Uri(options.Referer);
            }

            // Set Cookie
            if (!string.IsNullOrEmpty(options.Cookie))
            {
                request.Headers.TryAddWithoutValidation("Cookie", options.Cookie);
            }

            // Set authentication
            if (!string.IsNullOrEmpty(options.UserAuth))
            {
                var parts = options.UserAuth.Split(':');
                var username = parts[0];
                var password = parts.Length > 1 ? parts[1] : "";
                var authBytes = Encoding.ASCII.GetBytes($"{username}:{password}");
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(authBytes));
            }

            // Add request body
            if (!string.IsNullOrEmpty(options.Data))
            {
                request.Content = new StringContent(options.Data, Encoding.UTF8);

                // Try to detect content type
                if (options.Data.StartsWith("{") || options.Data.StartsWith("["))
                {
                    request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                }
                else if (options.Data.Contains("=") && !options.Data.Contains(" "))
                {
                    request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
                }
            }
            else if (!string.IsNullOrEmpty(options.DataBinary))
            {
                // Handle binary data
                if (options.DataBinary.StartsWith("@"))
                {
                    var filename = options.DataBinary.Substring(1);
                    if (File.Exists(filename))
                    {
                        request.Content = new ByteArrayContent(File.ReadAllBytes(filename));
                    }
                }
                else
                {
                    request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(options.DataBinary));
                }
            }
            else if (!string.IsNullOrEmpty(options.DataUrlEncode))
            {
                var encoded = Uri.EscapeDataString(options.DataUrlEncode);
                request.Content = new StringContent(encoded, Encoding.UTF8, "application/x-www-form-urlencoded");
            }
            else if (!string.IsNullOrEmpty(options.UploadFile))
            {
                if (File.Exists(options.UploadFile))
                {
                    request.Content = new ByteArrayContent(File.ReadAllBytes(options.UploadFile));
                }
            }

            return request;
        }

        private HttpMethod GetHttpMethod(string method)
        {
            switch (method?.ToUpperInvariant())
            {
                case "GET":
                    return HttpMethod.Get;
                case "POST":
                    return HttpMethod.Post;
                case "PUT":
                    return HttpMethod.Put;
                case "DELETE":
                    return HttpMethod.Delete;
                case "HEAD":
                    return HttpMethod.Head;
                case "OPTIONS":
                    return HttpMethod.Options;
                case "TRACE":
                    return HttpMethod.Trace;
                case "PATCH":
                    return new HttpMethod("PATCH");
                default:
                    return HttpMethod.Get;
            }
        }

        private bool IsRedirectStatus(HttpStatusCode statusCode)
        {
            return statusCode == HttpStatusCode.MovedPermanently ||
                   statusCode == HttpStatusCode.Found ||
                   statusCode == HttpStatusCode.SeeOther ||
                   statusCode == HttpStatusCode.TemporaryRedirect ||
                   statusCode == HttpStatusCode.PermanentRedirect;
        }

        private bool IsBinaryContent(HttpContentHeaders headers)
        {
            if (headers?.ContentType == null)
                return false;

            var mediaType = headers.ContentType.MediaType.ToLowerInvariant();

            // Text types
            if (mediaType.StartsWith("text/") ||
                mediaType.Contains("json") ||
                mediaType.Contains("xml") ||
                mediaType.Contains("javascript") ||
                mediaType.Contains("html"))
            {
                return false;
            }

            // Binary types
            if (mediaType.StartsWith("image/") ||
                mediaType.StartsWith("audio/") ||
                mediaType.StartsWith("video/") ||
                mediaType.StartsWith("application/octet-stream") ||
                mediaType.StartsWith("application/pdf") ||
                mediaType.StartsWith("application/zip"))
            {
                return true;
            }

            // Default to text
            return false;
        }

        private string FormatHeaders(HttpResponseHeaders headers, HttpContentHeaders contentHeaders)
        {
            var sb = new StringBuilder();

            foreach (var header in headers)
            {
                foreach (var value in header.Value)
                {
                    sb.AppendLine($"{header.Key}: {value}");
                }
            }

            if (contentHeaders != null)
            {
                foreach (var header in contentHeaders)
                {
                    foreach (var value in header.Value)
                    {
                        sb.AppendLine($"{header.Key}: {value}");
                    }
                }
            }

            return sb.ToString();
        }

        private string GetCurlVersion()
        {
            // Mimic curl's version string
            return "8.5.0";
        }
    }
}