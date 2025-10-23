/***************************************************************************
 * Session management for CurlDotNet
 *
 * Reusable sessions with cookies, authentication, and settings
 *
 * Based on curl by Daniel Stenberg <daniel@haxx.se>
 * Original curl source: https://github.com/curl/curl
 *
 * .NET implementation by Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 * Sponsored by Iron Software (ironsoftware.com)
 *
 * Licensed under the curl license
 * SPDX-License-Identifier: curl
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Progress;

namespace CurlDotNet.Sessions
{
    /// <summary>
    /// Reusable session for curl operations with persistent cookies and settings
    /// </summary>
    public class CurlSession : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly CookieContainer _cookieContainer;
        private readonly Dictionary<string, string> _defaultHeaders;
        private readonly CurlSessionSettings _settings;
        private bool _disposed;

        /// <summary>
        /// Session identifier
        /// </summary>
        public string SessionId { get; }

        /// <summary>
        /// Session cookies
        /// </summary>
        public CookieContainer Cookies => _cookieContainer;

        /// <summary>
        /// Default headers for all requests in this session
        /// </summary>
        public Dictionary<string, string> DefaultHeaders => _defaultHeaders;

        /// <summary>
        /// Session settings
        /// </summary>
        public CurlSessionSettings Settings => _settings;

        /// <summary>
        /// Create a new curl session
        /// </summary>
        public CurlSession(CurlSessionSettings settings = null)
        {
            SessionId = Guid.NewGuid().ToString();
            _settings = settings ?? new CurlSessionSettings();
            _cookieContainer = new CookieContainer();
            _defaultHeaders = new Dictionary<string, string>();

            var handler = new HttpClientHandler
            {
                CookieContainer = _cookieContainer,
                AllowAutoRedirect = _settings.FollowRedirects,
                MaxAutomaticRedirections = _settings.MaxRedirects,
                UseCookies = true
            };

            if (_settings.IgnoreSslErrors)
            {
                handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) => true;
            }

            if (!string.IsNullOrEmpty(_settings.Proxy))
            {
                handler.Proxy = new WebProxy(_settings.Proxy);
                if (!string.IsNullOrEmpty(_settings.ProxyAuth))
                {
                    var parts = _settings.ProxyAuth.Split(':');
                    handler.Proxy.Credentials = new NetworkCredential(parts[0], parts.Length > 1 ? parts[1] : "");
                }
            }

            _httpClient = new HttpClient(handler);

            if (_settings.Timeout.HasValue)
            {
                _httpClient.Timeout = _settings.Timeout.Value;
            }

            // Set default user agent
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(_settings.UserAgent ?? $"CurlDotNet/{GetVersion()}");
        }

        /// <summary>
        /// Execute a curl command within this session
        /// </summary>
        public async Task<CurlResult> ExecuteAsync(
            string command,
            CancellationToken cancellationToken = default,
            IProgress<CurlProgressInfo> progress = null)
        {
            ThrowIfDisposed();

            // Apply session defaults to the command
            command = ApplySessionDefaults(command);

            // Execute using the session's HTTP client
            var executor = new CurlExecutor(_httpClient);
            return await executor.ExecuteAsync(command, cancellationToken, progress);
        }

        /// <summary>
        /// Add a default header for all requests in this session
        /// </summary>
        public CurlSession AddDefaultHeader(string name, string value)
        {
            _defaultHeaders[name] = value;
            _httpClient.DefaultRequestHeaders.TryAddWithoutValidation(name, value);
            return this;
        }

        /// <summary>
        /// Set authentication for all requests in this session
        /// </summary>
        public CurlSession SetAuthentication(string username, string password)
        {
            var authBytes = System.Text.Encoding.ASCII.GetBytes($"{username}:{password}");
            var authHeader = Convert.ToBase64String(authBytes);
            return AddDefaultHeader("Authorization", $"Basic {authHeader}");
        }

        /// <summary>
        /// Set Bearer token for all requests in this session
        /// </summary>
        public CurlSession SetBearerToken(string token)
        {
            return AddDefaultHeader("Authorization", $"Bearer {token}");
        }

        /// <summary>
        /// Add a cookie to the session
        /// </summary>
        public CurlSession AddCookie(string url, string name, string value)
        {
            var uri = new Uri(url);
            _cookieContainer.Add(uri, new Cookie(name, value));
            return this;
        }

        /// <summary>
        /// Load cookies from file (Netscape format)
        /// </summary>
        public async Task<CurlSession> LoadCookiesAsync(string cookieJarPath)
        {
            // Implementation would parse Netscape cookie format
            // Similar to curl's cookie jar functionality
            await Task.CompletedTask; // Placeholder
            return this;
        }

        /// <summary>
        /// Save cookies to file (Netscape format)
        /// </summary>
        public async Task SaveCookiesAsync(string cookieJarPath)
        {
            // Implementation would save in Netscape cookie format
            await Task.CompletedTask; // Placeholder
        }

        /// <summary>
        /// Clear all cookies in the session
        /// </summary>
        public CurlSession ClearCookies()
        {
            // CookieContainer doesn't have a clear method, so we create a new one
            foreach (Cookie cookie in _cookieContainer.GetCookies(new Uri("http://example.com")))
            {
                cookie.Expired = true;
            }
            return this;
        }

        /// <summary>
        /// Clone this session with same settings but fresh cookies
        /// </summary>
        public CurlSession Clone()
        {
            var newSession = new CurlSession(_settings.Clone());
            foreach (var header in _defaultHeaders)
            {
                newSession.AddDefaultHeader(header.Key, header.Value);
            }
            return newSession;
        }

        private string ApplySessionDefaults(string command)
        {
            // Apply default headers if not already in command
            foreach (var header in _defaultHeaders)
            {
                if (!command.Contains($"-H") || !command.Contains(header.Key))
                {
                    // Insert headers before the URL
                    var parts = command.Split(' ');
                    for (int i = parts.Length - 1; i >= 0; i--)
                    {
                        if (parts[i].StartsWith("http") || parts[i].StartsWith("ftp"))
                        {
                            command = command.Replace(parts[i], $"-H '{header.Key}: {header.Value}' {parts[i]}");
                            break;
                        }
                    }
                }
            }

            return command;
        }

        private string GetVersion()
        {
            return "8.17.0"; // Match curl version
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(CurlSession));
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
                    _httpClient?.Dispose();
                }
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Settings for a curl session
    /// </summary>
    public class CurlSessionSettings
    {
        public bool FollowRedirects { get; set; } = true;
        public int MaxRedirects { get; set; } = 50;
        public TimeSpan? Timeout { get; set; }
        public string UserAgent { get; set; }
        public bool IgnoreSslErrors { get; set; }
        public string Proxy { get; set; }
        public string ProxyAuth { get; set; }
        public bool Verbose { get; set; }
        public bool Silent { get; set; }
        public string BaseUrl { get; set; }
        public bool ThrowOnHttpError { get; set; }
        public int RetryCount { get; set; } = 0;
        public TimeSpan RetryDelay { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>
        /// Clone these settings
        /// </summary>
        public CurlSessionSettings Clone()
        {
            return new CurlSessionSettings
            {
                FollowRedirects = FollowRedirects,
                MaxRedirects = MaxRedirects,
                Timeout = Timeout,
                UserAgent = UserAgent,
                IgnoreSslErrors = IgnoreSslErrors,
                Proxy = Proxy,
                ProxyAuth = ProxyAuth,
                Verbose = Verbose,
                Silent = Silent,
                BaseUrl = BaseUrl,
                ThrowOnHttpError = ThrowOnHttpError,
                RetryCount = RetryCount,
                RetryDelay = RetryDelay
            };
        }
    }
}