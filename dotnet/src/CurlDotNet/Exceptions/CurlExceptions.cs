/***************************************************************************
 * Comprehensive Exception Types for CurlDotNet
 *
 * Meaningful, catchable exceptions for every failure scenario
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 * Sponsored by Iron Software (ironsoftware.com)
 ***************************************************************************/

using System;

namespace CurlDotNet.Exceptions
{
    /// <summary>
    /// Base exception for all curl operations
    /// </summary>
    public class CurlException : Exception
    {
        public string Command { get; }
        public int? CurlErrorCode { get; }

        public CurlException(string message, string command = null, Exception innerException = null)
            : base(message, innerException)
        {
            Command = command;
        }

        public CurlException(string message, int curlErrorCode, string command = null)
            : base(message)
        {
            Command = command;
            CurlErrorCode = curlErrorCode;
        }
    }

    /// <summary>
    /// Thrown when the curl command syntax is invalid
    /// </summary>
    public class CurlInvalidCommandException : CurlException
    {
        public string InvalidPart { get; }

        public CurlInvalidCommandException(string message, string invalidPart = null)
            : base(message)
        {
            InvalidPart = invalidPart;
        }
    }

    /// <summary>
    /// Thrown when a network connection cannot be established
    /// </summary>
    public class CurlConnectionException : CurlException
    {
        public string Host { get; }
        public int? Port { get; }

        public CurlConnectionException(string message, string host, int? port = null, string command = null)
            : base(message, command)
        {
            Host = host;
            Port = port;
        }
    }

    /// <summary>
    /// Thrown when DNS resolution fails
    /// </summary>
    public class CurlDnsException : CurlConnectionException
    {
        public CurlDnsException(string hostname, string command = null)
            : base($"Could not resolve host: {hostname}", hostname, null, command)
        {
            // CURLE_COULDNT_RESOLVE_HOST = 6
            CurlErrorCode = 6;
        }
    }

    /// <summary>
    /// Thrown when an operation times out
    /// </summary>
    public class CurlTimeoutException : CurlException
    {
        public TimeSpan? Timeout { get; }

        public CurlTimeoutException(string message, string command = null, TimeSpan? timeout = null)
            : base(message, 28, command) // CURLE_OPERATION_TIMEDOUT = 28
        {
            Timeout = timeout;
        }
    }

    /// <summary>
    /// Thrown when SSL/TLS certificate validation fails
    /// </summary>
    public class CurlSslException : CurlException
    {
        public string CertificateError { get; }

        public CurlSslException(string message, string certError = null, string command = null)
            : base(message, 60, command) // CURLE_PEER_FAILED_VERIFICATION = 60
        {
            CertificateError = certError;
        }
    }

    /// <summary>
    /// Thrown when authentication fails
    /// </summary>
    public class CurlAuthenticationException : CurlException
    {
        public string AuthMethod { get; }

        public CurlAuthenticationException(string message, string authMethod = null, string command = null)
            : base(message, 67, command) // CURLE_LOGIN_DENIED = 67
        {
            AuthMethod = authMethod;
        }
    }

    /// <summary>
    /// Thrown for HTTP error responses when using ThrowOnError()
    /// </summary>
    public class CurlHttpException : CurlException
    {
        public int StatusCode { get; }
        public string StatusText { get; }
        public string ResponseBody { get; }

        public CurlHttpException(string message, int statusCode, string statusText = null, string responseBody = null, string command = null)
            : base(message, command)
        {
            StatusCode = statusCode;
            StatusText = statusText;
            ResponseBody = responseBody;
        }

        /// <summary>
        /// Check if this is a client error (4xx)
        /// </summary>
        public bool IsClientError => StatusCode >= 400 && StatusCode < 500;

        /// <summary>
        /// Check if this is a server error (5xx)
        /// </summary>
        public bool IsServerError => StatusCode >= 500 && StatusCode < 600;
    }

    /// <summary>
    /// Thrown when file operations fail
    /// </summary>
    public class CurlFileException : CurlException
    {
        public string FilePath { get; }
        public FileOperation Operation { get; }

        public enum FileOperation
        {
            Read,
            Write,
            Create,
            Delete,
            Upload,
            Download
        }

        public CurlFileException(string message, string filePath, FileOperation operation, string command = null, Exception innerException = null)
            : base(message, command, innerException)
        {
            FilePath = filePath;
            Operation = operation;
        }
    }

    /// <summary>
    /// Thrown when retry attempts are exhausted
    /// </summary>
    public class CurlRetryException : CurlException
    {
        public int RetryCount { get; }
        public Exception LastAttemptException { get; }

        public CurlRetryException(string message, string command, int retryCount, Exception lastException)
            : base(message, command, lastException)
        {
            RetryCount = retryCount;
            LastAttemptException = lastException;
        }
    }

    /// <summary>
    /// Thrown when FTP operations fail
    /// </summary>
    public class CurlFtpException : CurlException
    {
        public int FtpCode { get; }

        public CurlFtpException(string message, int ftpCode, string command = null)
            : base(message, 9, command) // CURLE_FTP_ACCESS_DENIED = 9
        {
            FtpCode = ftpCode;
        }
    }

    /// <summary>
    /// Thrown when proxy connection fails
    /// </summary>
    public class CurlProxyException : CurlConnectionException
    {
        public string ProxyHost { get; }
        public int? ProxyPort { get; }

        public CurlProxyException(string message, string proxyHost, int? proxyPort = null, string command = null)
            : base(message, proxyHost, proxyPort, command)
        {
            ProxyHost = proxyHost;
            ProxyPort = proxyPort;
            // CURLE_COULDNT_RESOLVE_PROXY = 5
            CurlErrorCode = 5;
        }
    }

    /// <summary>
    /// Thrown when content parsing fails
    /// </summary>
    public class CurlParsingException : CurlException
    {
        public string ContentType { get; }
        public Type ExpectedType { get; }

        public CurlParsingException(string message, string contentType, Type expectedType, string command = null, Exception innerException = null)
            : base(message, command, innerException)
        {
            ContentType = contentType;
            ExpectedType = expectedType;
        }
    }

    /// <summary>
    /// Thrown when rate limiting is encountered
    /// </summary>
    public class CurlRateLimitException : CurlHttpException
    {
        public TimeSpan? RetryAfter { get; }
        public int? RemainingLimit { get; }

        public CurlRateLimitException(string message, TimeSpan? retryAfter = null, int? remainingLimit = null, string command = null)
            : base(message, 429, "Too Many Requests", null, command)
        {
            RetryAfter = retryAfter;
            RemainingLimit = remainingLimit;
        }
    }

    /// <summary>
    /// Thrown when execution fails for general reasons
    /// </summary>
    public class CurlExecutionException : CurlException
    {
        public CurlExecutionException(string message, string command = null, Exception innerException = null)
            : base(message, command, innerException)
        {
        }
    }

    /// <summary>
    /// Thrown when a required feature is not supported
    /// </summary>
    public class CurlNotSupportedException : CurlException
    {
        public string Feature { get; }

        public CurlNotSupportedException(string feature, string command = null)
            : base($"Feature not supported: {feature}", command)
        {
            Feature = feature;
            // CURLE_UNSUPPORTED_PROTOCOL = 1
            CurlErrorCode = 1;
        }
    }

    /// <summary>
    /// Thrown when cookie operations fail
    /// </summary>
    public class CurlCookieException : CurlException
    {
        public string CookieJarPath { get; }

        public CurlCookieException(string message, string cookieJarPath = null, string command = null, Exception innerException = null)
            : base(message, command, innerException)
        {
            CookieJarPath = cookieJarPath;
        }
    }

    /// <summary>
    /// Thrown when redirect limit is exceeded
    /// </summary>
    public class CurlRedirectException : CurlException
    {
        public int RedirectCount { get; }
        public string LastUrl { get; }

        public CurlRedirectException(string message, int redirectCount, string lastUrl = null, string command = null)
            : base(message, 47, command) // CURLE_TOO_MANY_REDIRECTS = 47
        {
            RedirectCount = redirectCount;
            LastUrl = lastUrl;
        }
    }
}