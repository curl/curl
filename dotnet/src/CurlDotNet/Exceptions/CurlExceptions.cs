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
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;

namespace CurlDotNet.Exceptions
{
    /// <summary>
    /// Base exception for all curl operations. This is the base class for all curl-specific exceptions.
    /// </summary>
    /// <remarks>
    /// <para>This exception provides common properties for all curl errors including the command that was executed and the curl error code.</para>
    /// <para>Curl error codes match the original curl error codes from the C implementation.</para>
    /// <para>AI-Usage: Catch this exception type to handle any curl-related error generically.</para>
    /// <para>AI-Pattern: Use specific derived exceptions for targeted error handling.</para>
    /// </remarks>
    /// <example>
    /// <code>
    /// try
    /// {
    ///     var result = await curl.ExecuteAsync("curl https://api.example.com");
    /// }
    /// catch (CurlConnectionException ex)
    /// {
    ///     // Handle connection-specific issues
    ///     Console.WriteLine($"Failed to connect to {ex.Host}:{ex.Port}");
    /// }
    /// catch (CurlException ex)
    /// {
    ///     // Handle any other curl error
    ///     Console.WriteLine($"Curl failed: {ex.Message}");
    ///     Console.WriteLine($"Command: {ex.Command}");
    ///     Console.WriteLine($"Error code: {ex.CurlErrorCode}");
    /// }
    /// </code>
    /// </example>
    [Serializable]
    public class CurlException : Exception
    {
        /// <summary>
        /// Gets the curl command that was being executed when the exception occurred.
        /// </summary>
        /// <value>The full curl command string, or null if not applicable.</value>
        /// <remarks>
        /// <para>This property contains the exact command that was passed to the Execute method.</para>
        /// <para>AI-Usage: Use this for logging and debugging to understand what command failed.</para>
        /// </remarks>
        public string Command { get; }

        /// <summary>
        /// Gets the curl error code matching the original curl implementation.
        /// </summary>
        /// <value>The curl error code (e.g., 6 for DNS resolution failure, 28 for timeout), or null if not a curl-specific error.</value>
        /// <remarks>
        /// <para>Error codes match the CURLE_* constants from curl.h</para>
        /// <para>Common codes: 6=DNS failure, 7=connection failed, 28=timeout, 35=SSL error</para>
        /// <para>AI-Usage: Use this to determine the specific type of curl error programmatically.</para>
        /// </remarks>
        public int? CurlErrorCode { get; }

        /// <summary>
        /// Gets additional context information added via fluent methods.
        /// </summary>
        public Dictionary<string, object> Context { get; } = new Dictionary<string, object>();

        /// <summary>
        /// Gets suggestions for resolving this error.
        /// </summary>
        public List<string> Suggestions { get; } = new List<string>();

        /// <summary>
        /// Gets or sets custom diagnostic information.
        /// </summary>
        public string DiagnosticInfo { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="CurlException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="command">The curl command that was executing when the error occurred.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public CurlException(string message, string command = null, Exception innerException = null)
            : base(message, innerException)
        {
            Command = command;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CurlException"/> class with a curl error code.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="curlErrorCode">The curl error code from the original curl implementation.</param>
        /// <param name="command">The curl command that was executing when the error occurred.</param>
        public CurlException(string message, int curlErrorCode, string command = null)
            : base(message)
        {
            Command = command;
            CurlErrorCode = curlErrorCode;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CurlException"/> class with serialized data.
        /// </summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
        protected CurlException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
            Command = info.GetString(nameof(Command));
            CurlErrorCode = (int?)info.GetValue(nameof(CurlErrorCode), typeof(int?));
        }

        /// <summary>
        /// Sets the <see cref="SerializationInfo"/> with information about the exception.
        /// </summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue(nameof(Command), Command);
            info.AddValue(nameof(CurlErrorCode), CurlErrorCode);
        }

        #region Fluent Methods for Easy Inspection

        /// <summary>
        /// Add contextual information to the exception (fluent).
        /// </summary>
        /// <param name="key">Context key</param>
        /// <param name="value">Context value</param>
        /// <returns>This exception for chaining</returns>
        public CurlException WithContext(string key, object value)
        {
            Context[key] = value;
            return this;
        }

        /// <summary>
        /// Add multiple context values (fluent).
        /// </summary>
        /// <param name="context">Dictionary of context values</param>
        /// <returns>This exception for chaining</returns>
        public CurlException WithContext(Dictionary<string, object> context)
        {
            foreach (var kvp in context)
            {
                Context[kvp.Key] = kvp.Value;
            }
            return this;
        }

        /// <summary>
        /// Add a suggestion for resolving this error (fluent).
        /// </summary>
        /// <param name="suggestion">Helpful suggestion text</param>
        /// <returns>This exception for chaining</returns>
        public CurlException WithSuggestion(string suggestion)
        {
            Suggestions.Add(suggestion);
            return this;
        }

        /// <summary>
        /// Add diagnostic information (fluent).
        /// </summary>
        /// <param name="diagnosticInfo">Diagnostic details</param>
        /// <returns>This exception for chaining</returns>
        public CurlException WithDiagnostics(string diagnosticInfo)
        {
            DiagnosticInfo = diagnosticInfo;
            return this;
        }

        /// <summary>
        /// Get a detailed string representation of the exception.
        /// </summary>
        /// <returns>Detailed error information</returns>
        public virtual string ToDetailedString()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"=== CURL EXCEPTION DETAILS ===");
            sb.AppendLine($"Type: {GetType().Name}");
            sb.AppendLine($"Message: {Message}");

            if (!string.IsNullOrEmpty(Command))
                sb.AppendLine($"Command: {Command}");

            if (CurlErrorCode.HasValue)
            {
                sb.AppendLine($"Curl Error Code: {CurlErrorCode} ({GetCurlErrorName()})");
            }

            if (Context.Count > 0)
            {
                sb.AppendLine("Context:");
                foreach (var kvp in Context)
                {
                    sb.AppendLine($"  {kvp.Key}: {kvp.Value}");
                }
            }

            if (Suggestions.Count > 0)
            {
                sb.AppendLine("Suggestions:");
                foreach (var suggestion in Suggestions)
                {
                    sb.AppendLine($"  - {suggestion}");
                }
            }

            if (!string.IsNullOrEmpty(DiagnosticInfo))
            {
                sb.AppendLine($"Diagnostics: {DiagnosticInfo}");
            }

            if (InnerException != null)
            {
                sb.AppendLine($"Inner Exception: {InnerException.Message}");
            }

            sb.AppendLine($"Stack Trace:\n{StackTrace}");
            sb.AppendLine("=============================");

            return sb.ToString();
        }

        /// <summary>
        /// Get the exception as a structured JSON object for logging.
        /// </summary>
        /// <returns>JSON representation of the exception</returns>
        public virtual string ToJson()
        {
            var errorObject = new Dictionary<string, object>
            {
                ["type"] = GetType().Name,
                ["message"] = Message,
                ["command"] = Command,
                ["curlErrorCode"] = CurlErrorCode,
                ["curlErrorName"] = GetCurlErrorName(),
                ["context"] = Context,
                ["suggestions"] = Suggestions,
                ["diagnostics"] = DiagnosticInfo,
                ["isRetryable"] = IsRetryable(),
                ["stackTrace"] = StackTrace,
                ["innerException"] = InnerException?.Message
            };

            #if NETSTANDARD2_0
            return Newtonsoft.Json.JsonConvert.SerializeObject(errorObject, Newtonsoft.Json.Formatting.Indented);
            #else
            return System.Text.Json.JsonSerializer.Serialize(errorObject, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            #endif
        }

        /// <summary>
        /// Get diagnostic information for debugging.
        /// </summary>
        /// <returns>Diagnostic details</returns>
        public virtual Dictionary<string, object> GetDiagnosticInfo()
        {
            return new Dictionary<string, object>
            {
                ["ExceptionType"] = GetType().FullName,
                ["Message"] = Message,
                ["Command"] = Command ?? "N/A",
                ["CurlErrorCode"] = CurlErrorCode?.ToString() ?? "N/A",
                ["CurlErrorName"] = GetCurlErrorName(),
                ["Timestamp"] = DateTime.UtcNow.ToString("O"),
                ["MachineName"] = Environment.MachineName,
                ["OSVersion"] = Environment.OSVersion.ToString(),
                ["IsRetryable"] = IsRetryable(),
                ["Context"] = Context,
                ["Suggestions"] = Suggestions,
                ["HasInnerException"] = InnerException != null,
                ["InnerExceptionType"] = InnerException?.GetType().Name,
                ["InnerExceptionMessage"] = InnerException?.Message
            };
        }

        /// <summary>
        /// Get the CURLE_* constant name for the error code.
        /// </summary>
        /// <returns>Curl error constant name</returns>
        public string GetCurlErrorName()
        {
            if (!CurlErrorCode.HasValue) return null;

            return CurlErrorCode.Value switch
            {
                0 => "CURLE_OK",
                1 => "CURLE_UNSUPPORTED_PROTOCOL",
                2 => "CURLE_FAILED_INIT",
                3 => "CURLE_URL_MALFORMAT",
                4 => "CURLE_NOT_BUILT_IN",
                5 => "CURLE_COULDNT_RESOLVE_PROXY",
                6 => "CURLE_COULDNT_RESOLVE_HOST",
                7 => "CURLE_COULDNT_CONNECT",
                8 => "CURLE_WEIRD_SERVER_REPLY",
                9 => "CURLE_FTP_ACCESS_DENIED",
                22 => "CURLE_HTTP_RETURNED_ERROR",
                23 => "CURLE_WRITE_ERROR",
                26 => "CURLE_READ_ERROR",
                27 => "CURLE_OUT_OF_MEMORY",
                28 => "CURLE_OPERATION_TIMEDOUT",
                35 => "CURLE_SSL_CONNECT_ERROR",
                47 => "CURLE_TOO_MANY_REDIRECTS",
                51 => "CURLE_PEER_FAILED_VERIFICATION",
                52 => "CURLE_GOT_NOTHING",
                53 => "CURLE_SSL_ENGINE_NOTFOUND",
                54 => "CURLE_SSL_ENGINE_SETFAILED",
                55 => "CURLE_SEND_ERROR",
                56 => "CURLE_RECV_ERROR",
                58 => "CURLE_SSL_CERTPROBLEM",
                59 => "CURLE_SSL_CIPHER",
                60 => "CURLE_PEER_FAILED_VERIFICATION",
                61 => "CURLE_BAD_CONTENT_ENCODING",
                67 => "CURLE_LOGIN_DENIED",
                _ => $"CURLE_UNKNOWN_{CurlErrorCode}"
            };
        }

        /// <summary>
        /// Check if this error is potentially retryable.
        /// </summary>
        /// <returns>True if the error might succeed on retry</returns>
        public virtual bool IsRetryable()
        {
            if (!CurlErrorCode.HasValue) return false;

            // These error codes are potentially transient and worth retrying
            return CurlErrorCode.Value switch
            {
                6 => true,  // DNS resolution might be temporary
                7 => true,  // Connection failed - might be temporary
                28 => true, // Timeout - might work with longer timeout
                35 => false, // SSL errors usually require configuration changes
                52 => true, // Got nothing - server might be temporarily overloaded
                55 => true, // Send error - network glitch
                56 => true, // Recv error - network glitch
                _ => false
            };
        }

        /// <summary>
        /// Log this exception with structured data.
        /// </summary>
        /// <param name="logger">Action to perform logging</param>
        public void Log(Action<string, Dictionary<string, object>> logger)
        {
            logger(ToDetailedString(), GetDiagnosticInfo());
        }

        /// <summary>
        /// Create a user-friendly error message.
        /// </summary>
        /// <returns>Simplified error message for end users</returns>
        public virtual string ToUserFriendlyMessage()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Error: {Message}");

            if (Suggestions.Count > 0)
            {
                sb.AppendLine("\nPossible solutions:");
                foreach (var suggestion in Suggestions)
                {
                    sb.AppendLine($"• {suggestion}");
                }
            }

            if (IsRetryable())
            {
                sb.AppendLine("\nThis error might be temporary. Please try again.");
            }

            return sb.ToString();
        }

        #endregion
    }

    /// <summary>
    /// Thrown when the curl command syntax is invalid or cannot be parsed.
    /// </summary>
    /// <remarks>
    /// <para>This exception indicates a problem with the curl command syntax, not a network or execution error.</para>
    /// <para>AI-Usage: Catch this to handle command syntax errors separately from execution errors.</para>
    /// <para>AI-Pattern: Validate commands before execution to avoid this exception.</para>
    /// </remarks>
    /// <example>
    /// <code>
    /// try
    /// {
    ///     // Missing URL will throw CurlInvalidCommandException
    ///     var result = await curl.ExecuteAsync("curl -X POST");
    /// }
    /// catch (CurlInvalidCommandException ex)
    /// {
    ///     Console.WriteLine($"Invalid command syntax: {ex.Message}");
    ///     Console.WriteLine($"Problem with: {ex.InvalidPart}");
    ///     // Suggest correction to user
    ///     Console.WriteLine("Did you forget to specify a URL?");
    /// }
    /// </code>
    /// </example>
    [Serializable]
    public class CurlInvalidCommandException : CurlException
    {
        /// <summary>
        /// Gets the part of the command that is invalid.
        /// </summary>
        /// <value>The specific option, argument, or syntax element that caused the parsing error.</value>
        /// <remarks>
        /// <para>This helps identify exactly what part of the command is wrong.</para>
        /// <para>AI-Usage: Use this to provide specific feedback about what needs to be corrected.</para>
        /// </remarks>
        public string InvalidPart { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="CurlInvalidCommandException"/> class.
        /// </summary>
        /// <param name="message">The error message describing the invalid syntax.</param>
        /// <param name="invalidPart">The specific part of the command that is invalid.</param>
        /// <param name="command">The full curl command that failed to parse.</param>
        public CurlInvalidCommandException(string message, string invalidPart = null, string command = null)
            : base(message, command)
        {
            InvalidPart = invalidPart;
        }

        /// <summary>
        /// Initializes a new instance with serialized data.
        /// </summary>
        protected CurlInvalidCommandException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
            InvalidPart = info.GetString(nameof(InvalidPart));
        }

        /// <inheritdoc/>
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue(nameof(InvalidPart), InvalidPart);
        }
    }

    /// <summary>
    /// Thrown when a network connection cannot be established to the target host.
    /// </summary>
    /// <remarks>
    /// <para>This exception indicates network-level connection failures, not HTTP errors.</para>
    /// <para>Common causes include: host unreachable, port closed, firewall blocking, network timeout.</para>
    /// <para>AI-Usage: Catch this to implement retry logic or fallback servers.</para>
    /// <para>AI-Pattern: Check Host and Port properties to log connection details.</para>
    /// </remarks>
    /// <example>
    /// <code>
    /// try
    /// {
    ///     var result = await curl.ExecuteAsync("curl https://internal-server:8443/api");
    /// }
    /// catch (CurlDnsException ex)
    /// {
    ///     // DNS couldn't resolve the hostname
    ///     Console.WriteLine($"DNS lookup failed for {ex.Host}");
    ///     // Try fallback server
    ///     result = await curl.ExecuteAsync("curl https://backup-server/api");
    /// }
    /// catch (CurlConnectionException ex)
    /// {
    ///     // Connection failed but DNS worked
    ///     Console.WriteLine($"Cannot connect to {ex.Host}:{ex.Port}");
    ///     Console.WriteLine("Check if the service is running and firewall rules");
    /// }
    /// </code>
    /// </example>
    [Serializable]
    public class CurlConnectionException : CurlException
    {
        /// <summary>
        /// Gets the host that could not be connected to.
        /// </summary>
        /// <value>The hostname or IP address that failed to connect.</value>
        /// <remarks>
        /// <para>This may be a hostname (e.g., "api.example.com") or IP address (e.g., "192.168.1.1").</para>
        /// <para>AI-Usage: Use this to implement host-specific retry or fallback logic.</para>
        /// </remarks>
        public string Host { get; }

        /// <summary>
        /// Gets the port number that was attempted.
        /// </summary>
        /// <value>The TCP port number, or null if using the default port for the protocol.</value>
        /// <remarks>
        /// <para>Default ports: HTTP=80, HTTPS=443, FTP=21, FTPS=990.</para>
        /// <para>AI-Usage: Check if non-standard ports might be blocked by firewalls.</para>
        /// </remarks>
        public int? Port { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="CurlConnectionException"/> class.
        /// </summary>
        /// <param name="message">The error message describing the connection failure.</param>
        /// <param name="host">The host that could not be connected to.</param>
        /// <param name="port">The port number that was attempted.</param>
        /// <param name="command">The curl command that was executing.</param>
        public CurlConnectionException(string message, string host, int? port = null, string command = null)
            : base(message, command)
        {
            Host = host;
            Port = port;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CurlConnectionException"/> class with an error code.
        /// </summary>
        /// <param name="message">The error message describing the connection failure.</param>
        /// <param name="curlErrorCode">The curl error code.</param>
        /// <param name="host">The host that could not be connected to.</param>
        /// <param name="port">The port number that was attempted.</param>
        /// <param name="command">The curl command that was executing.</param>
        protected CurlConnectionException(string message, int curlErrorCode, string host, int? port = null, string command = null)
            : base(message, curlErrorCode, command)
        {
            Host = host;
            Port = port;
        }

        /// <summary>
        /// Initializes a new instance with serialized data.
        /// </summary>
        protected CurlConnectionException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
            Host = info.GetString(nameof(Host));
            Port = (int?)info.GetValue(nameof(Port), typeof(int?));
        }

        /// <inheritdoc/>
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue(nameof(Host), Host);
            info.AddValue(nameof(Port), Port);
        }
    }

    /// <summary>
    /// Thrown when DNS resolution fails for a hostname.
    /// </summary>
    /// <remarks>
    /// <para>This exception indicates the hostname could not be resolved to an IP address.</para>
    /// <para>Curl error code: CURLE_COULDNT_RESOLVE_HOST (6)</para>
    /// <para>AI-Usage: Catch this to handle DNS failures separately from other connection issues.</para>
    /// <para>AI-Pattern: Check for typos in hostname or DNS server configuration.</para>
    /// </remarks>
    /// <example>
    /// <code>
    /// try
    /// {
    ///     var result = await curl.ExecuteAsync("curl https://non-existent-domain.invalid");
    /// }
    /// catch (CurlDnsException ex)
    /// {
    ///     Console.WriteLine($"DNS lookup failed for: {ex.Host}");
    ///
    ///     // Suggest alternatives
    ///     if (ex.Host.Contains("github"))
    ///         Console.WriteLine("Did you mean: github.com?");
    ///
    ///     // Or try with IP address directly
    ///     var ipAddress = "140.82.114.3"; // github.com IP
    ///     result = await curl.ExecuteAsync($"curl https://{ipAddress}");
    /// }
    /// </code>
    /// </example>
    [Serializable]
    public class CurlDnsException : CurlConnectionException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CurlDnsException"/> class.
        /// </summary>
        /// <param name="hostname">The hostname that could not be resolved.</param>
        /// <param name="command">The curl command that was executing.</param>
        public CurlDnsException(string hostname, string command = null)
            : base($"Could not resolve host: {hostname}", 6, hostname, null, command)
        {
            // CURLE_COULDNT_RESOLVE_HOST = 6
        }

        /// <summary>
        /// Initializes a new instance with serialized data.
        /// </summary>
        protected CurlDnsException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    /// <summary>
    /// Thrown when an operation exceeds the configured timeout period.
    /// </summary>
    /// <remarks>
    /// <para>This can occur for connection timeout or total operation timeout.</para>
    /// <para>Curl error code: CURLE_OPERATION_TIMEDOUT (28)</para>
    /// <para>AI-Usage: Catch this to implement retry with longer timeout or fail fast.</para>
    /// <para>AI-Pattern: Log timeout value to help diagnose if timeout is too short.</para>
    /// </remarks>
    /// <example>
    /// <code>
    /// try
    /// {
    ///     // Set a 5 second timeout
    ///     var result = await curl.ExecuteAsync("curl --max-time 5 https://slow-server.com/large-file");
    /// }
    /// catch (CurlTimeoutException ex)
    /// {
    ///     Console.WriteLine($"Operation timed out after {ex.Timeout?.TotalSeconds ?? 0} seconds");
    ///
    ///     // Retry with longer timeout
    ///     Console.WriteLine("Retrying with 30 second timeout...");
    ///     result = await curl.ExecuteAsync("curl --max-time 30 https://slow-server.com/large-file");
    /// }
    /// </code>
    /// </example>
    [Serializable]
    public class CurlTimeoutException : CurlException
    {
        /// <summary>
        /// Gets the timeout duration that was exceeded.
        /// </summary>
        /// <value>The timeout duration, or null if not specified.</value>
        /// <remarks>
        /// <para>This represents the --max-time or --connect-timeout value that was exceeded.</para>
        /// <para>AI-Usage: Use this to determine if timeout should be increased.</para>
        /// </remarks>
        public TimeSpan? Timeout { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="CurlTimeoutException"/> class.
        /// </summary>
        /// <param name="message">The error message describing the timeout.</param>
        /// <param name="command">The curl command that was executing.</param>
        /// <param name="timeout">The timeout duration that was exceeded.</param>
        public CurlTimeoutException(string message, string command = null, TimeSpan? timeout = null)
            : base(message, 28, command) // CURLE_OPERATION_TIMEDOUT = 28
        {
            Timeout = timeout;
        }

        /// <summary>
        /// Initializes a new instance with serialized data.
        /// </summary>
        protected CurlTimeoutException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
            Timeout = (TimeSpan?)info.GetValue(nameof(Timeout), typeof(TimeSpan?));
        }

        /// <inheritdoc/>
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue(nameof(Timeout), Timeout);
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
        public Dictionary<string, string> ResponseHeaders { get; set; } = new Dictionary<string, string>();

        public CurlHttpException(string message, int statusCode, string statusText = null, string responseBody = null, string command = null)
            : base(message, command)
        {
            StatusCode = statusCode;
            StatusText = statusText;
            ResponseBody = responseBody;

            // Add automatic suggestions based on status code
            AutoAddSuggestions();
        }

        /// <summary>
        /// Check if this is a client error (4xx)
        /// </summary>
        public bool IsClientError => StatusCode >= 400 && StatusCode < 500;

        /// <summary>
        /// Check if this is a server error (5xx)
        /// </summary>
        public bool IsServerError => StatusCode >= 500 && StatusCode < 600;

        /// <summary>
        /// Check if this is a specific status code.
        /// </summary>
        public bool IsStatus(int code) => StatusCode == code;

        /// <summary>
        /// Check if this is unauthorized (401).
        /// </summary>
        public bool IsUnauthorized => StatusCode == 401;

        /// <summary>
        /// Check if this is forbidden (403).
        /// </summary>
        public bool IsForbidden => StatusCode == 403;

        /// <summary>
        /// Check if this is not found (404).
        /// </summary>
        public bool IsNotFound => StatusCode == 404;

        /// <summary>
        /// Check if this is a rate limit error (429).
        /// </summary>
        public bool IsRateLimited => StatusCode == 429;

        /// <summary>
        /// Add response headers (fluent).
        /// </summary>
        public CurlHttpException WithHeaders(Dictionary<string, string> headers)
        {
            ResponseHeaders = headers;
            return this;
        }

        /// <summary>
        /// Get retry-after value if present in headers.
        /// </summary>
        public TimeSpan? GetRetryAfter()
        {
            if (ResponseHeaders.TryGetValue("Retry-After", out var retryAfter))
            {
                if (int.TryParse(retryAfter, out var seconds))
                {
                    return TimeSpan.FromSeconds(seconds);
                }
            }
            return null;
        }

        private void AutoAddSuggestions()
        {
            switch (StatusCode)
            {
                case 400:
                    Suggestions.Add("Check the request parameters and body format");
                    Suggestions.Add("Ensure all required fields are included");
                    break;
                case 401:
                    Suggestions.Add("Check your authentication credentials");
                    Suggestions.Add("Ensure your API key or token is valid");
                    Suggestions.Add("Check if the token has expired");
                    break;
                case 403:
                    Suggestions.Add("Check if you have permission to access this resource");
                    Suggestions.Add("Verify your API key has the required scopes");
                    break;
                case 404:
                    Suggestions.Add("Verify the URL is correct");
                    Suggestions.Add("Check if the resource exists");
                    break;
                case 429:
                    Suggestions.Add("You've hit a rate limit - wait before retrying");
                    Suggestions.Add("Consider implementing exponential backoff");
                    break;
                case 500:
                case 502:
                case 503:
                    Suggestions.Add("This is a server error - try again later");
                    Suggestions.Add("If the problem persists, contact the API provider");
                    break;
            }
        }

        public override string ToDetailedString()
        {
            var details = base.ToDetailedString();
            var sb = new StringBuilder(details);

            sb.AppendLine($"HTTP Status: {StatusCode} {StatusText}");
            sb.AppendLine($"Is Client Error: {IsClientError}");
            sb.AppendLine($"Is Server Error: {IsServerError}");

            if (!string.IsNullOrEmpty(ResponseBody))
            {
                sb.AppendLine($"Response Body: {ResponseBody}");
            }

            if (ResponseHeaders.Count > 0)
            {
                sb.AppendLine("Response Headers:");
                foreach (var header in ResponseHeaders)
                {
                    sb.AppendLine($"  {header.Key}: {header.Value}");
                }
            }

            return sb.ToString();
        }

        public override bool IsRetryable()
        {
            // Server errors and rate limits are typically retryable
            return StatusCode == 429 || StatusCode >= 500;
        }
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
            : base(message, 5, proxyHost, proxyPort, command)
        {
            ProxyHost = proxyHost;
            ProxyPort = proxyPort;
            // CURLE_COULDNT_RESOLVE_PROXY = 5
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
            : base($"Feature not supported: {feature}", 1, command)
        {
            Feature = feature;
            // CURLE_UNSUPPORTED_PROTOCOL = 1
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