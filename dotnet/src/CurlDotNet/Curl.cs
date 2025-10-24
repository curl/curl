/***************************************************************************
 * CurlDotNet - Pure .NET implementation of curl
 *
 * Inspired by and based on curl (https://curl.se) by Daniel Stenberg
 * Original curl Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This .NET implementation:
 * Copyright (C) 2024 IronSoftware
 *
 * The killer feature: Copy curl commands from anywhere and they just work!
 *
 * This could revolutionize how developers use HTTP in every language.
 * Imagine: Same curl commands working in C#, Rust, JavaScript, Python...
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 *
 * This file structure inspired by curl's src/tool_operate.c
 ***************************************************************************/

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Core;

namespace CurlDotNet
{
    /// <summary>
    /// <para><b>🚀 THE MAIN CURLDOTNET CLASS - Start here!</b></para>
    ///
    /// <para>This class lets you run ANY curl command in C# by just copying and pasting it as a string.
    /// No translation needed. No learning curve. If it works in curl, it works here.</para>
    ///
    /// <para><b>Quick Start:</b></para>
    /// <code>
    /// // Just paste any curl command as a string:
    /// var response = await Curl.Execute("curl https://api.github.com");
    /// Console.WriteLine(response.Body);  // That's it! You're done!
    /// </code>
    ///
    /// <para><b>What is curl?</b> curl is the universal tool for making HTTP requests from the command line.
    /// Every API documentation uses it. Now you can use those exact same commands in your C# code.</para>
    ///
    /// <para><b>Learn more:</b></para>
    /// <list type="bullet">
    /// <item>📖 curl documentation: <see href="https://curl.se/docs/"/></item>
    /// <item>📚 curl tutorial: <see href="https://curl.se/docs/tutorial.html"/></item>
    /// <item>⌨️ curl command generator: <see href="https://curlbuilder.com/"/></item>
    /// </list>
    /// </summary>
    /// <remarks>
    /// <para><b>Why use CurlDotNet instead of HttpClient?</b></para>
    /// <list type="number">
    /// <item>✂️ <b>Copy &amp; Paste</b> - Use commands directly from API docs without translation</item>
    /// <item>🎓 <b>No Learning Curve</b> - If you know curl (everyone does), you know this</item>
    /// <item>🔄 <b>Easy Migration</b> - Move from bash scripts to C# without rewriting</item>
    /// <item>📦 <b>All Features</b> - Supports all 300+ curl options out of the box</item>
    /// </list>
    ///
    /// <para><b>Thread Safety:</b> All methods are thread-safe. You can call them from multiple threads simultaneously.</para>
    ///
    /// <para><b>Memory Efficiency:</b> Responses are streamed, not loaded into memory all at once. Perfect for large files.</para>
    ///
    /// <para><b>Sponsored by</b> <see href="https://ironsoftware.com">IronSoftware</see> - creators of IronPDF, IronOCR, IronXL, and IronBarcode.</para>
    /// </remarks>
    public static partial class Curl
    {
        private static readonly CurlEngine _engine = new CurlEngine();

        // Global settings - thread-safe with volatile
        private static volatile int _defaultMaxTimeSeconds = 0; // 0 = no timeout
        private static volatile int _defaultConnectTimeoutSeconds = 0;
        private static volatile bool _defaultFollowRedirects = false;
        private static volatile bool _defaultInsecure = false;

        /// <summary>
        /// <para><b>Sets a global timeout for all curl operations (in seconds).</b></para>
        ///
        /// <para>This is like adding <c>--max-time</c> to every curl command automatically.
        /// Set to 0 (default) for no timeout. Individual commands can still override this.</para>
        ///
        /// <para><b>Example:</b></para>
        /// <code>
        /// // Set 30 second timeout for all operations
        /// Curl.DefaultMaxTimeSeconds = 30;
        ///
        /// // Now all commands timeout after 30 seconds
        /// await Curl.Execute("curl https://slow-api.example.com");  // Times out after 30s
        ///
        /// // Override for specific command
        /// await Curl.Execute("curl --max-time 60 https://very-slow-api.example.com");  // 60s timeout
        /// </code>
        ///
        /// <para><b>Learn more:</b> <see href="https://curl.se/docs/manpage.html#-m">curl --max-time documentation</see></para>
        /// </summary>
        /// <value>Timeout in seconds. 0 = no timeout (wait forever). Default is 0.</value>
        public static int DefaultMaxTimeSeconds
        {
            get => _defaultMaxTimeSeconds;
            set => _defaultMaxTimeSeconds = value;
        }

        /// <summary>
        /// <para><b>Sets how long to wait for a connection to be established (in seconds).</b></para>
        ///
        /// <para>This is different from the total timeout - it only applies to making the initial connection.
        /// Like adding <c>--connect-timeout</c> to every curl command.</para>
        ///
        /// <para><b>Example:</b></para>
        /// <code>
        /// // Give servers 10 seconds to accept connection
        /// Curl.DefaultConnectTimeoutSeconds = 10;
        ///
        /// // If server doesn't respond in 10 seconds, fails fast
        /// await Curl.Execute("curl https://overloaded-server.example.com");
        /// </code>
        ///
        /// <para><b>Tip:</b> Set this lower than DefaultMaxTimeSeconds to fail fast on dead servers.</para>
        /// <para><b>Learn more:</b> <see href="https://curl.se/docs/manpage.html#--connect-timeout">curl --connect-timeout documentation</see></para>
        /// </summary>
        /// <value>Connection timeout in seconds. 0 = no timeout. Default is 0.</value>
        public static int DefaultConnectTimeoutSeconds
        {
            get => _defaultConnectTimeoutSeconds;
            set => _defaultConnectTimeoutSeconds = value;
        }

        /// <summary>
        /// <para><b>Controls whether curl automatically follows HTTP redirects (301, 302, etc).</b></para>
        ///
        /// <para>When true, acts like adding <c>-L</c> or <c>--location</c> to every command.
        /// Many APIs use redirects, so you often want this enabled.</para>
        ///
        /// <para><b>Example:</b></para>
        /// <code>
        /// // Enable redirect following globally
        /// Curl.DefaultFollowRedirects = true;
        ///
        /// // Now shortened URLs work automatically
        /// var response = await Curl.Execute("curl https://bit.ly/example");  // Follows to final destination
        ///
        /// // Or use -L flag per command
        /// var response = await Curl.Execute("curl -L https://bit.ly/example");
        /// </code>
        ///
        /// <para><b>Security note:</b> Be careful following redirects to untrusted sources.</para>
        /// <para><b>Learn more:</b> <see href="https://curl.se/docs/manpage.html#-L">curl -L documentation</see></para>
        /// </summary>
        /// <value>true to follow redirects, false to stop at first response. Default is false.</value>
        public static bool DefaultFollowRedirects
        {
            get => _defaultFollowRedirects;
            set => _defaultFollowRedirects = value;
        }

        /// <summary>
        /// <para><b>⚠️ WARNING: Disables SSL certificate validation - ONLY use for development/testing!</b></para>
        ///
        /// <para>When true, acts like adding <c>-k</c> or <c>--insecure</c> to every command.
        /// This accepts any SSL certificate, even self-signed or expired ones.</para>
        ///
        /// <para><b>Example (DEVELOPMENT ONLY):</b></para>
        /// <code>
        /// #if DEBUG
        /// // Only in debug builds for local testing
        /// Curl.DefaultInsecure = true;
        ///
        /// // Now works with self-signed certificates
        /// await Curl.Execute("curl https://localhost:5001");  // Works even with invalid cert
        /// #endif
        /// </code>
        ///
        /// <para><b>🔴 NEVER use this in production!</b> It makes you vulnerable to man-in-the-middle attacks.</para>
        /// <para><b>Learn more:</b> <see href="https://curl.se/docs/manpage.html#-k">curl -k documentation</see></para>
        /// </summary>
        /// <value>true to skip SSL validation (DANGEROUS), false to validate (safe). Default is false.</value>
        public static bool DefaultInsecure
        {
            get => _defaultInsecure;
            set => _defaultInsecure = value;
        }

        /// <summary>
        /// <para><b>🎯 THE MAIN METHOD - Executes any curl command and returns the response.</b></para>
        ///
        /// <para>Just paste ANY curl command as a string. It works exactly like running curl from the command line,
        /// but returns the result as a nice C# object you can work with.</para>
        ///
        /// <para><b>Simple Example:</b></para>
        /// <code language="csharp">
        /// // Copy any curl command from documentation and paste it here:
        /// var response = await Curl.Execute("curl https://api.github.com/users/octocat");
        ///
        /// // Work with the response:
        /// Console.WriteLine($"Status: {response.StatusCode}");  // 200
        /// Console.WriteLine($"Body: {response.Body}");          // JSON data
        /// var user = response.ParseJson&lt;GitHubUser&gt;();        // Parse to object
        /// </code>
        ///
        /// <para><b>Real-World Example from Stripe Docs:</b></para>
        /// <code language="csharp">
        /// // Paste the exact command from Stripe's documentation:
        /// var response = await Curl.Execute(@"
        ///     curl https://api.stripe.com/v1/charges \
        ///       -u sk_test_4eC39HqLyjWDarjtT1zdp7dc: \
        ///       -d amount=2000 \
        ///       -d currency=usd \
        ///       -d source=tok_mastercard \
        ///       -d description='My First Test Charge'
        /// ");
        ///
        /// if (response.IsSuccess)
        /// {
        ///     var charge = response.ParseJson&lt;StripeCharge&gt;();
        ///     Console.WriteLine($"Payment successful! ID: {charge.Id}");
        /// }
        /// </code>
        ///
        /// <para><b>All HTTP Methods Supported:</b></para>
        /// <code language="csharp">
        /// await Curl.Execute("curl -X GET https://api.example.com/users");     // GET (default)
        /// await Curl.Execute("curl -X POST https://api.example.com/users");    // POST
        /// await Curl.Execute("curl -X PUT https://api.example.com/users/123"); // PUT
        /// await Curl.Execute("curl -X DELETE https://api.example.com/users/123"); // DELETE
        /// await Curl.Execute("curl -X PATCH https://api.example.com/users/123"); // PATCH
        /// </code>
        ///
        /// <para><b>Common Options:</b></para>
        /// <code language="csharp">
        /// // Headers
        /// await Curl.Execute("curl -H 'Authorization: Bearer token123' https://api.example.com");
        ///
        /// // POST data
        /// await Curl.Execute("curl -d '{\"name\":\"John\"}' https://api.example.com");
        ///
        /// // Save to file
        /// await Curl.Execute("curl -o download.pdf https://example.com/file.pdf");
        ///
        /// // Follow redirects
        /// await Curl.Execute("curl -L https://short.link/abc");
        ///
        /// // Basic auth
        /// await Curl.Execute("curl -u username:password https://api.example.com");
        ///
        /// // Timeout
        /// await Curl.Execute("curl --max-time 30 https://slow-api.example.com");
        /// </code>
        /// </summary>
        /// <param name="command">
        /// <para>Any valid curl command as a string. You can literally copy and paste from:</para>
        /// <list type="bullet">
        /// <item>📖 API documentation (Stripe, Twilio, GitHub, etc.)</item>
        /// <item>💬 Stack Overflow answers</item>
        /// <item>📝 Blog posts and tutorials</item>
        /// <item>🖥️ Your terminal history</item>
        /// <item>🔧 Postman's "Code" export feature</item>
        /// <item>🌐 Browser DevTools "Copy as cURL"</item>
        /// </list>
        /// <para>The "curl" prefix is optional - both work:</para>
        /// <code>
        /// await Curl.Execute("curl https://api.example.com");  // With "curl"
        /// await Curl.Execute("https://api.example.com");       // Without "curl"
        /// </code>
        /// </param>
        /// <returns>
        /// <para>A <see cref="CurlResult"/> object containing everything from the HTTP response:</para>
        /// <list type="bullet">
        /// <item><b>StatusCode</b> - HTTP status (200, 404, 500, etc.)</item>
        /// <item><b>Body</b> - Response body as string</item>
        /// <item><b>Headers</b> - All response headers as dictionary</item>
        /// <item><b>IsSuccess</b> - True if status is 200-299</item>
        /// <item><b>ParseJson&lt;T&gt;()</b> - Parse JSON response to your class</item>
        /// <item><b>SaveToFile()</b> - Save response to disk</item>
        /// </list>
        /// <para>See <see cref="CurlResult"/> for all available properties and methods.</para>
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// <para>Thrown when command is null or empty.</para>
        /// <code>
        /// // ❌ These will throw:
        /// await Curl.Execute(null);
        /// await Curl.Execute("");
        /// await Curl.Execute("   ");
        /// </code>
        /// </exception>
        /// <exception cref="CurlParseException">
        /// <para>Thrown when the curl command can't be understood. Usually means typo or unsupported option.</para>
        /// <code>
        /// // ❌ This will throw CurlParseException:
        /// await Curl.Execute("curl --invalid-option https://example.com");
        /// </code>
        /// <para>Error codes: CURLE_URL_MALFORMAT (3), CURLE_UNSUPPORTED_PROTOCOL (1)</para>
        /// <para>See: <see href="https://curl.se/libcurl/c/libcurl-errors.html">curl error codes</see></para>
        /// </exception>
        /// <exception cref="CurlDnsException">
        /// <para>Thrown when the hostname cannot be resolved (DNS failure).</para>
        /// <code>
        /// try
        /// {
        ///     await Curl.Execute("curl https://this-domain-does-not-exist.com");
        /// }
        /// catch (CurlDnsException ex)
        /// {
        ///     Console.WriteLine($"Could not find server: {ex.Hostname}");
        /// }
        /// </code>
        /// <para>Error code: CURLE_COULDNT_RESOLVE_HOST (6)</para>
        /// </exception>
        /// <exception cref="CurlTimeoutException">
        /// <para>Thrown when the operation takes longer than the timeout.</para>
        /// <code>
        /// try
        /// {
        ///     await Curl.Execute("curl --max-time 5 https://very-slow-api.com");
        /// }
        /// catch (CurlTimeoutException ex)
        /// {
        ///     Console.WriteLine($"Timed out after {ex.Timeout} seconds");
        /// }
        /// </code>
        /// <para>Error code: CURLE_OPERATION_TIMEDOUT (28)</para>
        /// <para>To cancel operations, see the <see cref="Execute(string, CancellationToken)"/> overload.</para>
        /// </exception>
        /// <exception cref="CurlSslException">
        /// <para>Thrown for SSL/TLS certificate problems.</para>
        /// <code>
        /// try
        /// {
        ///     await Curl.Execute("curl https://self-signed-cert.example.com");
        /// }
        /// catch (CurlSslException ex)
        /// {
        ///     Console.WriteLine($"SSL problem: {ex.Message}");
        ///     // In development only, you could use: curl -k (insecure)
        /// }
        /// </code>
        /// <para>Error codes: CURLE_SSL_CONNECT_ERROR (35), CURLE_PEER_FAILED_VERIFICATION (60)</para>
        /// </exception>
        /// <seealso cref="Execute(string, CancellationToken)">Execute with cancellation support</seealso>
        /// <seealso cref="ExecuteMany(string[])">Execute multiple commands in parallel</seealso>
        /// <seealso cref="CurlResult">The response object returned</seealso>
        /// <seealso href="https://curl.se/docs/manpage.html">Complete curl documentation</seealso>
        public static async Task<CurlResult> ExecuteAsync(string command)
        {
            return await _engine.ExecuteAsync(command);
        }

        /// <summary>
        /// <para><b>Execute a curl command with cancellation support - perfect for long-running operations.</b></para>
        ///
        /// <para>This lets you cancel the HTTP request if it's taking too long or if the user cancels.
        /// Essential for good user experience in desktop and mobile apps.</para>
        ///
        /// <para><b>Basic Example:</b></para>
        /// <code language="csharp">
        /// // Create a cancellation token that times out after 30 seconds
        /// using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        ///
        /// try
        /// {
        ///     var response = await Curl.Execute(
        ///         "curl https://slow-api.example.com/large-file",
        ///         cts.Token
        ///     );
        ///     Console.WriteLine("Download complete!");
        /// }
        /// catch (OperationCanceledException)
        /// {
        ///     Console.WriteLine("Download cancelled or timed out after 30 seconds");
        /// }
        /// </code>
        ///
        /// <para><b>User-Cancellable Download:</b></para>
        /// <code language="csharp">
        /// private CancellationTokenSource _downloadCts;
        ///
        /// // Start download
        /// async Task StartDownload()
        /// {
        ///     _downloadCts = new CancellationTokenSource();
        ///
        ///     try
        ///     {
        ///         var result = await Curl.Execute(
        ///             "curl -o large-file.zip https://example.com/huge-file.zip",
        ///             _downloadCts.Token
        ///         );
        ///         MessageBox.Show("Download complete!");
        ///     }
        ///     catch (OperationCanceledException)
        ///     {
        ///         MessageBox.Show("Download cancelled by user");
        ///     }
        /// }
        ///
        /// // Cancel button click
        /// void CancelButton_Click()
        /// {
        ///     _downloadCts?.Cancel();  // This stops the download
        /// }
        /// </code>
        ///
        /// <para><b>Web API with Request Timeout:</b></para>
        /// <code language="csharp">
        /// [HttpGet]
        /// public async Task&lt;IActionResult&gt; ProxyRequest(CancellationToken cancellationToken)
        /// {
        ///     // ASP.NET Core passes cancellation token that triggers when:
        ///     // - Client disconnects
        ///     // - Request timeout is reached
        ///     // - Server is shutting down
        ///
        ///     var result = await Curl.Execute(
        ///         "curl https://external-api.example.com/data",
        ///         cancellationToken  // Pass it through!
        ///     );
        ///
        ///     return Ok(result.Body);
        /// }
        /// </code>
        /// </summary>
        /// <param name="command">
        /// Any curl command string. See <see cref="Execute(string)"/> for full documentation.
        /// </param>
        /// <param name="cancellationToken">
        /// <para>Token to cancel the operation. Get this from:</para>
        /// <list type="bullet">
        /// <item>⏱️ <c>new CancellationTokenSource(TimeSpan.FromSeconds(30))</c> - Timeout</item>
        /// <item>🔘 <c>CancellationTokenSource</c> linked to Cancel button - User cancellation</item>
        /// <item>🌐 ASP.NET Core action parameter - Web request cancellation</item>
        /// <item>🔗 <c>CancellationTokenSource.CreateLinkedTokenSource()</c> - Multiple conditions</item>
        /// </list>
        /// <para>Learn more: <see href="https://docs.microsoft.com/en-us/dotnet/standard/threading/cancellation-in-managed-threads">Cancellation in .NET</see></para>
        /// </param>
        /// <returns>
        /// Same as <see cref="Execute(string)"/> - a <see cref="CurlResult"/> with the response.
        /// </returns>
        /// <exception cref="OperationCanceledException">
        /// <para>Thrown when the operation is cancelled via the token.</para>
        /// <code>
        /// try
        /// {
        ///     await Curl.Execute("curl https://api.example.com", cancelToken);
        /// }
        /// catch (OperationCanceledException)
        /// {
        ///     // Handle cancellation gracefully
        ///     Console.WriteLine("Request was cancelled");
        /// }
        /// </code>
        /// </exception>
        /// <remarks>
        /// <para><b>Best Practices:</b></para>
        /// <list type="number">
        /// <item>Always dispose CancellationTokenSource when done: <c>using var cts = new...</c></item>
        /// <item>Check <c>token.IsCancellationRequested</c> before starting expensive operations</item>
        /// <item>Pass tokens through your entire async call chain</item>
        /// <item>Combine multiple tokens with CreateLinkedTokenSource for complex scenarios</item>
        /// </list>
        /// </remarks>
        public static async Task<CurlResult> ExecuteAsync(string command, CancellationToken cancellationToken)
        {
            return await _engine.ExecuteAsync(command, cancellationToken);
        }

        /// <summary>
        /// <para><b>Execute with advanced settings - for when you need more control.</b></para>
        ///
        /// <para>Use this overload when you need features beyond what curl command strings provide,
        /// like progress callbacks, custom HTTP handlers, or retry policies.</para>
        ///
        /// <para><b>Example with Progress Reporting:</b></para>
        /// <code language="csharp">
        /// var settings = new CurlSettings
        /// {
        ///     OnProgress = (bytes, total) =>
        ///     {
        ///         var percent = (bytes * 100.0) / total;
        ///         Console.WriteLine($"Downloaded: {percent:F1}%");
        ///     }
        /// };
        ///
        /// await Curl.Execute("curl -O https://example.com/large-file.zip", settings);
        /// </code>
        ///
        /// <para><b>Example with Custom Retry Policy:</b></para>
        /// <code language="csharp">
        /// var settings = new CurlSettings
        /// {
        ///     RetryCount = 3,
        ///     RetryDelay = TimeSpan.FromSeconds(2),
        ///     RetryOn = new[] { 500, 502, 503, 504 }  // Retry on server errors
        /// };
        ///
        /// await Curl.Execute("curl https://unstable-api.example.com", settings);
        /// </code>
        /// </summary>
        /// <param name="command">Any curl command string.</param>
        /// <param name="settings">
        /// <para>Advanced settings including:</para>
        /// <list type="bullet">
        /// <item><b>OnProgress</b> - Callback for download/upload progress</item>
        /// <item><b>RetryCount</b> - Number of retry attempts</item>
        /// <item><b>RetryDelay</b> - Delay between retries</item>
        /// <item><b>CustomHttpMessageHandler</b> - Use your own HttpMessageHandler</item>
        /// <item><b>Middleware</b> - Add custom processing pipeline</item>
        /// </list>
        /// <para>See <see cref="CurlSettings"/> for all options.</para>
        /// </param>
        /// <returns>A <see cref="CurlResult"/> with the response.</returns>
        public static async Task<CurlResult> ExecuteAsync(string command, CurlSettings settings)
        {
            return await _engine.ExecuteAsync(command, settings);
        }

        /// <summary>
        /// <para><b>Quick GET request - simpler syntax for basic GET operations.</b></para>
        ///
        /// <para>When you just need to GET a URL without any options, use this shortcut method.</para>
        ///
        /// <para><b>Example:</b></para>
        /// <code language="csharp">
        /// // Instead of:
        /// await Curl.Execute("curl https://api.github.com/users/octocat");
        ///
        /// // You can use:
        /// var response = await Curl.Get("https://api.github.com/users/octocat");
        ///
        /// // Work with response
        /// var user = response.ParseJson&lt;GitHubUser&gt;();
        /// Console.WriteLine($"Followers: {user.Followers}");
        /// </code>
        /// </summary>
        /// <param name="url">
        /// The URL to GET. Can be HTTP or HTTPS. Query parameters can be included.
        /// <code>
        /// await Curl.Get("https://api.example.com/users?page=1&amp;limit=10");
        /// </code>
        /// </param>
        /// <returns>A <see cref="CurlResult"/> with the response.</returns>
        /// <remarks>
        /// <para>This is equivalent to: <c>Curl.Execute($"curl {url}")</c></para>
        /// <para>For GET requests with headers or auth, use the full <see cref="Execute(string)"/> method.</para>
        /// </remarks>
        public static async Task<CurlResult> GetAsync(string url)
        {
            return await ExecuteAsync($"curl {url}");
        }

        /// <summary>
        /// <para><b>Quick POST request - simpler syntax for posting data.</b></para>
        ///
        /// <para>Convenient method for simple POST requests with string data.</para>
        ///
        /// <para><b>Example:</b></para>
        /// <code language="csharp">
        /// // Post form data
        /// var response = await Curl.Post(
        ///     "https://api.example.com/login",
        ///     "username=john&amp;password=secret123"
        /// );
        ///
        /// // Post JSON data
        /// var json = "{\"name\":\"John\",\"age\":30}";
        /// var result = await Curl.Post("https://api.example.com/users", json);
        /// </code>
        /// </summary>
        /// <param name="url">The URL to POST to.</param>
        /// <param name="data">
        /// The data to send in the POST body. Can be:
        /// <list type="bullet">
        /// <item>JSON string: <c>"{\"key\":\"value\"}"</c></item>
        /// <item>Form data: <c>"key1=value1&amp;key2=value2"</c></item>
        /// <item>XML or any other string content</item>
        /// </list>
        /// </param>
        /// <returns>A <see cref="CurlResult"/> with the response.</returns>
        /// <remarks>
        /// <para>This is equivalent to: <c>Curl.Execute($"curl -X POST -d '{data}' {url}")</c></para>
        /// <para>For POST with headers, use <see cref="PostJson"/> or the full <see cref="Execute(string)"/> method.</para>
        /// </remarks>
        public static async Task<CurlResult> PostAsync(string url, string data)
        {
            return await ExecuteAsync($"curl -X POST -d '{data}' {url}");
        }

        /// <summary>
        /// <para><b>POST with JSON data - automatically serializes objects to JSON.</b></para>
        ///
        /// <para>The easiest way to POST JSON data. Pass any object and it's automatically
        /// serialized to JSON with the correct Content-Type header.</para>
        ///
        /// <para><b>Example:</b></para>
        /// <code language="csharp">
        /// // Create your data object
        /// var newUser = new
        /// {
        ///     name = "John Smith",
        ///     email = "john@example.com",
        ///     age = 30
        /// };
        ///
        /// // Post it as JSON automatically
        /// var response = await Curl.PostJson("https://api.example.com/users", newUser);
        ///
        /// // Check if successful
        /// if (response.IsSuccess)
        /// {
        ///     var created = response.ParseJson&lt;User&gt;();
        ///     Console.WriteLine($"User created with ID: {created.Id}");
        /// }
        /// </code>
        ///
        /// <para><b>Works with any object:</b></para>
        /// <code language="csharp">
        /// // Anonymous objects
        /// await Curl.PostJson(url, new { key = "value" });
        ///
        /// // Your classes
        /// await Curl.PostJson(url, myUserObject);
        ///
        /// // Collections
        /// await Curl.PostJson(url, new[] { item1, item2, item3 });
        ///
        /// // Dictionaries
        /// await Curl.PostJson(url, new Dictionary&lt;string, object&gt; { ["key"] = "value" });
        /// </code>
        /// </summary>
        /// <param name="url">The URL to POST to.</param>
        /// <param name="data">
        /// Any object to serialize as JSON. Can be:
        /// <list type="bullet">
        /// <item>Anonymous objects: <c>new { name = "John" }</c></item>
        /// <item>Your classes: <c>new User { Name = "John" }</c></item>
        /// <item>Collections: <c>new[] { 1, 2, 3 }</c></item>
        /// <item>Dictionaries: <c>Dictionary&lt;string, object&gt;</c></item>
        /// </list>
        /// </param>
        /// <returns>A <see cref="CurlResult"/> with the response.</returns>
        /// <remarks>
        /// <para>Automatically adds: <c>Content-Type: application/json</c> header</para>
        /// <para>Uses System.Text.Json on .NET 6+ or Newtonsoft.Json on older frameworks</para>
        /// </remarks>
        public static async Task<CurlResult> PostJsonAsync(string url, object data)
        {
            var json = SerializeJson(data);
            return await ExecuteAsync($"curl -X POST -H 'Content-Type: application/json' -d '{json}' {url}");
        }

        /// <summary>
        /// <para><b>Download a file from a URL and save it to disk.</b></para>
        ///
        /// <para>Downloads any file and saves it to the specified path. Shows progress if the file is large.</para>
        ///
        /// <para><b>Example:</b></para>
        /// <code language="csharp">
        /// // Download a PDF
        /// await Curl.Download(
        ///     "https://example.com/manual.pdf",
        ///     @"C:\Downloads\manual.pdf"
        /// );
        ///
        /// // Download with original filename
        /// await Curl.Download(
        ///     "https://example.com/installer.exe",
        ///     @"C:\Downloads\installer.exe"
        /// );
        ///
        /// Console.WriteLine("Download complete!");
        /// </code>
        ///
        /// <para><b>With Error Handling:</b></para>
        /// <code language="csharp">
        /// try
        /// {
        ///     await Curl.Download(url, "output.zip");
        ///     Console.WriteLine("✅ Download successful");
        /// }
        /// catch (CurlHttpException ex) when (ex.StatusCode == 404)
        /// {
        ///     Console.WriteLine("❌ File not found");
        /// }
        /// catch (Exception ex)
        /// {
        ///     Console.WriteLine($"❌ Download failed: {ex.Message}");
        /// }
        /// </code>
        /// </summary>
        /// <param name="url">The URL of the file to download.</param>
        /// <param name="outputPath">
        /// Where to save the file. Can be:
        /// <list type="bullet">
        /// <item>Full path: <c>@"C:\Downloads\file.pdf"</c></item>
        /// <item>Relative path: <c>"downloads/file.pdf"</c></item>
        /// <item>Just filename: <c>"file.pdf"</c> (saves to current directory)</item>
        /// </list>
        /// </param>
        /// <returns>A <see cref="CurlResult"/> with download information.</returns>
        /// <remarks>
        /// <para>This is equivalent to: <c>Curl.Execute($"curl -o {outputPath} {url}")</c></para>
        /// <para>For large files with progress, use <see cref="Execute(string, CurlSettings)"/> with OnProgress callback.</para>
        /// </remarks>
        public static async Task<CurlResult> DownloadAsync(string url, string outputPath)
        {
            return await ExecuteAsync($"curl -o {outputPath} {url}");
        }

        /// <summary>
        /// <para><b>Execute multiple curl commands in parallel - great for performance!</b></para>
        ///
        /// <para>Runs multiple HTTP requests at the same time, which is much faster than running them one by one.
        /// Perfect for fetching data from multiple APIs or endpoints simultaneously.</para>
        ///
        /// <para><b>Example - Fetch Multiple APIs:</b></para>
        /// <code language="csharp">
        /// // These all run at the same time (parallel), not one after another
        /// var results = await Curl.ExecuteMany(
        ///     "curl https://api.github.com/users/microsoft",
        ///     "curl https://api.github.com/users/dotnet",
        ///     "curl https://api.github.com/users/azure"
        /// );
        ///
        /// // Process results - array order matches command order
        /// Console.WriteLine($"Microsoft: {results[0].Body}");
        /// Console.WriteLine($"DotNet: {results[1].Body}");
        /// Console.WriteLine($"Azure: {results[2].Body}");
        /// </code>
        ///
        /// <para><b>Example - Aggregate Data:</b></para>
        /// <code language="csharp">
        /// // Fetch from multiple services simultaneously
        /// var results = await Curl.ExecuteMany(
        ///     "curl https://api.weather.com/temperature",
        ///     "curl https://api.weather.com/humidity",
        ///     "curl https://api.weather.com/forecast"
        /// );
        ///
        /// // Check if all succeeded
        /// if (results.All(r => r.IsSuccess))
        /// {
        ///     var temp = results[0].ParseJson&lt;Temperature&gt;();
        ///     var humidity = results[1].ParseJson&lt;Humidity&gt;();
        ///     var forecast = results[2].ParseJson&lt;Forecast&gt;();
        ///
        ///     DisplayWeatherDashboard(temp, humidity, forecast);
        /// }
        /// </code>
        ///
        /// <para><b>Error Handling - Some May Fail:</b></para>
        /// <code language="csharp">
        /// var results = await Curl.ExecuteMany(commands);
        ///
        /// for (int i = 0; i &lt; results.Length; i++)
        /// {
        ///     if (results[i].IsSuccess)
        ///     {
        ///         Console.WriteLine($"✅ Command {i} succeeded");
        ///     }
        ///     else
        ///     {
        ///         Console.WriteLine($"❌ Command {i} failed: {results[i].StatusCode}");
        ///     }
        /// }
        /// </code>
        /// </summary>
        /// <param name="commands">
        /// Array of curl command strings to execute. Can pass as:
        /// <list type="bullet">
        /// <item>Multiple parameters: <c>ExecuteMany(cmd1, cmd2, cmd3)</c></item>
        /// <item>Array: <c>ExecuteMany(commandArray)</c></item>
        /// <item>List: <c>ExecuteMany(commandList.ToArray())</c></item>
        /// </list>
        /// </param>
        /// <returns>
        /// Array of <see cref="CurlResult"/> objects in the same order as the commands.
        /// Even if some fail, you still get results for all commands.
        /// </returns>
        /// <remarks>
        /// <para><b>Performance Note:</b> If you have 10 commands that each take 1 second,
        /// running them in parallel takes ~1 second total instead of 10 seconds sequentially!</para>
        /// <para><b>Limit:</b> Be respectful of APIs - don't send hundreds of parallel requests.</para>
        /// </remarks>
        public static async Task<CurlResult[]> ExecuteManyAsync(params string[] commands)
        {
            var tasks = commands.Select(cmd => ExecuteAsync(cmd));
            return await Task.WhenAll(tasks);
        }

        /// <summary>
        /// <para><b>Check if a curl command is valid without executing it.</b></para>
        ///
        /// <para>Useful for validating user input or checking commands before running them.
        /// This only checks syntax, not whether the URL actually exists.</para>
        ///
        /// <para><b>Example:</b></para>
        /// <code language="csharp">
        /// // Check if command is valid
        /// var validation = Curl.Validate("curl -X POST https://api.example.com");
        ///
        /// if (validation.IsValid)
        /// {
        ///     Console.WriteLine("✅ Command is valid!");
        ///     // Safe to execute
        ///     var result = await Curl.Execute(command);
        /// }
        /// else
        /// {
        ///     Console.WriteLine($"❌ Invalid command: {validation.ErrorMessage}");
        ///     Console.WriteLine($"Problem at position {validation.ErrorPosition}");
        /// }
        /// </code>
        ///
        /// <para><b>Validate User Input:</b></para>
        /// <code language="csharp">
        /// Console.Write("Enter curl command: ");
        /// var userCommand = Console.ReadLine();
        ///
        /// var validation = Curl.Validate(userCommand);
        /// if (!validation.IsValid)
        /// {
        ///     Console.WriteLine($"Error: {validation.ErrorMessage}");
        ///     if (validation.Suggestions.Any())
        ///     {
        ///         Console.WriteLine("Did you mean:");
        ///         foreach (var suggestion in validation.Suggestions)
        ///         {
        ///             Console.WriteLine($"  - {suggestion}");
        ///         }
        ///     }
        /// }
        /// </code>
        /// </summary>
        /// <param name="command">The curl command string to validate.</param>
        /// <returns>
        /// A <see cref="ValidationResult"/> containing:
        /// <list type="bullet">
        /// <item><b>IsValid</b> - true if command is valid</item>
        /// <item><b>ErrorMessage</b> - Description of what's wrong (if invalid)</item>
        /// <item><b>ErrorPosition</b> - Character position of error</item>
        /// <item><b>Suggestions</b> - Possible fixes for common mistakes</item>
        /// </list>
        /// </returns>
        public static ValidationResult Validate(string command)
        {
            return _engine.Validate(command);
        }

        /// <summary>
        /// <para><b>Convert curl command to C# HttpClient code - great for learning!</b></para>
        ///
        /// <para>Shows you exactly how to write the same request using HttpClient.
        /// Perfect for understanding what curl is doing or migrating to pure HttpClient.</para>
        ///
        /// <para><b>Example:</b></para>
        /// <code language="csharp">
        /// var curlCommand = @"
        ///     curl -X POST https://api.example.com/users \
        ///       -H 'Content-Type: application/json' \
        ///       -H 'Authorization: Bearer token123' \
        ///       -d '{""name"":""John"",""age"":30}'
        /// ";
        ///
        /// string code = Curl.ToHttpClient(curlCommand);
        /// Console.WriteLine(code);
        ///
        /// // Output:
        /// // using var client = new HttpClient();
        /// // var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/users");
        /// // request.Headers.Add("Authorization", "Bearer token123");
        /// // request.Content = new StringContent("{\"name\":\"John\",\"age\":30}",
        /// //     Encoding.UTF8, "application/json");
        /// // var response = await client.SendAsync(request);
        /// </code>
        /// </summary>
        /// <param name="command">The curl command to convert.</param>
        /// <returns>C# code using HttpClient that does the same thing.</returns>
        /// <remarks>
        /// <para>Great for:</para>
        /// <list type="bullet">
        /// <item>Learning how HttpClient works</item>
        /// <item>Migrating from CurlDotNet to pure HttpClient</item>
        /// <item>Understanding what curl commands actually do</item>
        /// <item>Code generation for your projects</item>
        /// </list>
        /// </remarks>
        public static string ToHttpClient(string command)
        {
            return _engine.ToHttpClientCode(command);
        }

        /// <summary>
        /// <para><b>Convert curl command to JavaScript fetch() code.</b></para>
        ///
        /// <para>Generates JavaScript code that does the same thing as your curl command.
        /// Useful for web developers who need the same request in JavaScript.</para>
        ///
        /// <para><b>Example:</b></para>
        /// <code language="javascript">
        /// var curlCommand = "curl -X GET https://api.example.com/data -H 'Authorization: Bearer token'";
        ///
        /// string jsCode = Curl.ToFetch(curlCommand);
        /// Console.WriteLine(jsCode);
        ///
        /// // Output:
        /// // fetch('https://api.example.com/data', {
        /// //     method: 'GET',
        /// //     headers: {
        /// //         'Authorization': 'Bearer token'
        /// //     }
        /// // })
        /// // .then(response => response.json())
        /// // .then(data => console.log(data));
        /// </code>
        /// </summary>
        /// <param name="command">The curl command to convert.</param>
        /// <returns>JavaScript fetch() code that does the same thing.</returns>
        public static string ToFetch(string command)
        {
            return _engine.ToFetchCode(command);
        }

        /// <summary>
        /// <para><b>Convert curl command to Python requests code.</b></para>
        ///
        /// <para>Generates Python code using the popular 'requests' library.
        /// Great for Python developers or data scientists.</para>
        ///
        /// <para><b>Example:</b></para>
        /// <code language="python">
        /// var curlCommand = "curl -u user:pass https://api.example.com/data";
        ///
        /// string pythonCode = Curl.ToPythonRequests(curlCommand);
        /// Console.WriteLine(pythonCode);
        ///
        /// // Output:
        /// // import requests
        /// //
        /// // response = requests.get(
        /// //     'https://api.example.com/data',
        /// //     auth=('user', 'pass')
        /// // )
        /// // print(response.json())
        /// </code>
        /// </summary>
        /// <param name="command">The curl command to convert.</param>
        /// <returns>Python code using requests library.</returns>
        public static string ToPythonRequests(string command)
        {
            return _engine.ToPythonCode(command);
        }

        private static string SerializeJson(object data)
        {
            #if NETSTANDARD2_0
            return Newtonsoft.Json.JsonConvert.SerializeObject(data);
            #else
            return System.Text.Json.JsonSerializer.Serialize(data);
            #endif
        }
    }
}