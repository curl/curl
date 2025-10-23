# CurlDotNet - Top 20 Real-World Use Cases

Based on curl by Daniel Stenberg <daniel@haxx.se>
Original curl source: https://github.com/curl/curl
.NET implementation by Jacob Mellor: https://github.com/jacob-mellor
Sponsored by Iron Software: https://ironsoftware.com

## Table of Contents
1. [Simple GET Request](#1-simple-get-request)
2. [POST JSON to REST API](#2-post-json-to-rest-api)
3. [Download File with Progress Bar](#3-download-file-with-progress-bar)
4. [Authentication (Basic, Bearer, API Key)](#4-authentication)
5. [Handle Cookies and Sessions](#5-cookies-and-sessions)
6. [Follow Redirects](#6-follow-redirects)
7. [Custom Headers](#7-custom-headers)
8. [Upload Files](#8-upload-files)
9. [Form Data Submission](#9-form-data-submission)
10. [Timeout and Retry Logic](#10-timeout-and-retry)
11. [Proxy Configuration](#11-proxy-configuration)
12. [HTTPS with Certificate Issues](#12-https-certificate-handling)
13. [GraphQL Queries](#13-graphql-queries)
14. [WebSocket Upgrade](#14-websocket-upgrade)
15. [FTP Operations](#15-ftp-operations)
16. [Parallel Requests](#16-parallel-requests)
17. [Rate-Limited APIs](#17-rate-limited-apis)
18. [Webhook Testing](#18-webhook-testing)
19. [Health Checks and Monitoring](#19-health-checks)
20. [Web Scraping](#20-web-scraping)

---

## 1. Simple GET Request

The most basic use case - fetching data from an API.

```csharp
// Linux/Mac command line:
// curl https://api.github.com/users/torvalds

// CurlDotNet - Method 1: Direct string
string response = await Curl.Curl("https://api.github.com/users/torvalds");
Console.WriteLine(response);

// Method 2: With error handling
var result = await Curl.Curl("https://api.github.com/users/torvalds");
if (result.IsSuccess)
{
    var user = result.ToJson<GitHubUser>();
    Console.WriteLine($"Name: {user.Name}, Repos: {user.PublicRepos}");
}

// Method 3: Synchronous
var data = Curl.CurlSync("https://api.github.com/users/torvalds");
```

## 2. POST JSON to REST API

Creating resources via REST APIs - the second most common use case.

```csharp
// Linux command line:
// curl -X POST https://api.example.com/users \
//      -H "Content-Type: application/json" \
//      -d '{"name":"John Doe","email":"john@example.com"}'

// CurlDotNet - Method 1: Raw curl command
var result = await Curl.Curl(@"
    curl -X POST https://api.example.com/users
         -H 'Content-Type: application/json'
         -d '{""name"":""John Doe"",""email"":""john@example.com""}'
");

// Method 2: Strongly typed
var user = new { name = "John Doe", email = "john@example.com" };
var result = await Http.Post("https://api.example.com/users", user);

// Method 3: With response parsing
var createdUser = await Http.PostJson<object, User>(
    "https://api.example.com/users",
    new { name = "John", email = "john@example.com" }
);
Console.WriteLine($"Created user with ID: {createdUser.Id}");
```

## 3. Download File with Progress Bar

Downloading large files with progress tracking.

```csharp
// Linux command line:
// curl -L -o ubuntu.iso https://releases.ubuntu.com/22.04/ubuntu-22.04-desktop-amd64.iso

// CurlDotNet with progress tracking
var progress = new Progress<CurlProgressInfo>(p =>
{
    Console.Write($"\rDownloading: {p.PercentComplete:F1}% " +
                  $"({p.TransferredBytes / 1024 / 1024}MB / {p.TotalBytes / 1024 / 1024}MB) " +
                  $"Speed: {p.GetSpeedString()}");
});

var result = await Curl.Curl(
    "curl -L -o ubuntu.iso https://releases.ubuntu.com/22.04/ubuntu-22.04-desktop-amd64.iso",
    progress: progress
);

Console.WriteLine("\nDownload complete!");

// Alternative with progress bar
var progressBar = new CurlProgressBar();
await Http.Download(
    "https://releases.ubuntu.com/22.04/ubuntu-22.04-desktop-amd64.iso",
    @"C:\Downloads\ubuntu.iso",
    p => progressBar.Render(p)
);
progressBar.Complete();
```

## 4. Authentication

Various authentication methods commonly used in APIs.

```csharp
// Basic Authentication
// curl -u username:password https://api.example.com/private

var result = await Curl.Curl("curl -u john:secret123 https://api.example.com/private");

// Bearer Token (OAuth 2.0)
// curl -H "Authorization: Bearer YOUR_TOKEN" https://api.example.com/data

var result = await Curl.Curl(@"
    curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
         https://api.example.com/data
");

// API Key in header
var result = await Curl.Curl(@"
    curl -H 'X-API-Key: your-api-key-here'
         https://api.example.com/data
");

// Using session for persistent auth
using var session = new CurlSession();
session.SetBearerToken("your-token-here");
var result1 = await session.ExecuteAsync("https://api.example.com/endpoint1");
var result2 = await session.ExecuteAsync("https://api.example.com/endpoint2");
```

## 5. Cookies and Sessions

Managing cookies for stateful interactions.

```csharp
// Save cookies to file
// curl -c cookies.txt -b cookies.txt https://example.com/login

// CurlDotNet with session management
using var session = new CurlSession();

// Login and save cookies
var loginResult = await session.ExecuteAsync(@"
    curl -X POST https://example.com/login
         -d 'username=john&password=secret'
");

// Subsequent requests use saved cookies
var profileResult = await session.ExecuteAsync("https://example.com/profile");
var ordersResult = await session.ExecuteAsync("https://example.com/orders");

// Save cookies for later use
await session.SaveCookiesAsync("cookies.txt");

// Load cookies in new session
using var newSession = new CurlSession();
await newSession.LoadCookiesAsync("cookies.txt");
```

## 6. Follow Redirects

Handling URL redirects automatically.

```csharp
// curl -L https://bit.ly/shortened-url

var result = await Curl.Curl("curl -L https://bit.ly/shortened-url");
Console.WriteLine($"Final URL: {result.EffectiveUrl}");
Console.WriteLine($"Number of redirects: {result.RedirectCount}");

// With max redirects limit
var result = await Curl.Curl("curl -L --max-redirs 5 https://example.com/redirect");
```

## 7. Custom Headers

Setting custom headers for API requirements.

```csharp
// Multiple headers
// curl -H "Accept: application/json" \
//      -H "Accept-Language: en-US" \
//      -H "X-Custom-Header: value" \
//      https://api.example.com/data

var result = await Curl.Curl(@"
    curl -H 'Accept: application/json'
         -H 'Accept-Language: en-US'
         -H 'X-Custom-Header: value'
         -H 'Cache-Control: no-cache'
         https://api.example.com/data
");

// User-Agent spoofing
var result = await Curl.Curl(@"
    curl -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0'
         https://example.com
");
```

## 8. Upload Files

Uploading files to servers.

```csharp
// Upload with PUT
// curl -T file.pdf https://example.com/upload

var result = await Curl.Curl("curl -T 'C:\\Documents\\report.pdf' https://example.com/upload");

// Multipart form upload
// curl -F "file=@photo.jpg" -F "name=vacation" https://example.com/upload

var result = await Curl.Curl(@"
    curl -F 'file=@C:\Photos\photo.jpg'
         -F 'name=vacation'
         -F 'description=Summer 2024'
         https://example.com/upload
");

// FTP upload
var result = await Curl.Curl("curl -T file.zip ftp://ftp.example.com/ -u user:pass");
```

## 9. Form Data Submission

Submitting HTML forms programmatically.

```csharp
// URL-encoded form data
// curl -d "name=John&age=30&city=NewYork" https://example.com/form

var result = await Curl.Curl(@"
    curl -d 'name=John&age=30&city=NewYork'
         https://example.com/form
");

// Form with file upload
var result = await Curl.Curl(@"
    curl -F 'username=john'
         -F 'avatar=@profile.jpg'
         -F 'bio=Software Developer'
         https://example.com/profile/update
");

// URL-encoded with special characters
var result = await Curl.Curl(@"
    curl --data-urlencode 'message=Hello World & Special Characters!'
         https://example.com/submit
");
```

## 10. Timeout and Retry

Handling slow or unreliable endpoints.

```csharp
// With timeout
// curl --connect-timeout 10 --max-time 30 https://slow-api.com

var result = await Curl.CurlWithTimeout(
    "https://slow-api.com/endpoint",
    TimeSpan.FromSeconds(30)
);

// With retry logic
var result = await Curl.CurlWithRetry(
    "https://unreliable-api.com/data",
    maxRetries: 3,
    retryDelay: TimeSpan.FromSeconds(2)
);

// With cancellation token
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
var result = await Curl.Curl("https://api.example.com/long-running", cts.Token);
```

## 11. Proxy Configuration

Using proxies for requests.

```csharp
// HTTP proxy
// curl -x http://proxy.example.com:8080 https://api.example.com

var result = await Curl.Curl(@"
    curl -x http://proxy.example.com:8080
         https://api.example.com/data
");

// Proxy with authentication
var result = await Curl.Curl(@"
    curl -x http://proxy.example.com:8080
         -U proxyuser:proxypass
         https://api.example.com/data
");

// SOCKS5 proxy
var result = await Curl.Curl(@"
    curl --socks5 localhost:1080
         https://api.example.com/data
");
```

## 12. HTTPS Certificate Handling

Dealing with SSL/TLS certificates.

```csharp
// Ignore certificate errors (development only!)
// curl -k https://self-signed.example.com

var result = await Curl.Curl("curl -k https://self-signed.example.com");

// Specify CA certificate
var result = await Curl.Curl(@"
    curl --cacert /path/to/ca-cert.pem
         https://secure.example.com
");

// Client certificate authentication
var result = await Curl.Curl(@"
    curl --cert client-cert.pem --key client-key.pem
         https://secure-api.example.com
");
```

## 13. GraphQL Queries

Working with GraphQL APIs.

```csharp
// GraphQL query
var query = @"
    query GetUser($id: ID!) {
        user(id: $id) {
            name
            email
            posts {
                title
                content
            }
        }
    }
";

var result = await Http.GraphQL(
    "https://api.example.com/graphql",
    query,
    new { id = "123" }
);

// Using raw curl
var result = await Curl.Curl(@"
    curl -X POST https://api.example.com/graphql
         -H 'Content-Type: application/json'
         -d '{""query"": ""{ users { id name email } }""}'
");
```

## 14. WebSocket Upgrade

Initial HTTP request for WebSocket connections.

```csharp
// WebSocket handshake
var result = await Curl.Curl(@"
    curl -H 'Upgrade: websocket'
         -H 'Connection: Upgrade'
         -H 'Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw=='
         -H 'Sec-WebSocket-Version: 13'
         https://ws.example.com/socket
");
```

## 15. FTP Operations

File transfer protocol operations.

```csharp
// List FTP directory
// curl ftp://ftp.example.com/pub/ -u user:pass

var result = await Curl.Curl("curl ftp://ftp.example.com/pub/ -u user:pass");

// Download from FTP
var result = await Curl.Curl(@"
    curl -o file.zip ftp://ftp.example.com/files/file.zip
         -u username:password
");

// Upload to FTP
var result = await Curl.Curl(@"
    curl -T localfile.pdf ftp://ftp.example.com/uploads/
         -u username:password
");
```

## 16. Parallel Requests

Making multiple requests concurrently.

```csharp
// Fetch multiple endpoints in parallel
var results = await Curl.CurlParallel(new[]
{
    "https://api1.example.com/data",
    "https://api2.example.com/data",
    "https://api3.example.com/data"
});

// Named parallel requests
var results = await Http.Parallel(
    ("users", "curl https://api.example.com/users"),
    ("posts", "curl https://api.example.com/posts"),
    ("comments", "curl https://api.example.com/comments")
);

Console.WriteLine($"Users: {results["users"].Body}");
Console.WriteLine($"Posts: {results["posts"].Body}");
```

## 17. Rate-Limited APIs

Handling APIs with rate limiting.

```csharp
try
{
    var result = await Curl.Curl("https://api.example.com/limited")
        .ThrowOnError();
}
catch (CurlRateLimitException ex)
{
    Console.WriteLine($"Rate limited. Retry after: {ex.RetryAfter}");
    await Task.Delay(ex.RetryAfter.Value);

    // Retry the request
    var result = await Curl.Curl("https://api.example.com/limited");
}

// Check rate limit headers
var result = await Curl.Curl("https://api.example.com/data");
var remaining = result.GetHeader("X-RateLimit-Remaining");
var reset = result.GetHeader("X-RateLimit-Reset");
Console.WriteLine($"Remaining: {remaining}, Reset: {reset}");
```

## 18. Webhook Testing

Testing webhook endpoints.

```csharp
// Send webhook
var webhookData = new
{
    @event = "user.created",
    timestamp = DateTime.UtcNow,
    data = new { userId = 123, email = "user@example.com" }
};

var result = await Http.Post("https://example.com/webhook", webhookData);

// Verify webhook signature
var result = await Curl.Curl(@"
    curl -X POST https://example.com/webhook
         -H 'X-Webhook-Signature: sha256=...'
         -d '{""event"":""payment.completed""}'
");
```

## 19. Health Checks

Monitoring service health.

```csharp
// Simple health check
bool isHealthy = await Http.IsHealthy("https://api.example.com/health");

// Detailed health check
var result = await Curl.Curl("curl -I https://api.example.com/health");
if (result.StatusCode == 200)
{
    Console.WriteLine("Service is healthy");
}

// Multiple service health checks
var services = new[] { "api", "auth", "database" };
foreach (var service in services)
{
    var health = await Curl.CurlWithTimeout(
        $"https://{service}.example.com/health",
        TimeSpan.FromSeconds(5)
    );
    Console.WriteLine($"{service}: {health.StatusCode == 200 ? "✓" : "✗"}");
}
```

## 20. Web Scraping

Extracting data from websites.

```csharp
// Basic scraping with headers to avoid bot detection
var result = await Curl.Curl(@"
    curl -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0'
         -H 'Accept: text/html,application/xhtml+xml'
         -H 'Accept-Language: en-US,en;q=0.9'
         -H 'Cache-Control: no-cache'
         https://example.com/page
");

// Parse HTML content
var html = result.Body;
// Use HtmlAgilityPack or AngleSharp to parse

// With session for maintaining state
using var session = new CurlSession(new CurlSessionSettings
{
    UserAgent = "Mozilla/5.0 (compatible; MyBot/1.0)",
    FollowRedirects = true
});

// Login if needed
await session.ExecuteAsync(@"
    curl -X POST https://example.com/login
         -d 'username=user&password=pass'
");

// Scrape protected content
var content = await session.ExecuteAsync("https://example.com/protected-content");
```

---

## Advanced Patterns

### Creating a REST API Client

```csharp
public class ApiClient
{
    private readonly CurlSession _session;

    public ApiClient(string apiKey)
    {
        _session = new CurlSession(new CurlSessionSettings
        {
            BaseUrl = "https://api.example.com",
            ThrowOnHttpError = true,
            RetryCount = 3
        });

        _session.AddDefaultHeader("X-API-Key", apiKey);
        _session.AddDefaultHeader("Accept", "application/json");
    }

    public async Task<T> GetAsync<T>(string endpoint)
    {
        var result = await _session.ExecuteAsync($"{endpoint}");
        return result.ToJson<T>();
    }

    public async Task<TResponse> PostAsync<TRequest, TResponse>(string endpoint, TRequest data)
    {
        var json = JsonSerializer.Serialize(data);
        var result = await _session.ExecuteAsync($@"
            curl -X POST {endpoint}
                 -H 'Content-Type: application/json'
                 -d '{json}'
        ");
        return result.ToJson<TResponse>();
    }
}
```

### Implementing Circuit Breaker

```csharp
public class CurlCircuitBreaker
{
    private int _failureCount = 0;
    private DateTime _lastFailureTime;
    private readonly int _threshold = 5;
    private readonly TimeSpan _timeout = TimeSpan.FromMinutes(1);

    public async Task<CurlResult> ExecuteAsync(string command)
    {
        if (_failureCount >= _threshold)
        {
            if (DateTime.UtcNow - _lastFailureTime < _timeout)
            {
                throw new Exception("Circuit breaker is open");
            }
            _failureCount = 0; // Reset
        }

        try
        {
            var result = await Curl.Curl(command);
            if (!result.IsSuccess)
            {
                _failureCount++;
                _lastFailureTime = DateTime.UtcNow;
            }
            else
            {
                _failureCount = 0; // Reset on success
            }
            return result;
        }
        catch
        {
            _failureCount++;
            _lastFailureTime = DateTime.UtcNow;
            throw;
        }
    }
}
```

---

## Performance Tips

1. **Reuse Sessions**: For multiple requests to the same host, use `CurlSession`
2. **Connection Pooling**: HttpClient handles this automatically
3. **Compression**: Use `--compressed` flag for large responses
4. **Parallel Requests**: Use `CurlParallel` for independent requests
5. **Streaming**: For large files, use progress callbacks to avoid memory issues

## Error Handling Best Practices

```csharp
try
{
    var result = await Curl.Curl("https://api.example.com/data")
        .ThrowOnError()
        .EnsureSuccess();

    var data = result.ToJson<MyData>();
}
catch (CurlTimeoutException ex)
{
    // Handle timeout
    _logger.LogError($"Request timed out: {ex.Message}");
}
catch (CurlHttpException ex) when (ex.StatusCode == 404)
{
    // Handle not found
    return null;
}
catch (CurlHttpException ex) when (ex.IsServerError)
{
    // Handle server errors with retry
    await Task.Delay(5000);
    // Retry...
}
catch (CurlConnectionException ex)
{
    // Handle connection issues
    _logger.LogError($"Connection failed to {ex.Host}: {ex.Message}");
}
catch (CurlException ex)
{
    // Handle other curl errors
    _logger.LogError($"Curl error: {ex.Message}, Command: {ex.Command}");
}
```

---

*Based on curl by Daniel Stenberg and the curl community*
*CurlDotNet - Bringing the power of curl to .NET*
*Sponsored by Iron Software*