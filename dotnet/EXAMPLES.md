# CurlDotNet Examples

A comprehensive collection of examples showing how to use CurlDotNet for various HTTP operations and curl commands.

## Table of Contents

- [Basic Usage](#basic-usage)
- [HTTP Methods](#http-methods)
- [Headers & Authentication](#headers--authentication)
- [File Operations](#file-operations)
- [Advanced Features](#advanced-features)
- [Error Handling](#error-handling)
- [Multiple Languages](#multiple-languages)
- [Real-World Scenarios](#real-world-scenarios)

---

## Basic Usage

### The Killer Feature - Just Paste Any curl Command!

```csharp
using CurlDotNet;
using System;
using System.Threading.Tasks;

// Works with or without the "curl" prefix
var response = await Curl.ExecuteAsync("curl https://api.github.com/users/octocat");
Console.WriteLine(response.Body);

// Also works without "curl" prefix
var data = await Curl.ExecuteAsync("https://httpbin.org/get");
Console.WriteLine(data.StatusCode); // 200
```

### Synchronous API

```csharp
using CurlDotNet;
using System;

// Synchronous version for legacy code (blocks the thread)
var result = Curl.Execute("curl https://api.example.com/data");
Console.WriteLine(result.Body);

// Or use DotNetCurl.Curl() for synchronous execution
var data = DotNetCurl.Curl("curl https://api.example.com/data");
Console.WriteLine(data.StatusCode);
```

### Multiple Commands

```csharp
using CurlDotNet;
using System;
using System.Threading.Tasks;

// Execute multiple curl commands at once
var results = await Curl.ExecuteManyAsync(new[] {
    "curl https://api.github.com/users/octocat",
    "curl https://api.github.com/users/torvalds",
    "curl https://api.github.com/users/dotnet"
});

foreach (var result in results)
{
    Console.WriteLine($"Status: {result.StatusCode}, Size: {result.Body.Length}");
}
```

## HTTP Methods

### GET Request

```csharp
using CurlDotNet;
using System;
using System.Threading.Tasks;

// Simple GET
var response = await Curl.ExecuteAsync("curl https://jsonplaceholder.typicode.com/posts/1");

// GET with query parameters
var users = await Curl.ExecuteAsync("curl 'https://api.example.com/users?page=1&limit=10'");

// GET with custom headers
var data = await Curl.ExecuteAsync(@"
    curl https://api.example.com/data
    -H 'Accept: application/json'
    -H 'User-Agent: CurlDotNet/1.0'
");
```

### POST Request

```csharp
using CurlDotNet;
using CurlDotNet.Core;
using System;
using System.Threading.Tasks;

// POST with JSON data
var result = await Curl.ExecuteAsync(@"
    curl -X POST https://jsonplaceholder.typicode.com/posts
    -H 'Content-Type: application/json'
    -d '{""title"":""foo"",""body"":""bar"",""userId"":1}'
");

// Parse the JSON response
var post = result.ParseJson<Post>();
Console.WriteLine($"Created post with ID: {post.Id}");

// POST with form data
var response = await Curl.ExecuteAsync(@"
    curl -X POST https://httpbin.org/post
    -F 'username=john'
    -F 'password=secret'
    -F 'file=@/path/to/file.pdf'
");

// POST with URL-encoded data
var login = await Curl.ExecuteAsync(@"
    curl -X POST https://example.com/login
    -d 'username=john&password=secret'
");
```

### PUT Request

```csharp
// PUT to update resource
var updated = await Curl.ExecuteAsync(@"
    curl -X PUT https://jsonplaceholder.typicode.com/posts/1
    -H 'Content-Type: application/json'
    -d '{""id"":1,""title"":""Updated"",""body"":""New content"",""userId"":1}'
");
```

### DELETE Request

```csharp
// DELETE a resource
var deleted = await Curl.ExecuteAsync("curl -X DELETE https://jsonplaceholder.typicode.com/posts/1");
```

### PATCH Request

```csharp
// PATCH for partial updates
var patched = await Curl.ExecuteAsync(@"
    curl -X PATCH https://api.example.com/users/123
    -H 'Content-Type: application/json'
    -d '{""email"":""newemail@example.com""}'
");
```

## Headers & Authentication

### Basic Authentication

```csharp
// Basic auth with username:password
var response = await Curl.ExecuteAsync("curl -u admin:password123 https://api.example.com/admin");

// Basic auth with header
var data = await Curl.ExecuteAsync(@"
    curl https://api.example.com/secure
    -H 'Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM='
");
```

### Bearer Token

```csharp
// OAuth 2.0 Bearer token
var result = await Curl.ExecuteAsync(@"
    curl https://api.example.com/protected
    -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
");

// GitHub API with token
var repos = await Curl.ExecuteAsync(@"
    curl https://api.github.com/user/repos
    -H 'Authorization: token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
");
```

### API Key Authentication

```csharp
// API key in header
var weather = await Curl.ExecuteAsync(@"
    curl 'https://api.openweathermap.org/data/2.5/weather?q=London'
    -H 'X-API-Key: your-api-key-here'
");

// API key in query string
var maps = await Curl.ExecuteAsync("curl 'https://maps.googleapis.com/maps/api/geocode/json?address=Seattle&key=YOUR_API_KEY'");
```

### Custom Headers

```csharp
// Multiple custom headers
var response = await Curl.ExecuteAsync(@"
    curl https://api.example.com/data
    -H 'Accept: application/json'
    -H 'X-Request-ID: 12345'
    -H 'X-Client-Version: 2.0.0'
    -H 'Cache-Control: no-cache'
");
```

## File Operations

### Download Files

```csharp
// Download to specific file
await Curl.ExecuteAsync("curl -o output.pdf https://example.com/document.pdf");

// Download with original filename
await Curl.ExecuteAsync("curl -O https://example.com/report-2024.xlsx");

// Download multiple files
await Curl.ExecuteAsync(@"
    curl -O https://example.com/file1.zip
    -O https://example.com/file2.zip
    -O https://example.com/file3.zip
");

// Download with progress bar
await Curl.ExecuteAsync("curl --progress-bar -o large-file.iso https://example.com/large.iso");
```

### Upload Files

```csharp
// Upload single file
var uploaded = await Curl.ExecuteAsync(@"
    curl -X POST https://api.example.com/upload
    -F 'file=@/path/to/document.pdf'
    -F 'description=Annual Report'
");

// Upload multiple files
var result = await Curl.ExecuteAsync(@"
    curl -X POST https://api.example.com/batch-upload
    -F 'files[]=@file1.jpg'
    -F 'files[]=@file2.jpg'
    -F 'files[]=@file3.jpg'
    -F 'album=vacation'
");

// Upload with metadata
var response = await Curl.ExecuteAsync(@"
    curl -X POST https://api.cloudinary.com/v1_1/demo/image/upload
    -F 'file=@photo.jpg'
    -F 'upload_preset=unsigned'
    -F 'tags=nature,mountains'
");
```

### FTP Operations

```csharp
// FTP download
await Curl.ExecuteAsync("curl -u ftpuser:ftppass ftp://ftp.example.com/file.txt -o local.txt");

// FTP upload
await Curl.ExecuteAsync("curl -u ftpuser:ftppass -T localfile.txt ftp://ftp.example.com/remote.txt");

// FTP with SSL/TLS
await Curl.ExecuteAsync("curl --ftp-ssl -u user:pass ftp://secure.example.com/file.txt");
```

## Advanced Features

### Following Redirects

```csharp
// Follow redirects automatically
var final = await Curl.ExecuteAsync("curl -L https://bit.ly/shortened-url");

// Limit redirect count
var limited = await Curl.ExecuteAsync("curl -L --max-redirs 3 https://example.com/redirect");
```

### Cookies

```csharp
// Save cookies
await Curl.ExecuteAsync("curl -c cookies.txt https://example.com/login");

// Use saved cookies
var response = await Curl.ExecuteAsync("curl -b cookies.txt https://example.com/protected");

// Send specific cookie
var data = await Curl.ExecuteAsync(@"
    curl https://example.com/api
    -H 'Cookie: session=abc123; user=john'
");
```

### Timeouts

```csharp
// Connection timeout
var fast = await Curl.ExecuteAsync("curl --connect-timeout 5 https://api.example.com/data");

// Total timeout
var limited = await Curl.ExecuteAsync("curl --max-time 30 https://slow-api.example.com/report");

// Both timeouts
var robust = await Curl.ExecuteAsync(@"
    curl --connect-timeout 5 --max-time 60
    https://api.example.com/large-download
");
```

### Proxy Configuration

```csharp
// HTTP proxy
var proxied = await Curl.ExecuteAsync("curl -x http://proxy.company.com:8080 https://example.com");

// SOCKS5 proxy
var secure = await Curl.ExecuteAsync("curl --socks5 localhost:1080 https://blocked-site.com");

// Proxy with authentication
var authed = await Curl.ExecuteAsync(@"
    curl -x http://proxy.example.com:8080
    --proxy-user username:password
    https://external-api.com
");
```

### SSL/TLS Options

```csharp
// Skip certificate verification (dev only!)
var insecure = await Curl.ExecuteAsync("curl -k https://self-signed.example.com");

// Use client certificate
var mutual = await Curl.ExecuteAsync(@"
    curl --cert client.crt --key client.key
    https://mutual-tls.example.com/api
");

// Specify TLS version
var tls13 = await Curl.ExecuteAsync("curl --tlsv1.3 https://modern-api.example.com");
```

### Rate Limiting

```csharp
// Limit download speed
await Curl.ExecuteAsync("curl --limit-rate 200K https://example.com/large-file.zip -o file.zip");

// Limit upload speed
await Curl.ExecuteAsync(@"
    curl --limit-rate 100K
    -T large-upload.zip
    https://upload.example.com/files
");
```

## Error Handling

### Handling Specific Exceptions

```csharp
try
{
    var response = await Curl.ExecuteAsync("curl https://api.example.com/data");
}
catch (CurlDnsException ex)
{
    Console.WriteLine($"DNS resolution failed: {ex.Message}");
}
catch (CurlTimeoutException ex)
{
    Console.WriteLine($"Request timed out: {ex.Message}");
}
catch (CurlSslException ex)
{
    Console.WriteLine($"SSL/TLS error: {ex.Message}");
}
catch (CurlAuthenticationException ex)
{
    Console.WriteLine($"Authentication failed: {ex.Message}");
}
catch (CurlHttpException ex)
{
    Console.WriteLine($"HTTP error {ex.StatusCode}: {ex.Message}");
}
catch (CurlException ex)
{
    Console.WriteLine($"General curl error: {ex.Message}");
}
```

### Retry Logic

```csharp
// Manual retry with exponential backoff
async Task<CurlResult> ExecuteWithRetry(string command, int maxRetries = 3)
{
    for (int i = 0; i < maxRetries; i++)
    {
        try
        {
            return await Curl.ExecuteAsync(command);
        }
        catch (CurlException) when (i < maxRetries - 1)
        {
            await Task.Delay((int)Math.Pow(2, i) * 1000); // Exponential backoff
        }
    }
    throw new Exception("Max retries exceeded");
}

// Usage
var result = await ExecuteWithRetry("curl https://flaky-api.example.com/data");
```

## Multiple Languages

### C# Examples

```csharp
// Async/await pattern
public async Task<string> GetUserDataAsync(int userId)
{
    var response = await Curl.ExecuteAsync($"curl https://api.example.com/users/{userId}");
    return response.Body;
}

// LINQ with multiple requests
var userIds = new[] { 1, 2, 3, 4, 5 };
var tasks = userIds.Select(id =>
    Curl.Execute($"curl https://api.example.com/users/{id}")
);
var results = await Task.WhenAll(tasks);

// Pattern matching (C# 8+)
var statusMessage = response.StatusCode switch
{
    200 => "Success",
    404 => "Not found",
    500 => "Server error",
    _ => "Unknown status"
};
```

### VB.NET Examples

```vb
Imports CurlDotNet
Imports System.Threading.Tasks

Module Program
    Sub Main()
        ' Synchronous execution
        Dim response = Curl.ExecuteSync("curl https://api.github.com/users/dotnet")
        Console.WriteLine(response.Body)

        ' Async execution
        RunAsync().Wait()
    End Sub

    Private Async Function RunAsync() As Task
        ' GET request
        Dim result = Await Curl.Execute("curl https://httpbin.org/get")
        Console.WriteLine($"Status: {result.StatusCode}")

        ' POST request
        Dim postData = "curl -X POST https://httpbin.org/post -d 'test=value'"
        Dim postResult = Await Curl.Execute(postData)
        Console.WriteLine(postResult.Body)

        ' With error handling
        Try
            Dim data = Await Curl.Execute("curl https://api.example.com/data")
            Console.WriteLine(data.Body)
        Catch ex As CurlException
            Console.WriteLine($"Error: {ex.Message}")
        End Try
    End Function

    ' Function with return value
    Private Async Function GetWeatherAsync(city As String) As Task(Of String)
        Dim url = $"https://api.openweathermap.org/data/2.5/weather?q={city}"
        Dim response = Await Curl.Execute($"curl '{url}'")
        Return response.Body
    End Function
End Module
```

### F# Examples

```fsharp
open System
open CurlDotNet
open System.Threading.Tasks

// Simple GET request
let getUser username =
    async {
        let! response =
            Curl.Execute(sprintf "curl https://api.github.com/users/%s" username)
            |> Async.AwaitTask
        return response.Body
    }

// Pattern matching with status codes
let handleResponse (response: CurlResult) =
    match response.StatusCode with
    | 200 -> printfn "Success: %s" response.Body
    | 404 -> printfn "Not found"
    | 500 -> printfn "Server error"
    | code -> printfn "Unexpected status: %d" code

// Pipeline operator usage
let processData url =
    url
    |> sprintf "curl %s"
    |> Curl.Execute
    |> Async.AwaitTask
    |> Async.RunSynchronously
    |> handleResponse

// Async workflow with multiple requests
let fetchMultiple urls =
    async {
        let! responses =
            urls
            |> List.map (sprintf "curl %s" >> Curl.Execute >> Async.AwaitTask)
            |> Async.Parallel

        responses
        |> Array.iter (fun r -> printfn "Status: %d, Size: %d" r.StatusCode r.Body.Length)
    }

// Error handling
let safeExecute command =
    async {
        try
            let! result = Curl.Execute(command) |> Async.AwaitTask
            return Ok result
        with
        | :? CurlDnsException as ex -> return Error (sprintf "DNS error: %s" ex.Message)
        | :? CurlTimeoutException as ex -> return Error (sprintf "Timeout: %s" ex.Message)
        | :? CurlException as ex -> return Error (sprintf "Curl error: %s" ex.Message)
    }

// Computation expression
type CurlBuilder() =
    member _.Bind(x, f) =
        async {
            let! result = Curl.Execute(x) |> Async.AwaitTask
            return! f result
        }
    member _.Return(x) = async { return x }

let curl = CurlBuilder()

// Usage of computation expression
let workflow =
    curl {
        let! user = "curl https://api.github.com/users/fsharp"
        let! repos = "curl https://api.github.com/users/fsharp/repos"
        return (user.Body, repos.Body)
    }
```

## Real-World Scenarios

### REST API Client

```csharp
public class ApiClient
{
    private readonly string _baseUrl;
    private readonly string _apiKey;

    public ApiClient(string baseUrl, string apiKey)
    {
        _baseUrl = baseUrl;
        _apiKey = apiKey;
    }

    public async Task<T> GetAsync<T>(string endpoint)
    {
        var response = await Curl.ExecuteAsync($@"
            curl {_baseUrl}/{endpoint}
            -H 'Authorization: Bearer {_apiKey}'
            -H 'Accept: application/json'
        ");

        return JsonSerializer.Deserialize<T>(response.Body);
    }

    public async Task<T> PostAsync<T>(string endpoint, object data)
    {
        var json = JsonSerializer.Serialize(data);
        var response = await Curl.ExecuteAsync($@"
            curl -X POST {_baseUrl}/{endpoint}
            -H 'Authorization: Bearer {_apiKey}'
            -H 'Content-Type: application/json'
            -d '{json}'
        ");

        return JsonSerializer.Deserialize<T>(response.Body);
    }
}
```

### CI/CD Integration

```csharp
// Deploy script using curl commands
public async Task DeployToProduction()
{
    // Check health endpoint
    var health = await Curl.ExecuteAsync("curl https://api.production.com/health");
    if (health.StatusCode != 200)
        throw new Exception("Production API is not healthy");

    // Upload deployment artifact
    var upload = await Curl.ExecuteAsync(@"
        curl -X POST https://deploy.production.com/artifacts
        -F 'file=@./release.zip'
        -F 'version=1.2.3'
        -F 'environment=production'
    ");

    // Trigger deployment
    var deploy = await Curl.ExecuteAsync(@"
        curl -X POST https://deploy.production.com/trigger
        -H 'Content-Type: application/json'
        -d '{""artifactId"":""' + upload.Body + '"",""strategy"":""rolling""}'
    ");

    // Wait for deployment to complete
    string status;
    do
    {
        await Task.Delay(5000);
        var check = await Curl.ExecuteAsync($"curl https://deploy.production.com/status/{deploy.Body}");
        status = check.Body;
    }
    while (status != "completed" && status != "failed");

    if (status == "failed")
        throw new Exception("Deployment failed");
}
```

### Web Scraping

```csharp
// Scrape product information
public async Task<List<Product>> ScrapeProducts(string category)
{
    var products = new List<Product>();

    // Get category page
    var response = await Curl.ExecuteAsync($@"
        curl https://shop.example.com/category/{category}
        -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        -H 'Accept: text/html,application/xhtml+xml'
    ");

    // Parse HTML and extract product URLs
    var productUrls = ExtractProductUrls(response.Body);

    // Fetch each product with rate limiting
    foreach (var url in productUrls)
    {
        var productResponse = await Curl.ExecuteAsync($@"
            curl {url}
            -H 'User-Agent: Mozilla/5.0'
            --compressed
        ");

        products.Add(ParseProduct(productResponse.Body));

        // Rate limiting
        await Task.Delay(1000);
    }

    return products;
}
```

### GraphQL Queries

```csharp
// GitHub GraphQL API
public async Task<string> GetRepositoryInfo(string owner, string name)
{
    var query = @"{
        repository(owner: """ + owner + @""", name: """ + name + @""") {
            name
            description
            stargazerCount
            forkCount
            primaryLanguage { name }
            issues(states: OPEN) { totalCount }
            pullRequests(states: OPEN) { totalCount }
        }
    }";

    var response = await Curl.ExecuteAsync($@"
        curl -X POST https://api.github.com/graphql
        -H 'Authorization: Bearer {githubToken}'
        -H 'Content-Type: application/json'
        -d '{{""query"":""{query.Replace("\"", "\\\"")}""}}'"
    ");

    return response.Body;
}
```

### Webhook Testing

```csharp
// Test webhook endpoint
public async Task TestWebhook()
{
    var payload = new
    {
        @event = "order.completed",
        orderId = "ORD-123456",
        amount = 99.99,
        timestamp = DateTime.UtcNow.ToString("o")
    };

    var json = JsonSerializer.Serialize(payload);
    var signature = ComputeHmacSignature(json, "webhook-secret");

    var response = await Curl.ExecuteAsync($@"
        curl -X POST https://localhost:5001/webhooks/stripe
        -H 'Content-Type: application/json'
        -H 'X-Webhook-Signature: {signature}'
        -d '{json}'
    ");

    Console.WriteLine($"Webhook response: {response.StatusCode}");
}
```

### Batch Processing

```csharp
// Process multiple API calls in parallel with batching
public async Task<List<UserData>> GetUsersInBatches(List<int> userIds)
{
    const int batchSize = 10;
    var allResults = new List<UserData>();

    for (int i = 0; i < userIds.Count; i += batchSize)
    {
        var batch = userIds.Skip(i).Take(batchSize);
        var commands = batch.Select(id =>
            $"curl https://api.example.com/users/{id}"
        ).ToArray();

        var results = await Curl.ExecuteManyAsync(commands);

        foreach (var result in results)
        {
            if (result.StatusCode == 200)
            {
                var userData = JsonSerializer.Deserialize<UserData>(result.Body);
                allResults.Add(userData);
            }
        }

        // Rate limiting between batches
        if (i + batchSize < userIds.Count)
            await Task.Delay(1000);
    }

    return allResults;
}
```

### Health Monitoring

```csharp
// Monitor multiple endpoints
public async Task<Dictionary<string, bool>> CheckEndpointHealth()
{
    var endpoints = new[]
    {
        "https://api.service1.com/health",
        "https://api.service2.com/health",
        "https://api.service3.com/health"
    };

    var commands = endpoints.Select(e =>
        $"curl --max-time 5 --connect-timeout 2 {e}"
    ).ToArray();

    var results = await Curl.ExecuteManyAsync(commands);

    return endpoints.Zip(results, (endpoint, result) =>
        new { endpoint, healthy = result.StatusCode == 200 }
    ).ToDictionary(x => x.endpoint, x => x.healthy);
}
```

## Testing with CurlDotNet

### Unit Testing

```csharp
[TestClass]
public class ApiTests
{
    [TestMethod]
    public async Task TestGetUser()
    {
        // Arrange
        var userId = 123;

        // Act
        var response = await Curl.ExecuteAsync($"curl https://api.example.com/users/{userId}");

        // Assert
        Assert.AreEqual(200, response.StatusCode);
        Assert.IsTrue(response.Body.Contains("\"id\":123"));
    }

    [TestMethod]
    public async Task TestAuthenticationRequired()
    {
        // Act & Assert
        await Assert.ThrowsExceptionAsync<CurlAuthenticationException>(async () =>
        {
            await Curl.ExecuteAsync("curl https://api.example.com/admin");
        });
    }
}
```

### Integration Testing

```csharp
[TestClass]
[TestCategory("Integration")]
public class IntegrationTests
{
    [TestMethod]
    public async Task TestFullWorkflow()
    {
        // Create resource
        var createResponse = await Curl.ExecuteAsync(@"
            curl -X POST https://api.example.com/items
            -H 'Content-Type: application/json'
            -d '{""name"":""Test Item""}'
        ");
        Assert.AreEqual(201, createResponse.StatusCode);

        var id = ExtractId(createResponse.Body);

        // Read resource
        var getResponse = await Curl.ExecuteAsync($"curl https://api.example.com/items/{id}");
        Assert.AreEqual(200, getResponse.StatusCode);

        // Update resource
        var updateResponse = await Curl.ExecuteAsync($@"
            curl -X PUT https://api.example.com/items/{id}
            -H 'Content-Type: application/json'
            -d '{{""name"":""Updated Item""}}'
        ");
        Assert.AreEqual(200, updateResponse.StatusCode);

        // Delete resource
        var deleteResponse = await Curl.ExecuteAsync($"curl -X DELETE https://api.example.com/items/{id}");
        Assert.AreEqual(204, deleteResponse.StatusCode);
    }
}
```

## Performance Tips

### Connection Pooling

```csharp
// Reuse connections for multiple requests to same host
var commands = Enumerable.Range(1, 100)
    .Select(i => $"curl https://api.example.com/data/{i}")
    .ToArray();

// CurlDotNet automatically manages connection pooling
var results = await Curl.ExecuteManyAsync(commands);
```

### Streaming Large Responses

```csharp
// Stream large files without buffering entire content
public async Task DownloadLargeFile(string url, string outputPath)
{
    // CurlDotNet streams directly to file
    await Curl.ExecuteAsync($"curl -o {outputPath} {url}");
}
```

### Compression

```csharp
// Request compressed responses
var response = await Curl.ExecuteAsync(@"
    curl https://api.example.com/large-data
    --compressed
    -H 'Accept-Encoding: gzip, deflate, br'
");
```

## Debugging

### Verbose Output

```csharp
// Enable verbose output for debugging
var response = await Curl.ExecuteAsync("curl -v https://api.example.com/debug");

// Access debug information
Console.WriteLine($"Request headers: {response.RequestHeaders}");
Console.WriteLine($"Response headers: {response.ResponseHeaders}");
Console.WriteLine($"Timing: {response.TimingInfo}");
```

### Trace Network Activity

```csharp
// Trace all network activity
var response = await Curl.ExecuteAsync("curl --trace-ascii debug.txt https://api.example.com/data");

// Or capture in response
var result = await Curl.ExecuteAsync("curl --trace - https://api.example.com/data");
Console.WriteLine(result.TraceOutput);
```

---

## Additional Resources

- [Full API Documentation](./api/index.html)
- [Architecture Guide](./ARCHITECTURE.md)
- [Contributing Guide](./CONTRIBUTING.md)
- [NuGet Package](https://www.nuget.org/packages/CurlDotNet/)

---

Made with ❤️ by the CurlDotNet Team | Sponsored by [IronSoftware](https://ironsoftware.com)