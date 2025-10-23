# CurlDotNet - Pure .NET Implementation of curl

[![NuGet](https://img.shields.io/nuget/v/CurlDotNet.svg)](https://www.nuget.org/packages/CurlDotNet/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%206.0%20%7C%20Framework%204.7.2-512BD4)](https://dotnet.microsoft.com/)
[![Sponsored by IronSoftware](https://img.shields.io/badge/Sponsored%20by-IronSoftware-red.svg)](https://ironsoftware.com)

**CurlDotNet** brings the power and familiarity of curl to .NET developers. Simply paste any curl command and it works - no translation needed. Perfect for CI/CD pipelines, automated testing, and any scenario where you need reliable HTTP operations.

## 🚀 The Killer Feature

**Copy and paste any curl command - it just works!**

```csharp
using CurlDotNet;

// Works with or without the "curl" prefix
var response = await DotNetCurl.CurlAsync("curl -X POST https://api.example.com/data -H 'Content-Type: application/json' -d '{\"key\":\"value\"}'");

// Also works without "curl"
var response2 = await DotNetCurl.CurlAsync("-X GET https://api.example.com/users");

// Even handles multiple commands
var responses = await DotNetCurl.CurlMultipleAsync(@"
    curl https://api.example.com/users;
    curl https://api.example.com/posts;
    curl https://api.example.com/comments
");
```

## 📦 Installation

Install CurlDotNet via NuGet:

```bash
# Package Manager Console
Install-Package CurlDotNet

# .NET CLI
dotnet add package CurlDotNet

# PackageReference
<PackageReference Include="CurlDotNet" Version="1.0.0" />
```

## 🎯 Quick Start

### Basic GET Request

```csharp
using CurlDotNet;

// Simple GET request
var response = await DotNetCurl.CurlAsync("curl https://api.github.com/users/octocat");
Console.WriteLine(response.Body);
```

### POST with JSON

```csharp
// POST JSON data
var response = await DotNetCurl.CurlAsync(@"
    curl -X POST https://api.example.com/users
    -H 'Content-Type: application/json'
    -d '{""name"":""John"",""email"":""john@example.com""}'
");

// Check status
if (response.IsSuccess)
{
    var user = response.ParseJson<User>();
    Console.WriteLine($"Created user: {user.Id}");
}
```

### Download Files

```csharp
// Download a file
var response = await DotNetCurl.CurlAsync("curl -o report.pdf https://example.com/report.pdf");

// Or use the fluent API
var response = await DotNetCurl.CurlAsync("curl https://example.com/image.jpg");
response.SaveToFile("image.jpg");
```

### Authentication

```csharp
// Basic authentication
var response = await DotNetCurl.CurlAsync("curl -u username:password https://api.example.com/private");

// Bearer token
var response = await DotNetCurl.CurlAsync("curl -H 'Authorization: Bearer YOUR_TOKEN' https://api.example.com/data");

// OAuth, NTLM, Kerberos - all supported!
```

## 💪 Advanced Features

### Fluent API

```csharp
var settings = new CurlSettings()
    .WithUrl("https://api.example.com/data")
    .WithMethod("POST")
    .WithHeader("Content-Type", "application/json")
    .WithData("{\"key\":\"value\"}")
    .WithTimeout(TimeSpan.FromSeconds(30))
    .WithAuthentication("Bearer", "YOUR_TOKEN");

var response = await DotNetCurl.CurlAsync(settings);
```

### Stream-Based for Large Files

```csharp
// Efficient streaming - never loads entire file into memory
var response = await DotNetCurl.CurlAsync("curl https://example.com/largefile.zip");

using (var fileStream = File.Create("largefile.zip"))
{
    await response.DataStream.CopyToAsync(fileStream);
}
```

### Error Handling

Every curl error code has its own exception type for precise error handling:

```csharp
try
{
    var response = await DotNetCurl.CurlAsync("curl https://invalid-url");
}
catch (CurlDnsException ex)
{
    // DNS resolution failed (error code 6)
    Console.WriteLine($"Could not resolve: {ex.Hostname}");
}
catch (CurlTimeoutException ex)
{
    // Operation timed out (error code 28)
    Console.WriteLine($"Timeout after {ex.Timeout}");
}
catch (CurlSslException ex)
{
    // SSL/TLS error (various codes)
    Console.WriteLine($"SSL error: {ex.Message}");
}
```

### CI/CD Integration

Optimized for build pipelines and automation:

```csharp
// Returns proper exit codes like curl
var result = DotNetCurl.Curl("curl --fail https://api.example.com/health");
Environment.Exit(result.ExitCode); // 0 for success, non-zero for failure

// Retry logic for reliability
var settings = new CurlSettings()
    .WithRetryCount(3)
    .WithRetryDelay(TimeSpan.FromSeconds(2))
    .WithExponentialBackoff();

// Environment variable support
// Automatically uses HTTP_PROXY, HTTPS_PROXY, NO_PROXY
```

## 🎨 Code Examples

### REST API Testing

```csharp
// Complete CRUD operations
public class ApiTests
{
    // CREATE
    public async Task<User> CreateUser(User user)
    {
        var json = JsonSerializer.Serialize(user);
        var response = await DotNetCurl.CurlAsync($@"
            curl -X POST https://api.example.com/users
            -H 'Content-Type: application/json'
            -d '{json}'
        ");
        return response.ParseJson<User>();
    }

    // READ
    public async Task<User> GetUser(int id)
    {
        var response = await DotNetCurl.CurlAsync($"curl https://api.example.com/users/{id}");
        return response.ParseJson<User>();
    }

    // UPDATE
    public async Task<User> UpdateUser(int id, User user)
    {
        var json = JsonSerializer.Serialize(user);
        var response = await DotNetCurl.CurlAsync($@"
            curl -X PUT https://api.example.com/users/{id}
            -H 'Content-Type: application/json'
            -d '{json}'
        ");
        return response.ParseJson<User>();
    }

    // DELETE
    public async Task DeleteUser(int id)
    {
        await DotNetCurl.CurlAsync($"curl -X DELETE https://api.example.com/users/{id}");
    }
}
```

### WebHook Handler

```csharp
// Send webhooks with retries
public async Task SendWebhook(string url, object payload)
{
    var settings = new CurlSettings()
        .WithUrl(url)
        .WithMethod("POST")
        .WithHeader("Content-Type", "application/json")
        .WithData(JsonSerializer.Serialize(payload))
        .WithTimeout(TimeSpan.FromSeconds(10))
        .WithRetryCount(3);

    var response = await DotNetCurl.CurlAsync(settings);

    if (!response.IsSuccess)
    {
        throw new WebhookException($"Webhook failed: {response.StatusCode}");
    }
}
```

### File Upload

```csharp
// Multipart form upload
var response = await DotNetCurl.CurlAsync(@"
    curl -X POST https://api.example.com/upload
    -F 'file=@/path/to/file.pdf'
    -F 'description=Monthly Report'
");

// Check response
if (response.StatusCode == 200)
{
    var result = response.ParseJson<UploadResult>();
    Console.WriteLine($"File uploaded: {result.FileId}");
}
```

## 🏗️ Architecture & Extensibility

### Middleware Support

```csharp
// Add custom middleware for logging, metrics, etc.
DotNetCurl.AddMiddleware(async (request, next) =>
{
    Console.WriteLine($"Request: {request.Method} {request.Url}");
    var response = await next(request);
    Console.WriteLine($"Response: {response.StatusCode}");
    return response;
});
```

### Dependency Injection

```csharp
// Register in DI container
services.AddCurlDotNet(options =>
{
    options.DefaultTimeout = TimeSpan.FromSeconds(30);
    options.EnableLogging = true;
    options.LogStream = Console.Out;
});

// Inject and use
public class MyService
{
    private readonly ICurl _curl;

    public MyService(ICurl curl)
    {
        _curl = curl;
    }
}
```

## 📊 Platform Support

| Platform | Supported | Notes |
|----------|-----------|--------|
| .NET 8.0 | ✅ | Full support |
| .NET 6.0 | ✅ | Full support |
| .NET Framework 4.7.2 | ✅ | Windows only |
| .NET Standard 2.0 | ✅ | Maximum compatibility |
| Xamarin | ✅ | iOS, Android, Mac |
| Unity | ✅ | 2018.1+ |
| Blazor | ✅ | WASM & Server |

## 🔧 Configuration

```csharp
// Global configuration
DotNetCurl.Configure(config =>
{
    config.UserAgent = "MyApp/1.0";
    config.DefaultHeaders.Add("X-API-Version", "2.0");
    config.EnableCookies = true;
    config.CookieFile = "cookies.txt";
    config.ProxyUrl = "http://proxy.company.com:8080";
    config.InsecureMode = false; // Never ignore SSL errors in production!
});
```

## 📈 Performance

- **Zero allocations** for streaming operations
- **Connection pooling** for improved performance
- **HTTP/2** and **HTTP/3** support
- **Compression** (gzip, deflate, brotli) handled automatically
- **Concurrent requests** with optimal thread usage

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📜 License

CurlDotNet is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💎 Sponsored by IronSoftware

CurlDotNet is proudly sponsored by [IronSoftware](https://ironsoftware.com), creators of:
- [IronPDF](https://ironpdf.com) - PDF Generation & Manipulation
- [IronOCR](https://ironsoftware.com/csharp/ocr/) - Advanced OCR
- [IronXL](https://ironsoftware.com/csharp/excel/) - Excel Processing
- [IronBarcode](https://ironsoftware.com/csharp/barcode/) - Barcode Generation
- [IronWebScraper](https://ironsoftware.com/csharp/webscraper/) - Web Scraping

## 🌟 Why CurlDotNet?

- **Familiar**: If you know curl, you know CurlDotNet
- **Reliable**: Battle-tested curl behavior in pure .NET
- **Fast**: Optimized for performance and low memory usage
- **Complete**: Supports all 300+ curl options
- **Cross-platform**: Works everywhere .NET runs
- **CI/CD Ready**: Built for automation and scripting
- **Well-documented**: IntelliSense everywhere, with examples
- **Exception Hierarchy**: Catch exactly the errors you want

## 📚 Resources

- [Full Documentation](https://curldotnet.com/docs)
- [API Reference](https://curldotnet.com/api)
- [Examples](./EXAMPLES.md)
- [Curl Command Reference](https://curl.se/docs/manpage.html)
- [NuGet Package](https://www.nuget.org/packages/CurlDotNet/)
- [GitHub Repository](https://github.com/jacob/curl-dot-net)

## ✨ Get Started Now!

```bash
dotnet add package CurlDotNet
```

Transform your curl commands into powerful .NET applications today!