# CurlDotNet - Pure .NET Implementation of curl

A pure .NET/C# implementation of curl that allows you to execute curl commands directly from your .NET code without shell execution or interop.

## Features

- ✅ Pure .NET implementation - no native dependencies
- ✅ Compatible with .NET Standard 2.0 (.NET Framework 4.7.2+ and .NET Core/5+)
- ✅ Execute curl commands using familiar curl syntax
- ✅ Programmatic access to response data
- ✅ Support for HTTP/HTTPS, FTP/FTPS, and FILE protocols
- ✅ Full support for common curl options
- ✅ Async/await support throughout
- ✅ Output to files or in-memory results

## Installation

```bash
# Install via NuGet
dotnet add package CurlDotNet

# Or via Package Manager Console
Install-Package CurlDotNet
```

## Quick Start

```csharp
using CurlDotNet;

// Create a curl instance
var curl = new Curl();

// Execute a simple GET request
var result = await curl.ExecuteAsync("curl https://api.github.com/users/jacob-mellor");

// Access the response
Console.WriteLine(result.ResponseBody);
Console.WriteLine($"Status Code: {result.StatusCode}");
```

## Examples

### Simple GET Request

```csharp
var curl = new Curl();
var result = await curl.ExecuteAsync("curl https://api.example.com/data");
Console.WriteLine(result.ResponseBody);
```

### POST with JSON Data

```csharp
var result = await curl.ExecuteAsync(@"
    curl -X POST https://api.example.com/users \
         -H 'Content-Type: application/json' \
         -d '{""name"":""John"",""email"":""john@example.com""}'
");
```

### Download File

```csharp
// Download and save to specific file
var result = await curl.ExecuteAsync("curl -o download.pdf https://example.com/file.pdf");
Console.WriteLine($"File saved to: {result.OutputPath}");

// Use remote filename
await curl.ExecuteAsync("curl -O https://example.com/document.pdf");
```

### Authentication

```csharp
// Basic authentication
var result = await curl.ExecuteAsync("curl -u username:password https://api.example.com/secure");

// Bearer token
var result = await curl.ExecuteAsync(@"
    curl -H 'Authorization: Bearer YOUR_TOKEN' https://api.example.com/data
");
```

### Follow Redirects

```csharp
var result = await curl.ExecuteAsync("curl -L https://short.link/abc123");
```

### Custom Headers

```csharp
var result = await curl.ExecuteAsync(@"
    curl -H 'Accept: application/json' \
         -H 'X-API-Key: your-key' \
         https://api.example.com/data
");
```

### Verbose Output

```csharp
// Get detailed request/response information
var result = await curl.ExecuteAsync("curl -v https://example.com");
Console.WriteLine(result.FormattedOutput); // Includes verbose output
```

### Multiple Parallel Requests

```csharp
var results = await curl.ExecuteMultipleAsync(
    "curl https://api1.example.com/data",
    "curl https://api2.example.com/data",
    "curl https://api3.example.com/data"
);

foreach (var kvp in results)
{
    Console.WriteLine($"Command: {kvp.Key}");
    Console.WriteLine($"Response: {kvp.Value.ResponseBody}");
}
```

### Working with Files

```csharp
// Upload file
var result = await curl.ExecuteAsync("curl -T upload.txt ftp://ftp.example.com/");

// Download with resume
var result = await curl.ExecuteAsync("curl -C - -O https://example.com/largefile.zip");

// Read local file
var result = await curl.ExecuteAsync("curl file:///path/to/local/file.txt");
```

### Error Handling

```csharp
var result = await curl.ExecuteAsync("curl -f https://example.com/404");

if (result.IsError)
{
    Console.WriteLine($"Error: {result.ErrorMessage}");
    Console.WriteLine($"Status Code: {result.StatusCode}");
}
```

### Output Formatting

```csharp
// Custom write-out format
var result = await curl.ExecuteAsync(@"
    curl -w '\nTime: %{time_total}s\nSize: %{size_download} bytes' \
         https://example.com
");

// Silent mode with error display
var result = await curl.ExecuteAsync("curl -sS https://example.com");
```

## Supported curl Options

| Option | Description | Supported |
|--------|-------------|-----------|
| `-X, --request` | HTTP method | ✅ |
| `-H, --header` | Custom header | ✅ |
| `-d, --data` | POST data | ✅ |
| `--data-binary` | Binary POST data | ✅ |
| `--data-urlencode` | URL-encoded POST data | ✅ |
| `-o, --output` | Output to file | ✅ |
| `-O, --remote-name` | Use remote filename | ✅ |
| `-L, --location` | Follow redirects | ✅ |
| `-v, --verbose` | Verbose output | ✅ |
| `-s, --silent` | Silent mode | ✅ |
| `-S, --show-error` | Show errors in silent mode | ✅ |
| `-i, --include` | Include headers in output | ✅ |
| `-I, --head` | HEAD request | ✅ |
| `-u, --user` | Authentication | ✅ |
| `-A, --user-agent` | User agent | ✅ |
| `-e, --referer` | Referer header | ✅ |
| `-b, --cookie` | Cookie string | ✅ |
| `-c, --cookie-jar` | Cookie jar file | ✅ |
| `-T, --upload-file` | Upload file | ✅ |
| `--proxy` | Proxy server | ✅ |
| `-k, --insecure` | Allow insecure SSL | ✅ |
| `--compressed` | Request compression | ✅ |
| `-f, --fail` | Fail on HTTP errors | ✅ |
| `--connect-timeout` | Connection timeout | ✅ |
| `-m, --max-time` | Maximum time | ✅ |
| `-w, --write-out` | Custom output format | ✅ |
| `-G, --get` | Use GET for data | ✅ |
| `--http1.0` | Use HTTP/1.0 | ✅ |
| `--http1.1` | Use HTTP/1.1 | ✅ |
| `--http2` | Use HTTP/2 | ✅ |

## OutputResult Object

The `ExecuteAsync` method returns an `OutputResult` object with the following properties:

```csharp
public class OutputResult
{
    public string FormattedOutput { get; set; }    // Formatted curl-like output
    public string ResponseBody { get; set; }       // Raw response body
    public byte[] BinaryData { get; set; }         // Binary data (if applicable)
    public string Headers { get; set; }            // Response headers
    public int StatusCode { get; set; }            // HTTP status code
    public string OutputPath { get; set; }         // File path (if written to file)
    public bool WroteToFile { get; set; }          // Whether output was written to file
    public long BytesWritten { get; set; }         // Number of bytes written
    public bool IsError { get; set; }              // Whether an error occurred
    public string ErrorMessage { get; set; }       // Error message (if any)

    public Stream GetStream()                      // Get response as stream
}
```

## Architecture

This implementation transpiles curl's C source code to .NET/C#, maintaining compatibility with curl's command-line interface while providing a native .NET API. The library:

- Uses low-level .NET networking APIs for accurate curl behavior
- Implements curl's exact command-line parsing logic
- Maintains curl's output formatting and error codes
- Supports curl's various protocols and options

## Contributing

Contributions are welcome! This project aims to:
1. Maintain exact compatibility with curl's command-line interface
2. Provide a pure .NET implementation without native dependencies
3. Support all major curl features and options

## License

This project is licensed under the curl license (MIT/X derivative license). See the [COPYING](COPYING) file for details.

## Credits

- Original curl by Daniel Stenberg and contributors: https://github.com/curl/curl
- .NET implementation by Jacob Mellor: https://github.com/jacob-mellor
- Repository: https://github.com/jacob-mellor/curl-dot-net

## Roadmap

- [ ] Add wget command support
- [ ] WebAssembly compilation
- [ ] Rust implementation
- [ ] Additional protocol support (SFTP, SCP, etc.)
- [ ] Full curl test suite migration
- [ ] Performance optimizations
- [ ] HTTP/3 support

## Related Projects

- [curl](https://github.com/curl/curl) - The original curl project
- [curlie](https://github.com/rs/curlie) - A frontend to curl with colors
- [curl-to-csharp](https://github.com/olsh/curl-to-csharp) - Convert curl commands to C# code