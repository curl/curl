# CurlDotNet Architecture Decisions

**Date:** October 23, 2025
**Updated:** Each time new decisions are made

## IMPORTANT NOTE FOR CLAUDE
**Always append to `/dotnet/claude_code_transcript.log` during every session to preserve conversation history and decisions. This ensures continuity if the session is interrupted.**

## Core Architecture Questions and Decisions

### 1. Library Goal
**Question:** What is the primary goal for the CurlDotNet library - should it be a direct port of curl's functionality or a .NET-idiomatic wrapper?

**Decision:** Direct Port with .NET conventions
- Maintain curl command-line compatibility
- Provide a .NET-friendly API alongside
- Balance between familiarity for curl users and .NET best practices

### 2. Framework Support Strategy
**Question:** Which .NET frameworks should we prioritize support for?

**Decision:** Include Legacy - Support .NET Framework 4.7.2+ and .NET Standard 2.0
- **User's Response:** ".NET Standard 2.0 trying to target everything So yeah that's Include Legacy"
- **Rationale:** Maximum compatibility across different platforms and versions
- **Targets:**
  - .NET Standard 2.0 (for maximum library compatibility)
  - .NET Framework 4.7.2+ (for Windows legacy apps)
  - .NET Core 3.1 (legacy LTS)
  - .NET 6.0 (LTS)
  - .NET 8.0 (current LTS)

### 3. Async/Await Pattern Implementation
**Question:** How should we handle the async compatibility issues with older frameworks?

**Decision:** Conditional Compilation with Standard Async/Await Pattern
- **User's Response:** "I think async 0.4.72 and standard both have async/await no? If not then we're going to have Conditional compile. There's always `Task.Run` to make any method async. So just a normal async wait pattern is a good idea."
- **Implementation Details:**
  - Use conditional compilation (#if directives) where needed
  - .NET Standard 2.0 does support async/await (confirmed)
  - Use Task.Run as fallback for synchronous operations that need async wrappers
  - **Main API Surface:**
    - `DotNetCurl.Curl()` - Synchronous static method
    - `DotNetCurl.CurlAsync()` - Asynchronous static method
  - Both methods should be static for ease of use

### 4. Primary Use Case Optimization
**Question:** What should be the primary use case we optimize for?

**Decision:** CI/CD Integration
- **User's Response:** "CI/CD Integration"
- **Focus Areas:**
  - Optimize for build scripts and automation scenarios
  - Ensure reliable error codes and exit statuses
  - Support environment variable configuration
  - Provide clear, parseable output formats
  - Minimize dependencies for easy deployment
  - Support common CI/CD patterns (retries, timeouts, proxy configuration)

## Implementation Guidelines Based on Decisions

### API Design
```csharp
// Main static entry points
public static class DotNetCurl
{
    // Synchronous method for CI/CD scripts
    public static CurlResult Curl(string command);
    public static CurlResult Curl(CurlOptions options);

    // Async method for modern applications
    public static Task<CurlResult> CurlAsync(string command);
    public static Task<CurlResult> CurlAsync(CurlOptions options);
}
```

### Framework-Specific Implementation Strategy

#### For File Operations (File.ReadAllTextAsync missing in older frameworks)
```csharp
#if NETSTANDARD2_0 || NET472
    // Use Task.Run with synchronous methods
    return Task.Run(() => File.ReadAllText(path));
#else
    // Use native async methods
    return File.ReadAllTextAsync(path);
#endif
```

#### For HTTP Operations
- HttpClient is available in .NET Standard 2.0
- Use it consistently across all framework targets
- Handle missing enum values (like HttpStatusCode.PermanentRedirect) with constants

### CI/CD Specific Features to Prioritize

1. **Exit Codes:** Match curl's exit codes exactly
   - 0: Success
   - 6: Could not resolve host
   - 7: Failed to connect
   - 22: HTTP error
   - 28: Timeout
   - etc.

2. **Environment Variables:**
   - Support standard curl environment variables
   - Support proxy configuration via environment
   - Allow configuration override via environment

3. **Output Formats:**
   - Support `-o` for output to file
   - Support `-s` for silent mode
   - Support `-v` for verbose output
   - JSON output format for structured data

4. **Retry Logic:**
   - Built-in retry support with exponential backoff
   - Configurable retry count and delay
   - Important for CI/CD reliability

5. **Timeout Handling:**
   - Connection timeout
   - Request timeout
   - Total operation timeout

## Technical Debt and Future Considerations

### Current Issues to Address
1. File.ReadAllTextAsync and similar async methods missing in older frameworks
2. HttpStatusCode.PermanentRedirect not available in older frameworks
3. Dictionary.TryAdd not available in .NET Standard 2.0
4. Dynamic runtime binder issues in tests

### Solutions in Progress
- Adding conditional compilation directives
- Creating compatibility shims/polyfills
- Using Task.Run for async wrappers where needed

## Testing Strategy

Given the CI/CD focus:
1. Test all major CI/CD platforms (GitHub Actions, Azure DevOps, Jenkins)
2. Test with common CI/CD scenarios (artifact download, API calls, webhook notifications)
3. Ensure proper exit codes in all error scenarios
4. Test timeout and retry mechanisms thoroughly
5. Verify environment variable handling

## Additional Architecture Decisions (Session 2)

### 5. Command-Line Options Support
**Question:** How should we handle curl's extensive command-line options (300+ flags)?

**Decision:** Full Support
- **User's Response:** "Full Support"
- Implement all 300+ curl options, not just a core subset
- This ensures complete curl compatibility

### 6. Authentication Strategy
**Question:** What should be the authentication strategy?

**Decision:** Built-in All
- **User's Response:** "Built-in All"
- Support Basic, Bearer, OAuth, NTLM, Kerberos, etc. natively
- No need for external authentication providers

### 7. Response Data Architecture
**Question:** How should we handle the response data?

**Decision:** Stream-based with Fluent API
- **User's Response:** "There should be a settings object and there should be a response object. That response object may contain a stream. You should definitely use streams not buffers."
- **Key Requirements:**
  - Settings object for configuration
  - Response object containing streams (NEVER buffers)
  - Fluent API for response handling
  - Example: `response.SaveToHtml().SaveToFile()`
  - Stream can go straight to disk via settings object

### 8. Logging and Error Handling
**Question:** What logging/debugging approach should we use?

**Decision:** Comprehensive Exception Hierarchy with Multiple Logging Targets
- **User's Response Key Points:**
  - Log to: Console, Response object, or custom stream (via settings)
  - **CRITICAL:** Every single error code needs its own exception type
  - Complete exception hierarchy tree
  - Mermaid diagram for exception visualization
  - Perfect IntelliSense is a top priority
  - Full documentation with examples
  - AI-friendly tags for code understanding

### 9. KILLER FEATURE - Universal Curl String Acceptance
**User Requirement:** "The killer feature here is you copy and paste a curl string in and it works."
- Accept curl commands with or without "curl" prefix
- Handle commands even if "curl" is inside the string
- Support semicolon-separated multiple curl commands
- Implement `CurlMultiple` and `CurlMultipleAsync` for multiple commands

### 10. Implementation Philosophy
**User Guidance:**
- "We're not editing the C++ we're using it as a reference"
- "Try and use low-level objects if we can"
- "Built-in .NET objects only if necessary because they're HTTP objects have generally been very verbosely implemented and don't map well to Curl"
- Consider transpiling C code where appropriate

## Comprehensive API Design

```csharp
// Main static entry points with KILLER FEATURE
public static class DotNetCurl
{
    // Single command - accepts any curl string format
    public static CurlResponse Curl(string command);
    public static Task<CurlResponse> CurlAsync(string command);

    // Settings-based approach for programmatic use
    public static CurlResponse Curl(CurlSettings settings);
    public static Task<CurlResponse> CurlAsync(CurlSettings settings);

    // Multiple curl commands (semicolon separated)
    public static CurlResponse[] CurlMultiple(string commands);
    public static Task<CurlResponse[]> CurlMultipleAsync(string commands);
}

// Fluent response API
public class CurlResponse : IDisposable
{
    public Stream DataStream { get; }
    public int StatusCode { get; }
    public Dictionary<string, string> Headers { get; }

    // Fluent methods
    public CurlResponse SaveToFile(string path);
    public CurlResponse SaveToHtml(string path);
    public CurlResponse SaveToJson(string path);
    public T ParseJson<T>();
    public string AsString();
    // ... other fluent methods
}

// Comprehensive settings object
public class CurlSettings
{
    public Stream LogStream { get; set; }
    public string OutputPath { get; set; }
    public TimeSpan Timeout { get; set; }
    public IAuthenticationProvider Authentication { get; set; }
    // ... all 300+ curl options

    // Fluent builder pattern
    public CurlSettings WithTimeout(TimeSpan timeout);
    public CurlSettings WithAuthentication(string type, string credentials);
    public CurlSettings WithHeader(string key, string value);
    // ... etc
}
```

## Exception Hierarchy Requirements
- Create individual exception class for EVERY curl error code
- Maintain inheritance hierarchy for catch groups
- Include Mermaid diagram in documentation
- Perfect IntelliSense with XML documentation
- AI-Usage and AI-Pattern tags on all exceptions

## Notes
- All architecture decisions documented here should be referenced when implementing features
- Update this document when new decisions are made
- Keep the WORK_SUMMARY.md file updated with implementation progress
- **Always append to `/dotnet/claude_code_transcript.log` during sessions**