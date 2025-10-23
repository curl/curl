# CurlDotNet Architecture

## Vision
Universal curl command execution across all programming languages. Copy-paste any curl command from anywhere, and it just works.

## Architecture Diagram

```mermaid
graph TB
    subgraph "User API Layer"
        CLI["Curl (Static)<br/>Copy-paste curl commands"]
        LIBCURL["LibCurl (Instance)<br/>Object-oriented API"]
    end

    subgraph "Core Engine"
        ENGINE["CurlEngine<br/>Command processing"]
        PARSER["CommandParser<br/>Parse curl syntax"]
        VALIDATOR["Validator<br/>Command validation"]
    end

    subgraph "Protocol Handlers"
        HTTP["HttpHandler<br/>HTTP/HTTPS"]
        FTP["FtpHandler<br/>FTP/FTPS"]
        FILE["FileHandler<br/>file://"]
        FUTURE["Future: SFTP, SCP, etc."]
    end

    subgraph "Result Layer"
        RESULT["CurlResult<br/>Fluent API"]
        TIMINGS["CurlTimings<br/>Performance data"]
        OUTPUT["OutputFormatter<br/>Console/File output"]
    end

    subgraph "Settings"
        SETTINGS["CurlSettings<br/>Fluent builder"]
        OPTIONS["CurlOptions<br/>Parsed options"]
    end

    subgraph "Cross-Language Support"
        CODEGEN["Code Generators"]
        TOHTTPCLIENT["ToHttpClient()"]
        TOFETCH["ToFetch()"]
        TOPYTHON["ToPythonRequests()"]
    end

    CLI --> ENGINE
    LIBCURL --> ENGINE
    ENGINE --> PARSER
    ENGINE --> VALIDATOR
    PARSER --> OPTIONS
    ENGINE --> HTTP
    ENGINE --> FTP
    ENGINE --> FILE
    HTTP --> RESULT
    FTP --> RESULT
    FILE --> RESULT
    RESULT --> TIMINGS
    RESULT --> OUTPUT
    SETTINGS --> ENGINE
    ENGINE --> CODEGEN
    CODEGEN --> TOHTTPCLIENT
    CODEGEN --> TOFETCH
    CODEGEN --> TOPYTHON

    style CLI fill:#e1f5fe
    style LIBCURL fill:#e1f5fe
    style RESULT fill:#c8e6c9
    style ENGINE fill:#fff3e0
```

## Component Flow

```mermaid
sequenceDiagram
    participant User
    participant Curl
    participant CurlEngine
    participant CommandParser
    participant HttpHandler
    participant CurlResult

    User->>Curl: Execute("curl -X POST https://api.example.com")
    Curl->>CurlEngine: ExecuteAsync(command)
    CurlEngine->>CommandParser: Parse(command)
    CommandParser-->>CurlEngine: CurlOptions
    CurlEngine->>HttpHandler: ExecuteAsync(options)
    HttpHandler-->>CurlEngine: Response
    CurlEngine->>CurlResult: Create(response)
    CurlResult-->>Curl: Fluent result
    Curl-->>User: CurlResult

    Note over User: Fluent operations
    User->>CurlResult: .AsJson<T>()
    User->>CurlResult: .AssertStatus(200)
    User->>CurlResult: .SaveTo("file.json")
```

## Multi-Language Strategy

```mermaid
graph LR
    subgraph "Language Implementations"
        DOTNET[".NET<br/>CurlDotNet"]
        RUST["Rust<br/>rs-curl"]
        JS["JavaScript<br/>curl-js"]
        PYTHON["Python<br/>pycurl-easy"]
    end

    subgraph "Shared"
        CURLREF["curl C source<br/>(reference only)"]
        TESTS["Shared test suite<br/>Same curl commands"]
        DOCS["Shared documentation<br/>Same examples"]
    end

    CURLREF -.->|Reference| DOTNET
    CURLREF -.->|Reference| RUST
    CURLREF -.->|Reference| JS
    CURLREF -.->|Reference| PYTHON

    TESTS -->|Validate| DOTNET
    TESTS -->|Validate| RUST
    TESTS -->|Validate| JS
    TESTS -->|Validate| PYTHON

    style DOTNET fill:#512bd4
    style RUST fill:#ce422b
    style JS fill:#f7df1e
    style PYTHON fill:#3776ab
```

## Rust Implementation Plan

```rust
//! rs-curl - Rust implementation of curl command execution
//!
//! The same killer feature: Copy-paste curl commands!
//!
//! # Examples
//!
//! ```rust
//! use rs_curl::Curl;
//!
//! // Copy from Stack Overflow - it just works!
//! let result = Curl::execute("curl https://api.github.com/user").await?;
//!
//! // Fluent result handling (Rust idiomatic)
//! let data: User = result
//!     .assert_status(200)?
//!     .as_json()?;
//!
//! // With Rust's ownership model
//! let response = Curl::post("https://api.example.com", json!({
//!     "name": "Rust"
//! })).await?;
//! ```

/// Static curl API for command execution
///
/// # Documentation Quality Standards
/// - Every public item MUST have documentation
/// - Every function MUST have examples
/// - Every error case MUST be documented
/// - Use `#![warn(missing_docs)]` at crate level
/// - Include doctest examples that actually run
///
/// # Example
/// ```rust
/// /// Execute any curl command
/// ///
/// /// # Arguments
/// /// * `command` - A curl command string, exactly as you'd type it
/// ///
/// /// # Returns
/// /// * `Result<CurlResult, CurlError>` - Success with fluent result or error
/// ///
/// /// # Errors
/// /// * `CurlError::InvalidCommand` - Malformed curl syntax
/// /// * `CurlError::NetworkError` - Connection failed
/// /// * `CurlError::Timeout` - Request exceeded timeout
/// ///
/// /// # Examples
/// /// ```
/// /// # use rs_curl::Curl;
/// /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// /// // Simple GET
/// /// let result = Curl::execute("curl https://example.com").await?;
/// ///
/// /// // POST with data
/// /// let result = Curl::execute(
/// ///     r#"curl -X POST https://api.example.com -d '{"key":"value"}'"#
/// /// ).await?;
/// /// # Ok(())
/// /// # }
/// /// ```
/// pub async fn execute(command: &str) -> Result<CurlResult, CurlError> {
///     // Implementation
/// }
/// ```

pub struct Curl;

impl Curl {
    // Static methods matching .NET design
}

/// Fluent result type with builder pattern
pub struct CurlResult {
    // Rust idiomatic fields
}

impl CurlResult {
    /// Extract JSON using serde
    pub fn as_json<T: DeserializeOwned>(self) -> Result<T, Error> { }

    /// Assert status code
    pub fn assert_status(self, expected: u16) -> Result<Self, Error> { }

    /// Save to file using tokio::fs
    pub async fn save_to(self, path: impl AsRef<Path>) -> Result<(), Error> { }
}
```

## Platform Support Matrix

| Platform | .NET | Rust | JavaScript | Python |
|----------|------|------|------------|--------|
| Windows | ✅ | ✅ | ✅ | ✅ |
| macOS | ✅ | ✅ | ✅ | ✅ |
| Linux | ✅ | ✅ | ✅ | ✅ |
| Mobile (iOS/Android) | ✅ (Xamarin) | 🔧 | ✅ (React Native) | 🔧 |
| WebAssembly | 🔧 | ✅ | ✅ | 🔧 |

## Success Metrics

1. **Copy-paste success rate**: 95%+ of curl commands from the web should work without modification
2. **Cross-platform consistency**: Same curl command produces identical results across all platforms
3. **Documentation coverage**: 100% public API documentation with examples
4. **Test coverage**: 90%+ code coverage with real curl command tests
5. **Performance**: Within 10% of native curl for common operations

## Contributing Back to Curl

```mermaid
graph TD
    FORK["Fork curl/curl"]
    IMPL["Implement in separate repos<br/>(curl-dotnet, rs-curl, etc)"]
    TEST["Validate against curl test suite"]
    STABLE["Achieve stability"]
    PR["Pull Request to curl/curl<br/>as language bindings"]

    FORK --> IMPL
    IMPL --> TEST
    TEST --> STABLE
    STABLE --> PR
```

Goal: Get these implementations accepted as official curl language bindings, making curl truly universal across all programming languages.