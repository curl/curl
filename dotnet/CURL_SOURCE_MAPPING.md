# CurlDotNet to curl C Source File Mapping

This document maps CurlDotNet's .NET files to their corresponding curl C source files for easier maintenance and updates.

## Core Mapping

| CurlDotNet File | curl C Source | Purpose |
|-----------------|---------------|---------|
| `Curl.cs` | `src/tool_operate.c` | Main operation entry point |
| `CurlEngine.cs` | `src/tool_main.c` | Core execution engine |
| `CommandParser.cs` | `src/tool_getparam.c` | Command line parsing |
| `CurlSettings.cs` | `src/tool_cfgable.c` | Configuration structure |
| `CurlResult.cs` | `src/tool_cb_*.c` | Callbacks and results |
| `CurlExecutor.cs` | `src/tool_operate.c` | Execute operations |

## Options Mapping

| CurlDotNet File | curl C Source | Purpose |
|-----------------|---------------|---------|
| `CurlOptions.cs` | `include/curl/curl.h` | Option definitions |
| `AuthOption.cs` | `src/tool_setopt.c` | Authentication options |
| `HeaderOption.cs` | `src/tool_setopt.c` | Header options |
| `DataOption.cs` | `src/tool_formparse.c` | Form/data parsing |
| `ProxyOption.cs` | `src/tool_setopt.c` | Proxy settings |
| `SslOption.cs` | `src/tool_setopt.c` | SSL/TLS options |

## Error Handling

| CurlDotNet File | curl C Source | Purpose |
|-----------------|---------------|---------|
| `CurlExceptions.cs` | `include/curl/curl.h` (CURLE_*) | Error codes |
| `CurlDnsException.cs` | `CURLE_COULDNT_RESOLVE_HOST (6)` | DNS errors |
| `CurlTimeoutException.cs` | `CURLE_OPERATION_TIMEDOUT (28)` | Timeout errors |
| `CurlSslException.cs` | `CURLE_SSL_* (35, 60, etc)` | SSL errors |
| `CurlAuthException.cs` | `CURLE_LOGIN_DENIED (67)` | Auth errors |

## Parser Components

| CurlDotNet File | curl C Source | Purpose |
|-----------------|---------------|---------|
| `CommandParser.cs` | `src/tool_getparam.c` | Main parser |
| `QuoteHandler.cs` | `src/tool_parsecfg.c` | Quote parsing |
| `UrlParser.cs` | `src/tool_urlglob.c` | URL globbing |
| `DataParser.cs` | `src/tool_formparse.c` | Form data |

## Utility Files

| CurlDotNet File | curl C Source | Purpose |
|-----------------|---------------|---------|
| `HttpClientFactory.cs` | `lib/http.c` | HTTP implementation |
| `FileOperations.cs` | `src/tool_cb_wrt.c` | File I/O |
| `ProgressReporter.cs` | `src/tool_cb_prg.c` | Progress callback |
| `HeaderParser.cs` | `src/tool_cb_hdr.c` | Header callback |

## Version Information

| CurlDotNet File | curl C Source | Purpose |
|-----------------|---------------|---------|
| `CurlVersion.cs` | `src/tool_version.c` | Version info |
| `LibInfo.cs` | `lib/version.c` | Library info |

## Test Mapping

| CurlDotNet Test | curl Test | Purpose |
|-----------------|-----------|---------|
| `BasicTests.cs` | `tests/data/test1-99` | Basic operations |
| `AuthTests.cs` | `tests/data/test500-599` | Authentication |
| `SslTests.cs` | `tests/data/test300-399` | SSL/TLS |
| `ProxyTests.cs` | `tests/data/test200-299` | Proxy |
| `RedirectTests.cs` | `tests/data/test100-199` | Redirects |

## Notes on Naming Conventions

1. **tool_*.c files**: These are curl's command-line tool sources
   - We map these to our main API classes
   - `tool_operate.c` → `Curl.cs` (main entry)
   - `tool_getparam.c` → `CommandParser.cs` (parsing)

2. **lib/*.c files**: These are libcurl's library sources
   - We implement these functionalities in .NET
   - `lib/http.c` → `HttpClientFactory.cs`
   - `lib/url.c` → `UrlParser.cs`

3. **Error codes**: Directly from `include/curl/curl.h`
   - Each CURLE_* error gets its own exception
   - Error numbers match curl's definitions

4. **Callbacks (cb_*)**: Result handling
   - `tool_cb_wrt.c` → File writing in `CurlResult.SaveToFile()`
   - `tool_cb_hdr.c` → Header parsing in `CurlResult.Headers`

## Updating from curl Source

When curl releases updates:
1. Check the changelog at https://curl.se/changes.html
2. Map changes to corresponding CurlDotNet files using this guide
3. Update options in `CurlOptions.cs` from `curl.h`
4. Add new error codes to `CurlExceptions.cs`
5. Update command parsing from `tool_getparam.c` changes

## Attribution

Each file contains attribution to the original curl source:
```csharp
/*
 * Inspired by curl's src/tool_operate.c
 * Original curl Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 */
```

This mapping ensures we can track curl updates and maintain compatibility.