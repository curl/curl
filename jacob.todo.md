# Jacob's TODO - Curl to .NET Transpilation Project

## Project Overview
Creating pure implementations of curl in multiple languages:
- .NET/C# implementation with zero interop/bindings
- Rust implementation (fully static, exact curl/libcurl match)
- WebAssembly version (compiled from C or Rust)

## Current Progress

### Completed
- [x] Created dotnet subfolder structure
- [x] Created solution file (CurlDotNet.sln)
- [x] Started project structure setup

### In Progress
- [ ] Creating main CurlDotNet library project
- [ ] Setting up test project structure

### TODO List

#### Core Implementation
1. [ ] **Study curl source code architecture**
   - [ ] Analyze src/tool_*.c files for command-line parsing logic
   - [ ] Study lib/url.c for core URL handling
   - [ ] Review lib/transfer.c for data transfer logic
   - [ ] Understand lib/http.c for HTTP protocol implementation

2. [ ] **Create core .NET library structure**
   - [ ] Implement `Curl` main class with `Execute(string command)` method
   - [ ] Create command-line argument parser
   - [ ] Build option mapping system (curl options → .NET implementation)

3. [ ] **Implement protocol handlers**
   - [ ] HTTP/HTTPS using HttpClient
   - [ ] FTP support
   - [ ] File:// protocol
   - [ ] Other protocols as needed

4. [ ] **Core curl options to implement**
   - [ ] `-X, --request` (HTTP method)
   - [ ] `-H, --header` (custom headers)
   - [ ] `-d, --data` (POST data)
   - [ ] `-o, --output` (output to file)
   - [ ] `-O, --remote-name` (save with remote name)
   - [ ] `-L, --location` (follow redirects)
   - [ ] `-v, --verbose` (verbose output)
   - [ ] `-s, --silent` (silent mode)
   - [ ] `-u, --user` (authentication)
   - [ ] `--cookie` (cookie handling)
   - [ ] `-A, --user-agent` (user agent string)
   - [ ] `-e, --referer` (referer header)
   - [ ] `-T, --upload-file` (file upload)
   - [ ] `--proxy` (proxy support)
   - [ ] `-k, --insecure` (ignore SSL errors)
   - [ ] `--compressed` (compression support)

#### Testing
5. [ ] **Mirror curl's test suite**
   - [ ] Study tests/ directory structure
   - [ ] Create .NET equivalents of curl tests
   - [ ] Test all command-line option combinations
   - [ ] Performance testing

6. [ ] **Create synthetic .NET tests**
   - [ ] Unit tests for argument parser
   - [ ] Integration tests for HTTP operations
   - [ ] Edge case testing
   - [ ] Async/await pattern tests

#### Documentation
7. [ ] **Create comprehensive documentation**
   - [ ] README.md with usage examples
   - [ ] API documentation
   - [ ] Migration guide from curl to CurlDotNet
   - [ ] Performance comparison documentation

#### WebAssembly Version
8. [ ] **Create WebAssembly implementation**
   - [ ] Create webassembly subfolder
   - [ ] Option A: Compile C code directly to WASM using Emscripten
     - [ ] Setup Emscripten build configuration
     - [ ] Handle WASM-specific syscalls and limitations
   - [ ] Option B: Transpile C to Rust, then compile to WASM
     - [ ] Use c2rust or similar transpiler
     - [ ] Clean up and optimize Rust code
     - [ ] Use wasm-pack for WASM compilation
   - [ ] Handle WASM-specific constraints (CORS, sandboxing, etc.)
   - [ ] Create demo page showing curl running in browser
   - [ ] Create JavaScript bindings for WASM module

#### Package & Distribution
9. [ ] **NuGet Package Setup**
   - [ ] Configure package metadata
   - [ ] Create package icon
   - [ ] Setup CI/CD for package publishing
   - [ ] Version management

## Key Files to Create

### Source Files (dotnet/src/CurlDotNet/)
- `Curl.cs` - Main entry point
- `CommandParser.cs` - Parses curl command strings
- `Options/CurlOptions.cs` - Options model
- `Handlers/HttpHandler.cs` - HTTP protocol handler
- `Handlers/FtpHandler.cs` - FTP protocol handler
- `Output/OutputFormatter.cs` - Format output like curl
- `Authentication/AuthenticationHandler.cs` - Auth support

### Test Files (dotnet/tests/CurlDotNet.Tests/)
- `CurlTests.cs` - Main functionality tests
- `CommandParserTests.cs` - Parser tests
- `HttpHandlerTests.cs` - HTTP-specific tests
- `CompatibilityTests.cs` - Tests matching curl behavior

### Documentation Files
- `dotnet/README.md` - Main documentation
- `dotnet/EXAMPLES.md` - Usage examples
- `dotnet/COMPATIBILITY.md` - Curl compatibility matrix

## Technical Decisions

### Architecture Choices (REVISED)
- Transpile directly from curl C source code for accuracy
- Create low-level socket implementations matching curl's behavior
- Avoid high-level .NET APIs (HttpClient, WebRequest) where possible
- Implement curl's exact state machines and protocol handling
- Share transpilation approach between .NET and Rust versions
- Use P/Invoke sparingly only for OS-specific features (not for curl logic)

### Challenges to Address
1. **SSL/TLS handling** - Map curl's SSL options to .NET
2. **Cookie management** - Implement curl-compatible cookie jar
3. **Progress callbacks** - Implement curl's progress reporting
4. **Custom protocols** - Extensibility for protocol handlers
5. **Performance** - Match curl's performance characteristics
6. **Platform differences** - Handle Windows vs Linux/Mac differences

## Rust Implementation Plans
10. [ ] **Create Rust version**
   - [ ] Study existing Rust HTTP clients (reqwest, hyper, ureq)
   - [ ] Create rust subfolder
   - [ ] Implement curl command parser in Rust
   - [ ] Build static binary with no dependencies
   - [ ] Match curl's exact behavior and output
   - [ ] Support all curl protocols
   - [ ] Can compile to both native static binary and WASM

## Next Immediate Steps
1. Complete the basic project structure
2. Study curl's main.c and tool_getparam.c for argument parsing
3. Create Curl.cs with Execute method skeleton
4. Implement basic HTTP GET functionality
5. Add first unit test

## Resources
- Curl source: https://github.com/curl/curl
- Curl documentation: https://curl.se/docs/
- Everything curl book: https://everything.curl.dev/

## Notes
- Zero interop - pure .NET implementation
- Must pass all mirrored curl tests
- WebAssembly version for browser execution
- Maintain curl's command-line compatibility