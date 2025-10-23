# curl-dot-net Implementation Notes

## Project Structure

This repository contains multiple implementations of curl in different languages:

```
curl-dot-net/
├── dotnet/          # Pure .NET/C# implementation (COMPLETED)
├── rust/            # Pure Rust implementation (TODO)
├── webassembly/     # WebAssembly compilation (TODO)
└── jacob.todo.md    # Detailed TODO list and plans
```

## .NET Implementation Status ✅

The .NET implementation in the `dotnet/` folder is functionally complete with:

### Core Features
- ✅ Full curl command-line parser
- ✅ HTTP/HTTPS support via HttpClient
- ✅ FTP/FTPS support via FtpWebRequest
- ✅ FILE protocol support
- ✅ Comprehensive option support (-X, -H, -d, -o, -L, -v, etc.)
- ✅ Output handling (file, memory, streams)
- ✅ Parallel execution support
- ✅ Error handling and reporting

### Architecture
- Pure .NET Standard 2.0 for maximum compatibility
- Zero native dependencies or interop
- Transpilation approach from curl's C source
- Low-level implementations where possible
- Maintains curl's exact command-line syntax

### Testing & Documentation
- ✅ xUnit test suite
- ✅ Comprehensive README with examples
- ✅ Example application
- ✅ Proper attribution and licensing

## Rust Implementation Plans 🦀

The Rust implementation will:
- Be a complete, static, zero-dependency binary
- Match curl's exact behavior and output
- Compile to both native and WebAssembly
- Use low-level socket operations
- Support all curl protocols

## WebAssembly Compilation 🌐

Two approaches planned:
1. **Direct C to WASM**: Use Emscripten to compile curl's C code
2. **Rust to WASM**: Compile the Rust implementation to WASM

Both will:
- Run in browsers with JavaScript bindings
- Handle WASM-specific constraints (CORS, sandboxing)
- Provide demo pages

## Future Additions

### Wget Support
- Add `Wget` class alongside `Curl`
- Implement wget's command-line interface
- Support wget-specific features (recursive download, etc.)

### Additional Features
- More protocols (SFTP, SCP, LDAP, etc.)
- Performance optimizations
- HTTP/3 support
- Browser extension for testing

## Usage Philosophy

The key design principle is **string-based command interface**:

```csharp
// Developers can copy curl commands directly from documentation
var result = await curl.ExecuteAsync("curl -X POST https://api.example.com/data -H 'Content-Type: application/json' -d '{\"key\":\"value\"}'");
```

This approach:
- Eliminates learning curve
- Allows direct copy-paste from examples
- Maintains exact curl compatibility
- Works identically across all language implementations

## Transpilation Approach

Rather than reimplementing curl's logic, we:
1. Study curl's C source code
2. Transpile core logic to target language
3. Use lowest-level APIs available
4. Maintain exact behavior and output format
5. Preserve curl's error codes and messages

## Contributing

When adding to this project:
1. Maintain curl command-line compatibility
2. Use transpilation from C where possible
3. Add comprehensive tests
4. Document with examples
5. Keep implementations consistent across languages

## Credits

- Original curl: Daniel Stenberg (https://github.com/curl/curl)
- .NET Implementation: Jacob Mellor (https://github.com/jacob-mellor)
- License: curl license (MIT/X derivative)

## Build Instructions

### .NET Version
```bash
cd dotnet
dotnet build
dotnet test
dotnet pack  # Creates NuGet package
```

### Rust Version (TODO)
```bash
cd rust
cargo build --release
cargo test
```

### WebAssembly (TODO)
```bash
cd webassembly
# Emscripten or wasm-pack commands
```

## Next Steps

1. [ ] Finalize NuGet package configuration and publish
2. [ ] Start Rust implementation
3. [ ] Set up WebAssembly build pipeline
4. [ ] Add wget support
5. [ ] Create comprehensive test harness
6. [ ] Performance benchmarking against native curl