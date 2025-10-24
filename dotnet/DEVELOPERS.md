# Developer Guide for CurlDotNet

This guide is for developers who want to contribute to or build CurlDotNet from source.

## 📋 Prerequisites & Dependencies

### Core Requirements

| Dependency | Version | Purpose | Installation |
|------------|---------|---------|--------------|
| **.NET SDK** | 8.0+ | Build & compile | [Download](https://dotnet.microsoft.com/download) |
| **Git** | Latest | Source control | `brew install git` (macOS) |
| **DocFX** | Latest | Documentation generation | `brew install docfx` or `dotnet tool install -g docfx` |

### Platform-Specific Tools

#### macOS (via Homebrew)
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install dotnet-sdk
brew install git
brew install docfx
```

#### Windows (via Chocolatey)
```powershell
# Install Chocolatey if not already installed
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install dependencies
choco install dotnet-sdk
choco install git
choco install docfx
```

#### Linux (Ubuntu/Debian)
```bash
# Add Microsoft package repository
wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb

# Install dependencies
sudo apt-get update
sudo apt-get install -y dotnet-sdk-8.0
sudo apt-get install -y git

# Install DocFX via .NET tool
dotnet tool install -g docfx
```

### Optional Development Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Visual Studio 2022** | IDE (Windows/Mac) | [Download](https://visualstudio.microsoft.com/) |
| **Visual Studio Code** | Lightweight IDE | [Download](https://code.visualstudio.com/) |
| **Rider** | JetBrains IDE | [Download](https://www.jetbrains.com/rider/) |
| **Docker** | Container testing | `brew install docker` |
| **Act** | GitHub Actions locally | `brew install act` |

## 🏗️ Building from Source

### Clone the Repository
```bash
git clone https://github.com/jacob/curl-dot-net.git
cd curl-dot-net/dotnet
```

### Build Commands

#### Build for Current Platform
```bash
dotnet build --configuration Release
```

#### Build for All Platforms
```bash
./build-all.sh
```

#### Build NuGet Package
```bash
dotnet pack --configuration Release --output ./nupkg
```

#### Build Specific Runtime
```bash
# Windows x64
dotnet publish -r win-x64 -c Release

# Linux x64
dotnet publish -r linux-x64 -c Release

# macOS ARM64 (Apple Silicon)
dotnet publish -r osx-arm64 -c Release
```

## 🧪 Running Tests

### Run All Tests
```bash
dotnet test
```

### Run Specific Test Category
```bash
# Unit tests only
dotnet test --filter "Category=Unit"

# Integration tests only
dotnet test --filter "Category=Integration"

# Performance tests
dotnet test --filter "Category=Performance"
```

### Run with Coverage
```bash
dotnet test --collect:"XPlat Code Coverage"
```

## 📚 Generating Documentation

### Install DocFX
```bash
# Via .NET tool (recommended)
dotnet tool install -g docfx

# Via Homebrew (macOS)
brew install docfx
```

### Generate Documentation
```bash
./generate-docs.sh
```

### Serve Documentation Locally
```bash
docfx serve _site --port 8080
# Open http://localhost:8080
```

## 🔧 Development Workflow

### 1. Create Feature Branch
```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes
- Write code
- Add tests
- Update documentation

### 3. Run Tests
```bash
dotnet test
```

### 4. Build Package
```bash
dotnet pack --configuration Release
```

### 5. Test Package Locally
```bash
# Create local NuGet source
dotnet nuget add source ./nupkg --name LocalFeed

# Test in a new project
dotnet new console -n TestApp
cd TestApp
dotnet add package CurlDotNet --source ../nupkg
```

### 6. Commit Changes
```bash
git add .
git commit -m "feat: Add your feature description"
```

## 🎯 Code Examples in Multiple Languages

### C# Example
```csharp
using CurlDotNet;

var response = await Curl.ExecuteAsync("curl https://api.example.com/data");
Console.WriteLine(response.Body);
```

### VB.NET Example
```vb
Imports CurlDotNet

Module Program
    Sub Main()
        Dim response = Curl.ExecuteAsync("curl https://api.example.com/data").Result
        Console.WriteLine(response.Body)
    End Sub
End Module
```

### F# Example
```fsharp
open CurlDotNet

[<EntryPoint>]
let main argv =
    async {
        let! response = Curl.ExecuteAsync("curl https://api.example.com/data") |> Async.AwaitTask
        printfn "%s" response.Body
        return 0
    } |> Async.RunSynchronously
```

## 🐛 Debugging

### Enable Verbose Logging
```bash
export CURLDOTNET_DEBUG=true
dotnet run
```

### Attach Debugger
```json
// .vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": ".NET Core Launch",
            "type": "coreclr",
            "request": "launch",
            "preLaunchTask": "build",
            "program": "${workspaceFolder}/bin/Debug/net8.0/CurlDotNet.dll",
            "args": [],
            "cwd": "${workspaceFolder}",
            "console": "internalConsole",
            "stopAtEntry": false
        }
    ]
}
```

## 📦 NuGet Package Structure

```
CurlDotNet.nupkg
├── lib/
│   ├── netstandard2.0/
│   │   └── CurlDotNet.dll
│   ├── net6.0/
│   │   └── CurlDotNet.dll
│   └── net8.0/
│       └── CurlDotNet.dll
├── README.md
├── LICENSE
└── icon.png
```

## 🔒 Signing & Security

### Strong Name Signing
```xml
<!-- In .csproj -->
<PropertyGroup>
    <SignAssembly>true</SignAssembly>
    <AssemblyOriginatorKeyFile>CurlDotNet.snk</AssemblyOriginatorKeyFile>
</PropertyGroup>
```

### Code Signing (Windows)
```bash
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com CurlDotNet.dll
```

## 🚀 Release Process

1. **Update Version**
   ```xml
   <!-- In .csproj -->
   <Version>1.0.1</Version>
   ```

2. **Update Release Notes**
   ```xml
   <PackageReleaseNotes>
   Version 1.0.1
   - Fixed bug X
   - Added feature Y
   </PackageReleaseNotes>
   ```

3. **Create Git Tag**
   ```bash
   git tag v1.0.1
   git push origin v1.0.1
   ```

4. **Build Release Package**
   ```bash
   dotnet pack -c Release
   ```

5. **Publish to NuGet** (maintainers only)
   ```bash
   dotnet nuget push ./nupkg/CurlDotNet.1.0.1.nupkg --api-key YOUR_API_KEY --source https://api.nuget.org/v3/index.json
   ```

## 📊 Performance Profiling

### Using BenchmarkDotNet
```bash
cd benchmarks
dotnet run -c Release
```

### Using PerfView (Windows)
```bash
PerfView collect dotnet run
```

### Using dotnet-trace
```bash
dotnet tool install --global dotnet-trace
dotnet trace collect --process-id $(pgrep dotnet)
```

## 🤝 Contributing

Please read our [Contributing Guide](./CONTRIBUTING.md) for details on:
- Code style guidelines
- Commit message format
- Pull request process
- Code review checklist

## 📞 Getting Help

- **Discord**: [Join our developer channel](https://discord.gg/curldotnet)
- **GitHub Issues**: [Report bugs or request features](https://github.com/jacob/curl-dot-net/issues)
- **Documentation**: [Full documentation](https://curldotnet.com/docs)

## License

CurlDotNet is licensed under the MIT License. See [LICENSE](../LICENSE) for details.