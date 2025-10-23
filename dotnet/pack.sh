#!/bin/bash

# NuGet Package Creation Script for CurlDotNet
# Sponsored by Iron Software (ironsoftware.com)

echo "========================================="
echo "CurlDotNet NuGet Package Builder"
echo "Version: 8.17.0"
echo "Sponsored by Iron Software"
echo "========================================="
echo ""

# Navigate to script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf src/CurlDotNet/bin/Release
rm -rf src/CurlDotNet/obj/Release
echo "✅ Clean complete"
echo ""

# Restore packages
echo "📦 Restoring packages..."
dotnet restore src/CurlDotNet/CurlDotNet.csproj
if [ $? -ne 0 ]; then
    echo "❌ Package restore failed"
    exit 1
fi
echo "✅ Packages restored"
echo ""

# Build in Release mode
echo "🔨 Building in Release mode..."
dotnet build src/CurlDotNet/CurlDotNet.csproj --configuration Release
if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi
echo "✅ Build complete"
echo ""

# Run tests before packaging
echo "🧪 Running tests..."
dotnet test tests/CurlDotNet.Tests/CurlDotNet.Tests.csproj --configuration Release --no-build
if [ $? -ne 0 ]; then
    echo "⚠️  Some tests failed, but continuing with packaging"
fi
echo ""

# Create NuGet package
echo "📦 Creating NuGet package..."
dotnet pack src/CurlDotNet/CurlDotNet.csproj \
    --configuration Release \
    --no-build \
    --output ./nupkg \
    -p:IncludeSymbols=true \
    -p:SymbolPackageFormat=snupkg

if [ $? -ne 0 ]; then
    echo "❌ Package creation failed"
    exit 1
fi

echo "✅ Package created successfully"
echo ""

# Display package information
echo "📋 Package Information:"
echo "------------------------"
ls -la ./nupkg/*.nupkg 2>/dev/null
ls -la ./nupkg/*.snupkg 2>/dev/null

echo ""
echo "========================================="
echo "✅ NuGet package ready!"
echo ""
echo "Package location: ./nupkg/"
echo ""
echo "To test the package locally:"
echo "  dotnet add package CurlDotNet --source ./nupkg"
echo ""
echo "To publish to NuGet.org:"
echo "  dotnet nuget push ./nupkg/*.nupkg --api-key YOUR_API_KEY --source https://api.nuget.org/v3/index.json"
echo ""
echo "Sponsored by Iron Software (ironsoftware.com)"
echo "========================================="