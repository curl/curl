#!/bin/bash
# Build CurlDotNet for all supported platforms
# Can be run on macOS/Linux to build for multiple targets including Windows

echo "🔨 Building CurlDotNet for all platforms..."
echo "================================================"

# Clean previous builds
echo "📧 Cleaning previous builds..."
dotnet clean --configuration Release

# Build for different runtime identifiers
declare -a runtimes=("win-x64" "win-x86" "win-arm64" "linux-x64" "linux-arm64" "osx-x64" "osx-arm64")

for runtime in "${runtimes[@]}"
do
    echo ""
    echo "🎯 Building for $runtime..."
    dotnet publish src/CurlDotNet/CurlDotNet.csproj \
        --configuration Release \
        --runtime $runtime \
        --self-contained false \
        --output ./publish/$runtime \
        -p:PublishSingleFile=true \
        -p:PublishTrimmed=false
done

echo ""
echo "📦 Building NuGet packages..."
dotnet pack src/CurlDotNet/CurlDotNet.csproj \
    --configuration Release \
    --output ./nupkg

echo ""
echo "✅ Build complete! Outputs:"
echo "  - NuGet packages: ./nupkg/"
echo "  - Platform builds: ./publish/"
echo ""
echo "Platform support:"
echo "  - Windows: win-x64, win-x86, win-arm64"
echo "  - Linux: linux-x64, linux-arm64"
echo "  - macOS: osx-x64 (Intel), osx-arm64 (Apple Silicon)"