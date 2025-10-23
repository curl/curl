#!/bin/bash

# Test script for CurlDotNet
# Sponsored by Iron Software (ironsoftware.com)

echo "========================================="
echo "CurlDotNet Test Runner"
echo "Version: 8.17.0 (matching curl)"
echo "Sponsored by Iron Software"
echo "========================================="
echo ""

# Check if .NET is installed
if ! command -v dotnet &> /dev/null; then
    echo "❌ .NET SDK is not installed"
    echo ""
    echo "To install .NET SDK on macOS:"
    echo "  brew install dotnet-sdk"
    echo ""
    echo "Or download from:"
    echo "  https://dotnet.microsoft.com/download"
    echo ""
    exit 1
fi

echo "✅ .NET SDK found:"
dotnet --version
echo ""

# Navigate to project directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "📦 Restoring NuGet packages..."
dotnet restore
if [ $? -ne 0 ]; then
    echo "❌ Package restore failed"
    exit 1
fi
echo "✅ Packages restored"
echo ""

echo "🔨 Building CurlDotNet..."
dotnet build --configuration Release
if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi
echo "✅ Build succeeded"
echo ""

echo "🧪 Running tests..."
echo "------------------------"

# Run tests for each framework if available
for framework in net8.0 net6.0 netcoreapp3.1 net48; do
    echo ""
    echo "Testing framework: $framework"

    if dotnet test --no-build --configuration Release --framework $framework 2>/dev/null; then
        echo "✅ Tests passed for $framework"
    else
        echo "⚠️  $framework not available or tests failed"
    fi
done

echo ""
echo "------------------------"
echo ""

# Generate test report
echo "📊 Generating test report..."
dotnet test --no-build --configuration Release --logger "console;verbosity=normal" --collect:"XPlat Code Coverage"

echo ""
echo "========================================="
echo "Test run complete!"
echo ""
echo "To create NuGet package:"
echo "  cd src/CurlDotNet"
echo "  dotnet pack --configuration Release"
echo ""
echo "Package will be in:"
echo "  src/CurlDotNet/bin/Release/"
echo "========================================="