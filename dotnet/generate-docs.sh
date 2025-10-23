#!/bin/bash
# Generate HTML documentation using DocFX

echo "📚 Generating CurlDotNet Documentation..."
echo "=========================================="

# Check if DocFX is installed
if ! command -v docfx &> /dev/null
then
    echo "❌ DocFX is not installed."
    echo ""
    echo "To install DocFX, run one of these commands:"
    echo ""
    echo "  Using .NET tool:"
    echo "    dotnet tool install -g docfx"
    echo ""
    echo "  Using Homebrew (macOS):"
    echo "    brew install docfx"
    echo ""
    echo "  Using Chocolatey (Windows):"
    echo "    choco install docfx"
    echo ""
    exit 1
fi

# Clean previous documentation
echo "🧹 Cleaning previous documentation..."
rm -rf _site
rm -rf api

# Build the project first to generate XML documentation
echo "🔨 Building project to generate XML documentation..."
dotnet build src/CurlDotNet/CurlDotNet.csproj --configuration Release

# Generate metadata and build documentation
echo "📝 Generating API documentation..."
docfx metadata docfx.json --force

echo "🎨 Building HTML site..."
docfx build docfx.json

echo ""
echo "✅ Documentation generated successfully!"
echo ""
echo "📂 Output location: _site/"
echo ""
echo "To view the documentation locally, run:"
echo "  docfx serve _site"
echo ""
echo "Or open: _site/index.html"