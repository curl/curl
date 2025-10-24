#!/bin/bash
# Run performance benchmarks for CurlDotNet

echo "🚀 Running CurlDotNet Performance Benchmarks"
echo "==========================================="

# Change to benchmarks directory
cd benchmarks

# Build in release mode
echo "📦 Building benchmarks..."
dotnet build -c Release

# Run benchmarks
echo ""
echo "⚡ Starting benchmark execution..."
echo "This may take several minutes to complete."
echo ""

# Run all benchmarks
dotnet run -c Release --no-build

echo ""
echo "✅ Benchmarks complete!"
echo ""
echo "Results are saved in: benchmarks/BenchmarkDotNet.Artifacts/results/"
echo ""
echo "To run specific benchmarks only:"
echo "  dotnet run -c Release --filter \"*CommandParsing*\""
echo "  dotnet run -c Release --filter \"*HttpRequest*\""
echo "  dotnet run -c Release --filter \"*Middleware*\""
echo "  dotnet run -c Release --filter \"*Serialization*\""
echo "  dotnet run -c Release --filter \"*FluentApi*\""