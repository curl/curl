# Test script for CurlDotNet (Windows)
# Sponsored by Iron Software (ironsoftware.com)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "CurlDotNet Test Runner" -ForegroundColor White
Write-Host "Version: 8.17.0 (matching curl)" -ForegroundColor White
Write-Host "Sponsored by Iron Software" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Check if .NET is installed
try {
    $dotnetVersion = dotnet --version
    Write-Host "✅ .NET SDK found: $dotnetVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ .NET SDK is not installed" -ForegroundColor Red
    Write-Host ""
    Write-Host "Download from:" -ForegroundColor Yellow
    Write-Host "  https://dotnet.microsoft.com/download" -ForegroundColor White
    Write-Host ""
    exit 1
}

Write-Host ""

# Navigate to script directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptPath

Write-Host "📦 Restoring NuGet packages..." -ForegroundColor Cyan
dotnet restore
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Package restore failed" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Packages restored" -ForegroundColor Green
Write-Host ""

Write-Host "🔨 Building CurlDotNet..." -ForegroundColor Cyan
dotnet build --configuration Release
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Build failed" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Build succeeded" -ForegroundColor Green
Write-Host ""

Write-Host "🧪 Running tests..." -ForegroundColor Cyan
Write-Host "------------------------"

# Test each framework
$frameworks = @("net8.0", "net6.0", "net48", "netstandard2.0")
foreach ($framework in $frameworks) {
    Write-Host ""
    Write-Host "Testing framework: $framework" -ForegroundColor Yellow

    $output = dotnet test --no-build --configuration Release --framework $framework 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Tests passed for $framework" -ForegroundColor Green
    } else {
        Write-Host "⚠️  $framework not available or tests failed" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "------------------------"
Write-Host ""

# Generate test report
Write-Host "📊 Generating test report..." -ForegroundColor Cyan
dotnet test --no-build --configuration Release --logger "console;verbosity=normal" --collect:"XPlat Code Coverage"

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Test run complete!" -ForegroundColor Green
Write-Host ""
Write-Host "To create NuGet package:" -ForegroundColor Yellow
Write-Host "  cd src\CurlDotNet" -ForegroundColor White
Write-Host "  dotnet pack --configuration Release" -ForegroundColor White
Write-Host ""
Write-Host "Package will be in:" -ForegroundColor Yellow
Write-Host "  src\CurlDotNet\bin\Release\" -ForegroundColor White
Write-Host "=========================================" -ForegroundColor Cyan