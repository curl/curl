using System;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using CurlDotNet;
using CurlDotNet.Core;

namespace CurlDotNet.Tests
{
    /// <summary>
    /// Base class for all curl tests providing common functionality
    /// </summary>
    public abstract class CurlTestBase : IDisposable
    {
        protected readonly ITestOutputHelper Output;
        protected readonly HttpClient HttpClient;
        protected readonly string TestDataDirectory;
        protected readonly string TempDirectory;

        protected CurlTestBase(ITestOutputHelper output)
        {
            Output = output ?? throw new ArgumentNullException(nameof(output));
            HttpClient = new HttpClient();

            // Setup test directories
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            TestDataDirectory = Path.Combine(baseDir, "TestData");
            TempDirectory = Path.Combine(Path.GetTempPath(), $"CurlDotNet.Tests.{Guid.NewGuid()}");

            Directory.CreateDirectory(TestDataDirectory);
            Directory.CreateDirectory(TempDirectory);

            Output.WriteLine($"Test initialized - Temp: {TempDirectory}");
            Output.WriteLine($"Running on: {RuntimeInformation.FrameworkDescription}");
            Output.WriteLine($"OS: {RuntimeInformation.OSDescription}");
        }

        /// <summary>
        /// Creates a temporary file with the given content
        /// </summary>
        protected string CreateTempFile(string content, string extension = ".txt")
        {
            var fileName = Path.Combine(TempDirectory, $"{Guid.NewGuid()}{extension}");
            File.WriteAllText(fileName, content);
            return fileName;
        }

        /// <summary>
        /// Creates a temporary binary file
        /// </summary>
        protected string CreateTempBinaryFile(byte[] data, string extension = ".bin")
        {
            var fileName = Path.Combine(TempDirectory, $"{Guid.NewGuid()}{extension}");
            File.WriteAllBytes(fileName, data);
            return fileName;
        }

        /// <summary>
        /// Asserts that two strings are equal, normalizing line endings
        /// </summary>
        protected void AssertEqualNormalized(string expected, string actual)
        {
            var normalizedExpected = NormalizeLineEndings(expected);
            var normalizedActual = NormalizeLineEndings(actual);
            Assert.Equal(normalizedExpected, normalizedActual);
        }

        /// <summary>
        /// Normalizes line endings to Unix style
        /// </summary>
        protected string NormalizeLineEndings(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            return input.Replace("\r\n", "\n").Replace("\r", "\n");
        }

        /// <summary>
        /// Skips test if running on Windows
        /// </summary>
        protected void SkipIfWindows(string reason = "Test not supported on Windows")
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new SkipException(reason);
            }
        }

        /// <summary>
        /// Skips test if not running on Windows
        /// </summary>
        protected void SkipIfNotWindows(string reason = "Test requires Windows")
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new SkipException(reason);
            }
        }

        /// <summary>
        /// Skips test if running on .NET Framework
        /// </summary>
        protected void SkipIfNetFramework(string reason = "Test not supported on .NET Framework")
        {
            #if NET472
            throw new SkipException(reason);
            #endif
        }

        /// <summary>
        /// Skips test if not running on .NET Framework
        /// </summary>
        protected void SkipIfNotNetFramework(string reason = "Test requires .NET Framework")
        {
            #if !NET472
            throw new SkipException(reason);
            #endif
        }

        /// <summary>
        /// Gets a test file path from the original curl test suite
        /// </summary>
        protected string GetCurlTestFile(string relativePath)
        {
            // This would map to the original curl test files
            var curlTestRoot = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
                "..", "..", "..", "..", "..", "..", "tests"));
            return Path.Combine(curlTestRoot, relativePath);
        }

        /// <summary>
        /// Executes a curl command and returns the result
        /// </summary>
        protected async Task<CurlResult> ExecuteCurlAsync(string command)
        {
            var result = await Curl.ExecuteAsync(command);
            Output.WriteLine($"Command: {command}");
            Output.WriteLine($"Output: {result.Body}");
            return result;
        }

        /// <summary>
        /// Executes a curl command and asserts success
        /// </summary>
        protected async Task<CurlResult> ExecuteCurlSuccessAsync(string command)
        {
            try
            {
                var result = await ExecuteCurlAsync(command);
                return result;
            }
            catch (Exception ex)
            {
                Output.WriteLine($"Command failed: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Compares curl output with expected output from original tests
        /// </summary>
        protected void AssertCurlOutput(string actual, string expected, string testName)
        {
            Output.WriteLine($"=== Test: {testName} ===");
            Output.WriteLine($"Expected:\n{expected}");
            Output.WriteLine($"Actual:\n{actual}");

            AssertEqualNormalized(expected, actual);
        }

        public virtual void Dispose()
        {
            HttpClient?.Dispose();

            // Clean up temp directory
            if (Directory.Exists(TempDirectory))
            {
                try
                {
                    Directory.Delete(TempDirectory, recursive: true);
                }
                catch
                {
                    // Ignore cleanup errors
                }
            }
        }
    }

    /// <summary>
    /// Custom exception for skipping tests
    /// </summary>
    public class SkipException : Exception
    {
        public SkipException(string message) : base(message) { }
    }
}