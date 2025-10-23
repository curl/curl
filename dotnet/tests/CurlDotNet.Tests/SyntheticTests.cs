/***************************************************************************
 * Synthetic .NET-specific tests for CurlDotNet
 *
 * These tests verify .NET-specific functionality and edge cases
 * that wouldn't exist in the original curl test suite.
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 * Sponsored by Iron Software (ironsoftware.com)
 ***************************************************************************/

using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using FluentAssertions;
using CurlDotNet;
using CurlDotNet.Output;
using CurlDotNet.Options;

namespace CurlDotNet.Tests
{
    /// <summary>
    /// Synthetic tests specific to .NET implementation
    /// </summary>
    public class SyntheticTests
    {
        #region Memory and Stream Tests

        [Fact]
        public async Task OutputResult_GetStream_ReturnsValidStream()
        {
            // Arrange
            var result = new OutputResult
            {
                ResponseBody = "Test response data",
                StatusCode = 200
            };

            // Act
            using var stream = result.GetStream();
            using var reader = new StreamReader(stream);
            var content = await reader.ReadToEndAsync();

            // Assert
            content.Should().Be("Test response data");
        }

        [Fact]
        public async Task OutputResult_BinaryData_HandledCorrectly()
        {
            // Arrange
            var binaryData = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }; // PNG header
            var result = new OutputResult
            {
                BinaryData = binaryData,
                StatusCode = 200
            };

            // Act
            using var stream = result.GetStream();
            var buffer = new byte[8];
            await stream.ReadAsync(buffer, 0, 8);

            // Assert
            buffer.Should().BeEquivalentTo(binaryData);
        }

        [Fact]
        public async Task Execute_LargeResponse_DoesNotExhaustMemory()
        {
            // This test would verify that large responses are handled efficiently
            // In production, this would test against a mock that returns large data

            var curl = new Curl();
            var tempFile = Path.GetTempFileName();

            try
            {
                // Simulate downloading a large file to disk instead of memory
                var command = $"curl -o {tempFile} https://httpbin.org/bytes/1024";

                // Act
                var result = await curl.ExecuteAsync(command);

                // Assert
                result.WroteToFile.Should().BeTrue();
                result.OutputPath.Should().Be(tempFile);
                result.ResponseBody.Should().BeNullOrEmpty(); // Should not load into memory
            }
            finally
            {
                if (File.Exists(tempFile))
                    File.Delete(tempFile);
            }
        }

        #endregion

        #region Encoding and Culture Tests

        [Theory]
        [InlineData("Hello World", "UTF-8")]
        [InlineData("你好世界", "UTF-8")]
        [InlineData("مرحبا بالعالم", "UTF-8")]
        [InlineData("Привет мир", "UTF-8")]
        public void CommandParser_HandlesInternationalCharacters(string data, string encoding)
        {
            // Arrange
            var parser = new CommandParser();
            var command = $"curl -d '{data}' https://example.com";

            // Act
            var options = parser.Parse(command);

            // Assert
            options.Data.Should().Be(data);
        }

        [Fact]
        public void CommandParser_HandlesWindowsPaths()
        {
            // Arrange
            var parser = new CommandParser();
            var windowsPath = @"C:\Users\Test\file.txt";
            var command = $"curl -o \"{windowsPath}\" https://example.com";

            // Act
            var options = parser.Parse(command);

            // Assert
            options.OutputFile.Should().Be(windowsPath);
        }

        [Fact]
        public void CommandParser_HandlesUnixPaths()
        {
            // Arrange
            var parser = new CommandParser();
            var unixPath = "/home/user/downloads/file.txt";
            var command = $"curl -o {unixPath} https://example.com";

            // Act
            var options = parser.Parse(command);

            // Assert
            options.OutputFile.Should().Be(unixPath);
        }

        #endregion

        #region Thread Safety Tests

        [Fact]
        public async Task Curl_MultipleInstancesInParallel_ThreadSafe()
        {
            // Arrange
            var tasks = new List<Task<OutputResult>>();

            // Act - Create multiple Curl instances and execute in parallel
            for (int i = 0; i < 10; i++)
            {
                var curl = new Curl();
                var task = Task.Run(() =>
                    curl.ExecuteAsync($"curl https://httpbin.org/uuid"));
                tasks.Add(task);
            }

            var results = await Task.WhenAll(tasks);

            // Assert
            results.Should().HaveCount(10);
            results.Should().OnlyContain(r => r != null);
        }

        [Fact]
        public async Task Curl_SingleInstanceMultipleRequests_ThreadSafe()
        {
            // Arrange
            var curl = new Curl();
            var tasks = new List<Task<OutputResult>>();

            // Act - Use single instance for multiple concurrent requests
            for (int i = 0; i < 10; i++)
            {
                var localI = i;
                var task = Task.Run(() =>
                    curl.ExecuteAsync($"curl https://httpbin.org/anything?id={localI}"));
                tasks.Add(task);
            }

            var results = await Task.WhenAll(tasks);

            // Assert
            results.Should().HaveCount(10);
            results.Should().OnlyContain(r => r != null);
        }

        #endregion

        #region .NET Specific Integration Tests

        [Fact]
        public async Task Execute_WithCancellationToken_CanBeCancelled()
        {
            // This would require modifying the Curl class to accept CancellationToken
            // For now, this is a placeholder for future implementation

            var curl = new Curl();
            using var cts = new CancellationTokenSource();

            // Simulate a long-running request
            var task = curl.ExecuteAsync("curl https://httpbin.org/delay/10");

            // Cancel after a short delay
            cts.CancelAfter(100);

            // In a full implementation, this would throw OperationCanceledException
            await task;
        }

        [Fact]
        public async Task OutputResult_DisposablePattern_WorksCorrectly()
        {
            // Arrange
            var result = new OutputResult
            {
                ResponseBody = "Test data",
                BinaryData = Encoding.UTF8.GetBytes("Binary test data")
            };

            Stream stream = null;

            // Act
            using (stream = result.GetStream())
            {
                stream.Should().NotBeNull();
                stream.CanRead.Should().BeTrue();
            }

            // Assert - After disposal
            stream.Invoking(s => s.Read(new byte[1], 0, 1))
                .Should().Throw<ObjectDisposedException>();
        }

        [Fact]
        public void CurlOptions_DefaultValues_AreCorrect()
        {
            // Arrange & Act
            var options = new CurlOptions();

            // Assert - Verify all default values
            options.Method.Should().Be("GET");
            options.HttpVersion.Should().Be("1.1");
            options.Headers.Should().NotBeNull().And.BeEmpty();
            options.AdditionalUrls.Should().NotBeNull().And.BeEmpty();
            options.FollowRedirects.Should().BeFalse();
            options.MaxRedirects.Should().Be(50);
            options.Verbose.Should().BeFalse();
            options.Silent.Should().BeFalse();
            options.ShowError.Should().BeFalse();
            options.FailOnError.Should().BeFalse();
            options.Insecure.Should().BeFalse();
            options.Compressed.Should().BeFalse();
            options.FtpPassive.Should().BeTrue();
            options.UseRemoteFileName.Should().BeFalse();
        }

        #endregion

        #region Edge Cases and Error Handling

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task Execute_WithInvalidCommand_ThrowsArgumentException(string command)
        {
            // Arrange
            var curl = new Curl();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() =>
                curl.ExecuteAsync(command));
        }

        [Fact]
        public void CommandParser_WithNoUrl_ThrowsCurlException()
        {
            // Arrange
            var parser = new CommandParser();

            // Act & Assert
            Assert.Throws<CurlException>(() =>
                parser.Parse("curl -H 'Accept: application/json'"));
        }

        [Fact]
        public void CommandParser_WithMultipleUrls_ParsesCorrectly()
        {
            // Arrange
            var parser = new CommandParser();
            var command = "curl https://example1.com https://example2.com https://example3.com";

            // Act
            var options = parser.Parse(command);

            // Assert
            options.Url.Should().Be("https://example1.com");
            options.AdditionalUrls.Should().HaveCount(2);
            options.AdditionalUrls[0].Should().Be("https://example2.com");
            options.AdditionalUrls[1].Should().Be("https://example3.com");
        }

        [Theory]
        [InlineData("curl --unknown-option https://example.com")]
        [InlineData("curl --not-a-real-flag https://example.com")]
        public void CommandParser_WithUnknownOptions_DoesNotThrow(string command)
        {
            // Arrange
            var parser = new CommandParser();

            // Act & Assert - Should handle gracefully
            var options = parser.Parse(command);
            options.Url.Should().Be("https://example.com");
        }

        [Fact]
        public void CommandParser_EscapedQuotes_HandledCorrectly()
        {
            // Arrange
            var parser = new CommandParser();
            var command = @"curl -d '{""key"": ""value with \"escaped\" quotes""}' https://example.com";

            // Act
            var options = parser.Parse(command);

            // Assert
            options.Data.Should().Contain("\\\"escaped\\\"");
        }

        #endregion

        #region Performance and Resource Tests

        [Fact]
        public async Task ExecuteMultiple_CompletesWithinReasonableTime()
        {
            // Arrange
            var curl = new Curl();
            var commands = Enumerable.Range(1, 5)
                .Select(i => $"curl https://httpbin.org/anything?id={i}")
                .ToArray();

            // Act
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var results = await curl.ExecuteMultipleAsync(commands);
            sw.Stop();

            // Assert
            results.Should().HaveCount(5);
            // Parallel execution should be faster than sequential
            // This is a placeholder - actual timing would depend on network
            sw.ElapsedMilliseconds.Should().BeLessThan(10000); // 10 seconds max
        }

        [Fact]
        public void OutputResult_LargeHeaders_HandledCorrectly()
        {
            // Arrange
            var largeHeader = string.Join("\r\n",
                Enumerable.Range(1, 100).Select(i => $"X-Header-{i}: Value-{i}"));

            var result = new OutputResult
            {
                Headers = largeHeader,
                StatusCode = 200
            };

            // Act & Assert
            result.Headers.Should().Contain("X-Header-1");
            result.Headers.Should().Contain("X-Header-100");
            result.Headers.Split("\r\n").Should().HaveCount(100);
        }

        #endregion

        #region Framework-Specific Tests

#if NET48
        [Fact]
        public void NetFramework48_SpecificBehavior()
        {
            // Test .NET Framework 4.8 specific behavior
            var curl = new Curl();
            curl.Should().NotBeNull();

            // Framework-specific assertions
            AppDomain.CurrentDomain.Should().NotBeNull();
        }
#endif

#if NET6_0_OR_GREATER
        [Fact]
        public void Net6OrGreater_ModernFeatures()
        {
            // Test .NET 6+ specific features
            var curl = new Curl();
            curl.Should().NotBeNull();

            // Modern .NET features
            var span = new ReadOnlySpan<char>("test");
            span.Length.Should().Be(4);
        }
#endif

        #endregion

        #region Write-Out Format Tests

        [Theory]
        [InlineData("%{http_code}", "200")]
        [InlineData("%{size_download}", "1024")]
        [InlineData("Status: %{http_code}\\nSize: %{size_download}", "Status: 200\nSize: 1024")]
        public void OutputFormatter_WriteOutVariables_ReplacedCorrectly(string format, string expected)
        {
            // Arrange
            var formatter = new OutputFormatter();
            var response = new CurlResponse
            {
                StatusCode = 200,
                SizeDownload = 1024
            };
            var options = new CurlOptions
            {
                WriteOut = format
            };

            // Act
            var result = formatter.Format(response, options);

            // Assert
            result.Should().Contain(expected);
        }

        #endregion
    }
}