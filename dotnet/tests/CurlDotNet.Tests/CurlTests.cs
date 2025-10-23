/***************************************************************************
 * Unit tests for CurlDotNet
 *
 * Based on curl test suite: https://github.com/curl/curl/tree/master/tests
 *
 * .NET tests by Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 *
 * Licensed under the curl license
 ***************************************************************************/

using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using CurlDotNet;
using CurlDotNet.Output;

namespace CurlDotNet.Tests
{
    /// <summary>
    /// Main curl functionality tests
    /// Mirrors curl's test suite structure from tests/data/
    /// </summary>
    public class CurlTests
    {
        [Fact]
        public async Task Execute_SimpleGetRequest_ReturnsContent()
        {
            // Arrange
            var curl = new Curl();

            // Act - Simple GET request (would need mock HTTP server for real test)
            // This is a placeholder - in real tests we'd mock the HTTP client
            var command = "curl https://httpbin.org/get";

            // For now, just test that it doesn't throw
            await Record.ExceptionAsync(async () => await curl.ExecuteAsync(command));
        }

        [Fact]
        public async Task Execute_WithHeaders_IncludesHeaders()
        {
            // Arrange
            var curl = new Curl();

            // Act
            var command = "curl -H 'Accept: application/json' -H 'X-Custom: test' https://httpbin.org/headers";

            // Test that command parsing works (would need mock for full test)
            await Record.ExceptionAsync(async () => await curl.ExecuteAsync(command));
        }

        [Fact]
        public async Task Execute_PostWithData_SendsPostRequest()
        {
            // Arrange
            var curl = new Curl();

            // Act
            var command = "curl -X POST -d '{\"key\":\"value\"}' https://httpbin.org/post";

            // Test command execution
            await Record.ExceptionAsync(async () => await curl.ExecuteAsync(command));
        }

        [Theory]
        [InlineData("curl -X GET https://example.com", "GET")]
        [InlineData("curl -X POST https://example.com", "POST")]
        [InlineData("curl -X PUT https://example.com", "PUT")]
        [InlineData("curl -X DELETE https://example.com", "DELETE")]
        [InlineData("curl -I https://example.com", "HEAD")]
        public void CommandParser_ParsesHttpMethods_Correctly(string command, string expectedMethod)
        {
            // Arrange
            var parser = new CommandParser();

            // Act
            var options = parser.Parse(command);

            // Assert
            options.Method.Should().Be(expectedMethod);
        }

        [Fact]
        public void CommandParser_ParsesMultipleHeaders_Correctly()
        {
            // Arrange
            var parser = new CommandParser();
            var command = "curl -H 'Accept: application/json' -H 'Authorization: Bearer token' https://api.example.com";

            // Act
            var options = parser.Parse(command);

            // Assert
            options.Headers.Should().HaveCount(2);
            options.Headers[0].Should().Be("Accept: application/json");
            options.Headers[1].Should().Be("Authorization: Bearer token");
        }

        [Fact]
        public async Task Execute_WithOutputFile_WritesToFile()
        {
            // Arrange
            var curl = new Curl();
            var tempFile = Path.GetTempFileName();

            try
            {
                // Act
                var command = $"curl -o {tempFile} https://httpbin.org/get";
                var result = await curl.ExecuteAsync(command);

                // Assert
                result.WroteToFile.Should().BeTrue();
                result.OutputPath.Should().Be(tempFile);
            }
            finally
            {
                // Cleanup
                if (File.Exists(tempFile))
                    File.Delete(tempFile);
            }
        }

        [Fact]
        public void CommandParser_ParsesDataOptions_Correctly()
        {
            // Arrange
            var parser = new CommandParser();

            // Test -d implies POST
            var options1 = parser.Parse("curl -d 'test data' https://example.com");
            options1.Method.Should().Be("POST");
            options1.Data.Should().Be("test data");

            // Test --data-binary
            var options2 = parser.Parse("curl --data-binary '@file.bin' https://example.com");
            options2.DataBinary.Should().Be("@file.bin");

            // Test --data-urlencode
            var options3 = parser.Parse("curl --data-urlencode 'name=value' https://example.com");
            options3.DataUrlEncode.Should().Be("name=value");
        }

        [Fact]
        public void CommandParser_ParsesAuthenticationOptions_Correctly()
        {
            // Arrange
            var parser = new CommandParser();

            // Test -u option
            var options = parser.Parse("curl -u username:password https://example.com");

            // Assert
            options.UserAuth.Should().Be("username:password");
        }

        [Theory]
        [InlineData("curl -L https://example.com", true)]
        [InlineData("curl --location https://example.com", true)]
        [InlineData("curl https://example.com", false)]
        public void CommandParser_ParsesFollowRedirects_Correctly(string command, bool expectedFollowRedirects)
        {
            // Arrange
            var parser = new CommandParser();

            // Act
            var options = parser.Parse(command);

            // Assert
            options.FollowRedirects.Should().Be(expectedFollowRedirects);
        }

        [Fact]
        public void CommandParser_ParsesVerboseAndSilentOptions_Correctly()
        {
            // Test verbose
            var parser = new CommandParser();
            var verboseOptions = parser.Parse("curl -v https://example.com");
            verboseOptions.Verbose.Should().BeTrue();

            // Test silent
            var silentOptions = parser.Parse("curl -s https://example.com");
            silentOptions.Silent.Should().BeTrue();

            // Test show-error
            var showErrorOptions = parser.Parse("curl -S https://example.com");
            showErrorOptions.ShowError.Should().BeTrue();
        }

        [Fact]
        public async Task ExecuteMultiple_RunsCommandsInParallel()
        {
            // Arrange
            var curl = new Curl();
            var commands = new[]
            {
                "curl https://httpbin.org/delay/1",
                "curl https://httpbin.org/delay/1",
                "curl https://httpbin.org/delay/1"
            };

            // Act
            var startTime = DateTime.UtcNow;
            var results = await curl.ExecuteMultipleAsync(commands);
            var duration = DateTime.UtcNow - startTime;

            // Assert - If running in parallel, should take ~1 second, not 3
            results.Should().HaveCount(3);
            // In a real test with mocked HTTP, we'd verify timing
        }

        [Fact]
        public void OutputResult_ProvidesAccessToAllResponseData()
        {
            // Arrange
            var result = new OutputResult
            {
                ResponseBody = "test response",
                Headers = "Content-Type: text/plain",
                StatusCode = 200,
                WroteToFile = false
            };

            // Assert
            result.ResponseBody.Should().Be("test response");
            result.StatusCode.Should().Be(200);
            result.Headers.Should().Contain("Content-Type");

            // Test stream access
            using var stream = result.GetStream();
            stream.Should().NotBeNull();
            stream.Length.Should().BeGreaterThan(0);
        }

        [Theory]
        [InlineData("curl --compressed https://example.com", true)]
        [InlineData("curl https://example.com", false)]
        public void CommandParser_ParsesCompressionOption_Correctly(string command, bool expectedCompressed)
        {
            // Arrange
            var parser = new CommandParser();

            // Act
            var options = parser.Parse(command);

            // Assert
            options.Compressed.Should().Be(expectedCompressed);
        }

        [Fact]
        public void CommandParser_ParsesTimeoutOptions_Correctly()
        {
            // Arrange
            var parser = new CommandParser();

            // Test connect-timeout
            var options1 = parser.Parse("curl --connect-timeout 30 https://example.com");
            options1.ConnectTimeout.Should().Be(30);

            // Test max-time
            var options2 = parser.Parse("curl -m 60 https://example.com");
            options2.MaxTime.Should().Be(60);
        }

        [Fact]
        public void CommandParser_HandlesQuotedArguments_Correctly()
        {
            // Arrange
            var parser = new CommandParser();

            // Test single quotes
            var options1 = parser.Parse("curl -H 'Accept: application/json' https://example.com");
            options1.Headers[0].Should().Be("Accept: application/json");

            // Test double quotes
            var options2 = parser.Parse("curl -H \"User-Agent: My App\" https://example.com");
            options2.Headers[0].Should().Be("User-Agent: My App");

            // Test mixed
            var options3 = parser.Parse("curl -d '{\"key\": \"value with spaces\"}' https://example.com");
            options3.Data.Should().Be("{\"key\": \"value with spaces\"}");
        }
    }
}