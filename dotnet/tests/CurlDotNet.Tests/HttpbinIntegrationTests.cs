using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using CurlDotNet;
using CurlDotNet.Exceptions;

namespace CurlDotNet.Tests
{
    /// <summary>
    /// Integration tests using httpbin.org - a service for testing HTTP requests.
    /// These tests require internet connectivity.
    /// </summary>
    /// <remarks>
    /// <para>httpbin.org is a popular service for testing HTTP clients.</para>
    /// <para>These tests verify real-world HTTP functionality.</para>
    /// <para>AI-Usage: These tests demonstrate actual curl usage patterns with a real API.</para>
    /// <para>Note: Tests may fail if httpbin.org is down or rate-limited.</para>
    /// </remarks>
    [Trait("Category", TestCategories.Integration)]
    [Trait("Category", TestCategories.Http)]
    [Collection("HttpbinIntegration")] // Prevents parallel execution to avoid rate limiting
    public class HttpbinIntegrationTests : CurlTestBase, IClassFixture<HttpbinIntegrationTests.HttpbinFixture>
    {
        private readonly string _httpbinUrl;

        public HttpbinIntegrationTests(ITestOutputHelper output, HttpbinFixture fixture) : base(output)
        {
            _httpbinUrl = fixture.HttpbinUrl;
            Output.WriteLine($"Using httpbin endpoint: {_httpbinUrl}");
        }

        #region GET Tests

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Get_SimpleRequest_ShouldReturnSuccess()
        {
            // Arrange
            var command = $"curl {_httpbinUrl}/get";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            result.Should().NotBeNull();
            result.Body.Should().Contain("\"url\":");
            result.Body.Should().Contain($"{_httpbinUrl}/get");

            // Parse JSON response
            var json = JsonDocument.Parse(result.Body);
            json.RootElement.GetProperty("url").GetString().Should().Be($"{_httpbinUrl}/get");
        }

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Get_WithQueryParameters_ShouldIncludeInResponse()
        {
            // Arrange
            var command = $"curl \"{_httpbinUrl}/get?param1=value1&param2=value2\"";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            var json = JsonDocument.Parse(result.Body);
            var args = json.RootElement.GetProperty("args");

            args.GetProperty("param1").GetString().Should().Be("value1");
            args.GetProperty("param2").GetString().Should().Be("value2");
        }

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Get_WithCustomHeaders_ShouldReflectHeaders()
        {
            // Arrange
            var command = $@"curl -H 'X-Custom-Header: CustomValue' -H 'Accept: application/json' {_httpbinUrl}/headers";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            var json = JsonDocument.Parse(result.Body);
            var headers = json.RootElement.GetProperty("headers");

            headers.GetProperty("X-Custom-Header").GetString().Should().Be("CustomValue");
            headers.GetProperty("Accept").GetString().Should().Be("application/json");
        }

        #endregion

        #region POST Tests

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Post_WithJsonData_ShouldEchoBack()
        {
            // Arrange
            var jsonData = "{\"name\":\"test\",\"value\":123}";
            var command = $@"curl -X POST -H 'Content-Type: application/json' -d '{jsonData}' {_httpbinUrl}/post";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            var json = JsonDocument.Parse(result.Body);

            // httpbin echoes back the posted data
            var data = json.RootElement.GetProperty("data").GetString();
            data.Should().Be(jsonData);

            var contentType = json.RootElement.GetProperty("headers").GetProperty("Content-Type").GetString();
            contentType.Should().Be("application/json");
        }

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Post_FormData_ShouldParseCorrectly()
        {
            // Arrange
            var command = $@"curl -X POST -d 'field1=value1&field2=value2' {_httpbinUrl}/post";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            var json = JsonDocument.Parse(result.Body);
            var form = json.RootElement.GetProperty("form");

            form.GetProperty("field1").GetString().Should().Be("value1");
            form.GetProperty("field2").GetString().Should().Be("value2");
        }

        #endregion

        #region PUT/DELETE Tests

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Put_WithData_ShouldWork()
        {
            // Arrange
            var command = $@"curl -X PUT -d 'updated=true' {_httpbinUrl}/put";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            var json = JsonDocument.Parse(result.Body);
            json.RootElement.GetProperty("form").GetProperty("updated").GetString().Should().Be("true");
        }

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Delete_Request_ShouldWork()
        {
            // Arrange
            var command = $@"curl -X DELETE {_httpbinUrl}/delete";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            result.Body.Should().Contain("\"url\":");
            result.Body.Should().Contain("/delete");
        }

        #endregion

        #region Authentication Tests

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task BasicAuth_WithCredentials_ShouldAuthenticate()
        {
            // Arrange
            var command = $@"curl -u testuser:testpass {_httpbinUrl}/basic-auth/testuser/testpass";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            var json = JsonDocument.Parse(result.Body);
            json.RootElement.GetProperty("authenticated").GetBoolean().Should().BeTrue();
            json.RootElement.GetProperty("user").GetString().Should().Be("testuser");
        }

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task BearerAuth_WithToken_ShouldWork()
        {
            // Arrange
            var command = $@"curl -H 'Authorization: Bearer test-token-123' {_httpbinUrl}/bearer";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            var json = JsonDocument.Parse(result.Body);
            json.RootElement.GetProperty("authenticated").GetBoolean().Should().BeTrue();
            json.RootElement.GetProperty("token").GetString().Should().Be("test-token-123");
        }

        #endregion

        #region Status Code Tests

        [Theory]
        [InlineData(200)]
        [InlineData(201)]
        [InlineData(204)]
        [InlineData(301)]
        [InlineData(400)]
        [InlineData(404)]
        [InlineData(500)]
        [Trait("OnlineRequired", "true")]
        public async Task StatusCode_Various_ShouldReturnCorrectCode(int statusCode)
        {
            // Arrange
            var command = $@"curl -i {_httpbinUrl}/status/{statusCode}";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            result.Body.Should().Contain($"HTTP/1.1 {statusCode}");
        }

        #endregion

        #region Redirect Tests

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Redirect_WithoutFollow_ShouldReturn302()
        {
            // Arrange
            var command = $@"curl -i {_httpbinUrl}/redirect/1";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            result.Body.Should().Contain("HTTP/1.1 302");
            result.Body.Should().Contain("Location:");
        }

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Redirect_WithFollow_ShouldFollowRedirect()
        {
            // Arrange
            var command = $@"curl -L {_httpbinUrl}/redirect/1";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            // Should get the final destination content
            var json = JsonDocument.Parse(result.Body);
            json.RootElement.GetProperty("url").GetString().Should().Contain("/get");
        }

        #endregion

        #region Cookie Tests

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Cookies_SetAndGet_ShouldWork()
        {
            // Arrange - First set a cookie
            var setCookieCommand = $@"curl {_httpbinUrl}/cookies/set?testcookie=testvalue";

            // Act - Follow redirect to see the cookie
            var result = await Curl.ExecuteAsync($@"curl -L -b 'testcookie=testvalue' {_httpbinUrl}/cookies");

            // Assert
            var json = JsonDocument.Parse(result.Body);
            var cookies = json.RootElement.GetProperty("cookies");
            cookies.GetProperty("testcookie").GetString().Should().Be("testvalue");
        }

        #endregion

        #region User Agent Tests

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task UserAgent_Custom_ShouldBeReflected()
        {
            // Arrange
            var command = $@"curl -A 'CurlDotNet/1.0 Testing' {_httpbinUrl}/user-agent";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            var json = JsonDocument.Parse(result.Body);
            json.RootElement.GetProperty("user-agent").GetString().Should().Be("CurlDotNet/1.0 Testing");
        }

        #endregion

        #region Compression Tests

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Compression_Gzip_ShouldWork()
        {
            // Arrange
            var command = $@"curl --compressed {_httpbinUrl}/gzip";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            var json = JsonDocument.Parse(result.Body);
            json.RootElement.GetProperty("gzipped").GetBoolean().Should().BeTrue();
        }

        #endregion

        #region Delay/Timeout Tests

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Delay_WithinTimeout_ShouldComplete()
        {
            // Arrange - 1 second delay with 5 second timeout
            var command = $@"curl --max-time 5 {_httpbinUrl}/delay/1";

            // Act
            var result = await Curl.ExecuteAsync(command);

            // Assert
            result.Should().NotBeNull();
            var json = JsonDocument.Parse(result.Body);
            json.RootElement.GetProperty("url").GetString().Should().Contain("/delay/1");
        }

        [Fact]
        [Trait("OnlineRequired", "true")]
        public async Task Delay_ExceedsTimeout_ShouldThrow()
        {
            // Arrange - 3 second delay with 1 second timeout
            var command = $@"curl --max-time 1 {_httpbinUrl}/delay/3";

            // Act & Assert
            await Assert.ThrowsAsync<CurlTimeoutException>(
                () => Curl.ExecuteAsync(command));
        }

        #endregion

        #region Fixtures

        public class HttpbinFixture : IDisposable
        {
            public string HttpbinUrl { get; }

            public HttpbinFixture()
            {
                // Use httpbin.org by default, but allow override via environment variable
                // This allows using a local httpbin instance for faster testing
                HttpbinUrl = Environment.GetEnvironmentVariable("HTTPBIN_URL") ?? "https://httpbin.org";
            }

            public void Dispose()
            {
                // Cleanup if needed
            }
        }

        #endregion
    }
}