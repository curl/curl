/***************************************************************************
 * Integration tests for CurlDotNet
 *
 * Tests against real endpoints and mock servers
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 * Sponsored by Iron Software (ironsoftware.com)
 ***************************************************************************/

using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using CurlDotNet;
using CurlDotNet.Core;
using Moq;
using Moq.Protected;
using System.Threading;

namespace CurlDotNet.Tests
{
    /// <summary>
    /// Integration tests with mocked HTTP responses
    /// </summary>
    public class IntegrationTests : IDisposable
    {
        private readonly string _tempDirectory;

        public IntegrationTests()
        {
            _tempDirectory = Path.Combine(Path.GetTempPath(), $"CurlDotNet_Tests_{Guid.NewGuid()}");
            Directory.CreateDirectory(_tempDirectory);
        }

        public void Dispose()
        {
            if (Directory.Exists(_tempDirectory))
            {
                Directory.Delete(_tempDirectory, true);
            }
        }

        #region Mocked HTTP Tests

        [Fact]
        public async Task Execute_GetRequest_ReturnsMockedResponse()
        {
            // Arrange
            var mockHandler = CreateMockHttpHandler(
                HttpStatusCode.OK,
                "{\"message\": \"Hello World\"}",
                "application/json");

            var httpClient = new HttpClient(mockHandler.Object);
            var curl = new CurlEngine(httpClient);

            // Act
            var result = await curl.ExecuteAsync("curl https://api.example.com/test");

            // Assert
            result.StatusCode.Should().Be(200);
            result.Body.Should().Contain("Hello World");
        }

        [Fact]
        public async Task Execute_PostRequest_SendsCorrectData()
        {
            // Arrange
            string capturedContent = null;
            var mockHandler = new Mock<HttpMessageHandler>();

            mockHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>(async (request, token) =>
                {
                    if (request.Content != null)
                    {
                        capturedContent = await request.Content.ReadAsStringAsync();
                    }
                })
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.Created,
                    Content = new StringContent("{\"id\": 123}")
                });

            var httpClient = new HttpClient(mockHandler.Object);
            var curl = new CurlEngine(httpClient);

            // Act
            var result = await curl.ExecuteAsync(
                "curl -X POST -d '{\"name\":\"test\"}' https://api.example.com/users");

            // Assert
            result.StatusCode.Should().Be(201);
            capturedContent.Should().Be("{\"name\":\"test\"}");
        }

        [Fact]
        public async Task Execute_WithHeaders_SendsHeadersCorrectly()
        {
            // Arrange
            var capturedHeaders = new System.Collections.Generic.Dictionary<string, string>();
            var mockHandler = new Mock<HttpMessageHandler>();

            mockHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((request, token) =>
                {
                    foreach (var header in request.Headers)
                    {
                        capturedHeaders[header.Key] = string.Join(",", header.Value);
                    }
                })
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("OK")
                });

            var httpClient = new HttpClient(mockHandler.Object);
            var curl = new CurlEngine(httpClient);

            // Act
            await curl.ExecuteAsync(
                "curl -H 'X-API-Key: secret123' -H 'Accept: application/json' https://api.example.com");

            // Assert
            capturedHeaders.Should().ContainKey("X-API-Key");
            capturedHeaders["X-API-Key"].Should().Be("secret123");
            capturedHeaders.Should().ContainKey("Accept");
            capturedHeaders["Accept"].Should().Be("application/json");
        }

        [Fact]
        public async Task Execute_WithAuthentication_SendsAuthHeader()
        {
            // Arrange
            string authHeader = null;
            var mockHandler = new Mock<HttpMessageHandler>();

            mockHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((request, token) =>
                {
                    authHeader = request.Headers.Authorization?.ToString();
                })
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("Authorized")
                });

            var httpClient = new HttpClient(mockHandler.Object);
            var curl = new CurlEngine(httpClient);

            // Act
            await curl.ExecuteAsync("curl -u user:pass https://api.example.com/secure");

            // Assert
            authHeader.Should().NotBeNull();
            authHeader.Should().StartWith("Basic ");
            var decoded = Encoding.ASCII.GetString(
                Convert.FromBase64String(authHeader.Substring(6)));
            decoded.Should().Be("user:pass");
        }

        #endregion

        #region File Operation Tests

        [Fact]
        public async Task Execute_OutputToFile_CreatesFile()
        {
            // Arrange
            var outputFile = Path.Combine(_tempDirectory, "output.json");
            var mockHandler = CreateMockHttpHandler(
                HttpStatusCode.OK,
                "{\"test\": \"data\"}",
                "application/json");

            var httpClient = new HttpClient(mockHandler.Object);
            var curl = new CurlEngine(httpClient);

            // Act
            var result = await curl.ExecuteAsync($"curl -o {outputFile} https://api.example.com/data");

            // Assert
            result.OutputFiles.Should().Contain(outputFile);
            File.Exists(outputFile).Should().BeTrue();

            var content = await File.ReadAllTextAsync(outputFile);
            content.Should().Contain("test");
        }

        [Fact]
        public async Task Execute_UseRemoteFileName_CreatesFileWithCorrectName()
        {
            // Arrange
            Directory.SetCurrentDirectory(_tempDirectory);
            var mockHandler = CreateMockHttpHandler(
                HttpStatusCode.OK,
                "File content",
                "text/plain");

            var httpClient = new HttpClient(mockHandler.Object);
            var curl = new CurlEngine(httpClient);

            // Act
            var result = await curl.ExecuteAsync("curl -O https://example.com/document.txt");

            // Assert
            result.OutputFiles.Should().NotBeEmpty();
            var expectedFile = Path.Combine(_tempDirectory, "document.txt");
            File.Exists(expectedFile).Should().BeTrue();
        }

        [Fact]
        public async Task Execute_FileProtocol_ReadsLocalFile()
        {
            // Arrange
            var testFile = Path.Combine(_tempDirectory, "test.txt");
            var testContent = "Local file content";
            await File.WriteAllTextAsync(testFile, testContent);

            var curl = new CurlEngine();

            // Act
            var result = await curl.ExecuteAsync($"curl file://{testFile}");

            // Assert
            result.StatusCode.Should().Be(200);
            result.Body.Should().Be(testContent);
        }

        [Fact]
        public async Task Execute_FileProtocol_NonExistentFile_Returns404()
        {
            // Arrange
            var curl = new CurlEngine();
            var nonExistentFile = Path.Combine(_tempDirectory, "does-not-exist.txt");

            // Act
            var result = await curl.ExecuteAsync($"curl file://{nonExistentFile}");

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.StatusCode.Should().Be(404);
        }

        #endregion

        #region Error Handling Tests

        [Fact]
        public async Task Execute_FailFlag_With4xxError_ReturnsError()
        {
            // Arrange
            var mockHandler = CreateMockHttpHandler(
                HttpStatusCode.NotFound,
                "Not Found",
                "text/plain");

            var httpClient = new HttpClient(mockHandler.Object);
            var curl = new CurlEngine(httpClient);

            // Act
            var result = await curl.ExecuteAsync("curl -f https://api.example.com/missing");

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.StatusCode.Should().Be(404);
        }

        [Fact]
        public async Task Execute_Timeout_ReturnsTimeoutError()
        {
            // Arrange
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ThrowsAsync(new TaskCanceledException());

            var httpClient = new HttpClient(mockHandler.Object);
            var curl = new CurlEngine(httpClient);

            // Act
            var result = await curl.ExecuteAsync("curl --connect-timeout 1 https://api.example.com/slow");

            // Assert
            result.IsSuccess.Should().BeFalse();
            // Timeout should result in an error status
        }

        #endregion

        #region Response Format Tests

        [Fact]
        public async Task Execute_IncludeHeaders_ReturnsHeadersInOutput()
        {
            // Arrange
            var mockHandler = CreateMockHttpHandler(
                HttpStatusCode.OK,
                "Response body",
                "text/plain",
                new[] { ("X-Custom-Header", "CustomValue") });

            var httpClient = new HttpClient(mockHandler.Object);
            var curl = new CurlEngine(httpClient);

            // Act
            var result = await curl.ExecuteAsync("curl -i https://api.example.com");

            // Assert
            result.Body.Should().Contain("HTTP/");
            result.Body.Should().Contain("200");
            result.Headers.Should().ContainKey("X-Custom-Header");
        }

        [Fact]
        public async Task Execute_Verbose_IncludesDetailedOutput()
        {
            // Arrange
            var mockHandler = CreateMockHttpHandler(
                HttpStatusCode.OK,
                "OK",
                "text/plain");

            var httpClient = new HttpClient(mockHandler.Object);
            var curl = new CurlEngine(httpClient);

            // Act
            var result = await curl.ExecuteAsync("curl -v https://api.example.com");

            // Assert
            result.Body.Should().Contain("* Trying");
            result.Body.Should().Contain("> GET");
            result.Body.Should().Contain("< HTTP/");
        }

        [Fact]
        public async Task Execute_WriteOut_FormatsOutput()
        {
            // Arrange
            var mockHandler = CreateMockHttpHandler(
                HttpStatusCode.OK,
                "Response",
                "text/plain");

            var httpClient = new HttpClient(mockHandler.Object);
            var curl = new CurlEngine(httpClient);

            // Act
            var result = await curl.ExecuteAsync(
                "curl -w '\\nCode: %{http_code}\\nSize: %{size_download}' https://api.example.com");

            // Assert
            result.Body.Should().Contain("Code: 200");
            result.Body.Should().Contain("Size: ");
        }

        #endregion

        #region Helper Methods

        private Mock<HttpMessageHandler> CreateMockHttpHandler(
            HttpStatusCode statusCode,
            string content,
            string contentType,
            (string, string)[] additionalHeaders = null)
        {
            var mockHandler = new Mock<HttpMessageHandler>();
            var response = new HttpResponseMessage
            {
                StatusCode = statusCode,
                Content = new StringContent(content, Encoding.UTF8, contentType)
            };

            if (additionalHeaders != null)
            {
                foreach (var (key, value) in additionalHeaders)
                {
                    response.Headers.TryAddWithoutValidation(key, value);
                }
            }

            mockHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(response);

            return mockHandler;
        }

        #endregion
    }
}