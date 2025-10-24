using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using Moq;
using Moq.Protected;
using CurlDotNet.Core;
using CurlDotNet.Exceptions;

namespace CurlDotNet.Tests
{
    /// <summary>
    /// Unit tests for the HttpHandler class.
    /// Tests HTTP/HTTPS protocol handling.
    /// </summary>
    /// <remarks>
    /// <para>These tests verify HTTP request formation, response handling, and error conditions.</para>
    /// <para>Uses Moq to mock HttpMessageHandler for isolated testing.</para>
    /// <para>AI-Usage: These tests demonstrate all HTTP features supported by CurlDotNet.</para>
    /// </remarks>
    [Trait("Category", TestCategories.Http)]
    [Trait("Category", TestCategories.Synthetic)]
    public class HttpHandlerTests : CurlTestBase
    {
        private readonly Mock<HttpMessageHandler> _mockHttpMessageHandler;
        private readonly HttpClient _httpClient;
        private readonly HttpHandler _handler;

        public HttpHandlerTests(ITestOutputHelper output) : base(output)
        {
            _mockHttpMessageHandler = new Mock<HttpMessageHandler>();
            _httpClient = new HttpClient(_mockHttpMessageHandler.Object);
            _handler = new HttpHandler();
        }

        #region GET Request Tests

        [Fact]
        public async Task ExecuteAsync_SimpleGet_ShouldReturnResponse()
        {
            // Arrange
            var options = new CurlOptions
            {
                Url = "https://api.example.com/users"
            };

            var responseContent = "{\"users\": [{\"id\": 1, \"name\": \"John\"}]}";
            SetupHttpResponse(HttpStatusCode.OK, responseContent);

            // Act
            var response = await _handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            response.Should().NotBeNull();
            response.StatusCode.Should().Be((int)HttpStatusCode.OK);
            response.Body.Should().Be(responseContent);
            response.IsSuccess.Should().BeTrue();
        }

        [Fact]
        public async Task ExecuteAsync_GetWithHeaders_ShouldIncludeHeaders()
        {
            // Arrange
            var options = new CurlOptions
            {
                Url = "https://api.example.com/data",
                Headers = new Dictionary<string, string>
                {
                    ["Accept"] = "application/json",
                    ["Authorization"] = "Bearer token123"
                }
            };

            HttpRequestMessage capturedRequest = null;
            SetupHttpResponse(HttpStatusCode.OK, "[]", req => capturedRequest = req);

            // Act
            await _handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            capturedRequest.Should().NotBeNull();
            capturedRequest.Headers.Accept.ToString().Should().Contain("application/json");
            capturedRequest.Headers.Authorization.ToString().Should().Be("Bearer token123");
        }

        #endregion

        #region POST Request Tests

        [Fact]
        public async Task ExecuteAsync_PostWithData_ShouldSendBody()
        {
            // Arrange
            var postData = "{\"name\": \"Test User\", \"email\": \"test@example.com\"}";
            var options = new CurlOptions
            {
                Url = "https://api.example.com/users",
                Method = "POST",
                Data = postData,
                Headers = new Dictionary<string, string>
                {
                    ["Content-Type"] = "application/json"
                }
            };

            HttpRequestMessage capturedRequest = null;
            string capturedBody = null;
            SetupHttpResponse(HttpStatusCode.Created, "{\"id\": 123}", async req =>
            {
                capturedRequest = req;
                capturedBody = await req.Content.ReadAsStringAsync();
            });

            // Act
            var response = await _handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            capturedRequest.Method.Should().Be(HttpMethod.Post);
            capturedBody.Should().Be(postData);
            capturedRequest.Content.Headers.ContentType.MediaType.Should().Be("application/json");
            response.StatusCode.Should().Be((int)HttpStatusCode.Created);
        }

        [Fact]
        public async Task ExecuteAsync_PostFormData_ShouldEncodeCorrectly()
        {
            // Arrange
            var options = new CurlOptions
            {
                Url = "https://api.example.com/form",
                Method = "POST",
                Data = "field1=value1&field2=value%20with%20spaces",
                Headers = new Dictionary<string, string>
                {
                    ["Content-Type"] = "application/x-www-form-urlencoded"
                }
            };

            string capturedBody = null;
            SetupHttpResponse(HttpStatusCode.OK, "success", async req =>
            {
                capturedBody = await req.Content.ReadAsStringAsync();
            });

            // Act
            await _handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            capturedBody.Should().Contain("field1=value1");
            capturedBody.Should().Contain("field2=value%20with%20spaces");
        }

        #endregion

        #region HTTP Methods Tests

        [Theory]
        [InlineData("GET", typeof(HttpMethod))]
        [InlineData("POST", typeof(HttpMethod))]
        [InlineData("PUT", typeof(HttpMethod))]
        [InlineData("DELETE", typeof(HttpMethod))]
        [InlineData("PATCH", typeof(HttpMethod))]
        [InlineData("HEAD", typeof(HttpMethod))]
        [InlineData("OPTIONS", typeof(HttpMethod))]
        public async Task ExecuteAsync_VariousMethods_ShouldUseCorrectHttpMethod(string method, Type _)
        {
            // Arrange
            var options = new CurlOptions
            {
                Url = "https://api.example.com/resource",
                Method = method
            };

            HttpRequestMessage capturedRequest = null;
            SetupHttpResponse(HttpStatusCode.OK, "", req => capturedRequest = req);

            // Act
            await _handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            capturedRequest.Method.Method.Should().Be(method);
        }

        #endregion

        #region Authentication Tests

        [Fact]
        public async Task ExecuteAsync_BasicAuth_ShouldAddAuthHeader()
        {
            // Arrange
            var options = new CurlOptions
            {
                Url = "https://api.example.com/secure",
                UserAuth = new NetworkCredential("username", "password")
            };

            HttpRequestMessage capturedRequest = null;
            SetupHttpResponse(HttpStatusCode.OK, "", req => capturedRequest = req);

            // Act
            await _handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            capturedRequest.Headers.Authorization.Should().NotBeNull();
            capturedRequest.Headers.Authorization.Scheme.Should().Be("Basic");

            // Verify base64 encoding
            var expectedAuth = Convert.ToBase64String(Encoding.UTF8.GetBytes("username:password"));
            capturedRequest.Headers.Authorization.Parameter.Should().Be(expectedAuth);
        }

        [Fact]
        public async Task ExecuteAsync_BearerToken_ShouldAddBearerHeader()
        {
            // Arrange
            var options = new CurlOptions
            {
                Url = "https://api.example.com/api",
                Headers = new Dictionary<string, string>
                {
                    ["Authorization"] = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                }
            };

            HttpRequestMessage capturedRequest = null;
            SetupHttpResponse(HttpStatusCode.OK, "", req => capturedRequest = req);

            // Act
            await _handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            capturedRequest.Headers.Authorization.Scheme.Should().Be("Bearer");
            capturedRequest.Headers.Authorization.Parameter.Should().StartWith("eyJ");
        }

        #endregion

        #region Error Handling Tests

        [Fact]
        public async Task ExecuteAsync_404NotFound_ShouldReturnError()
        {
            // Arrange
            var options = new CurlOptions
            {
                Url = "https://api.example.com/missing"
            };

            SetupHttpResponse(HttpStatusCode.NotFound, "Not Found");

            // Act
            var response = await _handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            response.StatusCode.Should().Be(404);
            response.IsSuccess.Should().BeFalse();
            response.Body.Should().Be("Not Found");
        }

        [Fact]
        public async Task ExecuteAsync_500ServerError_ShouldReturnError()
        {
            // Arrange
            var options = new CurlOptions
            {
                Url = "https://api.example.com/error"
            };

            SetupHttpResponse(HttpStatusCode.InternalServerError, "Internal Server Error");

            // Act
            var response = await _handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            response.StatusCode.Should().Be(500);
            response.IsSuccess.Should().BeFalse();
        }

        [Fact]
        public async Task ExecuteAsync_Timeout_ShouldThrowTimeoutException()
        {
            // Arrange
            var options = new CurlOptions
            {
                Url = "https://api.example.com/slow",
                MaxTime = 1 // 1 second timeout
            };

            _mockHttpMessageHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ThrowsAsync(new TaskCanceledException());

            // Act & Assert
            await Assert.ThrowsAsync<CurlTimeoutException>(
                () => _handler.ExecuteAsync(options, CancellationToken.None));
        }

        #endregion

        #region Response Headers Tests

        [Fact]
        public async Task ExecuteAsync_ResponseHeaders_ShouldCaptureAll()
        {
            // Arrange
            var options = new CurlOptions
            {
                Url = "https://api.example.com/data"
            };

            var responseHeaders = new Dictionary<string, string>
            {
                ["Content-Type"] = "application/json",
                ["X-Custom-Header"] = "custom-value",
                ["Cache-Control"] = "no-cache"
            };

            SetupHttpResponse(HttpStatusCode.OK, "{}", headers: responseHeaders);

            // Act
            var response = await _handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            response.Headers.Should().ContainKey("Content-Type");
            response.Headers["Content-Type"].Should().Be("application/json");
            response.Headers.Should().ContainKey("X-Custom-Header");
            response.Headers["X-Custom-Header"].Should().Be("custom-value");
        }

        #endregion

        #region Binary Data Tests

        [Fact]
        public async Task ExecuteAsync_BinaryResponse_ShouldHandleCorrectly()
        {
            // Arrange
            var options = new CurlOptions
            {
                Url = "https://api.example.com/file.bin"
            };

            var binaryData = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }; // PNG header
            SetupHttpResponse(HttpStatusCode.OK, binaryData);

            // Act
            var response = await _handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            response.IsBinary.Should().BeTrue();
            response.BinaryData.Should().Equal(binaryData);
            response.Body.Should().BeNullOrEmpty(); // Binary data should not be in Body
        }

        #endregion

        #region User Agent Tests

        [Fact]
        public async Task ExecuteAsync_CustomUserAgent_ShouldBeSet()
        {
            // Arrange
            var options = new CurlOptions
            {
                Url = "https://api.example.com/",
                UserAgent = "CurlDotNet/1.0 TestAgent"
            };

            HttpRequestMessage capturedRequest = null;
            SetupHttpResponse(HttpStatusCode.OK, "", req => capturedRequest = req);

            // Act
            await _handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            capturedRequest.Headers.UserAgent.ToString().Should().Contain("CurlDotNet/1.0 TestAgent");
        }

        #endregion

        #region Helper Methods

        private void SetupHttpResponse(
            HttpStatusCode statusCode,
            string content,
            Action<HttpRequestMessage> callback = null,
            Dictionary<string, string> headers = null)
        {
            var response = new HttpResponseMessage(statusCode)
            {
                Content = new StringContent(content)
            };

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    response.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            _mockHttpMessageHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync((HttpRequestMessage request, CancellationToken token) =>
                {
                    callback?.Invoke(request);
                    return response;
                });
        }

        private void SetupHttpResponse(HttpStatusCode statusCode, byte[] binaryContent)
        {
            var response = new HttpResponseMessage(statusCode)
            {
                Content = new ByteArrayContent(binaryContent)
            };

            response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

            _mockHttpMessageHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(response);
        }

        #endregion
    }
}