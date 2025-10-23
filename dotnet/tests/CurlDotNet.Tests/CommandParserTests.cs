using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using CurlDotNet;
using CurlDotNet.Options;

namespace CurlDotNet.Tests
{
    /// <summary>
    /// Unit tests for the CommandParser class.
    /// Tests parsing of curl command strings into CurlOptions.
    /// </summary>
    /// <remarks>
    /// <para>These tests verify that curl commands are correctly parsed into options.</para>
    /// <para>Tests are based on curl's tool_getparam.c behavior.</para>
    /// <para>AI-Usage: These tests demonstrate all supported curl command formats.</para>
    /// </remarks>
    [Trait("Category", TestCategories.CurlUnit)]
    [Trait("Category", TestCategories.Parser)]
    public class CommandParserTests : CurlTestBase
    {
        private readonly CommandParser _parser;

        public CommandParserTests(ITestOutputHelper output) : base(output)
        {
            _parser = new CommandParser();
        }

        #region Basic URL Parsing

        /// <summary>
        /// Tests parsing of a simple URL without any options.
        /// </summary>
        [Fact]
        public void Parse_SimpleUrl_ShouldSetUrl()
        {
            // Arrange
            const string command = "curl https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Should().NotBeNull();
            options.Url.Should().Be("https://example.com");
            options.Method.Should().BeNull(); // Default is GET
        }

        /// <summary>
        /// Tests that the 'curl' prefix is optional.
        /// </summary>
        [Theory]
        [InlineData("curl https://example.com")]
        [InlineData("https://example.com")]
        [InlineData("CURL https://example.com")]
        public void Parse_OptionalCurlPrefix_ShouldWork(string command)
        {
            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Url.Should().Be("https://example.com");
        }

        /// <summary>
        /// Tests parsing URLs with special characters.
        /// </summary>
        [Theory]
        [InlineData("https://example.com/path?query=value&another=test")]
        [InlineData("https://user:pass@example.com:8080/path")]
        [InlineData("ftp://ftp.example.com/file.txt")]
        [InlineData("file:///local/path/to/file.txt")]
        public void Parse_SpecialUrls_ShouldPreserveFormat(string url)
        {
            // Arrange
            var command = $"curl {url}";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Url.Should().Be(url);
        }

        #endregion

        #region HTTP Method Tests

        /// <summary>
        /// Tests parsing of HTTP methods using -X/--request.
        /// </summary>
        [Theory]
        [InlineData("-X GET", "GET")]
        [InlineData("-X POST", "POST")]
        [InlineData("-X PUT", "PUT")]
        [InlineData("-X DELETE", "DELETE")]
        [InlineData("-X PATCH", "PATCH")]
        [InlineData("-X HEAD", "HEAD")]
        [InlineData("-X OPTIONS", "OPTIONS")]
        [InlineData("--request GET", "GET")]
        [InlineData("--request POST", "POST")]
        public void Parse_HttpMethod_ShouldSetMethod(string methodFlag, string expectedMethod)
        {
            // Arrange
            var command = $"curl {methodFlag} https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Method.Should().Be(expectedMethod);
        }

        /// <summary>
        /// Tests HEAD request shortcuts.
        /// </summary>
        [Theory]
        [InlineData("-I")]
        [InlineData("--head")]
        public void Parse_HeadShortcuts_ShouldSetHeadMethod(string flag)
        {
            // Arrange
            var command = $"curl {flag} https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Method.Should().Be("HEAD");
        }

        #endregion

        #region Header Tests

        /// <summary>
        /// Tests parsing of custom headers.
        /// </summary>
        [Fact]
        public void Parse_SingleHeader_ShouldAddToHeaders()
        {
            // Arrange
            const string command = "curl -H 'Accept: application/json' https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Headers.Should().ContainSingle();
            options.Headers.Should().ContainKey("Accept");
            options.Headers["Accept"].Should().Be("application/json");
        }

        /// <summary>
        /// Tests parsing of multiple headers.
        /// </summary>
        [Fact]
        public void Parse_MultipleHeaders_ShouldAddAllHeaders()
        {
            // Arrange
            const string command = @"curl -H 'Accept: application/json' -H 'Authorization: Bearer token123' -H 'Content-Type: application/json' https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Headers.Should().HaveCount(3);
            options.Headers["Accept"].Should().Be("application/json");
            options.Headers["Authorization"].Should().Be("Bearer token123");
            options.Headers["Content-Type"].Should().Be("application/json");
        }

        /// <summary>
        /// Tests header formats with different quote styles.
        /// </summary>
        [Theory]
        [InlineData("-H 'Accept: application/json'", "Accept", "application/json")]
        [InlineData("-H \"Accept: application/json\"", "Accept", "application/json")]
        [InlineData("--header 'Accept: application/json'", "Accept", "application/json")]
        [InlineData("-H Accept:application/json", "Accept", "application/json")]
        public void Parse_HeaderFormats_ShouldParseCorrectly(string headerFlag, string expectedKey, string expectedValue)
        {
            // Arrange
            var command = $"curl {headerFlag} https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Headers.Should().ContainKey(expectedKey);
            options.Headers[expectedKey].Should().Be(expectedValue);
        }

        #endregion

        #region Data/Body Tests

        /// <summary>
        /// Tests parsing of POST data.
        /// </summary>
        [Theory]
        [InlineData("-d", "key=value")]
        [InlineData("--data", "key=value")]
        [InlineData("--data-raw", "{\"json\":\"data\"}")]
        [InlineData("--data-binary", "@file.bin")]
        public void Parse_PostData_ShouldSetData(string dataFlag, string data)
        {
            // Arrange
            var command = $"curl {dataFlag} '{data}' https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Data.Should().Be(data);
            // If -d is used without explicit method, it should default to POST
            if (!options.Method.HasValue() && dataFlag.StartsWith("-d"))
            {
                options.Method.Should().Be("POST");
            }
        }

        /// <summary>
        /// Tests URL encoding option.
        /// </summary>
        [Fact]
        public void Parse_DataUrlEncode_ShouldSetUrlEncodeFlag()
        {
            // Arrange
            const string command = "curl --data-urlencode 'name=John Doe' https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.DataUrlEncode.Should().BeTrue();
            options.Data.Should().Be("name=John Doe");
        }

        #endregion

        #region Authentication Tests

        /// <summary>
        /// Tests parsing of basic authentication.
        /// </summary>
        [Theory]
        [InlineData("-u user:pass", "user:pass")]
        [InlineData("--user admin:secret", "admin:secret")]
        [InlineData("-u 'domain\\user:pass'", "domain\\user:pass")]
        public void Parse_BasicAuth_ShouldSetUserAuth(string authFlag, string expectedAuth)
        {
            // Arrange
            var command = $"curl {authFlag} https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.UserAuth.Should().Be(expectedAuth);
        }

        /// <summary>
        /// Tests parsing of bearer token.
        /// </summary>
        [Fact]
        public void Parse_BearerToken_ShouldAddAuthHeader()
        {
            // Arrange
            const string command = "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Headers.Should().ContainKey("Authorization");
            options.Headers["Authorization"].Should().StartWith("Bearer ");
        }

        #endregion

        #region Output Options Tests

        /// <summary>
        /// Tests output file options.
        /// </summary>
        [Theory]
        [InlineData("-o output.txt", "output.txt", false)]
        [InlineData("--output /tmp/file.json", "/tmp/file.json", false)]
        [InlineData("-O", null, true)]
        [InlineData("--remote-name", null, true)]
        public void Parse_OutputOptions_ShouldSetCorrectly(string outputFlag, string expectedFile, bool useRemoteName)
        {
            // Arrange
            var command = $"curl {outputFlag} https://example.com/file.txt";

            // Act
            var options = _parser.Parse(command);

            // Assert
            if (expectedFile != null)
            {
                options.OutputFile.Should().Be(expectedFile);
            }
            options.UseRemoteFileName.Should().Be(useRemoteName);
        }

        #endregion

        #region Behavior Options Tests

        /// <summary>
        /// Tests follow redirects option.
        /// </summary>
        [Theory]
        [InlineData("-L", true)]
        [InlineData("--location", true)]
        [InlineData("", false)]
        public void Parse_FollowRedirects_ShouldSetCorrectly(string flag, bool expected)
        {
            // Arrange
            var command = $"curl {flag} https://example.com".Trim();

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.FollowRedirects.Should().Be(expected);
        }

        /// <summary>
        /// Tests verbose and silent modes.
        /// </summary>
        [Theory]
        [InlineData("-v", true, false)]
        [InlineData("--verbose", true, false)]
        [InlineData("-s", false, true)]
        [InlineData("--silent", false, true)]
        [InlineData("-sS", false, true)] // Silent with show-error
        public void Parse_VerboseSilent_ShouldSetCorrectly(string flag, bool expectVerbose, bool expectSilent)
        {
            // Arrange
            var command = $"curl {flag} https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Verbose.Should().Be(expectVerbose);
            options.Silent.Should().Be(expectSilent);
        }

        /// <summary>
        /// Tests include headers option.
        /// </summary>
        [Theory]
        [InlineData("-i", true)]
        [InlineData("--include", true)]
        [InlineData("", false)]
        public void Parse_IncludeHeaders_ShouldSetCorrectly(string flag, bool expected)
        {
            // Arrange
            var command = $"curl {flag} https://example.com".Trim();

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.IncludeHeaders.Should().Be(expected);
        }

        #endregion

        #region SSL/TLS Options Tests

        /// <summary>
        /// Tests insecure option for SSL.
        /// </summary>
        [Theory]
        [InlineData("-k", true)]
        [InlineData("--insecure", true)]
        [InlineData("", false)]
        public void Parse_Insecure_ShouldSetCorrectly(string flag, bool expected)
        {
            // Arrange
            var command = $"curl {flag} https://example.com".Trim();

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Insecure.Should().Be(expected);
        }

        /// <summary>
        /// Tests certificate options.
        /// </summary>
        [Fact]
        public void Parse_CertificateOptions_ShouldSetPaths()
        {
            // Arrange
            const string command = "curl --cert /path/to/cert.pem --key /path/to/key.pem --cacert /path/to/ca.pem https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.CertFile.Should().Be("/path/to/cert.pem");
            options.KeyFile.Should().Be("/path/to/key.pem");
            options.CaCert.Should().Be("/path/to/ca.pem");
        }

        #endregion

        #region Timeout Options Tests

        /// <summary>
        /// Tests timeout options.
        /// </summary>
        [Theory]
        [InlineData("--connect-timeout 30", 30, null)]
        [InlineData("-m 60", null, 60)]
        [InlineData("--max-time 120", null, 120)]
        [InlineData("--connect-timeout 10 -m 60", 10, 60)]
        public void Parse_Timeouts_ShouldSetCorrectly(string timeoutFlags, int? connectTimeout, int? maxTime)
        {
            // Arrange
            var command = $"curl {timeoutFlags} https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.ConnectTimeout.Should().Be(connectTimeout);
            options.MaxTime.Should().Be(maxTime);
        }

        #endregion

        #region Complex Command Tests

        /// <summary>
        /// Tests parsing of a complex curl command with multiple options.
        /// </summary>
        [Fact]
        public void Parse_ComplexCommand_ShouldParseAllOptions()
        {
            // Arrange
            const string command = @"curl -X POST
                -H 'Content-Type: application/json'
                -H 'Authorization: Bearer token123'
                -d '{""name"":""test"",""value"":123}'
                -o response.json
                -L
                -v
                --connect-timeout 30
                --max-time 120
                -k
                https://api.example.com/endpoint";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Method.Should().Be("POST");
            options.Headers.Should().HaveCount(2);
            options.Headers["Content-Type"].Should().Be("application/json");
            options.Headers["Authorization"].Should().Be("Bearer token123");
            options.Data.Should().Contain("\"name\":\"test\"");
            options.OutputFile.Should().Be("response.json");
            options.FollowRedirects.Should().BeTrue();
            options.Verbose.Should().BeTrue();
            options.ConnectTimeout.Should().Be(30);
            options.MaxTime.Should().Be(120);
            options.Insecure.Should().BeTrue();
            options.Url.Should().Be("https://api.example.com/endpoint");
        }

        #endregion

        #region Error Cases

        /// <summary>
        /// Tests that missing URL throws appropriate exception.
        /// </summary>
        [Fact]
        public void Parse_MissingUrl_ShouldThrowException()
        {
            // Arrange
            const string command = "curl -X POST -H 'Content-Type: application/json'";

            // Act & Assert
            Action act = () => _parser.Parse(command);
            act.Should().Throw<CurlInvalidCommandException>()
                .WithMessage("*URL*")
                .And.InvalidPart.Should().BeNull();
        }

        /// <summary>
        /// Tests invalid option format.
        /// </summary>
        [Theory]
        [InlineData("curl -Z https://example.com")] // Invalid option
        [InlineData("curl --invalid-option https://example.com")]
        public void Parse_InvalidOption_ShouldThrowOrIgnore(string command)
        {
            // The parser might either throw or ignore unknown options
            // depending on implementation. Both are valid behaviors.

            // Act
            var exception = Record.Exception(() => _parser.Parse(command));

            // Assert
            if (exception != null)
            {
                exception.Should().BeOfType<CurlInvalidCommandException>();
            }
            else
            {
                // If it doesn't throw, it should at least parse the URL
                var options = _parser.Parse(command);
                options.Url.Should().Be("https://example.com");
            }
        }

        #endregion

        #region Special curl Features

        /// <summary>
        /// Tests parsing of write-out format.
        /// </summary>
        [Theory]
        [InlineData("-w '%{http_code}'", "%{http_code}")]
        [InlineData("--write-out '%{time_total}'", "%{time_total}")]
        public void Parse_WriteOutFormat_ShouldSetCorrectly(string flag, string expected)
        {
            // Arrange
            var command = $"curl {flag} https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.WriteOut.Should().Be(expected);
        }

        /// <summary>
        /// Tests cookie options.
        /// </summary>
        [Fact]
        public void Parse_CookieOptions_ShouldSetCorrectly()
        {
            // Arrange
            const string command = "curl -b 'session=abc123' -c cookies.txt https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Cookie.Should().Be("session=abc123");
            options.CookieJar.Should().Be("cookies.txt");
        }

        /// <summary>
        /// Tests user agent option.
        /// </summary>
        [Theory]
        [InlineData("-A 'Mozilla/5.0'", "Mozilla/5.0")]
        [InlineData("--user-agent 'CustomBot/1.0'", "CustomBot/1.0")]
        public void Parse_UserAgent_ShouldSetCorrectly(string flag, string expected)
        {
            // Arrange
            var command = $"curl {flag} https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.UserAgent.Should().Be(expected);
        }

        /// <summary>
        /// Tests referer option.
        /// </summary>
        [Theory]
        [InlineData("-e 'https://google.com'", "https://google.com")]
        [InlineData("--referer 'https://example.com/page'", "https://example.com/page")]
        public void Parse_Referer_ShouldSetCorrectly(string flag, string expected)
        {
            // Arrange
            var command = $"curl {flag} https://example.com";

            // Act
            var options = _parser.Parse(command);

            // Assert
            options.Referer.Should().Be(expected);
        }

        #endregion
    }
}