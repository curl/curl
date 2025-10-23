using System;

namespace CurlDotNet.Tests
{
    /// <summary>
    /// Test categories for organizing and filtering tests
    /// </summary>
    public static class TestCategories
    {
        /// <summary>
        /// Tests ported from curl's unit test suite (tests/unit/*.c)
        /// </summary>
        public const string CurlUnit = "CurlUnit";

        /// <summary>
        /// Tests ported from curl's libtest suite (tests/libtest/*.c)
        /// </summary>
        public const string CurlLibTest = "CurlLibTest";

        /// <summary>
        /// Synthetic tests specific to the .NET implementation
        /// </summary>
        public const string Synthetic = "Synthetic";

        /// <summary>
        /// Integration tests that require network access
        /// </summary>
        public const string Integration = "Integration";

        /// <summary>
        /// Tests that verify command-line compatibility with curl
        /// </summary>
        public const string Compatibility = "Compatibility";

        /// <summary>
        /// Performance and benchmark tests
        /// </summary>
        public const string Performance = "Performance";

        /// <summary>
        /// Tests for HTTP/HTTPS functionality
        /// </summary>
        public const string Http = "HTTP";

        /// <summary>
        /// Tests for FTP/FTPS functionality
        /// </summary>
        public const string Ftp = "FTP";

        /// <summary>
        /// Tests for FILE protocol functionality
        /// </summary>
        public const string FileProtocol = "FILE";

        /// <summary>
        /// Tests for command parsing functionality
        /// </summary>
        public const string Parser = "Parser";

        /// <summary>
        /// Tests that require platform-specific features
        /// </summary>
        public const string PlatformSpecific = "PlatformSpecific";

        /// <summary>
        /// Tests that can run on .NET Framework 4.7.2
        /// </summary>
        public const string NetFramework = "NetFramework";

        /// <summary>
        /// Tests that require .NET Core 3.1 or later
        /// </summary>
        public const string NetCore = "NetCore";

        /// <summary>
        /// Tests that verify Xamarin compatibility
        /// </summary>
        public const string Xamarin = "Xamarin";
    }
}