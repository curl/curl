using System.Collections.Generic;

namespace CurlDotNet.Options
{
    /// <summary>
    /// Represents all options that can be passed to a curl command.
    /// Maps to curl's tool_operate.h OperationConfig structure.
    /// </summary>
    public class CurlOptions
    {
        public CurlOptions()
        {
            Headers = new List<string>();
            AdditionalUrls = new List<string>();
            Method = "GET";
            HttpVersion = "1.1";
        }

        // Core request options
        public string Url { get; set; }
        public List<string> AdditionalUrls { get; set; }
        public string Method { get; set; }
        public List<string> Headers { get; set; }

        // Data options
        public string Data { get; set; }
        public string DataBinary { get; set; }
        public string DataUrlEncode { get; set; }
        public bool ConvertPostToGet { get; set; }

        // Output options
        public string OutputFile { get; set; }
        public bool UseRemoteFileName { get; set; }
        public bool IncludeHeaders { get; set; }
        public string WriteOut { get; set; }

        // Behavior options
        public bool FollowRedirects { get; set; }
        public int MaxRedirects { get; set; } = 50;
        public bool Verbose { get; set; }
        public bool Silent { get; set; }
        public bool ShowError { get; set; }
        public bool FailOnError { get; set; }

        // Authentication
        public string UserAuth { get; set; }
        public string BearerToken { get; set; }

        // Headers shortcuts
        public string UserAgent { get; set; }
        public string Referer { get; set; }
        public string Cookie { get; set; }
        public string CookieJar { get; set; }

        // Upload/download
        public string UploadFile { get; set; }
        public bool Resume { get; set; }
        public string Range { get; set; }

        // Proxy
        public string Proxy { get; set; }
        public string ProxyAuth { get; set; }

        // SSL/TLS
        public bool Insecure { get; set; }
        public string CertFile { get; set; }
        public string KeyFile { get; set; }
        public string CaCert { get; set; }

        // Compression
        public bool Compressed { get; set; }

        // Timeouts (in seconds)
        public int? ConnectTimeout { get; set; }
        public int? MaxTime { get; set; }

        // HTTP version
        public string HttpVersion { get; set; }

        // FTP options
        public bool FtpPassive { get; set; } = true;
        public string FtpPort { get; set; }

        // Progress
        public bool NoProgress { get; set; }
        public bool ProgressBar { get; set; }

        // Rate limiting
        public string LimitRate { get; set; }

        // Retry options
        public int? Retry { get; set; }
        public int? RetryDelay { get; set; }
        public int? RetryMaxTime { get; set; }

        // DNS
        public string DnsServers { get; set; }
        public string Resolve { get; set; }

        // Interface
        public string Interface { get; set; }

        // Misc
        public bool Ipv4 { get; set; }
        public bool Ipv6 { get; set; }
        public string UnixSocket { get; set; }
        public bool Tcp { get; set; }
        public bool TcpNoDelay { get; set; }
    }
}