/***************************************************************************
 * CurlOptions - Parsed curl command options
 *
 * Represents all curl options after parsing
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.Net;

namespace CurlDotNet.Core
{
    /// <summary>
    /// Represents parsed curl command options.
    /// </summary>
    /// <remarks>
    /// <para>This class contains all options extracted from a curl command string.</para>
    /// <para>AI-Usage: This is the intermediate representation between curl syntax and HTTP operations.</para>
    /// </remarks>
    public class CurlOptions
    {
        /// <summary>
        /// The target URL.
        /// </summary>
        public string Url { get; set; }

        /// <summary>
        /// HTTP method (GET, POST, PUT, DELETE, etc.).
        /// </summary>
        public string Method { get; set; } = "GET";

        /// <summary>
        /// Request headers.
        /// </summary>
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Request body data.
        /// </summary>
        public string Data { get; set; }

        /// <summary>
        /// Whether to URL encode the data (--data-urlencode flag).
        /// </summary>
        public bool DataUrlEncode { get; set; }

        /// <summary>
        /// Binary data for upload.
        /// </summary>
        public byte[] BinaryData { get; set; }

        /// <summary>
        /// Form data for multipart/form-data.
        /// </summary>
        public Dictionary<string, string> FormData { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Files to upload (for -F flag with @file).
        /// </summary>
        public Dictionary<string, string> Files { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Output file path (-o flag).
        /// </summary>
        public string OutputFile { get; set; }

        /// <summary>
        /// Whether to use remote filename for output (-O flag).
        /// </summary>
        public bool UseRemoteFileName { get; set; }

        /// <summary>
        /// Whether to include headers in output (-i flag).
        /// </summary>
        public bool IncludeHeaders { get; set; }

        /// <summary>
        /// Whether to show only headers (-I or --head flag).
        /// </summary>
        public bool HeadOnly { get; set; }

        /// <summary>
        /// Whether to follow redirects (-L flag).
        /// </summary>
        public bool FollowLocation { get; set; }

        /// <summary>
        /// Alias for FollowLocation for test compatibility.
        /// </summary>
        public bool FollowRedirects
        {
            get => FollowLocation;
            set => FollowLocation = value;
        }

        /// <summary>
        /// Maximum number of redirects to follow (--max-redirs).
        /// </summary>
        public int MaxRedirects { get; set; } = 50;

        /// <summary>
        /// Whether to ignore SSL errors (-k flag).
        /// </summary>
        public bool Insecure { get; set; }

        /// <summary>
        /// Verbose output (-v flag).
        /// </summary>
        public bool Verbose { get; set; }

        /// <summary>
        /// Silent mode (-s flag).
        /// </summary>
        public bool Silent { get; set; }

        /// <summary>
        /// Show error even in silent mode (-S flag).
        /// </summary>
        public bool ShowError { get; set; }

        /// <summary>
        /// Fail silently on HTTP errors (-f flag).
        /// </summary>
        public bool FailOnError { get; set; }

        /// <summary>
        /// User agent string (-A or --user-agent).
        /// </summary>
        public string UserAgent { get; set; }

        /// <summary>
        /// Referer header (-e or --referer).
        /// </summary>
        public string Referer { get; set; }

        /// <summary>
        /// Cookie string (-b or --cookie).
        /// </summary>
        public string Cookie { get; set; }

        /// <summary>
        /// Cookie jar file path (-c or --cookie-jar).
        /// </summary>
        public string CookieJar { get; set; }

        /// <summary>
        /// Basic authentication (-u or --user).
        /// </summary>
        public NetworkCredential Credentials { get; set; }

        /// <summary>
        /// Alias for Credentials for test compatibility.
        /// </summary>
        public NetworkCredential UserAuth
        {
            get => Credentials;
            set => Credentials = value;
        }

        /// <summary>
        /// Proxy URL (-x or --proxy).
        /// </summary>
        public string Proxy { get; set; }

        /// <summary>
        /// Proxy authentication (--proxy-user).
        /// </summary>
        public NetworkCredential ProxyCredentials { get; set; }

        /// <summary>
        /// Maximum time in seconds (--max-time).
        /// </summary>
        public int MaxTime { get; set; }

        /// <summary>
        /// Connection timeout in seconds (--connect-timeout).
        /// </summary>
        public int ConnectTimeout { get; set; }

        /// <summary>
        /// Speed limit in bytes per second (--limit-rate).
        /// </summary>
        public long SpeedLimit { get; set; }

        /// <summary>
        /// Speed time period for limit (--speed-time).
        /// </summary>
        public int SpeedTime { get; set; }

        /// <summary>
        /// Resume from byte offset (-C or --continue-at).
        /// </summary>
        public long? ResumeFrom { get; set; }

        /// <summary>
        /// Range of bytes to request (-r or --range).
        /// </summary>
        public string Range { get; set; }

        /// <summary>
        /// Whether to use compressed encoding (--compressed).
        /// </summary>
        public bool Compressed { get; set; }

        /// <summary>
        /// Certificate file for client authentication (--cert).
        /// </summary>
        public string CertFile { get; set; }

        /// <summary>
        /// Certificate key file (--key).
        /// </summary>
        public string KeyFile { get; set; }

        /// <summary>
        /// CA certificate file (--cacert).
        /// </summary>
        public string CaCertFile { get; set; }

        /// <summary>
        /// Alias for CaCertFile for test compatibility.
        /// </summary>
        public string CaCert
        {
            get => CaCertFile;
            set => CaCertFile = value;
        }

        /// <summary>
        /// Interface to use for outgoing connections (--interface).
        /// </summary>
        public string Interface { get; set; }

        /// <summary>
        /// HTTP version to use (--http1.0, --http1.1, --http2).
        /// </summary>
        public string HttpVersion { get; set; }

        /// <summary>
        /// Request method override (-X flag value).
        /// </summary>
        public string CustomMethod { get; set; }

        /// <summary>
        /// Write-out format string (-w or --write-out).
        /// </summary>
        public string WriteOut { get; set; }

        /// <summary>
        /// Progress callback handler.
        /// </summary>
        public Action<double, long, long> ProgressHandler { get; set; }

        /// <summary>
        /// The original command string.
        /// </summary>
        public string OriginalCommand { get; set; }

        /// <summary>
        /// Whether to show progress bar (--progress-bar).
        /// </summary>
        public bool ProgressBar { get; set; }

        /// <summary>
        /// Whether to use TCP keepalive (--keepalive-time).
        /// </summary>
        public int? KeepAliveTime { get; set; }

        /// <summary>
        /// DNS servers to use (--dns-servers).
        /// </summary>
        public string DnsServers { get; set; }

        /// <summary>
        /// Resolve host to IP (--resolve).
        /// </summary>
        public Dictionary<string, string> Resolve { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// FTP/SFTP commands to execute after transfer (--quote).
        /// </summary>
        public List<string> Quote { get; set; } = new List<string>();

        /// <summary>
        /// Whether to create missing directories for output (--create-dirs).
        /// </summary>
        public bool CreateDirs { get; set; }

        /// <summary>
        /// Whether to use passive mode for FTP (--ftp-pasv).
        /// </summary>
        public bool FtpPassive { get; set; } = true;

        /// <summary>
        /// Whether to use SSL/TLS for FTP (--ftp-ssl).
        /// </summary>
        public bool FtpSsl { get; set; }

        /// <summary>
        /// SOCKS proxy (--socks5).
        /// </summary>
        public string Socks5Proxy { get; set; }

        /// <summary>
        /// Retry count (--retry).
        /// </summary>
        public int Retry { get; set; }

        /// <summary>
        /// Retry delay in seconds (--retry-delay).
        /// </summary>
        public int RetryDelay { get; set; }

        /// <summary>
        /// Maximum retry time (--retry-max-time).
        /// </summary>
        public int RetryMaxTime { get; set; }

        /// <summary>
        /// Location trusted for automatic authentication (--location-trusted).
        /// </summary>
        public bool LocationTrusted { get; set; }

        /// <summary>
        /// Whether to disable EPSV for FTP (--disable-epsv).
        /// </summary>
        public bool DisableEpsv { get; set; }

        /// <summary>
        /// Whether to disable EPRT for FTP (--disable-eprt).
        /// </summary>
        public bool DisableEprt { get; set; }

        /// <summary>
        /// Clone this options object.
        /// </summary>
        public CurlOptions Clone()
        {
            return new CurlOptions
            {
                Url = Url,
                Method = Method,
                Headers = new Dictionary<string, string>(Headers),
                Data = Data,
                DataUrlEncode = DataUrlEncode,
                BinaryData = BinaryData,
                FormData = new Dictionary<string, string>(FormData),
                Files = new Dictionary<string, string>(Files),
                OutputFile = OutputFile,
                UseRemoteFileName = UseRemoteFileName,
                IncludeHeaders = IncludeHeaders,
                HeadOnly = HeadOnly,
                FollowLocation = FollowLocation,
                MaxRedirects = MaxRedirects,
                Insecure = Insecure,
                Verbose = Verbose,
                Silent = Silent,
                ShowError = ShowError,
                FailOnError = FailOnError,
                UserAgent = UserAgent,
                Referer = Referer,
                Cookie = Cookie,
                CookieJar = CookieJar,
                Credentials = Credentials,
                Proxy = Proxy,
                ProxyCredentials = ProxyCredentials,
                MaxTime = MaxTime,
                ConnectTimeout = ConnectTimeout,
                SpeedLimit = SpeedLimit,
                SpeedTime = SpeedTime,
                ResumeFrom = ResumeFrom,
                Range = Range,
                Compressed = Compressed,
                CertFile = CertFile,
                KeyFile = KeyFile,
                CaCertFile = CaCertFile,
                Interface = Interface,
                HttpVersion = HttpVersion,
                CustomMethod = CustomMethod,
                WriteOut = WriteOut,
                ProgressHandler = ProgressHandler,
                OriginalCommand = OriginalCommand,
                ProgressBar = ProgressBar,
                KeepAliveTime = KeepAliveTime,
                DnsServers = DnsServers,
                Resolve = new Dictionary<string, string>(Resolve),
                Quote = new List<string>(Quote),
                CreateDirs = CreateDirs,
                FtpPassive = FtpPassive,
                FtpSsl = FtpSsl,
                Socks5Proxy = Socks5Proxy,
                Retry = Retry,
                RetryDelay = RetryDelay,
                RetryMaxTime = RetryMaxTime,
                LocationTrusted = LocationTrusted,
                DisableEpsv = DisableEpsv,
                DisableEprt = DisableEprt
            };
        }
    }
}