using System.Net.Http;
using System.Threading.Tasks;
using CurlDotNet.Options;

namespace CurlDotNet.Handlers
{
    /// <summary>
    /// Interface for protocol-specific handlers (HTTP, FTP, FILE, etc.)
    /// </summary>
    public interface IProtocolHandler
    {
        Task<CurlResponse> ExecuteAsync(CurlOptions options, HttpClient httpClient);
    }

    /// <summary>
    /// Response from a curl operation
    /// </summary>
    public class CurlResponse
    {
        public int StatusCode { get; set; }
        public string StatusText { get; set; }
        public string Body { get; set; }
        public string Headers { get; set; }
        public byte[] BinaryData { get; set; }
        public long TotalTime { get; set; }
        public long NameLookupTime { get; set; }
        public long ConnectTime { get; set; }
        public long PreTransferTime { get; set; }
        public long StartTransferTime { get; set; }
        public long RedirectTime { get; set; }
        public long SizeDownload { get; set; }
        public long SizeUpload { get; set; }
        public long SpeedDownload { get; set; }
        public long SpeedUpload { get; set; }
        public string EffectiveUrl { get; set; }
        public string ContentType { get; set; }
        public int NumRedirects { get; set; }
        public string RedirectUrl { get; set; }
        public string PrimaryIp { get; set; }
        public int PrimaryPort { get; set; }
        public string LocalIp { get; set; }
        public int LocalPort { get; set; }
        public string HttpVersion { get; set; }
        public string Protocol { get; set; }
        public string SslVerifyResult { get; set; }
        public string ProxyStatusCode { get; set; }

        // Error information
        public bool IsError { get; set; }
        public string ErrorMessage { get; set; }
        public int ErrorCode { get; set; }
    }
}