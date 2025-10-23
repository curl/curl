using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using CurlDotNet.Options;

namespace CurlDotNet.Handlers
{
    /// <summary>
    /// Handles FTP and FTPS protocol requests.
    /// Implements curl's FTP functionality from lib/ftp.c
    /// </summary>
    public class FtpHandler : IProtocolHandler
    {
        public async Task<CurlResponse> ExecuteAsync(CurlOptions options, HttpClient httpClient)
        {
            var response = new CurlResponse();

            try
            {
                var uri = new Uri(options.Url);
                FtpWebRequest request = (FtpWebRequest)WebRequest.Create(uri);

                // Set credentials if provided
                if (!string.IsNullOrEmpty(options.UserAuth))
                {
                    var parts = options.UserAuth.Split(':');
                    var username = parts[0];
                    var password = parts.Length > 1 ? parts[1] : "";
                    request.Credentials = new NetworkCredential(username, password);
                }
                else
                {
                    request.Credentials = new NetworkCredential("anonymous", "anonymous@");
                }

                // Set FTP method based on curl options
                request.Method = DetermineFtpMethod(options, uri);
                request.UseBinary = true;
                request.UsePassive = options.FtpPassive;
                request.KeepAlive = true;

                // Set timeout if specified
                if (options.ConnectTimeout.HasValue)
                {
                    request.Timeout = options.ConnectTimeout.Value * 1000; // Convert to milliseconds
                }

                // Handle SSL for FTPS
                if (uri.Scheme.Equals("ftps", StringComparison.OrdinalIgnoreCase))
                {
                    request.EnableSsl = true;
                    if (options.Insecure)
                    {
                        // In a real implementation, we'd need to bypass cert validation
                        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;
                    }
                }

                // Handle upload
                if (!string.IsNullOrEmpty(options.UploadFile) || !string.IsNullOrEmpty(options.Data))
                {
                    request.Method = WebRequestMethods.Ftp.UploadFile;

                    byte[] fileContents;
                    if (!string.IsNullOrEmpty(options.UploadFile))
                    {
                        fileContents = File.ReadAllBytes(options.UploadFile);
                    }
                    else
                    {
                        fileContents = Encoding.UTF8.GetBytes(options.Data);
                    }

                    request.ContentLength = fileContents.Length;
                    using (Stream requestStream = request.GetRequestStream())
                    {
                        await requestStream.WriteAsync(fileContents, 0, fileContents.Length);
                    }
                }

                // Execute request
                using (FtpWebResponse ftpResponse = (FtpWebResponse)await Task.Factory.FromAsync(
                    request.BeginGetResponse, request.EndGetResponse, null))
                {
                    response.StatusCode = (int)ftpResponse.StatusCode;
                    response.StatusText = ftpResponse.StatusDescription;
                    response.Protocol = "FTP";

                    // Read response data for download operations
                    if (request.Method == WebRequestMethods.Ftp.DownloadFile ||
                        request.Method == WebRequestMethods.Ftp.ListDirectory ||
                        request.Method == WebRequestMethods.Ftp.ListDirectoryDetails)
                    {
                        using (Stream responseStream = ftpResponse.GetResponseStream())
                        using (StreamReader reader = new StreamReader(responseStream))
                        {
                            response.Body = await reader.ReadToEndAsync();
                            response.SizeDownload = Encoding.UTF8.GetByteCount(response.Body);
                        }
                    }

                    // Get FTP-specific information
                    response.Headers = $"Content-Length: {ftpResponse.ContentLength}\r\n" +
                                      $"Last-Modified: {ftpResponse.LastModified}\r\n" +
                                      $"Banner-Message: {ftpResponse.BannerMessage}\r\n" +
                                      $"Welcome-Message: {ftpResponse.WelcomeMessage}\r\n";
                }
            }
            catch (WebException ex)
            {
                response.IsError = true;
                response.ErrorCode = MapFtpErrorCode(ex);
                response.ErrorMessage = ex.Message;

                if (ex.Response is FtpWebResponse ftpResponse)
                {
                    response.StatusCode = (int)ftpResponse.StatusCode;
                    response.StatusText = ftpResponse.StatusDescription;
                }
            }
            catch (Exception ex)
            {
                response.IsError = true;
                response.ErrorCode = 1;
                response.ErrorMessage = ex.Message;
            }

            return response;
        }

        private string DetermineFtpMethod(CurlOptions options, Uri uri)
        {
            // Check if URL ends with / (directory listing)
            if (uri.AbsolutePath.EndsWith("/"))
            {
                return options.Verbose ?
                    WebRequestMethods.Ftp.ListDirectoryDetails :
                    WebRequestMethods.Ftp.ListDirectory;
            }

            // Check for upload
            if (!string.IsNullOrEmpty(options.UploadFile) || !string.IsNullOrEmpty(options.Data))
            {
                return WebRequestMethods.Ftp.UploadFile;
            }

            // Check HTTP-like methods that map to FTP
            switch (options.Method?.ToUpperInvariant())
            {
                case "DELETE":
                    return WebRequestMethods.Ftp.DeleteFile;
                case "HEAD":
                    return WebRequestMethods.Ftp.GetFileSize;
                default:
                    return WebRequestMethods.Ftp.DownloadFile;
            }
        }

        private int MapFtpErrorCode(WebException ex)
        {
            switch (ex.Status)
            {
                case WebExceptionStatus.ConnectFailure:
                    return 7; // CURLE_COULDNT_CONNECT
                case WebExceptionStatus.Timeout:
                    return 28; // CURLE_OPERATION_TIMEDOUT
                case WebExceptionStatus.NameResolutionFailure:
                    return 6; // CURLE_COULDNT_RESOLVE_HOST
                case WebExceptionStatus.ProtocolError:
                    return 9; // CURLE_FTP_ACCESS_DENIED
                default:
                    return 1; // CURLE_UNSUPPORTED_PROTOCOL
            }
        }
    }
}