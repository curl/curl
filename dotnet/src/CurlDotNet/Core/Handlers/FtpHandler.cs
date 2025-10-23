/***************************************************************************
 * FtpHandler - FTP/FTPS protocol handler
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Exceptions;

namespace CurlDotNet.Core
{
    /// <summary>
    /// Handler for FTP and FTPS protocols.
    /// </summary>
    /// <remarks>
    /// <para>Implements FTP operations using .NET's FtpWebRequest.</para>
    /// <para>AI-Usage: This handler supports FTP file operations matching curl's FTP functionality.</para>
    /// </remarks>
    public class FtpHandler : IProtocolHandler
    {
        public async Task<CurlResult> ExecuteAsync(CurlOptions options, CancellationToken cancellationToken)
        {
            try
            {
                var request = (FtpWebRequest)WebRequest.Create(options.Url);

                // Set method
                request.Method = DetermineFtpMethod(options);

                // Set credentials
                if (options.Credentials != null)
                {
                    request.Credentials = options.Credentials;
                }
                else
                {
                    request.Credentials = new NetworkCredential("anonymous", "anonymous@");
                }

                // Set options
                request.UseBinary = true;
                request.UsePassive = options.FtpPassive;
                request.EnableSsl = options.FtpSsl || options.Url.StartsWith("ftps://");
                request.KeepAlive = options.KeepAliveTime.HasValue;

                if (options.ConnectTimeout > 0)
                {
                    request.Timeout = options.ConnectTimeout * 1000;
                }

                // Set proxy if specified
                if (!string.IsNullOrEmpty(options.Proxy))
                {
                    request.Proxy = new WebProxy(options.Proxy);
                    if (options.ProxyCredentials != null)
                    {
                        request.Proxy.Credentials = options.ProxyCredentials;
                    }
                }

                // Handle upload
                if (request.Method == WebRequestMethods.Ftp.UploadFile && !string.IsNullOrEmpty(options.Data))
                {
                    byte[] fileContents = Encoding.UTF8.GetBytes(options.Data);
                    request.ContentLength = fileContents.Length;

                    using (Stream requestStream = await Task.Factory.FromAsync(
                        request.BeginGetRequestStream,
                        request.EndGetRequestStream,
                        null))
                    {
                        await requestStream.WriteAsync(fileContents, 0, fileContents.Length, cancellationToken);
                    }
                }

                // Get response
                using var response = (FtpWebResponse)await Task.Factory.FromAsync(
                    request.BeginGetResponse,
                    request.EndGetResponse,
                    null);

                var result = new CurlResult
                {
                    StatusCode = (int)response.StatusCode,
                    Command = options.OriginalCommand
                };

                // Add FTP-specific headers
                result.Headers["Status-Description"] = response.StatusDescription;
                result.Headers["Banner-Message"] = response.BannerMessage ?? "";
                result.Headers["Welcome-Message"] = response.WelcomeMessage ?? "";
                result.Headers["Exit-Message"] = response.ExitMessage ?? "";

                // Download content if applicable
                if (request.Method == WebRequestMethods.Ftp.DownloadFile ||
                    request.Method == WebRequestMethods.Ftp.ListDirectory ||
                    request.Method == WebRequestMethods.Ftp.ListDirectoryDetails)
                {
                    using (var stream = response.GetResponseStream())
                    using (var reader = new StreamReader(stream))
                    {
                        result.Body = await reader.ReadToEndAsync();
                    }

                    // Save to output file if specified
                    if (!string.IsNullOrEmpty(options.OutputFile))
                    {
                        #if NETSTANDARD2_0
                        await Task.Run(() => File.WriteAllText(options.OutputFile, result.Body), cancellationToken);
                        #else
                        await File.WriteAllTextAsync(options.OutputFile, result.Body, cancellationToken);
                        #endif
                        result.OutputFiles.Add(options.OutputFile);
                    }
                }

                return result;
            }
            catch (WebException ex)
            {
                if (ex.Response is FtpWebResponse ftpResponse)
                {
                    throw new CurlFtpException($"FTP error: {ftpResponse.StatusDescription}",
                        (int)ftpResponse.StatusCode);
                }

                throw new CurlCouldntConnectException($"FTP connection failed: {ex.Message}", ex);
            }
            catch (UriFormatException ex)
            {
                throw new CurlUrlMalformatException($"Invalid FTP URL: {options.Url}", ex);
            }
        }

        public bool SupportsProtocol(string protocol)
        {
            return protocol == "ftp" || protocol == "ftps";
        }

        private string DetermineFtpMethod(CurlOptions options)
        {
            // Determine FTP method based on options and URL
            if (!string.IsNullOrEmpty(options.CustomMethod))
            {
                return MapToFtpMethod(options.CustomMethod);
            }

            // If uploading data
            if (!string.IsNullOrEmpty(options.Data) || options.BinaryData != null)
            {
                return WebRequestMethods.Ftp.UploadFile;
            }

            // If URL ends with / assume directory listing
            if (options.Url.EndsWith("/"))
            {
                return options.Verbose
                    ? WebRequestMethods.Ftp.ListDirectoryDetails
                    : WebRequestMethods.Ftp.ListDirectory;
            }

            // Default to download
            return WebRequestMethods.Ftp.DownloadFile;
        }

        private string MapToFtpMethod(string method)
        {
            return method.ToUpper() switch
            {
                "LIST" => WebRequestMethods.Ftp.ListDirectory,
                "NLST" => WebRequestMethods.Ftp.ListDirectory,
                "RETR" => WebRequestMethods.Ftp.DownloadFile,
                "STOR" => WebRequestMethods.Ftp.UploadFile,
                "DELE" => WebRequestMethods.Ftp.DeleteFile,
                "MKD" => WebRequestMethods.Ftp.MakeDirectory,
                "RMD" => WebRequestMethods.Ftp.RemoveDirectory,
                "PWD" => WebRequestMethods.Ftp.PrintWorkingDirectory,
                "SIZE" => WebRequestMethods.Ftp.GetFileSize,
                "MDTM" => WebRequestMethods.Ftp.GetDateTimestamp,
                _ => WebRequestMethods.Ftp.DownloadFile
            };
        }
    }

    /// <summary>
    /// FTP-specific exception.
    /// </summary>
    public class CurlFtpException : CurlException
    {
        public int FtpStatusCode { get; }

        public CurlFtpException(string message, int ftpStatusCode)
            : base(message, 9) // CURLE_FTP_WEIRD_SERVER_REPLY
        {
            FtpStatusCode = ftpStatusCode;
        }
    }
}