using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using CurlDotNet.Options;

namespace CurlDotNet.Handlers
{
    /// <summary>
    /// Handles file:// protocol requests.
    /// Implements curl's FILE functionality from lib/file.c
    /// </summary>
    public class FileHandler : IProtocolHandler
    {
        public async Task<CurlResponse> ExecuteAsync(CurlOptions options, HttpClient httpClient)
        {
            var response = new CurlResponse();

            try
            {
                var uri = new Uri(options.Url);
                var filePath = uri.LocalPath;

                // On Windows, file URIs might have an extra slash
                if (Path.DirectorySeparatorChar == '\\' && filePath.StartsWith("/"))
                {
                    filePath = filePath.Substring(1);
                }

                response.Protocol = "FILE";
                response.EffectiveUrl = options.Url;

                if (File.Exists(filePath))
                {
                    // Handle file read
                    var fileInfo = new FileInfo(filePath);

                    response.StatusCode = 200;
                    response.StatusText = "OK";

                    // Set headers similar to curl's file handling
                    response.Headers = $"Content-Length: {fileInfo.Length}\r\n" +
                                      $"Last-Modified: {fileInfo.LastWriteTimeUtc:R}\r\n" +
                                      $"Accept-ranges: bytes\r\n";

                    // Read file content
                    if (options.Method != "HEAD")
                    {
                        // Check if it's binary or text
                        if (IsBinaryFile(filePath))
                        {
                            response.BinaryData = await File.ReadAllBytesAsync(filePath);
                            response.SizeDownload = response.BinaryData.Length;
                        }
                        else
                        {
                            response.Body = await File.ReadAllTextAsync(filePath);
                            response.SizeDownload = Encoding.UTF8.GetByteCount(response.Body);
                        }
                    }
                }
                else if (Directory.Exists(filePath))
                {
                    // Handle directory listing (curl behavior)
                    response.StatusCode = 200;
                    response.StatusText = "OK";

                    var entries = Directory.GetFileSystemEntries(filePath);
                    var sb = new StringBuilder();

                    // Format similar to curl's directory listing
                    sb.AppendLine($"<html><head><title>Directory listing of {filePath}</title></head>");
                    sb.AppendLine("<body>");
                    sb.AppendLine($"<h1>Directory listing of {filePath}</h1>");
                    sb.AppendLine("<pre>");

                    foreach (var entry in entries)
                    {
                        var name = Path.GetFileName(entry);
                        if (Directory.Exists(entry))
                        {
                            name += "/";
                        }
                        sb.AppendLine($"<a href=\"{name}\">{name}</a>");
                    }

                    sb.AppendLine("</pre></body></html>");

                    response.Body = sb.ToString();
                    response.SizeDownload = Encoding.UTF8.GetByteCount(response.Body);
                    response.ContentType = "text/html";
                }
                else
                {
                    // File not found
                    response.StatusCode = 404;
                    response.StatusText = "Not Found";
                    response.IsError = true;
                    response.ErrorCode = 37; // CURLE_FILE_COULDNT_READ_FILE
                    response.ErrorMessage = $"Couldn't open file {filePath}";
                }

                // Handle upload (write to file)
                if (!string.IsNullOrEmpty(options.UploadFile) || !string.IsNullOrEmpty(options.Data))
                {
                    byte[] dataToWrite;
                    if (!string.IsNullOrEmpty(options.UploadFile))
                    {
                        dataToWrite = File.ReadAllBytes(options.UploadFile);
                    }
                    else
                    {
                        dataToWrite = Encoding.UTF8.GetBytes(options.Data);
                    }

                    await File.WriteAllBytesAsync(filePath, dataToWrite);
                    response.SizeUpload = dataToWrite.Length;
                    response.StatusCode = 200;
                    response.StatusText = "OK";
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                response.IsError = true;
                response.ErrorCode = 37; // CURLE_FILE_COULDNT_READ_FILE
                response.ErrorMessage = $"Permission denied: {ex.Message}";
                response.StatusCode = 403;
                response.StatusText = "Forbidden";
            }
            catch (Exception ex)
            {
                response.IsError = true;
                response.ErrorCode = 37; // CURLE_FILE_COULDNT_READ_FILE
                response.ErrorMessage = ex.Message;
                response.StatusCode = 500;
                response.StatusText = "Internal Error";
            }

            return response;
        }

        private bool IsBinaryFile(string filePath)
        {
            // Simple heuristic - check first few bytes for null characters
            // Real curl does more sophisticated detection
            try
            {
                using (var stream = File.OpenRead(filePath))
                {
                    var buffer = new byte[Math.Min(8000, stream.Length)];
                    var bytesRead = stream.Read(buffer, 0, buffer.Length);

                    for (int i = 0; i < bytesRead; i++)
                    {
                        if (buffer[i] == 0)
                        {
                            return true; // Found null byte, likely binary
                        }
                    }
                }
            }
            catch
            {
                // If we can't read it, assume text
            }

            return false;
        }
    }
}