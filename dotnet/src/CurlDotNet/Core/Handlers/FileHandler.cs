/***************************************************************************
 * FileHandler - file:// protocol handler
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Exceptions;

namespace CurlDotNet.Core
{
    /// <summary>
    /// Handler for file:// protocol.
    /// </summary>
    public class FileHandler : IProtocolHandler
    {
        public async Task<CurlResult> ExecuteAsync(CurlOptions options, CancellationToken cancellationToken)
        {
            var uri = new Uri(options.Url);
            var filePath = uri.LocalPath;

            // Check if file exists
            if (!File.Exists(filePath))
            {
                throw new CurlFileCouldntReadException($"File not found: {filePath}");
            }

            try
            {
                var result = new CurlResult
                {
                    StatusCode = 200,
                    Command = options.OriginalCommand
                };

                var fileInfo = new FileInfo(filePath);
                result.Headers["Content-Length"] = fileInfo.Length.ToString();
                result.Headers["Last-Modified"] = fileInfo.LastWriteTimeUtc.ToString("R");

                // Determine if binary or text
                if (IsBinaryFile(filePath))
                {
                    #if NETSTANDARD2_0
                    result.BinaryData = await Task.Run(() => File.ReadAllBytes(filePath), cancellationToken);
                    #else
                    result.BinaryData = await File.ReadAllBytesAsync(filePath, cancellationToken);
                    #endif
                }
                else
                {
                    #if NETSTANDARD2_0
                    result.Body = await Task.Run(() => File.ReadAllText(filePath), cancellationToken);
                    #else
                    result.Body = await File.ReadAllTextAsync(filePath, cancellationToken);
                    #endif
                }

                // Handle output file
                if (!string.IsNullOrEmpty(options.OutputFile))
                {
                    if (result.BinaryData != null)
                    {
                        #if NETSTANDARD2_0
                        await Task.Run(() => File.WriteAllBytes(options.OutputFile, result.BinaryData), cancellationToken);
                        #else
                        await File.WriteAllBytesAsync(options.OutputFile, result.BinaryData, cancellationToken);
                        #endif
                    }
                    else
                    {
                        #if NETSTANDARD2_0
                        await Task.Run(() => File.WriteAllText(options.OutputFile, result.Body), cancellationToken);
                        #else
                        await File.WriteAllTextAsync(options.OutputFile, result.Body, cancellationToken);
                        #endif
                    }
                    result.OutputFiles.Add(options.OutputFile);
                }

                return result;
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new CurlFileCouldntReadException($"Permission denied: {filePath}");
            }
            catch (IOException ex)
            {
                throw new CurlReadErrorException(filePath, ex.Message);
            }
        }

        public bool SupportsProtocol(string protocol)
        {
            return protocol == "file";
        }

        private bool IsBinaryFile(string filePath)
        {
            var extension = Path.GetExtension(filePath).ToLower();
            var textExtensions = new[] { ".txt", ".json", ".xml", ".html", ".htm", ".css", ".js",
                ".csv", ".log", ".md", ".yml", ".yaml", ".ini", ".cfg", ".conf" };

            return !Array.Exists(textExtensions, ext => ext == extension);
        }
    }
}