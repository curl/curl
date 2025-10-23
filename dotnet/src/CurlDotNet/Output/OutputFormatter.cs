using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using CurlDotNet.Handlers;
using CurlDotNet.Options;

namespace CurlDotNet.Output
{
    /// <summary>
    /// Formats curl output according to the various output options.
    /// Mimics curl's output behavior from tool_writeout.c and tool_cb_wrt.c
    /// </summary>
    public class OutputFormatter
    {
        /// <summary>
        /// Format the response according to curl options
        /// </summary>
        public string Format(CurlResponse response, CurlOptions options)
        {
            if (response == null)
                return string.Empty;

            var output = new StringBuilder();

            // Handle verbose mode (-v)
            if (options.Verbose && !options.Silent)
            {
                output.AppendLine(FormatVerboseOutput(response, options));
            }

            // Handle include headers (-i)
            if (options.IncludeHeaders && !string.IsNullOrEmpty(response.Headers))
            {
                output.AppendLine($"HTTP/{response.HttpVersion ?? "1.1"} {response.StatusCode} {response.StatusText}");
                output.AppendLine(response.Headers);
            }

            // Handle write-out format (-w)
            if (!string.IsNullOrEmpty(options.WriteOut))
            {
                output.Append(FormatWriteOut(options.WriteOut, response));
            }

            // Add response body unless it's a HEAD request or error with fail flag
            if (options.Method != "HEAD" && !(options.FailOnError && response.IsError))
            {
                if (response.BinaryData != null)
                {
                    // For binary data, we'd typically write directly to output
                    // For string representation, we'll encode it
                    output.Append(Encoding.UTF8.GetString(response.BinaryData));
                }
                else if (!string.IsNullOrEmpty(response.Body))
                {
                    output.Append(response.Body);
                }
            }

            // Handle errors
            if (response.IsError && options.ShowError && !options.Silent)
            {
                return FormatError(response);
            }

            return output.ToString();
        }

        /// <summary>
        /// Handle output destination (file, stdout, etc.)
        /// </summary>
        public async Task<OutputResult> HandleOutputAsync(CurlResponse response, CurlOptions options)
        {
            var result = new OutputResult();

            try
            {
                string outputPath = null;

                // Determine output file
                if (!string.IsNullOrEmpty(options.OutputFile))
                {
                    outputPath = options.OutputFile;

                    // Handle special cases
                    if (outputPath == "-")
                    {
                        // "-" means stdout, don't write to file
                        outputPath = null;
                    }
                    else
                    {
                        // Expand environment variables and resolve path
                        outputPath = Environment.ExpandEnvironmentVariables(outputPath);
                        outputPath = Path.GetFullPath(outputPath);
                    }
                }
                else if (options.UseRemoteFileName)
                {
                    // Extract filename from URL
                    var uri = new Uri(options.Url);
                    var fileName = Path.GetFileName(uri.LocalPath);
                    if (string.IsNullOrEmpty(fileName))
                    {
                        fileName = "index.html";
                    }
                    outputPath = Path.Combine(Directory.GetCurrentDirectory(), fileName);
                }

                // Write to file if specified
                if (!string.IsNullOrEmpty(outputPath))
                {
                    var directory = Path.GetDirectoryName(outputPath);
                    if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }

                    if (response.BinaryData != null)
                    {
                        await File.WriteAllBytesAsync(outputPath, response.BinaryData);
                        result.BytesWritten = response.BinaryData.Length;
                    }
                    else
                    {
                        await File.WriteAllTextAsync(outputPath, response.Body ?? string.Empty);
                        result.BytesWritten = Encoding.UTF8.GetByteCount(response.Body ?? string.Empty);
                    }

                    result.OutputPath = outputPath;
                    result.WroteToFile = true;
                }

                // Always populate the result object for programmatic access
                result.ResponseBody = response.Body;
                result.BinaryData = response.BinaryData;
                result.Headers = response.Headers;
                result.StatusCode = response.StatusCode;
                result.IsError = response.IsError;
                result.ErrorMessage = response.ErrorMessage;

                // Format for display/return
                if (!result.WroteToFile || options.Verbose)
                {
                    result.FormattedOutput = Format(response, options);
                }
            }
            catch (Exception ex)
            {
                result.IsError = true;
                result.ErrorMessage = $"Failed to write output: {ex.Message}";
            }

            return result;
        }

        private string FormatVerboseOutput(CurlResponse response, CurlOptions options)
        {
            var sb = new StringBuilder();

            sb.AppendLine($"* Trying {options.Url}...");
            sb.AppendLine($"* Connected to {new Uri(options.Url).Host}");

            // Request info
            sb.AppendLine($"> {options.Method ?? "GET"} {new Uri(options.Url).PathAndQuery} HTTP/{options.HttpVersion}");
            sb.AppendLine($"> Host: {new Uri(options.Url).Host}");

            if (!string.IsNullOrEmpty(options.UserAgent))
            {
                sb.AppendLine($"> User-Agent: {options.UserAgent}");
            }

            foreach (var header in options.Headers)
            {
                sb.AppendLine($"> {header}");
            }

            // Response info
            sb.AppendLine($"< HTTP/{response.HttpVersion ?? "1.1"} {response.StatusCode} {response.StatusText}");

            if (!string.IsNullOrEmpty(response.Headers))
            {
                foreach (var line in response.Headers.Split('\n'))
                {
                    if (!string.IsNullOrWhiteSpace(line))
                    {
                        sb.AppendLine($"< {line.Trim()}");
                    }
                }
            }

            return sb.ToString();
        }

        private string FormatWriteOut(string format, CurlResponse response)
        {
            // Handle curl's write-out variables
            format = format.Replace("%{http_code}", response.StatusCode.ToString());
            format = format.Replace("%{http_version}", response.HttpVersion ?? "1.1");
            format = format.Replace("%{size_download}", response.SizeDownload.ToString());
            format = format.Replace("%{size_upload}", response.SizeUpload.ToString());
            format = format.Replace("%{speed_download}", response.SpeedDownload.ToString());
            format = format.Replace("%{speed_upload}", response.SpeedUpload.ToString());
            format = format.Replace("%{time_total}", (response.TotalTime / 1000.0).ToString("F3"));
            format = format.Replace("%{time_namelookup}", (response.NameLookupTime / 1000.0).ToString("F3"));
            format = format.Replace("%{time_connect}", (response.ConnectTime / 1000.0).ToString("F3"));
            format = format.Replace("%{time_pretransfer}", (response.PreTransferTime / 1000.0).ToString("F3"));
            format = format.Replace("%{time_starttransfer}", (response.StartTransferTime / 1000.0).ToString("F3"));
            format = format.Replace("%{url_effective}", response.EffectiveUrl ?? "");
            format = format.Replace("%{content_type}", response.ContentType ?? "");
            format = format.Replace("%{num_redirects}", response.NumRedirects.ToString());
            format = format.Replace("\\n", "\n");
            format = format.Replace("\\r", "\r");
            format = format.Replace("\\t", "\t");

            return format;
        }

        private string FormatError(CurlResponse response)
        {
            return $"curl: ({response.ErrorCode}) {response.ErrorMessage}";
        }
    }

    /// <summary>
    /// Result of output operation with both file and in-memory access
    /// </summary>
    public class OutputResult
    {
        /// <summary>
        /// The formatted output string (for display/console)
        /// </summary>
        public string FormattedOutput { get; set; }

        /// <summary>
        /// The raw response body (for programmatic access)
        /// </summary>
        public string ResponseBody { get; set; }

        /// <summary>
        /// Binary data if response was binary
        /// </summary>
        public byte[] BinaryData { get; set; }

        /// <summary>
        /// Response headers
        /// </summary>
        public string Headers { get; set; }

        /// <summary>
        /// HTTP status code
        /// </summary>
        public int StatusCode { get; set; }

        /// <summary>
        /// Path where output was written (if file output was used)
        /// </summary>
        public string OutputPath { get; set; }

        /// <summary>
        /// Whether output was written to a file
        /// </summary>
        public bool WroteToFile { get; set; }

        /// <summary>
        /// Number of bytes written
        /// </summary>
        public long BytesWritten { get; set; }

        /// <summary>
        /// Whether an error occurred
        /// </summary>
        public bool IsError { get; set; }

        /// <summary>
        /// Error message if an error occurred
        /// </summary>
        public string ErrorMessage { get; set; }

        /// <summary>
        /// Get the output as a stream for further processing
        /// </summary>
        public Stream GetStream()
        {
            if (BinaryData != null)
            {
                return new MemoryStream(BinaryData);
            }
            else if (ResponseBody != null)
            {
                return new MemoryStream(Encoding.UTF8.GetBytes(ResponseBody));
            }
            return new MemoryStream();
        }
    }
}