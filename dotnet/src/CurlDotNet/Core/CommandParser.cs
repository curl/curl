/***************************************************************************
 * CommandParser - Parses curl command strings into options
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using CurlDotNet.Exceptions;

namespace CurlDotNet.Core
{
    /// <summary>
    /// Parses curl command strings into CurlOptions.
    /// </summary>
    /// <remarks>
    /// <para>This parser handles all curl command-line syntax including short and long options.</para>
    /// <para>AI-Usage: This is the core parser that translates curl syntax to options.</para>
    /// </remarks>
    public class CommandParser : ICommandParser
    {
        private static readonly Dictionary<string, string> ShortToLongOptions = new Dictionary<string, string>
        {
            ["-X"] = "--request",
            ["-H"] = "--header",
            ["-d"] = "--data",
            ["-F"] = "--form",
            ["-o"] = "--output",
            ["-O"] = "--remote-name",
            ["-i"] = "--include",
            ["-I"] = "--head",
            ["-L"] = "--location",
            ["-k"] = "--insecure",
            ["-v"] = "--verbose",
            ["-s"] = "--silent",
            ["-S"] = "--show-error",
            ["-f"] = "--fail",
            ["-A"] = "--user-agent",
            ["-e"] = "--referer",
            ["-b"] = "--cookie",
            ["-c"] = "--cookie-jar",
            ["-u"] = "--user",
            ["-x"] = "--proxy",
            ["-w"] = "--write-out",
            ["-C"] = "--continue-at",
            ["-r"] = "--range",
            ["-T"] = "--upload-file"
        };

        public CurlOptions Parse(string command)
        {
            if (string.IsNullOrWhiteSpace(command))
                throw new ArgumentNullException(nameof(command));

            var options = new CurlOptions
            {
                OriginalCommand = command
            };

            // Remove "curl" from the beginning if present
            command = command.Trim();
            if (command.StartsWith("curl ", StringComparison.OrdinalIgnoreCase))
            {
                command = command.Substring(5);
            }
            else if (command.Equals("curl", StringComparison.OrdinalIgnoreCase))
            {
                throw new CurlException("No URL specified");
            }

            var args = ParseArguments(command);
            ProcessArguments(args, options);

            return options;
        }

        public bool IsValid(string command)
        {
            try
            {
                Parse(command);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private List<string> ParseArguments(string command)
        {
            var args = new List<string>();
            var current = "";
            var inQuote = false;
            var quoteChar = ' ';
            var escape = false;

            for (int i = 0; i < command.Length; i++)
            {
                var c = command[i];

                if (escape)
                {
                    current += c;
                    escape = false;
                    continue;
                }

                if (c == '\\')
                {
                    if (i + 1 < command.Length && (command[i + 1] == '"' || command[i + 1] == '\''))
                    {
                        escape = true;
                        continue;
                    }
                    current += c;
                    continue;
                }

                if (!inQuote && (c == '"' || c == '\''))
                {
                    inQuote = true;
                    quoteChar = c;
                    continue;
                }

                if (inQuote && c == quoteChar)
                {
                    inQuote = false;
                    continue;
                }

                if (!inQuote && c == ' ')
                {
                    if (!string.IsNullOrEmpty(current))
                    {
                        args.Add(current);
                        current = "";
                    }
                    continue;
                }

                current += c;
            }

            if (!string.IsNullOrEmpty(current))
            {
                args.Add(current);
            }

            return args;
        }

        private void ProcessArguments(List<string> args, CurlOptions options)
        {
            for (int i = 0; i < args.Count; i++)
            {
                var arg = args[i];

                if (arg.StartsWith("-"))
                {
                    // Handle options
                    var optionName = NormalizeOption(arg);
                    var value = "";

                    // Check if this option needs a value
                    if (NeedsValue(optionName) && i + 1 < args.Count && !args[i + 1].StartsWith("-"))
                    {
                        value = args[++i];
                    }

                    ProcessOption(optionName, value, options);
                }
                else if (string.IsNullOrEmpty(options.Url))
                {
                    // First non-option argument is the URL
                    options.Url = arg;
                }
                else
                {
                    // Additional URLs or data - handle based on context
                    // For simplicity, ignore additional URLs for now
                }
            }
        }

        private string NormalizeOption(string option)
        {
            // Convert short options to long form
            if (ShortToLongOptions.ContainsKey(option))
            {
                return ShortToLongOptions[option];
            }

            // Handle combined short options like -sSL
            if (option.StartsWith("-") && !option.StartsWith("--") && option.Length > 2)
            {
                // Process each character as a separate flag
                var firstFlag = "-" + option[1];
                if (ShortToLongOptions.ContainsKey(firstFlag))
                {
                    // Process first flag, rest will be handled in recursion
                    return ShortToLongOptions[firstFlag];
                }
            }

            return option;
        }

        private bool NeedsValue(string option)
        {
            var noValueOptions = new[] { "--include", "--head", "--location", "--insecure",
                "--verbose", "--silent", "--show-error", "--fail", "--compressed",
                "--remote-name", "--location-trusted", "--disable-epsv", "--disable-eprt",
                "--ftp-pasv", "--ftp-ssl", "--create-dirs", "--progress-bar" };

            return !noValueOptions.Contains(option);
        }

        private void ProcessOption(string option, string value, CurlOptions options)
        {
            switch (option)
            {
                case "--request":
                case "-X":
                    options.Method = value.ToUpper();
                    options.CustomMethod = value.ToUpper();
                    break;

                case "--header":
                case "-H":
                    ParseHeader(value, options);
                    break;

                case "--data":
                case "-d":
                    options.Data = value;
                    if (string.IsNullOrEmpty(options.Method))
                        options.Method = "POST";
                    break;

                case "--form":
                case "-F":
                    ParseFormField(value, options);
                    if (string.IsNullOrEmpty(options.Method))
                        options.Method = "POST";
                    break;

                case "--output":
                case "-o":
                    options.OutputFile = value;
                    break;

                case "--remote-name":
                case "-O":
                    options.OutputFile = ""; // Will use filename from URL
                    break;

                case "--include":
                case "-i":
                    options.IncludeHeaders = true;
                    break;

                case "--head":
                case "-I":
                    options.HeadOnly = true;
                    options.Method = "HEAD";
                    break;

                case "--location":
                case "-L":
                    options.FollowLocation = true;
                    break;

                case "--insecure":
                case "-k":
                    options.Insecure = true;
                    break;

                case "--verbose":
                case "-v":
                    options.Verbose = true;
                    break;

                case "--silent":
                case "-s":
                    options.Silent = true;
                    break;

                case "--show-error":
                case "-S":
                    options.ShowError = true;
                    break;

                case "--fail":
                case "-f":
                    options.FailOnError = true;
                    break;

                case "--user-agent":
                case "-A":
                    options.UserAgent = value;
                    break;

                case "--referer":
                case "-e":
                    options.Referer = value;
                    break;

                case "--cookie":
                case "-b":
                    options.Cookie = value;
                    break;

                case "--cookie-jar":
                case "-c":
                    options.CookieJar = value;
                    break;

                case "--user":
                case "-u":
                    ParseCredentials(value, options);
                    break;

                case "--proxy":
                case "-x":
                    options.Proxy = value;
                    break;

                case "--proxy-user":
                    ParseProxyCredentials(value, options);
                    break;

                case "--max-time":
                    options.MaxTime = int.Parse(value);
                    break;

                case "--connect-timeout":
                    options.ConnectTimeout = int.Parse(value);
                    break;

                case "--max-redirs":
                    options.MaxRedirects = int.Parse(value);
                    break;

                case "--compressed":
                    options.Compressed = true;
                    break;

                case "--write-out":
                case "-w":
                    options.WriteOut = value;
                    break;

                case "--range":
                case "-r":
                    options.Range = value;
                    break;

                case "--continue-at":
                case "-C":
                    if (value == "-")
                        options.ResumeFrom = -1; // Auto-resume
                    else
                        options.ResumeFrom = long.Parse(value);
                    break;

                case "--cert":
                    options.CertFile = value;
                    break;

                case "--key":
                    options.KeyFile = value;
                    break;

                case "--cacert":
                    options.CaCertFile = value;
                    break;

                case "--interface":
                    options.Interface = value;
                    break;

                case "--http1.0":
                    options.HttpVersion = "1.0";
                    break;

                case "--http1.1":
                    options.HttpVersion = "1.1";
                    break;

                case "--http2":
                    options.HttpVersion = "2.0";
                    break;

                case "--limit-rate":
                    options.SpeedLimit = ParseSize(value);
                    break;

                case "--speed-time":
                    options.SpeedTime = int.Parse(value);
                    break;

                case "--progress-bar":
                    options.ProgressBar = true;
                    break;

                case "--keepalive-time":
                    options.KeepAliveTime = int.Parse(value);
                    break;

                case "--dns-servers":
                    options.DnsServers = value;
                    break;

                case "--resolve":
                    ParseResolve(value, options);
                    break;

                case "--quote":
                    options.Quote.Add(value);
                    break;

                case "--create-dirs":
                    options.CreateDirs = true;
                    break;

                case "--ftp-pasv":
                    options.FtpPassive = true;
                    break;

                case "--ftp-ssl":
                    options.FtpSsl = true;
                    break;

                case "--disable-epsv":
                    options.DisableEpsv = true;
                    break;

                case "--disable-eprt":
                    options.DisableEprt = true;
                    break;

                case "--socks5":
                    options.Socks5Proxy = value;
                    break;

                case "--retry":
                    options.Retry = int.Parse(value);
                    break;

                case "--retry-delay":
                    options.RetryDelay = int.Parse(value);
                    break;

                case "--retry-max-time":
                    options.RetryMaxTime = int.Parse(value);
                    break;

                case "--location-trusted":
                    options.LocationTrusted = true;
                    break;
            }
        }

        private void ParseHeader(string header, CurlOptions options)
        {
            var colonIndex = header.IndexOf(':');
            if (colonIndex > 0)
            {
                var key = header.Substring(0, colonIndex).Trim();
                var value = header.Substring(colonIndex + 1).Trim();
                options.Headers[key] = value;
            }
        }

        private void ParseFormField(string field, CurlOptions options)
        {
            var equalIndex = field.IndexOf('=');
            if (equalIndex > 0)
            {
                var key = field.Substring(0, equalIndex);
                var value = field.Substring(equalIndex + 1);

                if (value.StartsWith("@"))
                {
                    // File upload
                    options.Files[key] = value.Substring(1);
                }
                else
                {
                    // Regular form field
                    options.FormData[key] = value;
                }
            }
        }

        private void ParseCredentials(string userPass, CurlOptions options)
        {
            var parts = userPass.Split(':');
            if (parts.Length == 2)
            {
                options.Credentials = new NetworkCredential(parts[0], parts[1]);
            }
            else
            {
                options.Credentials = new NetworkCredential(userPass, "");
            }
        }

        private void ParseProxyCredentials(string userPass, CurlOptions options)
        {
            var parts = userPass.Split(':');
            if (parts.Length == 2)
            {
                options.ProxyCredentials = new NetworkCredential(parts[0], parts[1]);
            }
        }

        private void ParseResolve(string resolve, CurlOptions options)
        {
            // Format: host:port:address
            var parts = resolve.Split(':');
            if (parts.Length >= 3)
            {
                var hostPort = parts[0] + ":" + parts[1];
                var address = string.Join(":", parts.Skip(2));
                options.Resolve[hostPort] = address;
            }
        }

        private long ParseSize(string size)
        {
            if (string.IsNullOrEmpty(size))
                return 0;

            var multiplier = 1L;
            var value = size;

            if (size.EndsWith("k", StringComparison.OrdinalIgnoreCase))
            {
                multiplier = 1024;
                value = size.Substring(0, size.Length - 1);
            }
            else if (size.EndsWith("m", StringComparison.OrdinalIgnoreCase))
            {
                multiplier = 1024 * 1024;
                value = size.Substring(0, size.Length - 1);
            }
            else if (size.EndsWith("g", StringComparison.OrdinalIgnoreCase))
            {
                multiplier = 1024 * 1024 * 1024;
                value = size.Substring(0, size.Length - 1);
            }

            if (long.TryParse(value, out var num))
            {
                return num * multiplier;
            }

            return 0;
        }
    }
}