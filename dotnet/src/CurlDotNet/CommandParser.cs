using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using CurlDotNet.Options;

namespace CurlDotNet
{
    /// <summary>
    /// Parses curl command-line strings into structured options.
    /// Mimics the behavior of curl's tool_getparam.c
    /// </summary>
    public class CommandParser
    {
        private static readonly Regex QuotedStringRegex = new Regex(@"(['""])([^\1]*?)\1|(\S+)", RegexOptions.Compiled);

        public CurlOptions Parse(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine))
                throw new ArgumentException("Command line cannot be empty", nameof(commandLine));

            // Remove "curl" from the beginning if present
            commandLine = commandLine.Trim();
            if (commandLine.StartsWith("curl ", StringComparison.OrdinalIgnoreCase))
            {
                commandLine = commandLine.Substring(5);
            }
            else if (commandLine.Equals("curl", StringComparison.OrdinalIgnoreCase))
            {
                throw new CurlException("No URL specified");
            }

            var options = new CurlOptions();
            var args = TokenizeCommandLine(commandLine);

            for (int i = 0; i < args.Count; i++)
            {
                var arg = args[i];

                if (arg.StartsWith("-"))
                {
                    i = ParseOption(args, i, options);
                }
                else
                {
                    // If it's not an option, it's the URL
                    if (string.IsNullOrEmpty(options.Url))
                    {
                        options.Url = arg;
                    }
                    else
                    {
                        // Multiple URLs - curl supports this, we'll handle the first for now
                        options.AdditionalUrls.Add(arg);
                    }
                }
            }

            return options;
        }

        private int ParseOption(List<string> args, int index, CurlOptions options)
        {
            var arg = args[index];
            string value = null;
            bool hasValue = false;

            // Handle long options with = syntax (e.g., --header=value)
            if (arg.StartsWith("--") && arg.Contains("="))
            {
                var parts = arg.Split(new[] { '=' }, 2);
                arg = parts[0];
                value = parts[1];
                hasValue = true;
            }

            switch (arg)
            {
                case "-X":
                case "--request":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.Method = value?.ToUpperInvariant() ?? "GET";
                    break;

                case "-H":
                case "--header":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    if (!string.IsNullOrEmpty(value))
                    {
                        options.Headers.Add(value);
                    }
                    break;

                case "-d":
                case "--data":
                case "--data-raw":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.Data = value;
                    if (string.IsNullOrEmpty(options.Method))
                    {
                        options.Method = "POST"; // -d implies POST if method not set
                    }
                    break;

                case "--data-binary":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.DataBinary = value;
                    if (string.IsNullOrEmpty(options.Method))
                    {
                        options.Method = "POST";
                    }
                    break;

                case "--data-urlencode":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.DataUrlEncode = value;
                    if (string.IsNullOrEmpty(options.Method))
                    {
                        options.Method = "POST";
                    }
                    break;

                case "-o":
                case "--output":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.OutputFile = value;
                    break;

                case "-O":
                case "--remote-name":
                    options.UseRemoteFileName = true;
                    break;

                case "-L":
                case "--location":
                    options.FollowRedirects = true;
                    break;

                case "-v":
                case "--verbose":
                    options.Verbose = true;
                    break;

                case "-s":
                case "--silent":
                    options.Silent = true;
                    break;

                case "-S":
                case "--show-error":
                    options.ShowError = true;
                    break;

                case "-i":
                case "--include":
                    options.IncludeHeaders = true;
                    break;

                case "-I":
                case "--head":
                    options.Method = "HEAD";
                    break;

                case "-u":
                case "--user":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.UserAuth = value;
                    break;

                case "-A":
                case "--user-agent":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.UserAgent = value;
                    break;

                case "-e":
                case "--referer":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.Referer = value;
                    break;

                case "-b":
                case "--cookie":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.Cookie = value;
                    break;

                case "-c":
                case "--cookie-jar":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.CookieJar = value;
                    break;

                case "-T":
                case "--upload-file":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.UploadFile = value;
                    break;

                case "--proxy":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.Proxy = value;
                    break;

                case "-k":
                case "--insecure":
                    options.Insecure = true;
                    break;

                case "--compressed":
                    options.Compressed = true;
                    break;

                case "-f":
                case "--fail":
                    options.FailOnError = true;
                    break;

                case "--connect-timeout":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    if (int.TryParse(value, out int connectTimeout))
                    {
                        options.ConnectTimeout = connectTimeout;
                    }
                    break;

                case "-m":
                case "--max-time":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    if (int.TryParse(value, out int maxTime))
                    {
                        options.MaxTime = maxTime;
                    }
                    break;

                case "-w":
                case "--write-out":
                    if (!hasValue && index + 1 < args.Count && !args[index + 1].StartsWith("-"))
                    {
                        value = args[++index];
                    }
                    options.WriteOut = value;
                    break;

                case "-G":
                case "--get":
                    options.Method = "GET";
                    options.ConvertPostToGet = true;
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

                case "--http3":
                    options.HttpVersion = "3.0";
                    break;

                default:
                    // Unknown option - curl would typically show an error
                    if (arg.StartsWith("-"))
                    {
                        Console.Error.WriteLine($"Warning: Unknown option '{arg}'");
                    }
                    break;
            }

            return index;
        }

        private List<string> TokenizeCommandLine(string commandLine)
        {
            var tokens = new List<string>();
            var matches = QuotedStringRegex.Matches(commandLine);

            foreach (Match match in matches)
            {
                // Group 2 contains the content within quotes, Group 3 contains unquoted tokens
                var token = match.Groups[2].Success ? match.Groups[2].Value : match.Groups[3].Value;
                if (!string.IsNullOrWhiteSpace(token))
                {
                    tokens.Add(token);
                }
            }

            return tokens;
        }
    }
}