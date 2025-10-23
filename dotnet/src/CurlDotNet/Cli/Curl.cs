/***************************************************************************
 * CurlDotNet.Cli - Command-line style curl for .NET
 *
 * The killer feature: Copy-paste curl commands from anywhere!
 *
 * Examples:
 * var result = await Curl.Execute("curl https://api.github.com/user");
 * var data = await Curl.Execute("curl -X POST https://api.example.com -d '{}'");
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Core;

namespace CurlDotNet.Cli
{
    /// <summary>
    /// Static curl API for command-line style execution.
    /// The main entry point for copy-paste curl commands.
    /// </summary>
    /// <remarks>
    /// <para>This is the primary API for CurlDotNet - just paste your curl command!</para>
    /// <para>AI-Usage: This class enables direct curl command execution from .NET</para>
    /// </remarks>
    public static class Curl
    {
        private static readonly CurlEngine _engine = new CurlEngine();

        /// <summary>
        /// Execute a curl command exactly as you would on the command line.
        /// </summary>
        /// <param name="command">The curl command (with or without 'curl' prefix)</param>
        /// <returns>A fluent result object with the response</returns>
        /// <example>
        /// <code>
        /// // Copy-paste from documentation
        /// var result = await Curl.Execute("curl https://api.github.com/user -H 'Accept: application/json'");
        ///
        /// // Extract data fluently
        /// var json = result.AsJson();
        /// var statusCode = result.StatusCode;
        ///
        /// // Chain requests
        /// var next = await result.FollowUp("curl https://api.github.com/user/repos");
        /// </code>
        /// </example>
        public static async Task<CurlResult> Execute(string command)
        {
            return await _engine.ExecuteAsync(command);
        }

        /// <summary>
        /// Execute with cancellation support.
        /// </summary>
        public static async Task<CurlResult> Execute(string command, CancellationToken cancellationToken)
        {
            return await _engine.ExecuteAsync(command, cancellationToken);
        }

        /// <summary>
        /// Execute with settings override.
        /// </summary>
        public static async Task<CurlResult> Execute(string command, CurlSettings settings)
        {
            return await _engine.ExecuteAsync(command, settings);
        }

        /// <summary>
        /// Execute with output to console (like real curl).
        /// </summary>
        public static async Task<CurlResult> ExecuteToConsole(string command)
        {
            var result = await Execute(command);
            result.WriteToConsole();
            return result;
        }

        /// <summary>
        /// Execute with output to directory (respecting -o flags).
        /// </summary>
        public static async Task<CurlResult> ExecuteToDirectory(string command, string directory)
        {
            var settings = new CurlSettings().WithOutputDirectory(directory);
            return await Execute(command, settings);
        }

        /// <summary>
        /// Validate a curl command without executing it.
        /// </summary>
        public static CurlValidation Validate(string command)
        {
            return _engine.Validate(command);
        }

        /// <summary>
        /// Convert a curl command to the equivalent C# HttpClient code.
        /// Great for learning and debugging!
        /// </summary>
        public static string ToHttpClientCode(string command)
        {
            return _engine.GenerateHttpClientCode(command);
        }
    }
}