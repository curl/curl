/***************************************************************************
 * IProtocolHandler - Interface for protocol-specific handlers
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System.Threading;
using System.Threading.Tasks;

namespace CurlDotNet.Core
{
    /// <summary>
    /// Interface for protocol-specific handlers (HTTP, FTP, FILE, etc.).
    /// </summary>
    internal interface IProtocolHandler
    {
        /// <summary>
        /// Execute a request with the given options.
        /// </summary>
        /// <param name="options">Parsed curl options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result of the operation</returns>
        Task<CurlResult> ExecuteAsync(CurlOptions options, CancellationToken cancellationToken);

        /// <summary>
        /// Check if this handler supports the given protocol.
        /// </summary>
        /// <param name="protocol">Protocol scheme (http, ftp, file, etc.)</param>
        /// <returns>True if supported</returns>
        bool SupportsProtocol(string protocol);
    }
}