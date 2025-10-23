/***************************************************************************
 * ICommandParser - Interface for parsing curl commands
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

namespace CurlDotNet.Core
{
    /// <summary>
    /// Interface for parsing curl command strings into options.
    /// </summary>
    public interface ICommandParser
    {
        /// <summary>
        /// Parse a curl command string into options.
        /// </summary>
        /// <param name="command">The curl command string</param>
        /// <returns>Parsed options</returns>
        CurlOptions Parse(string command);

        /// <summary>
        /// Validate a curl command without fully parsing.
        /// </summary>
        /// <param name="command">The curl command string</param>
        /// <returns>True if command syntax is valid</returns>
        bool IsValid(string command);
    }
}