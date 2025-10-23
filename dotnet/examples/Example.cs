/***************************************************************************
 * Example usage of CurlDotNet
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System;
using System.Threading.Tasks;
using CurlDotNet;

namespace CurlDotNet.Examples
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var curl = new Curl();

            Console.WriteLine("=== CurlDotNet Examples ===\n");

            // Example 1: Simple GET request
            Console.WriteLine("1. Simple GET Request:");
            Console.WriteLine("----------------------");
            var result1 = await curl.ExecuteAsync("curl https://httpbin.org/get");
            Console.WriteLine($"Status: {result1.StatusCode}");
            Console.WriteLine($"Response length: {result1.ResponseBody?.Length ?? 0} bytes\n");

            // Example 2: POST with JSON data
            Console.WriteLine("2. POST with JSON:");
            Console.WriteLine("------------------");
            var result2 = await curl.ExecuteAsync(@"
                curl -X POST https://httpbin.org/post \
                     -H 'Content-Type: application/json' \
                     -d '{""name"":""John"",""age"":30}'
            ");
            Console.WriteLine($"Status: {result2.StatusCode}");
            Console.WriteLine($"Response: {result2.ResponseBody?.Substring(0, Math.Min(100, result2.ResponseBody.Length ?? 0))}...\n");

            // Example 3: Download to file
            Console.WriteLine("3. Download to File:");
            Console.WriteLine("--------------------");
            var tempFile = System.IO.Path.GetTempFileName();
            var result3 = await curl.ExecuteAsync($"curl -o {tempFile} https://httpbin.org/html");
            Console.WriteLine($"Downloaded to: {result3.OutputPath}");
            Console.WriteLine($"Bytes written: {result3.BytesWritten}\n");

            // Example 4: Custom headers
            Console.WriteLine("4. Custom Headers:");
            Console.WriteLine("------------------");
            var result4 = await curl.ExecuteAsync(@"
                curl -H 'Accept: application/json' \
                     -H 'X-Custom-Header: TestValue' \
                     https://httpbin.org/headers
            ");
            Console.WriteLine($"Status: {result4.StatusCode}");
            Console.WriteLine("Headers were sent successfully\n");

            // Example 5: Verbose output
            Console.WriteLine("5. Verbose Output:");
            Console.WriteLine("------------------");
            var result5 = await curl.ExecuteAsync("curl -v https://httpbin.org/status/200");
            Console.WriteLine(result5.FormattedOutput?.Substring(0, Math.Min(200, result5.FormattedOutput.Length ?? 0)));
            Console.WriteLine("...\n");

            // Example 6: Error handling
            Console.WriteLine("6. Error Handling:");
            Console.WriteLine("------------------");
            var result6 = await curl.ExecuteAsync("curl -f https://httpbin.org/status/404");
            if (result6.IsError)
            {
                Console.WriteLine($"Error occurred: {result6.ErrorMessage}");
                Console.WriteLine($"Status code: {result6.StatusCode}\n");
            }

            // Example 7: Parallel requests
            Console.WriteLine("7. Parallel Requests:");
            Console.WriteLine("---------------------");
            var start = DateTime.UtcNow;
            var results = await curl.ExecuteMultipleAsync(
                "curl https://httpbin.org/delay/1",
                "curl https://httpbin.org/delay/1",
                "curl https://httpbin.org/delay/1"
            );
            var duration = DateTime.UtcNow - start;
            Console.WriteLine($"Executed {results.Count} requests in {duration.TotalSeconds:F2} seconds");
            Console.WriteLine("(Should be ~1 second if running in parallel)\n");

            // Example 8: Authentication
            Console.WriteLine("8. Basic Authentication:");
            Console.WriteLine("------------------------");
            var result8 = await curl.ExecuteAsync("curl -u user:passwd https://httpbin.org/basic-auth/user/passwd");
            Console.WriteLine($"Status: {result8.StatusCode}");
            Console.WriteLine($"Authenticated: {result8.StatusCode == 200}\n");

            // Example 9: Follow redirects
            Console.WriteLine("9. Follow Redirects:");
            Console.WriteLine("--------------------");
            var result9 = await curl.ExecuteAsync("curl -L https://httpbin.org/redirect/3");
            Console.WriteLine($"Final URL after redirects: {result9.StatusCode}");
            Console.WriteLine($"Response received successfully\n");

            // Example 10: Write-out format
            Console.WriteLine("10. Custom Output Format:");
            Console.WriteLine("-------------------------");
            var result10 = await curl.ExecuteAsync(@"
                curl -w '\nTime: %{time_total}s\nSize: %{size_download} bytes\nStatus: %{http_code}' \
                     -o /dev/null -s https://httpbin.org/get
            ");
            Console.WriteLine(result10.FormattedOutput);

            Console.WriteLine("\n=== Examples Complete ===");
        }
    }
}