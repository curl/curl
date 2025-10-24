/***************************************************************************
 * CurlResult - The response object from every curl command
 *
 * Inspired by curl's callback system in src/tool_cb_*.c
 * Original curl Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This .NET implementation:
 * Copyright (C) 2024 IronSoftware
 *
 * This class is designed to be so intuitive that you can guess every method.
 * If you want to save to a file, just type .Save and IntelliSense shows you
 * SaveToFile(), SaveAsJson(), SaveAsCsv(). It just flows naturally.
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CurlDotNet.Exceptions;

namespace CurlDotNet.Core
{
    /// <summary>
    /// <para><b>🎯 The response from your curl command - everything you need is here!</b></para>
    ///
    /// <para>After running any curl command, you get this object back. It has the status code,
    /// response body, headers, and helpful methods to work with the data.</para>
    ///
    /// <para><b>The API is designed to be intuitive - just type what you want to do:</b></para>
    /// <list type="bullet">
    /// <item>Want the body? → <c>result.Body</c></item>
    /// <item>Want JSON? → <c>result.ParseJson&lt;T&gt;()</c> or <c>result.AsJson&lt;T&gt;()</c></item>
    /// <item>Want to save? → <c>result.SaveToFile("path")</c></item>
    /// <item>Want headers? → <c>result.Headers["Content-Type"]</c></item>
    /// <item>Check success? → <c>result.IsSuccess</c> or <c>result.EnsureSuccess()</c></item>
    /// </list>
    ///
    /// <para><b>Quick Example:</b></para>
    /// <code>
    /// var result = await Curl.Execute("curl https://api.github.com/users/octocat");
    ///
    /// if (result.IsSuccess)  // Was it 200-299?
    /// {
    ///     var user = result.ParseJson&lt;User&gt;();  // Parse JSON to your type
    ///     result.SaveToFile("user.json");       // Save for later
    /// }
    /// </code>
    /// </summary>
    /// <remarks>
    /// <para><b>Design Philosophy:</b> Every method name tells you exactly what it does.
    /// No surprises. If you guess a method name, it probably exists and does what you expect.</para>
    ///
    /// <para><b>Fluent API:</b> Most methods return 'this' so you can chain operations:</para>
    /// <code>
    /// result
    ///     .EnsureSuccess()           // Throw if not 200-299
    ///     .SaveToFile("backup.json") // Save a copy
    ///     .ParseJson&lt;Data&gt;()        // Parse and return data
    /// </code>
    /// </remarks>
    public class CurlResult
    {
        #region Core Properties - The basics everyone needs

        /// <summary>
        /// <para><b>The HTTP status code - tells you what happened.</b></para>
        ///
        /// <para>Common codes you'll see:</para>
        /// <code>
        /// 200 = OK, it worked!
        /// 201 = Created something new
        /// 204 = Success, but no content returned
        /// 400 = Bad request (you sent something wrong)
        /// 401 = Unauthorized (need to login)
        /// 403 = Forbidden (not allowed)
        /// 404 = Not found
        /// 429 = Too many requests (slow down!)
        /// 500 = Server error (their fault, not yours)
        /// 503 = Service unavailable (try again later)
        /// </code>
        ///
        /// <para><b>Example - Handle different statuses:</b></para>
        /// <code>
        /// switch (result.StatusCode)
        /// {
        ///     case 200: ProcessData(result.Body); break;
        ///     case 404: Console.WriteLine("Not found"); break;
        ///     case 401: RedirectToLogin(); break;
        ///     case >= 500: Console.WriteLine("Server error, retry later"); break;
        /// }
        /// </code>
        /// </summary>
        public int StatusCode { get; set; }

        /// <summary>
        /// <para><b>The response body as a string - this is your data!</b></para>
        ///
        /// <para>Contains whatever the server sent back: JSON, HTML, XML, plain text, etc.</para>
        ///
        /// <para><b>Common patterns:</b></para>
        /// <code>
        /// // JSON API response (most common)
        /// if (result.Body.StartsWith("{"))
        /// {
        ///     var data = result.ParseJson&lt;MyClass&gt;();
        /// }
        ///
        /// // HTML webpage
        /// if (result.Body.Contains("&lt;html"))
        /// {
        ///     result.SaveToFile("page.html");
        /// }
        ///
        /// // Plain text
        /// Console.WriteLine(result.Body);
        /// </code>
        ///
        /// <para><b>Note:</b> For binary data (images, PDFs), use <see cref="BinaryData"/> instead.</para>
        /// <para><b>Note:</b> Can be null for 204 No Content or binary responses.</para>
        /// </summary>
        public string Body { get; set; }

        /// <summary>
        /// <para><b>All HTTP headers from the response - contains metadata about the response.</b></para>
        ///
        /// <para>Headers tell you things like content type, cache rules, rate limits, etc.
        /// Access them like a dictionary (case-insensitive keys).</para>
        ///
        /// <para><b>Get a specific header:</b></para>
        /// <code>
        /// // These all work (case-insensitive):
        /// var type = result.Headers["Content-Type"];
        /// var type = result.Headers["content-type"];
        /// var type = result.Headers["CONTENT-TYPE"];
        ///
        /// // Or use the helper:
        /// var type = result.GetHeader("Content-Type");
        /// </code>
        ///
        /// <para><b>Check rate limits (common in APIs):</b></para>
        /// <code>
        /// if (result.Headers.ContainsKey("X-RateLimit-Remaining"))
        /// {
        ///     var remaining = int.Parse(result.Headers["X-RateLimit-Remaining"]);
        ///     if (remaining < 10)
        ///         Console.WriteLine("⚠️ Only {0} API calls left!", remaining);
        /// }
        /// </code>
        ///
        /// <para><b>Common headers:</b></para>
        /// <list type="bullet">
        /// <item><b>Content-Type</b> - Format of the data (application/json, text/html)</item>
        /// <item><b>Content-Length</b> - Size in bytes</item>
        /// <item><b>Location</b> - Where you got redirected to</item>
        /// <item><b>Set-Cookie</b> - Cookies to store</item>
        /// <item><b>Cache-Control</b> - How long to cache</item>
        /// </list>
        /// </summary>
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// <para><b>Quick success check - true if status is 200-299.</b></para>
        ///
        /// <para>The easiest way to check if your request worked:</para>
        /// <code>
        /// if (result.IsSuccess)
        /// {
        ///     // It worked! Do something with result.Body
        /// }
        /// else
        /// {
        ///     // Something went wrong, check result.StatusCode
        /// }
        /// </code>
        ///
        /// <para>What's considered success: 200 OK, 201 Created, 204 No Content, etc.</para>
        /// <para>What's NOT success: 404 Not Found, 500 Server Error, etc.</para>
        /// </summary>
        public bool IsSuccess => StatusCode >= 200 && StatusCode < 300;

        /// <summary>
        /// <para><b>Binary data for files like images, PDFs, downloads.</b></para>
        ///
        /// <para>When you download non-text files, the bytes are here:</para>
        /// <code>
        /// // Download an image
        /// var result = await Curl.Execute("curl https://example.com/logo.png");
        ///
        /// if (result.IsBinary)
        /// {
        ///     File.WriteAllBytes("logo.png", result.BinaryData);
        ///     Console.WriteLine($"Saved {result.BinaryData.Length} bytes");
        /// }
        /// </code>
        /// </summary>
        public byte[] BinaryData { get; set; }

        /// <summary>
        /// <para><b>Is this binary data? (images, PDFs, etc.)</b></para>
        ///
        /// <para>Quick check before accessing BinaryData:</para>
        /// <code>
        /// if (result.IsBinary)
        ///     File.WriteAllBytes("file.bin", result.BinaryData);
        /// else
        ///     File.WriteAllText("file.txt", result.Body);
        /// </code>
        /// </summary>
        public bool IsBinary => BinaryData != null && BinaryData.Length > 0;

        /// <summary>
        /// <para><b>The original curl command that was executed.</b></para>
        ///
        /// <para>Useful for debugging or retrying:</para>
        /// <code>
        /// Console.WriteLine($"Executed: {result.Command}");
        ///
        /// // Retry the same command
        /// var retry = await Curl.Execute(result.Command);
        /// </code>
        /// </summary>
        public string Command { get; set; }

        /// <summary>
        /// <para><b>Detailed timing information (like curl -w).</b></para>
        ///
        /// <para>See how long each phase took:</para>
        /// <code>
        /// Console.WriteLine($"DNS lookup: {result.Timings.NameLookup}ms");
        /// Console.WriteLine($"Connect: {result.Timings.Connect}ms");
        /// Console.WriteLine($"Total: {result.Timings.Total}ms");
        /// </code>
        /// </summary>
        public CurlTimings Timings { get; set; }

        /// <summary>
        /// <para><b>Files that were saved (if using -o flag).</b></para>
        ///
        /// <para>Track what files were created:</para>
        /// <code>
        /// foreach (var file in result.OutputFiles)
        /// {
        ///     Console.WriteLine($"Saved: {file}");
        /// }
        /// </code>
        /// </summary>
        public List<string> OutputFiles { get; set; } = new List<string>();

        /// <summary>
        /// <para><b>Any exception if the request failed completely.</b></para>
        ///
        /// <para>Only set for network failures, not HTTP errors:</para>
        /// <code>
        /// if (result.Exception != null)
        /// {
        ///     // Network/DNS/Timeout failure
        ///     Console.WriteLine($"Failed: {result.Exception.Message}");
        /// }
        /// else if (!result.IsSuccess)
        /// {
        ///     // HTTP error (404, 500, etc)
        ///     Console.WriteLine($"HTTP {result.StatusCode}");
        /// }
        /// </code>
        /// </summary>
        public Exception Exception { get; set; }

        #endregion

        #region JSON Operations - Working with JSON responses

        /// <summary>
        /// <para><b>Parse the JSON response into your C# class.</b></para>
        ///
        /// <para>The most common operation - turning JSON into objects:</para>
        /// <code>
        /// // Define your class matching the JSON structure
        /// public class User
        /// {
        ///     public string Name { get; set; }
        ///     public string Email { get; set; }
        ///     public int Id { get; set; }
        /// }
        ///
        /// // Parse the response
        /// var user = result.ParseJson&lt;User&gt;();
        /// Console.WriteLine($"Hello {user.Name}!");
        ///
        /// // Or parse arrays
        /// var users = result.ParseJson&lt;List&lt;User&gt;&gt;();
        /// Console.WriteLine($"Found {users.Count} users");
        /// </code>
        ///
        /// <para><b>Tip:</b> Use https://json2csharp.com to generate C# classes from JSON!</para>
        /// </summary>
        /// <typeparam name="T">The type to deserialize to (your class)</typeparam>
        /// <returns>Your object with data from the JSON</returns>
        /// <exception cref="JsonException">If the JSON is invalid or doesn't match your type</exception>
        public T ParseJson<T>()
        {
            if (string.IsNullOrEmpty(Body))
                throw new InvalidOperationException("Cannot parse JSON: Body is empty");

            try
            {
                #if NETSTANDARD2_0
                return Newtonsoft.Json.JsonConvert.DeserializeObject<T>(Body);
                #else
                return System.Text.Json.JsonSerializer.Deserialize<T>(Body);
                #endif
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to parse JSON as {typeof(T).Name}: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// <para><b>Parse JSON response (alternative name, same as ParseJson).</b></para>
        ///
        /// <para>Some people prefer AsJson, some prefer ParseJson. Both work!</para>
        /// <code>
        /// var data = result.AsJson&lt;MyData&gt;();
        /// // Same as: result.ParseJson&lt;MyData&gt;()
        /// </code>
        /// </summary>
        public T AsJson<T>() => ParseJson<T>();

        /// <summary>
        /// <para><b>Parse JSON as dynamic object (when you don't have a class).</b></para>
        ///
        /// <para>Useful for quick exploration or simple JSON:</para>
        /// <code>
        /// dynamic json = result.AsJsonDynamic();
        /// Console.WriteLine(json.name);    // Access properties directly
        /// Console.WriteLine(json.users[0].email);  // Navigate arrays
        ///
        /// // Iterate dynamic arrays
        /// foreach (var item in json.items)
        /// {
        ///     Console.WriteLine(item.title);
        /// }
        /// </code>
        ///
        /// <para><b>Note:</b> No compile-time checking! Prefer typed classes when possible.</para>
        /// </summary>
        public dynamic AsJsonDynamic()
        {
            #if NETSTANDARD2_0
            return Newtonsoft.Json.JsonConvert.DeserializeObject(Body);
            #else
            return System.Text.Json.JsonDocument.Parse(Body);
            #endif
        }

        #endregion

        #region Save Operations - Save responses to files

        /// <summary>
        /// <para><b>Save the response to a file - works for both text and binary!</b></para>
        ///
        /// <para>Smart saving - automatically handles text vs binary:</para>
        /// <code>
        /// // Save any response
        /// result.SaveToFile("output.txt");     // Text saved as text
        /// result.SaveToFile("image.png");      // Binary saved as binary
        ///
        /// // Chain operations (returns this)
        /// result
        ///     .SaveToFile("backup.json")       // Save a backup
        ///     .ParseJson&lt;Data&gt;();              // Then parse it
        /// </code>
        ///
        /// <para><b>Path examples:</b></para>
        /// <code>
        /// result.SaveToFile("file.txt");              // Current directory
        /// result.SaveToFile("data/file.txt");         // Relative path
        /// result.SaveToFile(@"C:\temp\file.txt");     // Absolute path
        /// result.SaveToFile("/home/user/file.txt");   // Linux/Mac path
        /// </code>
        /// </summary>
        /// <param name="filePath">Where to save the file</param>
        /// <returns>This result (for chaining)</returns>
        public CurlResult SaveToFile(string filePath)
        {
            if (BinaryData != null)
                File.WriteAllBytes(filePath, BinaryData);
            else
                File.WriteAllText(filePath, Body ?? "");

            OutputFiles.Add(filePath);
            return this;
        }

        /// <summary>
        /// <para><b>Save the response to a file asynchronously.</b></para>
        ///
        /// <para>Same as SaveToFile but doesn't block:</para>
        /// <code>
        /// await result.SaveToFileAsync("large-file.json");
        ///
        /// // Or chain async operations
        /// await result
        ///     .SaveToFileAsync("backup.json")
        ///     .ContinueWith(_ => Console.WriteLine("Saved!"));
        /// </code>
        /// </summary>
        public async Task<CurlResult> SaveToFileAsync(string filePath)
        {
            if (BinaryData != null)
                await File.WriteAllBytesAsync(filePath, BinaryData);
            else
                await File.WriteAllTextAsync(filePath, Body ?? "");

            OutputFiles.Add(filePath);
            return this;
        }

        /// <summary>
        /// <para><b>Save as formatted JSON file (pretty-printed).</b></para>
        ///
        /// <para>Makes JSON human-readable with indentation:</para>
        /// <code>
        /// // Save with nice formatting
        /// result.SaveAsJson("data.json");           // Pretty-printed
        /// result.SaveAsJson("data.json", false);    // Minified
        ///
        /// // Before: {"name":"John","age":30}
        /// // After:  {
        /// //           "name": "John",
        /// //           "age": 30
        /// //         }
        /// </code>
        /// </summary>
        /// <param name="filePath">Where to save the JSON file</param>
        /// <param name="indented">true for pretty formatting (default), false for minified</param>
        /// <returns>This result (for chaining)</returns>
        public CurlResult SaveAsJson(string filePath, bool indented = true)
        {
            string formatted;

            try
            {
                #if NETSTANDARD2_0
                var obj = Newtonsoft.Json.JsonConvert.DeserializeObject(Body);
                formatted = Newtonsoft.Json.JsonConvert.SerializeObject(obj,
                    indented ? Newtonsoft.Json.Formatting.Indented : Newtonsoft.Json.Formatting.None);
                #else
                using var doc = System.Text.Json.JsonDocument.Parse(Body);
                var options = new System.Text.Json.JsonSerializerOptions { WriteIndented = indented };
                formatted = System.Text.Json.JsonSerializer.Serialize(doc.RootElement, options);
                #endif
            }
            catch
            {
                // If not valid JSON, save as-is
                formatted = Body;
            }

            File.WriteAllText(filePath, formatted);
            OutputFiles.Add(filePath);
            return this;
        }

        /// <summary>
        /// <para><b>Save JSON response as CSV file (for JSON arrays).</b></para>
        ///
        /// <para>Converts JSON arrays to CSV for Excel:</para>
        /// <code>
        /// // JSON: [{"name":"John","age":30}, {"name":"Jane","age":25}]
        /// result.SaveAsCsv("users.csv");
        ///
        /// // Creates CSV:
        /// // name,age
        /// // John,30
        /// // Jane,25
        ///
        /// // Open in Excel
        /// Process.Start("users.csv");
        /// </code>
        ///
        /// <para><b>Note:</b> Only works with JSON arrays of objects.</para>
        /// </summary>
        public CurlResult SaveAsCsv(string filePath)
        {
            var csv = ConvertJsonToCsv(Body);
            File.WriteAllText(filePath, csv);
            OutputFiles.Add(filePath);
            return this;
        }

        /// <summary>
        /// <para><b>Append response to an existing file.</b></para>
        ///
        /// <para>Add to a file without overwriting:</para>
        /// <code>
        /// // Log all responses
        /// result.AppendToFile("api-log.txt");
        ///
        /// // Build up a file over time
        /// foreach (var url in urls)
        /// {
        ///     var r = await Curl.Execute($"curl {url}");
        ///     r.AppendToFile("combined.txt");
        /// }
        /// </code>
        /// </summary>
        public CurlResult AppendToFile(string filePath)
        {
            if (BinaryData != null)
            {
                using var stream = new FileStream(filePath, FileMode.Append);
                stream.Write(BinaryData, 0, BinaryData.Length);
            }
            else
            {
                File.AppendAllText(filePath, Body ?? "");
            }
            return this;
        }

        #endregion

        #region Header Operations - Working with HTTP headers

        /// <summary>
        /// <para><b>Get a specific header value (case-insensitive).</b></para>
        ///
        /// <para>Easy header access with null safety:</para>
        /// <code>
        /// // Get content type
        /// var contentType = result.GetHeader("Content-Type");
        /// if (contentType?.Contains("json") == true)
        /// {
        ///     var data = result.ParseJson&lt;MyData&gt;();
        /// }
        ///
        /// // Check rate limits
        /// var remaining = result.GetHeader("X-RateLimit-Remaining");
        /// if (remaining != null &amp;&amp; int.Parse(remaining) &lt; 10)
        /// {
        ///     Console.WriteLine("Slow down!");
        /// }
        /// </code>
        /// </summary>
        /// <param name="headerName">Name of the header (case doesn't matter)</param>
        /// <returns>Header value or null if not found</returns>
        public string GetHeader(string headerName)
        {
            return Headers.TryGetValue(headerName, out var value) ? value : null;
        }

        /// <summary>
        /// <para><b>Check if a header exists.</b></para>
        ///
        /// <para>Test for header presence:</para>
        /// <code>
        /// if (result.HasHeader("Set-Cookie"))
        /// {
        ///     // Server sent cookies
        ///     var cookie = result.GetHeader("Set-Cookie");
        /// }
        /// </code>
        /// </summary>
        public bool HasHeader(string headerName)
        {
            return Headers.ContainsKey(headerName);
        }

        #endregion

        #region Validation Operations - Ensure everything worked

        /// <summary>
        /// <para><b>Throw an exception if the request wasn't successful (not 200-299).</b></para>
        ///
        /// <para>Use this when you expect success and want to fail fast:</para>
        /// <code>
        /// try
        /// {
        ///     var data = result
        ///         .EnsureSuccess()      // Throws if not 200-299
        ///         .ParseJson&lt;Data&gt;();  // Only runs if successful
        /// }
        /// catch (CurlHttpException ex)
        /// {
        ///     Console.WriteLine($"Failed with status {ex.StatusCode}");
        /// }
        /// </code>
        ///
        /// <para><b>Common pattern in APIs:</b></para>
        /// <code>
        /// var user = (await Curl.Execute("curl https://api.example.com/user/123"))
        ///     .EnsureSuccess()
        ///     .ParseJson&lt;User&gt;();
        /// </code>
        /// </summary>
        /// <returns>This result if successful (for chaining)</returns>
        /// <exception cref="CurlHttpException">Thrown if status is not 200-299</exception>
        public CurlResult EnsureSuccess()
        {
            if (!IsSuccess)
            {
                throw new CurlHttpException($"HTTP request failed with status {StatusCode}", StatusCode)
                {
                    ResponseBody = Body,
                    ResponseHeaders = Headers
                };
            }
            return this;
        }

        /// <summary>
        /// <para><b>Throw if status doesn't match what you expect.</b></para>
        ///
        /// <para>Validate specific status codes:</para>
        /// <code>
        /// // Expect 201 Created
        /// result.EnsureStatus(201);
        ///
        /// // Expect 204 No Content
        /// result.EnsureStatus(204);
        /// </code>
        /// </summary>
        /// <param name="expectedStatus">The status code you expect</param>
        /// <returns>This result if status matches (for chaining)</returns>
        /// <exception cref="CurlHttpException">Thrown if status doesn't match</exception>
        public CurlResult EnsureStatus(int expectedStatus)
        {
            if (StatusCode != expectedStatus)
            {
                throw new CurlHttpException(
                    $"Expected status {expectedStatus} but got {StatusCode}",
                    StatusCode);
            }
            return this;
        }

        /// <summary>
        /// <para><b>Throw if response body doesn't contain expected text.</b></para>
        ///
        /// <para>Validate response content:</para>
        /// <code>
        /// // Make sure we got the right response
        /// result.EnsureContains("success");
        ///
        /// // Check for error messages
        /// if (result.Body.Contains("error"))
        /// {
        ///     result.EnsureContains("recoverable");  // Make sure it's recoverable
        /// }
        /// </code>
        /// </summary>
        public CurlResult EnsureContains(string expectedText)
        {
            if (Body?.Contains(expectedText) != true)
            {
                throw new InvalidOperationException($"Response does not contain '{expectedText}'");
            }
            return this;
        }

        #endregion

        #region Retry Operations - Try again if something went wrong

        /// <summary>
        /// <para><b>Retry the same curl command again.</b></para>
        ///
        /// <para>Simple retry for transient failures:</para>
        /// <code>
        /// // First attempt
        /// var result = await Curl.Execute("curl https://flaky-api.example.com");
        ///
        /// // Retry if it failed
        /// if (!result.IsSuccess)
        /// {
        ///     result = await result.Retry();
        /// }
        ///
        /// // Retry with delay
        /// if (result.StatusCode == 429)  // Too many requests
        /// {
        ///     await Task.Delay(5000);
        ///     result = await result.Retry();
        /// }
        /// </code>
        /// </summary>
        /// <returns>New result from retrying the command</returns>
        public async Task<CurlResult> Retry()
        {
            if (string.IsNullOrEmpty(Command))
                throw new InvalidOperationException("Cannot retry: Original command not available");

            return await Curl.Execute(Command);
        }

        /// <summary>
        /// <para><b>Retry with modifications to the original command.</b></para>
        ///
        /// <para>Retry with different settings:</para>
        /// <code>
        /// // Retry with longer timeout
        /// var result = await result.RetryWith(settings =>
        /// {
        ///     settings.Timeout = TimeSpan.FromSeconds(60);
        /// });
        ///
        /// // Retry with authentication
        /// var result = await result.RetryWith(settings =>
        /// {
        ///     settings.AddHeader("Authorization", "Bearer " + token);
        /// });
        /// </code>
        /// </summary>
        public async Task<CurlResult> RetryWith(Action<CurlSettings> configure)
        {
            if (string.IsNullOrEmpty(Command))
                throw new InvalidOperationException("Cannot retry: Original command not available");

            var settings = new CurlSettings();
            configure(settings);
            return await Curl.Execute(Command, settings);
        }

        #endregion

        #region Display Operations - Show results in console

        /// <summary>
        /// <para><b>Print the response body to console.</b></para>
        ///
        /// <para>Quick debugging output:</para>
        /// <code>
        /// result.PrintBody();  // Just prints the body
        ///
        /// // Chain with other operations
        /// result
        ///     .PrintBody()           // Debug output
        ///     .SaveToFile("out.txt") // Also save it
        ///     .ParseJson&lt;Data&gt;();   // Then parse
        /// </code>
        /// </summary>
        /// <returns>This result (for chaining)</returns>
        public CurlResult PrintBody()
        {
            Console.WriteLine(Body);
            return this;
        }

        /// <summary>
        /// <para><b>Print status code and body to console.</b></para>
        ///
        /// <para>More detailed debug output:</para>
        /// <code>
        /// result.Print();
        /// // Output:
        /// // Status: 200
        /// // {"name":"John","age":30}
        /// </code>
        /// </summary>
        public CurlResult Print()
        {
            Console.WriteLine($"Status: {StatusCode}");
            Console.WriteLine(Body);
            return this;
        }

        /// <summary>
        /// <para><b>Print everything - status, headers, and body (like curl -v).</b></para>
        ///
        /// <para>Full debug output:</para>
        /// <code>
        /// result.PrintVerbose();
        /// // Output:
        /// // Status: 200
        /// // Headers:
        /// //   Content-Type: application/json
        /// //   Content-Length: 123
        /// // Body:
        /// // {"name":"John"}
        /// </code>
        /// </summary>
        public CurlResult PrintVerbose()
        {
            Console.WriteLine($"Status: {StatusCode}");
            Console.WriteLine("Headers:");
            foreach (var header in Headers)
            {
                Console.WriteLine($"  {header.Key}: {header.Value}");
            }
            Console.WriteLine("Body:");
            Console.WriteLine(Body);

            if (Timings != null)
            {
                Console.WriteLine("Timings:");
                Console.WriteLine($"  DNS: {Timings.NameLookup}ms");
                Console.WriteLine($"  Connect: {Timings.Connect}ms");
                Console.WriteLine($"  Total: {Timings.Total}ms");
            }

            return this;
        }

        #endregion

        #region Transformation Operations - Change or extract data

        /// <summary>
        /// <para><b>Transform the result using your own function.</b></para>
        ///
        /// <para>Extract or convert data however you need:</para>
        /// <code>
        /// // Extract just what you need
        /// var name = result.Transform(r =>
        /// {
        ///     var user = r.ParseJson&lt;User&gt;();
        ///     return user.Name;
        /// });
        ///
        /// // Convert to your own type
        /// var summary = result.Transform(r => new
        /// {
        ///     Success = r.IsSuccess,
        ///     Size = r.Body?.Length ?? 0,
        ///     Type = r.GetHeader("Content-Type")
        /// });
        /// </code>
        /// </summary>
        public T Transform<T>(Func<CurlResult, T> transformer)
        {
            return transformer(this);
        }

        /// <summary>
        /// <para><b>Extract lines that match a condition.</b></para>
        ///
        /// <para>Filter text responses:</para>
        /// <code>
        /// // Keep only error lines
        /// result.FilterLines(line => line.Contains("ERROR"));
        ///
        /// // Remove empty lines
        /// result.FilterLines(line => !string.IsNullOrWhiteSpace(line));
        ///
        /// // Keep lines starting with data
        /// result.FilterLines(line => line.StartsWith("data:"));
        /// </code>
        /// </summary>
        public CurlResult FilterLines(Func<string, bool> predicate)
        {
            if (Body != null)
            {
                var lines = Body.Split('\n').Where(predicate);
                Body = string.Join("\n", lines);
            }
            return this;
        }

        #endregion

        #region Private Helper Methods

        private string ConvertJsonToCsv(string json)
        {
            try
            {
                var sb = new StringBuilder();

                #if NETSTANDARD2_0
                var array = Newtonsoft.Json.Linq.JArray.Parse(json);
                if (array.Count == 0) return "";

                var first = array[0] as Newtonsoft.Json.Linq.JObject;
                if (first != null)
                {
                    // Headers
                    var headers = first.Properties().Select(p => p.Name).ToList();
                    sb.AppendLine(string.Join(",", headers));

                    // Rows
                    foreach (Newtonsoft.Json.Linq.JObject obj in array)
                    {
                        var values = headers.Select(h =>
                        {
                            var val = obj[h]?.ToString() ?? "";
                            if (val.Contains(",") || val.Contains("\""))
                                val = "\"" + val.Replace("\"", "\"\"") + "\"";
                            return val;
                        });
                        sb.AppendLine(string.Join(",", values));
                    }
                }
                #else
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Array)
                    return Body;

                var array = doc.RootElement.EnumerateArray().ToList();
                if (array.Count == 0) return "";

                var first = array[0];
                if (first.ValueKind == System.Text.Json.JsonValueKind.Object)
                {
                    // Headers
                    var headers = first.EnumerateObject().Select(p => p.Name).ToList();
                    sb.AppendLine(string.Join(",", headers));

                    // Rows
                    foreach (var obj in array)
                    {
                        var values = headers.Select(h =>
                        {
                            if (obj.TryGetProperty(h, out var prop))
                            {
                                var val = prop.ToString();
                                if (val.Contains(",") || val.Contains("\""))
                                    val = "\"" + val.Replace("\"", "\"\"") + "\"";
                                return val;
                            }
                            return "";
                        });
                        sb.AppendLine(string.Join(",", values));
                    }
                }
                #endif

                return sb.ToString();
            }
            catch
            {
                return Body; // Return as-is if not valid JSON array
            }
        }

        #endregion
    }

    /// <summary>
    /// <para><b>Detailed timing breakdown of the curl operation.</b></para>
    ///
    /// <para>See where time was spent (like curl -w):</para>
    /// <code>
    /// if (result.Timings.Total > 2000)
    /// {
    ///     Console.WriteLine("Slow request! Let's see why:");
    ///     Console.WriteLine($"DNS: {result.Timings.NameLookup}ms");
    ///     Console.WriteLine($"Connect: {result.Timings.Connect}ms");
    ///     Console.WriteLine($"SSL: {result.Timings.AppConnect}ms");
    ///     Console.WriteLine($"Wait: {result.Timings.StartTransfer}ms");
    /// }
    /// </code>
    /// </summary>
    public class CurlTimings
    {
        /// <summary>DNS resolution time in milliseconds</summary>
        public double NameLookup { get; set; }

        /// <summary>TCP connection time in milliseconds</summary>
        public double Connect { get; set; }

        /// <summary>SSL/TLS handshake time in milliseconds</summary>
        public double AppConnect { get; set; }

        /// <summary>Time until request was sent in milliseconds</summary>
        public double PreTransfer { get; set; }

        /// <summary>Time spent on redirects in milliseconds</summary>
        public double Redirect { get; set; }

        /// <summary>Time until first byte received in milliseconds</summary>
        public double StartTransfer { get; set; }

        /// <summary>Total time in milliseconds</summary>
        public double Total { get; set; }
    }

    /// <summary>
    /// <para><b>Exception for HTTP errors (4xx, 5xx status codes).</b></para>
    ///
    /// <para>Thrown by EnsureSuccess() when request fails:</para>
    /// <code>
    /// try
    /// {
    ///     result.EnsureSuccess();
    /// }
    /// catch (CurlHttpException ex)
    /// {
    ///     Console.WriteLine($"HTTP {ex.StatusCode}: {ex.Message}");
    ///     Console.WriteLine($"Response was: {ex.ResponseBody}");
    /// }
    /// </code>
    /// </summary>
    public class CurlHttpException : Exception
    {
        /// <summary>The HTTP status code that caused the error</summary>
        public int StatusCode { get; }

        /// <summary>The response body (may contain error details)</summary>
        public string ResponseBody { get; set; }

        /// <summary>The response headers</summary>
        public Dictionary<string, string> ResponseHeaders { get; set; }

        public CurlHttpException(string message, int statusCode) : base(message)
        {
            StatusCode = statusCode;
        }
    }
}