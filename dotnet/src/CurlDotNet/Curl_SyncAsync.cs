/***************************************************************************
 * CurlDotNet - Synchronous vs Asynchronous API Design
 *
 * Following .NET best practices for sync/async methods:
 * - Async methods end with "Async" suffix
 * - Sync methods have no suffix
 * - Both can accept CancellationToken
 * - Async is preferred, sync is for compatibility
 *
 * Copyright (C) 2024 IronSoftware
 ***************************************************************************/

using System;
using System.Threading;
using System.Threading.Tasks;
using CurlDotNet.Core;

namespace CurlDotNet
{
    public static partial class Curl
    {
        #region ASYNCHRONOUS Methods (Preferred) - Don't block the thread

        /// <summary>
        /// <para><b>🎯 ASYNCHRONOUS - Execute curl command WITHOUT blocking (RECOMMENDED).</b></para>
        ///
        /// <para>This is the PREFERRED way to execute curl commands in modern .NET applications.
        /// It doesn't block your thread, so your UI stays responsive and your server can handle more requests.</para>
        ///
        /// <para><b>When to use ASYNC (this method):</b></para>
        /// <list type="bullet">
        /// <item>✅ Web applications (ASP.NET Core)</item>
        /// <item>✅ Desktop apps (WPF, WinForms, MAUI)</item>
        /// <item>✅ Mobile apps (Xamarin, MAUI)</item>
        /// <item>✅ Any modern .NET application</item>
        /// <item>✅ When making multiple requests</item>
        /// <item>✅ When you don't want to freeze the UI</item>
        /// </list>
        ///
        /// <para><b>Example - The RIGHT way in modern apps:</b></para>
        /// <code>
        /// // ✅ GOOD - Doesn't block the thread
        /// public async Task GetDataAsync()
        /// {
        ///     var result = await Curl.ExecuteAsync("curl https://api.example.com");
        ///     ProcessResult(result);
        /// }
        ///
        /// // ✅ GOOD - UI stays responsive
        /// private async void Button_Click(object sender, EventArgs e)
        /// {
        ///     var result = await Curl.ExecuteAsync("curl https://api.example.com");
        ///     textBox.Text = result.Body;
        /// }
        ///
        /// // ✅ GOOD - Web API controller
        /// [HttpGet]
        /// public async Task&lt;IActionResult&gt; GetData()
        /// {
        ///     var result = await Curl.ExecuteAsync("curl https://external-api.com");
        ///     return Ok(result.Body);
        /// }
        /// </code>
        ///
        /// <para><b>Multiple requests in parallel (FAST!):</b></para>
        /// <code>
        /// // Run 3 requests at the same time (takes ~1 second total, not 3!)
        /// var task1 = Curl.ExecuteAsync("curl https://api1.example.com");
        /// var task2 = Curl.ExecuteAsync("curl https://api2.example.com");
        /// var task3 = Curl.ExecuteAsync("curl https://api3.example.com");
        ///
        /// var results = await Task.WhenAll(task1, task2, task3);
        /// </code>
        /// </summary>
        /// <param name="command">The curl command to execute</param>
        /// <returns>A Task that will complete with the result (doesn't block)</returns>
        public static async Task<CurlResult> ExecuteAsync(string command)
        {
            return await _engine.ExecuteAsync(command);
        }

        /// <summary>
        /// <para><b>ASYNCHRONOUS with cancellation - Can be cancelled if taking too long.</b></para>
        ///
        /// <para>Same as ExecuteAsync but can be cancelled. Still non-blocking (async).</para>
        ///
        /// <para><b>Example with timeout:</b></para>
        /// <code>
        /// // Cancel if takes longer than 30 seconds
        /// using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        ///
        /// try
        /// {
        ///     var result = await Curl.ExecuteAsync("curl https://slow-api.com", cts.Token);
        /// }
        /// catch (OperationCanceledException)
        /// {
        ///     Console.WriteLine("Request took too long and was cancelled");
        /// }
        /// </code>
        ///
        /// <para><b>Example with user cancellation:</b></para>
        /// <code>
        /// private CancellationTokenSource _cts;
        ///
        /// async Task StartDownload()
        /// {
        ///     _cts = new CancellationTokenSource();
        ///     var result = await Curl.ExecuteAsync("curl https://large-file.com", _cts.Token);
        /// }
        ///
        /// void CancelButton_Click() => _cts?.Cancel();
        /// </code>
        /// </summary>
        public static async Task<CurlResult> ExecuteAsync(string command, CancellationToken cancellationToken)
        {
            return await _engine.ExecuteAsync(command, cancellationToken);
        }

        /// <summary>
        /// <para><b>ASYNCHRONOUS with settings - Advanced async execution.</b></para>
        /// </summary>
        public static async Task<CurlResult> ExecuteAsync(string command, CurlSettings settings)
        {
            return await _engine.ExecuteAsync(command, settings);
        }

        #endregion

        #region SYNCHRONOUS Methods (Compatibility) - Blocks the thread

        /// <summary>
        /// <para><b>⚠️ SYNCHRONOUS - Execute curl command and WAIT for it to complete (BLOCKS thread).</b></para>
        ///
        /// <para>This method BLOCKS your thread until the HTTP request completes. Your application
        /// will FREEZE during this time. Only use when async is not possible.</para>
        ///
        /// <para><b>When to use SYNC (this method):</b></para>
        /// <list type="bullet">
        /// <item>⚠️ Console applications with simple flow</item>
        /// <item>⚠️ Legacy code that can't use async</item>
        /// <item>⚠️ Unit tests (sometimes)</item>
        /// <item>⚠️ Quick scripts or tools</item>
        /// <item>❌ NEVER in UI applications (will freeze)</item>
        /// <item>❌ NEVER in web applications (reduces throughput)</item>
        /// </list>
        ///
        /// <para><b>Example - When sync is OK:</b></para>
        /// <code>
        /// // ✅ OK - Simple console app
        /// static void Main()
        /// {
        ///     var result = Curl.Execute("curl https://api.example.com");
        ///     Console.WriteLine(result.Body);
        /// }
        ///
        /// // ✅ OK - Unit test
        /// [Test]
        /// public void TestApi()
        /// {
        ///     var result = Curl.Execute("curl https://api.example.com");
        ///     Assert.AreEqual(200, result.StatusCode);
        /// }
        ///
        /// // ❌ BAD - Will freeze UI!
        /// private void Button_Click(object sender, EventArgs e)
        /// {
        ///     var result = Curl.Execute("curl https://api.example.com"); // FREEZES UI!
        ///     textBox.Text = result.Body;
        /// }
        /// </code>
        ///
        /// <para><b>⚠️ WARNING:</b> This blocks your thread. The application cannot do anything else
        /// while waiting for the HTTP response. Use ExecuteAsync instead whenever possible!</para>
        /// </summary>
        /// <param name="command">The curl command to execute</param>
        /// <returns>The result (blocks until complete)</returns>
        public static CurlResult Execute(string command)
        {
            // This BLOCKS the thread until complete
            return ExecuteAsync(command).GetAwaiter().GetResult();
        }

        /// <summary>
        /// <para><b>⚠️ SYNCHRONOUS with cancellation - Blocks thread but can be cancelled.</b></para>
        ///
        /// <para>Still BLOCKS your thread, but can be cancelled. Prefer ExecuteAsync with cancellation.</para>
        ///
        /// <code>
        /// // Blocks thread but can timeout
        /// using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        /// var result = Curl.Execute("curl https://api.example.com", cts.Token);
        /// </code>
        /// </summary>
        public static CurlResult Execute(string command, CancellationToken cancellationToken)
        {
            // This BLOCKS the thread until complete or cancelled
            return ExecuteAsync(command, cancellationToken).GetAwaiter().GetResult();
        }

        /// <summary>
        /// <para><b>⚠️ SYNCHRONOUS with settings - Blocks thread with advanced options.</b></para>
        /// </summary>
        public static CurlResult Execute(string command, CurlSettings settings)
        {
            // This BLOCKS the thread until complete
            return ExecuteAsync(command, settings).GetAwaiter().GetResult();
        }

        #endregion

        #region Quick Helper Methods - Both sync and async versions

        /// <summary>
        /// <para><b>ASYNCHRONOUS GET request (recommended).</b></para>
        /// <code>
        /// var result = await Curl.GetAsync("https://api.example.com");
        /// </code>
        /// </summary>
        public static async Task<CurlResult> GetAsync(string url)
        {
            return await ExecuteAsync($"curl {url}");
        }

        /// <summary>
        /// <para><b>⚠️ SYNCHRONOUS GET request (blocks thread).</b></para>
        /// <code>
        /// var result = Curl.Get("https://api.example.com"); // Blocks!
        /// </code>
        /// </summary>
        public static CurlResult Get(string url)
        {
            return Execute($"curl {url}");
        }

        /// <summary>
        /// <para><b>ASYNCHRONOUS POST request (recommended).</b></para>
        /// <code>
        /// var result = await Curl.PostAsync("https://api.example.com", jsonData);
        /// </code>
        /// </summary>
        public static async Task<CurlResult> PostAsync(string url, string data)
        {
            return await ExecuteAsync($"curl -X POST -d '{data}' {url}");
        }

        /// <summary>
        /// <para><b>⚠️ SYNCHRONOUS POST request (blocks thread).</b></para>
        /// </summary>
        public static CurlResult Post(string url, string data)
        {
            return Execute($"curl -X POST -d '{data}' {url}");
        }

        /// <summary>
        /// <para><b>ASYNCHRONOUS POST with JSON (recommended).</b></para>
        /// <code>
        /// var result = await Curl.PostJsonAsync("https://api.example.com", myObject);
        /// </code>
        /// </summary>
        public static async Task<CurlResult> PostJsonAsync(string url, object data)
        {
            var json = SerializeJson(data);
            return await ExecuteAsync($"curl -X POST -H 'Content-Type: application/json' -d '{json}' {url}");
        }

        /// <summary>
        /// <para><b>⚠️ SYNCHRONOUS POST with JSON (blocks thread).</b></para>
        /// </summary>
        public static CurlResult PostJson(string url, object data)
        {
            var json = SerializeJson(data);
            return Execute($"curl -X POST -H 'Content-Type: application/json' -d '{json}' {url}");
        }

        /// <summary>
        /// <para><b>ASYNCHRONOUS file download (recommended).</b></para>
        /// <code>
        /// await Curl.DownloadAsync("https://example.com/file.zip", "file.zip");
        /// </code>
        /// </summary>
        public static async Task<CurlResult> DownloadAsync(string url, string outputPath)
        {
            return await ExecuteAsync($"curl -o {outputPath} {url}");
        }

        /// <summary>
        /// <para><b>⚠️ SYNCHRONOUS file download (blocks thread).</b></para>
        /// </summary>
        public static CurlResult Download(string url, string outputPath)
        {
            return Execute($"curl -o {outputPath} {url}");
        }

        #endregion

        #region Clear Documentation About Threading

        /// <summary>
        /// <para><b>📚 UNDERSTANDING SYNC vs ASYNC in CurlDotNet</b></para>
        ///
        /// <para><b>ASYNC Methods (end with "Async"):</b></para>
        /// <list type="bullet">
        /// <item>✅ Return Task&lt;CurlResult&gt;</item>
        /// <item>✅ Don't block your thread</item>
        /// <item>✅ UI stays responsive</item>
        /// <item>✅ Server can handle more requests</item>
        /// <item>✅ Can run multiple in parallel</item>
        /// <item>✅ THIS IS WHAT YOU SHOULD USE</item>
        /// </list>
        ///
        /// <para><b>SYNC Methods (no "Async" suffix):</b></para>
        /// <list type="bullet">
        /// <item>⚠️ Return CurlResult directly</item>
        /// <item>⚠️ BLOCK your thread completely</item>
        /// <item>⚠️ UI will FREEZE</item>
        /// <item>⚠️ Server throughput reduced</item>
        /// <item>⚠️ Run one at a time only</item>
        /// <item>⚠️ Only for legacy/simple scenarios</item>
        /// </list>
        ///
        /// <para><b>Examples showing the difference:</b></para>
        /// <code>
        /// // ASYNC - Doesn't block ✅
        /// public async Task MyMethodAsync()
        /// {
        ///     // Thread is FREE to do other work while waiting
        ///     var result = await Curl.ExecuteAsync("curl https://api.example.com");
        ///
        ///     // Can run multiple in parallel (very fast!)
        ///     var task1 = Curl.ExecuteAsync("curl https://api1.example.com");
        ///     var task2 = Curl.ExecuteAsync("curl https://api2.example.com");
        ///     await Task.WhenAll(task1, task2); // Both run at same time
        /// }
        ///
        /// // SYNC - Blocks thread ⚠️
        /// public void MyMethod()
        /// {
        ///     // Thread is BLOCKED here, can't do anything else
        ///     var result = Curl.Execute("curl https://api.example.com");
        ///
        ///     // These run one after another (slow!)
        ///     var result1 = Curl.Execute("curl https://api1.example.com");
        ///     var result2 = Curl.Execute("curl https://api2.example.com");
        /// }
        /// </code>
        ///
        /// <para><b>CancellationToken doesn't determine sync/async!</b></para>
        /// <code>
        /// // ASYNC with cancellation - Still async! ✅
        /// await Curl.ExecuteAsync(command, cancellationToken);
        ///
        /// // SYNC with cancellation - Still blocks! ⚠️
        /// Curl.Execute(command, cancellationToken);
        /// </code>
        /// </summary>
        private static void SyncVsAsyncDocumentation()
        {
            // This method exists only for documentation
            throw new NotImplementedException("This method is for documentation only");
        }

        #endregion
    }
}