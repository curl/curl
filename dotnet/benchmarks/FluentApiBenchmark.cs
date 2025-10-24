/***************************************************************************
 * Fluent API Performance Benchmarks
 *
 * Tests the performance of fluent API patterns
 *
 * By Jacob Mellor
 * Sponsored by IronSoftware
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using CurlDotNet;
using CurlDotNet.Core;
using CurlDotNet.Exceptions;

namespace CurlDotNet.Benchmarks
{
    [MemoryDiagnoser]
    [OrderProvider(SummaryOrderProvider.FastestToSlowest)]
    [RankColumn]
    public class FluentApiBenchmark
    {
        private CurlResult _testResult;
        private CurlSettings _basicSettings;
        private CurlException _testException;

        [GlobalSetup]
        public void Setup()
        {
            _testResult = new CurlResult
            {
                StatusCode = 200,
                Body = @"{""status"":""success"",""data"":{""id"":1,""name"":""Test""}}",
                Headers = new Dictionary<string, string>
                {
                    ["Content-Type"] = "application/json",
                    ["X-Request-Id"] = "12345"
                },
                Command = "curl https://api.example.com/data"
            };

            _basicSettings = new CurlSettings();

            _testException = new CurlHttpException(
                "Request failed",
                404,
                "Not Found",
                "Resource not found",
                "curl https://api.example.com/missing"
            );
        }

        [Benchmark(Baseline = true)]
        public CurlSettings CreateBasicSettings()
        {
            return new CurlSettings();
        }

        [Benchmark]
        public CurlSettings CreateFluentSettings()
        {
            return new CurlSettings()
                .WithTimeout(30)
                .WithRetries(3, 1000)
                .WithFollowRedirects(true)
                .WithInsecure(false)
                .WithUserAgent("CurlDotNet/1.0")
                .WithBufferSize(8192);
        }

        [Benchmark]
        public CurlSettings CreateComplexSettings()
        {
            return new CurlSettings()
                .WithTimeout(30)
                .WithConnectTimeout(10)
                .WithRetries(3, 1000)
                .WithFollowRedirects(true)
                .WithInsecure(false)
                .WithHeader("Authorization", "Bearer token123")
                .WithHeader("X-Custom-1", "Value1")
                .WithHeader("X-Custom-2", "Value2")
                .WithProxy("http://proxy.example.com:8080", "user", "pass")
                .WithUserAgent("CurlDotNet/1.0")
                .WithCookies()
                .WithAutoDecompression(true)
                .WithBufferSize(16384)
                .WithProgress((percent, total, current) => { })
                .WithRedirectHandler(url => { })
                .WithCancellation(CancellationToken.None);
        }

        [Benchmark]
        public CurlResult ChainResultOperations()
        {
            return _testResult
                .AssertStatus(200)
                .AssertContains("success")
                .AssertHeader("Content-Type", "application/json")
                .Map(body => body.ToUpper())
                .SaveTo("temp.json");
        }

        [Benchmark]
        public async Task<CurlResult> AsyncResultOperations()
        {
            return await _testResult
                .SaveToFileAsync("temp_async.json")
                .ContinueWith(t => t.Result.SaveToJsonAsync("temp_formatted.json"))
                .Unwrap();
        }

        [Benchmark]
        public string ExtractResultData()
        {
            var json = _testResult.ParseJson<dynamic>();
            var header = _testResult.Header("X-Request-Id");
            var query = _testResult.Query("$.data.name");
            return $"{json}_{header}_{query}";
        }

        [Benchmark]
        public CurlException BuildExceptionWithContext()
        {
            return _testException
                .WithContext("RequestId", "12345")
                .WithContext("UserId", "user-001")
                .WithContext("Timestamp", DateTime.UtcNow)
                .WithSuggestion("Check if the resource exists")
                .WithSuggestion("Verify the URL is correct")
                .WithDiagnostics("Failed at line 42");
        }

        [Benchmark]
        public string ExceptionToDetailedString()
        {
            return _testException.ToDetailedString();
        }

        [Benchmark]
        public string ExceptionToJson()
        {
            return _testException.ToJson();
        }

        [Benchmark]
        public Dictionary<string, object> ExceptionDiagnostics()
        {
            return _testException.GetDiagnosticInfo();
        }

        [Benchmark]
        public bool CheckExceptionRetryable()
        {
            return _testException.IsRetryable();
        }

        [Params(1, 5, 10)]
        public int ChainLength { get; set; }

        [Benchmark]
        public CurlSettings LongFluentChain()
        {
            var settings = new CurlSettings();

            for (int i = 0; i < ChainLength; i++)
            {
                settings = settings
                    .WithHeader($"Header-{i}", $"Value-{i}")
                    .WithTimeout(30 + i);
            }

            return settings;
        }

        [Benchmark]
        public CurlResult LongResultChain()
        {
            var result = _testResult;

            for (int i = 0; i < ChainLength; i++)
            {
                result = result.Map(body => body + i.ToString());
            }

            return result;
        }
    }
}