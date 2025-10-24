/***************************************************************************
 * HTTP Request Performance Benchmarks
 *
 * Tests the performance of executing HTTP requests
 *
 * By Jacob Mellor
 * Sponsored by IronSoftware
 ***************************************************************************/

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using CurlDotNet;
using CurlDotNet.Core;

namespace CurlDotNet.Benchmarks
{
    [MemoryDiagnoser]
    [OrderProvider(SummaryOrderProvider.FastestToSlowest)]
    [RankColumn]
    public class HttpRequestBenchmark
    {
        private HttpClient _httpClient;
        private string _testServerUrl;

        [GlobalSetup]
        public void Setup()
        {
            _httpClient = new HttpClient();

            // Use httpbin.org for testing (or mock server if available)
            _testServerUrl = "https://httpbin.org";
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            _httpClient?.Dispose();
        }

        [Benchmark(Baseline = true)]
        public async Task<CurlResult> CurlDotNet_SimpleGet()
        {
            return await Curl.Execute($"curl {_testServerUrl}/get");
        }

        [Benchmark]
        public async Task<HttpResponseMessage> HttpClient_SimpleGet()
        {
            return await _httpClient.GetAsync($"{_testServerUrl}/get");
        }

        [Benchmark]
        public async Task<CurlResult> CurlDotNet_PostJson()
        {
            return await Curl.Execute($@"
                curl -X POST {_testServerUrl}/post
                -H 'Content-Type: application/json'
                -d '{{""name"":""test"",""value"":123}}'
            ");
        }

        [Benchmark]
        public async Task<HttpResponseMessage> HttpClient_PostJson()
        {
            var content = new StringContent("{\"name\":\"test\",\"value\":123}",
                System.Text.Encoding.UTF8, "application/json");
            return await _httpClient.PostAsync($"{_testServerUrl}/post", content);
        }

        [Benchmark]
        public async Task<CurlResult> CurlDotNet_WithHeaders()
        {
            return await Curl.Execute($@"
                curl {_testServerUrl}/headers
                -H 'Authorization: Bearer token123'
                -H 'X-Custom-Header: value'
                -H 'Accept: application/json'
            ");
        }

        [Benchmark]
        public async Task<HttpResponseMessage> HttpClient_WithHeaders()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"{_testServerUrl}/headers");
            request.Headers.Add("Authorization", "Bearer token123");
            request.Headers.Add("X-Custom-Header", "value");
            request.Headers.Add("Accept", "application/json");
            return await _httpClient.SendAsync(request);
        }

        [Params(1, 5, 10)]
        public int ConcurrentRequests { get; set; }

        [Benchmark]
        public async Task CurlDotNet_Concurrent()
        {
            var tasks = new List<Task<CurlResult>>();
            for (int i = 0; i < ConcurrentRequests; i++)
            {
                tasks.Add(Curl.Execute($"curl {_testServerUrl}/get?id={i}"));
            }
            await Task.WhenAll(tasks);
        }

        [Benchmark]
        public async Task HttpClient_Concurrent()
        {
            var tasks = new List<Task<HttpResponseMessage>>();
            for (int i = 0; i < ConcurrentRequests; i++)
            {
                tasks.Add(_httpClient.GetAsync($"{_testServerUrl}/get?id={i}"));
            }
            await Task.WhenAll(tasks);
        }

        [Benchmark]
        public async Task<CurlResult[]> CurlDotNet_ExecuteMany()
        {
            var commands = new string[ConcurrentRequests];
            for (int i = 0; i < ConcurrentRequests; i++)
            {
                commands[i] = $"curl {_testServerUrl}/get?id={i}";
            }
            return await Curl.ExecuteMany(commands);
        }

        [Benchmark]
        public async Task<CurlResult> CurlDotNet_WithRetry()
        {
            var settings = new CurlSettings()
                .WithRetries(3, 100)
                .WithTimeout(10);

            return await Curl.Execute($"curl {_testServerUrl}/status/500", settings);
        }
    }
}