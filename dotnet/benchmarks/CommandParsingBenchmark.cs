/***************************************************************************
 * Command Parsing Performance Benchmarks
 *
 * Tests the performance of parsing curl commands
 *
 * By Jacob Mellor
 * Sponsored by IronSoftware
 ***************************************************************************/

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using CurlDotNet;
using CurlDotNet.Core;

namespace CurlDotNet.Benchmarks
{
    [MemoryDiagnoser]
    [OrderProvider(SummaryOrderProvider.FastestToSlowest)]
    [RankColumn]
    public class CommandParsingBenchmark
    {
        private readonly string _simpleCommand = "curl https://api.example.com/data";

        private readonly string _complexCommand = @"
            curl -X POST https://api.example.com/users
            -H 'Content-Type: application/json'
            -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            -H 'Accept: application/json'
            -H 'User-Agent: CurlDotNet/1.0'
            -d '{""name"":""John Doe"",""email"":""john@example.com"",""age"":30}'
            --max-time 30
            --connect-timeout 10
            --retry 3
            --retry-delay 2
            --compressed
            -L
            -k
            -o output.json
            -w '%{http_code}'
        ";

        private readonly string _multipleHeaders = @"
            curl https://api.example.com/data
            -H 'Header1: Value1'
            -H 'Header2: Value2'
            -H 'Header3: Value3'
            -H 'Header4: Value4'
            -H 'Header5: Value5'
            -H 'Header6: Value6'
            -H 'Header7: Value7'
            -H 'Header8: Value8'
            -H 'Header9: Value9'
            -H 'Header10: Value10'
        ";

        [Benchmark(Baseline = true)]
        public ValidationResult ParseSimpleCommand()
        {
            return Curl.Validate(_simpleCommand);
        }

        [Benchmark]
        public ValidationResult ParseComplexCommand()
        {
            return Curl.Validate(_complexCommand);
        }

        [Benchmark]
        public ValidationResult ParseMultipleHeaders()
        {
            return Curl.Validate(_multipleHeaders);
        }

        [Benchmark]
        public ValidationResult ParseWithoutCurlPrefix()
        {
            return Curl.Validate("https://api.example.com/data");
        }

        [Benchmark]
        public string ConvertToHttpClient()
        {
            return Curl.ToHttpClient(_simpleCommand);
        }

        [Benchmark]
        public string ConvertToFetch()
        {
            return Curl.ToFetch(_simpleCommand);
        }

        [Benchmark]
        public string ConvertToPython()
        {
            return Curl.ToPythonRequests(_simpleCommand);
        }

        [Params(1, 10, 100)]
        public int CommandCount { get; set; }

        [Benchmark]
        public void ParseMultipleCommands()
        {
            for (int i = 0; i < CommandCount; i++)
            {
                Curl.Validate($"curl https://api.example.com/data{i}");
            }
        }
    }
}