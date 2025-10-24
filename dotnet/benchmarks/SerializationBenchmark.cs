/***************************************************************************
 * Serialization Performance Benchmarks
 *
 * Tests JSON parsing and serialization performance
 *
 * By Jacob Mellor
 * Sponsored by IronSoftware
 ***************************************************************************/

using System.Collections.Generic;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using CurlDotNet.Core;

namespace CurlDotNet.Benchmarks
{
    [MemoryDiagnoser]
    [OrderProvider(SummaryOrderProvider.FastestToSlowest)]
    [RankColumn]
    public class SerializationBenchmark
    {
        private CurlResult _smallJsonResult;
        private CurlResult _mediumJsonResult;
        private CurlResult _largeJsonResult;
        private CurlResult _csvResult;

        public class TestModel
        {
            public int Id { get; set; }
            public string Name { get; set; }
            public string Email { get; set; }
            public bool Active { get; set; }
            public List<string> Tags { get; set; }
        }

        [GlobalSetup]
        public void Setup()
        {
            // Small JSON
            _smallJsonResult = new CurlResult
            {
                StatusCode = 200,
                Body = @"{""id"":1,""name"":""John Doe"",""email"":""john@example.com"",""active"":true}"
            };

            // Medium JSON (array of objects)
            var mediumJson = "[";
            for (int i = 0; i < 100; i++)
            {
                if (i > 0) mediumJson += ",";
                mediumJson += $@"{{""id"":{i},""name"":""User{i}"",""email"":""user{i}@example.com"",""active"":true,""tags"":[""tag1"",""tag2"",""tag3""]}}";
            }
            mediumJson += "]";

            _mediumJsonResult = new CurlResult
            {
                StatusCode = 200,
                Body = mediumJson
            };

            // Large JSON (nested structure)
            var largeJson = "{\"data\":[";
            for (int i = 0; i < 1000; i++)
            {
                if (i > 0) largeJson += ",";
                largeJson += $@"{{""id"":{i},""name"":""User{i}"",""email"":""user{i}@example.com"",""active"":true,""metadata"":{{""created"":""2024-01-01"",""updated"":""2024-01-02"",""version"":1}},""tags"":[""tag1"",""tag2"",""tag3"",""tag4"",""tag5""]}}";
            }
            largeJson += "]}";

            _largeJsonResult = new CurlResult
            {
                StatusCode = 200,
                Body = largeJson
            };

            // CSV data (for CSV conversion)
            _csvResult = new CurlResult
            {
                StatusCode = 200,
                Body = mediumJson
            };
        }

        [Benchmark(Baseline = true)]
        public TestModel ParseSmallJson()
        {
            return _smallJsonResult.ParseJson<TestModel>();
        }

        [Benchmark]
        public List<TestModel> ParseMediumJson()
        {
            return _mediumJsonResult.ParseJson<List<TestModel>>();
        }

        [Benchmark]
        public dynamic ParseLargeJsonDynamic()
        {
            return _largeJsonResult.AsJson();
        }

        [Benchmark]
        public CurlResult SaveJsonToFile()
        {
            return _mediumJsonResult.SaveToJson("temp_benchmark.json", indented: true);
        }

        [Benchmark]
        public CurlResult SaveCsvToFile()
        {
            return _csvResult.SaveToCsv("temp_benchmark.csv");
        }

        [Benchmark]
        public string QueryJsonPath()
        {
            return _smallJsonResult.Query("$.name");
        }

        [Benchmark]
        public CurlResult MapJsonBody()
        {
            return _smallJsonResult.Map(body => body.ToUpper());
        }

        [Benchmark]
        public CurlResult FilterJsonLines()
        {
            return _mediumJsonResult.FilterLines(line => line.Contains("\"active\":true"));
        }

        [Params(1, 10, 100)]
        public int TransformIterations { get; set; }

        [Benchmark]
        public string ChainedTransformations()
        {
            var result = _smallJsonResult;

            for (int i = 0; i < TransformIterations; i++)
            {
                result = result
                    .Map(body => body.Replace("John", "Jane"))
                    .Map(body => body.Replace("@example.com", "@test.com"));
            }

            return result.Body;
        }
    }
}