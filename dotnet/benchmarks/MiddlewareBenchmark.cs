/***************************************************************************
 * Middleware Performance Benchmarks
 *
 * Tests the overhead of middleware pipeline
 *
 * By Jacob Mellor
 * Sponsored by IronSoftware
 ***************************************************************************/

using System;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using CurlDotNet;
using CurlDotNet.Core;
using CurlDotNet.Middleware;

namespace CurlDotNet.Benchmarks
{
    [MemoryDiagnoser]
    [OrderProvider(SummaryOrderProvider.FastestToSlowest)]
    [RankColumn]
    public class MiddlewareBenchmark
    {
        private CurlMiddlewarePipeline _emptyPipeline;
        private CurlMiddlewarePipeline _singleMiddleware;
        private CurlMiddlewarePipeline _multipleMiddleware;
        private CurlMiddlewarePipeline _heavyMiddleware;

        private readonly Func<CurlContext, Task<CurlResult>> _mockHandler = async (context) =>
        {
            // Simulate some work
            await Task.Delay(1);
            return new CurlResult
            {
                StatusCode = 200,
                Body = "Mock response"
            };
        };

        [GlobalSetup]
        public void Setup()
        {
            // Empty pipeline (baseline)
            _emptyPipeline = new CurlMiddlewarePipeline(_mockHandler);

            // Single middleware
            _singleMiddleware = new CurlMiddlewarePipeline(_mockHandler)
                .Use(new LoggingMiddleware(msg => { }));

            // Multiple middleware
            _multipleMiddleware = CurlMiddlewarePipelineBuilder.CreateBuilder()
                .UseLogging(msg => { })
                .UseTiming()
                .UseRetry(3)
                .WithHandler(_mockHandler)
                .Build();

            // Heavy middleware with caching
            _heavyMiddleware = CurlMiddlewarePipelineBuilder.CreateBuilder()
                .UseLogging(msg => { })
                .UseTiming()
                .UseCaching(TimeSpan.FromMinutes(5))
                .UseRetry(3)
                .UseRateLimit(100)
                .WithHandler(_mockHandler)
                .Build();
        }

        [Benchmark(Baseline = true)]
        public async Task<CurlResult> NoMiddleware()
        {
            var context = new CurlContext
            {
                Command = "curl https://api.example.com"
            };
            return await _emptyPipeline.ExecuteAsync(context);
        }

        [Benchmark]
        public async Task<CurlResult> SingleMiddleware()
        {
            var context = new CurlContext
            {
                Command = "curl https://api.example.com"
            };
            return await _singleMiddleware.ExecuteAsync(context);
        }

        [Benchmark]
        public async Task<CurlResult> MultipleMiddleware()
        {
            var context = new CurlContext
            {
                Command = "curl https://api.example.com"
            };
            return await _multipleMiddleware.ExecuteAsync(context);
        }

        [Benchmark]
        public async Task<CurlResult> HeavyMiddleware()
        {
            var context = new CurlContext
            {
                Command = "curl https://api.example.com"
            };
            return await _heavyMiddleware.ExecuteAsync(context);
        }

        [Benchmark]
        public async Task<CurlResult> DynamicMiddleware()
        {
            var pipeline = CurlMiddlewarePipelineBuilder.CreateBuilder()
                .Use(async (context, next) =>
                {
                    // Custom logic before
                    context.Properties["StartTime"] = DateTime.UtcNow;
                    var result = await next();
                    // Custom logic after
                    context.Properties["EndTime"] = DateTime.UtcNow;
                    return result;
                })
                .WithHandler(_mockHandler)
                .Build();

            var context = new CurlContext
            {
                Command = "curl https://api.example.com"
            };

            return await pipeline.ExecuteAsync(context);
        }

        [Params(1, 5, 10, 20)]
        public int MiddlewareCount { get; set; }

        [Benchmark]
        public async Task<CurlResult> ScalingMiddleware()
        {
            var builder = CurlMiddlewarePipelineBuilder.CreateBuilder();

            for (int i = 0; i < MiddlewareCount; i++)
            {
                int index = i;
                builder.Use(async (context, next) =>
                {
                    context.Properties[$"Middleware{index}"] = true;
                    return await next();
                });
            }

            var pipeline = builder.WithHandler(_mockHandler).Build();

            var context = new CurlContext
            {
                Command = "curl https://api.example.com"
            };

            return await pipeline.ExecuteAsync(context);
        }
    }
}