using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;

using OneShot.Tests.Infrastructure;

namespace OneShot.Tests;

[Trait("Threat", "T1")]
[Trait("Threat", "T5")]
public sealed class LoggingTests : IClassFixture<CapturingWebApplicationFactory>
{
    private const string QueryCanary = "QUERYCANARY7f3a";

    private readonly CapturingWebApplicationFactory _factory;

    public LoggingTests(CapturingWebApplicationFactory factory) => _factory = factory;

    [Fact]
    public void Console_IsTheOnlyProductionProvider_AndWritesJson()
    {
        var providers = _factory.Services.GetServices<ILoggerProvider>().Where(provider => provider is not LogSink).ToList();

        var console = Assert.Single(providers);
        Assert.IsType<ConsoleLoggerProvider>(console);
        Assert.Equal(ConsoleFormatterNames.Json, _factory.Services.GetRequiredService<IOptions<ConsoleLoggerOptions>>().Value.FormatterName);
    }

    [Fact]
    public void FrameworkHttpLogging_IsSilenced_InCode()
    {
        var rules = _factory.Services.GetRequiredService<IOptions<LoggerFilterOptions>>().Value.Rules;

        Assert.Contains(rules, rule => rule.CategoryName == "Microsoft.AspNetCore.HttpLogging" && rule.LogLevel == LogLevel.None);
        Assert.Contains(rules, rule => rule.CategoryName == "Microsoft.AspNetCore.Hosting.Diagnostics" && rule.LogLevel >= LogLevel.Warning);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/js/oneshot.js")]
    [InlineData("/s/abcdefghijklmnopqrstuv")]
    [InlineData("/api/secrets/abcdefghijklmnopqrstuv")]
    [InlineData("/does-not-exist")]
    public async Task NoLogLine_ContainsTheQueryString(string path)
    {
        _factory.Logs.Clear();
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri($"{path}?k={QueryCanary}", UriKind.Relative));

        Assert.DoesNotContain(_factory.Logs.Entries, entry => entry.Contains(QueryCanary));
    }

    [Fact]
    public async Task Sink_WouldSeeTheQueryString_IfRequestLoggingWereOn()
    {
        using var factory = _factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.PostConfigure<LoggerFilterOptions>(options =>
                options.Rules.Add(new LoggerFilterRule(null, "Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Information, null)))));
        var sink = factory.Services.GetServices<ILoggerProvider>().OfType<LogSink>().Single();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync(new Uri($"/?k={QueryCanary}", UriKind.Relative));

        Assert.Contains(sink.Entries, entry => entry.Contains(QueryCanary));
    }
}
