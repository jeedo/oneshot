using System.Net;
using System.Security.Authentication;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Security;

namespace OneShot.Tests;

[Trait("Threat", "T5")]
[Trait("Threat", "T13")]
public sealed class KestrelHardeningTests : IClassFixture<KestrelHardeningTests.KestrelFactory>
{
    private readonly KestrelFactory _factory;

    public KestrelHardeningTests(KestrelFactory factory) => _factory = factory;

    [Fact]
    public void Apply_RemovesServerHeaderAndBoundsEveryRequestLimit()
    {
        var options = new KestrelServerOptions();

        KestrelHardening.Apply(options);

        Assert.False(options.AddServerHeader);
        Assert.Equal(128 * 1024, options.Limits.MaxRequestBodySize);
        Assert.Equal(4 * 1024, options.Limits.MaxRequestLineSize);
        Assert.Equal(16 * 1024, options.Limits.MaxRequestHeadersTotalSize);
        Assert.Equal(64, options.Limits.MaxRequestHeaderCount);
        Assert.Equal(TimeSpan.FromSeconds(60), options.Limits.KeepAliveTimeout);
        Assert.Equal(TimeSpan.FromSeconds(15), options.Limits.RequestHeadersTimeout);
    }

    [Fact]
    public void ConfigureHttps_AllowsOnlyTls12AndTls13()
    {
        var https = new HttpsConnectionAdapterOptions();

        KestrelHardening.ConfigureHttps(https);

        // CA5398 flags the literal TLS versions; the test must name them to pin the TLS 1.2+ floor (T8), see docs/threat-model.md.
#pragma warning disable CA5398
        Assert.Equal(SslProtocols.Tls12 | SslProtocols.Tls13, https.SslProtocols);
#pragma warning restore CA5398
    }

    [Fact]
    public async Task Responses_CarryNoServerHeader()
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri("/", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("Server"));
    }

    [Fact]
    public async Task RequestBody_Over128KiB_IsRejectedWith413()
    {
        using var client = _factory.CreateClient();
        using var body = new ByteArrayContent(new byte[(128 * 1024) + 1]);

        using var response = await client.PostAsync(new Uri("/__drain", UriKind.Relative), body);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task RequestBody_At128KiB_IsAccepted()
    {
        using var client = _factory.CreateClient();
        using var body = new ByteArrayContent(new byte[128 * 1024]);

        using var response = await client.PostAsync(new Uri("/__drain", UriKind.Relative), body);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task TooManyRequestHeaders_AreRejectedWith431()
    {
        using var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/", UriKind.Relative));
        for (var i = 0; i < 70; i++)
        {
            request.Headers.TryAddWithoutValidation($"X-Probe-{i}", "1");
        }

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.RequestHeaderFieldsTooLarge, response.StatusCode);
    }

    public sealed class KestrelFactory : OneShotFactory
    {
        public KestrelFactory() => UseKestrel();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureServices(services => services.AddTransient<IStartupFilter, DrainEndpointFilter>());
        }

        private sealed class DrainEndpointFilter : IStartupFilter
        {
            public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
            {
                app.Use(async (context, pipeline) =>
                {
                    if (context.Request.Path == "/__drain")
                    {
                        await context.Request.Body.CopyToAsync(Stream.Null, context.RequestAborted);
                        context.Response.StatusCode = StatusCodes.Status200OK;
                        return;
                    }

                    await pipeline(context);
                });
                next(app);
            };
        }
    }
}
