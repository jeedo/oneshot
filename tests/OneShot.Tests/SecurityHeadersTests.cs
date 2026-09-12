using System.Net;

using Microsoft.AspNetCore.Mvc.Testing;

using OneShot.Tests.Infrastructure;
using OneShot.Web;

namespace OneShot.Tests;

[Trait("Threat", "T7")]
[Trait("Threat", "T8")]
public sealed class SecurityHeadersTests : IClassFixture<OneShotFactory>
{
    private const string ExpectedPermissionsPolicy =
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), "
        + "geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), "
        + "picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), "
        + "web-share=(), xr-spatial-tracking=()";

    private static readonly string ExpectedContentSecurityPolicy =
        $"default-src 'none'; script-src '{ClientBundle.Integrity}'; style-src 'self'; connect-src 'self'; "
        + "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    private readonly OneShotFactory _factory;

    public SecurityHeadersTests(OneShotFactory factory) => _factory = factory;

    [Theory]
    [InlineData("/")]
    [InlineData("/js/oneshot.js")]
    [InlineData("/does-not-exist")]
    [InlineData("/api/secrets/does-not-exist")]
    public async Task EveryResponse_CarriesTheHardeningHeaders(string path)
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.Equal(ExpectedContentSecurityPolicy, Header(response, "Content-Security-Policy"));
        Assert.Equal("nosniff", Header(response, "X-Content-Type-Options"));
        Assert.Equal("no-referrer", Header(response, "Referrer-Policy"));
        Assert.Equal("DENY", Header(response, "X-Frame-Options"));
        Assert.Equal(ExpectedPermissionsPolicy, Header(response, "Permissions-Policy"));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/s/abcdefghijklmnopqrstuv")]
    [InlineData("/api/secrets/abcdefghijklmnopqrstuv")]
    public async Task SecretPaths_AreNeverCached(string path)
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.Equal("no-store", Header(response, "Cache-Control"));
        Assert.Equal("no-cache", Header(response, "Pragma"));
    }

    [Fact]
    public async Task Bundle_IsNotMarkedNoStore()
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri("/js/oneshot.js", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("Cache-Control"));
    }

    [Fact]
    public async Task HttpsResponse_CarriesOneYearPreloadHsts()
    {
        using var client = _factory.CreateClient();
        client.BaseAddress = new Uri("https://oneshot.test/");

        using var response = await client.GetAsync(new Uri("/", UriKind.Relative));

        Assert.Equal("max-age=31536000; includeSubDomains; preload", Header(response, "Strict-Transport-Security"));
    }

    [Fact]
    public async Task PlainHttpRequest_IsRedirectedToHttps()
    {
        using var factory = _factory.WithWebHostBuilder(builder => builder.UseSetting("HTTPS_PORT", "443"));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.BaseAddress = new Uri("http://oneshot.test/");

        using var response = await client.GetAsync(new Uri("/", UriKind.Relative));

        Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
        Assert.Equal(new Uri("https://oneshot.test/"), response.Headers.Location);
        Assert.False(response.Headers.Contains("Strict-Transport-Security"));
    }

    private static string Header(HttpResponseMessage response, string name)
    {
        var headers = response.Headers.TryGetValues(name, out var values)
            ? values
            : response.Content.Headers.TryGetValues(name, out var contentValues) ? contentValues : [];

        return Assert.Single(headers);
    }
}
