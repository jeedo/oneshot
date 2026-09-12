using System.Net;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Security;

// Task 20 pinned the ordinary bypass attempts. These cover the ways an attacker might still hope to mint a
// fresh rate-limit partition: a header ASP.NET does not process, address forms the parser might mishandle,
// and rotation within an allocation a single client controls.
[Trait("Threat", "T11")]
public sealed class RateLimitBypassTests : IClassFixture<OneShotFactory>
{
    private const int ReadLimit = 10;

    private readonly OneShotFactory _factory;

    public RateLimitBypassTests(OneShotFactory factory) => _factory = factory;

    [Fact]
    public async Task TheRfc7239ForwardedHeader_IsIgnoredEvenWhenSentByAKnownProxy()
    {
        // ASP.NET Core's middleware understands only X-Forwarded-*, so `Forwarded` must never move the
        // partition — otherwise a proxy operator's clients could rotate it freely.
        using var app = Limited(knownProxy: "10.0.0.1");
        using var client = app.CreateClient();

        for (var i = 0; i < ReadLimit; i++)
        {
            Assert.Equal(HttpStatusCode.NotFound, await Read(client, "10.0.0.1", ("Forwarded", $"for=198.51.100.{i + 1}")));
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, await Read(client, "10.0.0.1", ("Forwarded", "for=198.51.100.200")));
    }

    [Fact]
    public async Task XRealIp_IsIgnoredEvenWhenSentByAKnownProxy()
    {
        using var app = Limited(knownProxy: "10.0.0.1");
        using var client = app.CreateClient();

        for (var i = 0; i < ReadLimit; i++)
        {
            Assert.Equal(HttpStatusCode.NotFound, await Read(client, "10.0.0.1", ("X-Real-IP", $"198.51.100.{i + 1}")));
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, await Read(client, "10.0.0.1", ("X-Real-IP", "198.51.100.200")));
    }

    [Fact]
    public async Task AddressesDifferingOnlyBelowTheSlash64_ShareOnePartition()
    {
        using var app = Limited();
        using var client = app.CreateClient();

        // Every one of these is a distinct address a single client can mint at will inside its own /64.
        var suffixes = new[]
        {
            "::1", "::2", ":ffff:ffff:ffff:ffff", ":1:2:3:4", "::dead:beef", "::a", "::b", "::c", "::d", "::e",
        };
        foreach (var suffix in suffixes)
        {
            Assert.Equal(HttpStatusCode.NotFound, await Read(client, $"2001:db8:1:2{suffix}"));
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, await Read(client, "2001:db8:1:2::99"));
    }

    [Fact]
    public async Task AChangeWithinThePrefixItself_IsADifferentPartition()
    {
        using var app = Limited();
        using var client = app.CreateClient();

        for (var i = 0; i < ReadLimit; i++)
        {
            Assert.Equal(HttpStatusCode.NotFound, await Read(client, $"2001:db8:1:2::{i + 1:x}"));
        }
        Assert.Equal(HttpStatusCode.TooManyRequests, await Read(client, "2001:db8:1:2::ff"));

        // The neighbouring /64 is genuinely a different network, so it keeps its own budget.
        Assert.Equal(HttpStatusCode.NotFound, await Read(client, "2001:db8:1:3::1"));
    }

    [Fact]
    public async Task TheSameClientReachedOverIpv4AndItsMappedIpv6Form_SharesOnePartition()
    {
        using var app = Limited();
        using var client = app.CreateClient();

        for (var i = 0; i < ReadLimit; i++)
        {
            var address = i % 2 == 0 ? "203.0.113.77" : "::ffff:203.0.113.77";
            Assert.Equal(HttpStatusCode.NotFound, await Read(client, address));
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, await Read(client, "::ffff:203.0.113.77"));
    }

    [Fact]
    public async Task AForwardedForCarryingAPortOrBrackets_StillCannotMintPartitions()
    {
        using var app = Limited(knownProxy: "10.0.0.1");
        using var client = app.CreateClient();
        var forged = new[]
        {
            "198.51.100.1:1234", "[2001:db8::1]:443", "not-an-address", "", "198.51.100.1, 198.51.100.2",
            "198.51.100.1:99999", "[::1]", "0.0.0.0",
        };

        // Whatever the parser makes of these, the budget is the one client's: at most one of them may be
        // honoured as an address, so the limit still arrives within the number of requests sent.
        var rejected = 0;
        for (var i = 0; i < ReadLimit * 3; i++)
        {
            if (await Read(client, "10.0.0.1", ("X-Forwarded-For", forged[i % forged.Length])) == HttpStatusCode.TooManyRequests)
            {
                rejected++;
            }
        }

        Assert.True(rejected > 0, "rotating malformed X-Forwarded-For values escaped the rate limit entirely");
    }

    [Fact]
    public async Task AForgedForwardedProto_DoesNotConvinceTheAppItIsAlreadyOnHttps()
    {
        using var app = _factory.WithWebHostBuilder(builder => builder.UseSetting("HTTPS_PORT", "443"));
        using var client = app.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/", UriKind.Relative));
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
        request.Headers.TryAddWithoutValidation(RemoteIpStartupFilter.Header, "203.0.113.90");

        using var response = await client.SendAsync(request);

        // No proxy is configured, so the header is not consumed and the plain-HTTP request is still redirected.
        Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
    }

    private WebApplicationFactory<Program> Limited(string? knownProxy = null)
    {
        return _factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("RateLimiting:ReadPerWindow", ReadLimit.ToString(System.Globalization.CultureInfo.InvariantCulture));
            if (knownProxy is not null)
            {
                builder.UseSetting("ForwardedHeaders:KnownProxies:0", knownProxy);
            }
        });
    }

    private static async Task<HttpStatusCode> Read(HttpClient client, string remoteIp, params (string Name, string Value)[] headers)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"/api/secrets/{SecretId.NewId()}", UriKind.Relative));
        request.Headers.TryAddWithoutValidation(RemoteIpStartupFilter.Header, remoteIp);
        foreach (var (name, value) in headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        using var response = await client.SendAsync(request);
        return response.StatusCode;
    }
}
