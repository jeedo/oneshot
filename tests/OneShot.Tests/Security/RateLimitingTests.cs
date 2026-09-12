using System.Net;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Security;

[Trait("Threat", "T3")]
[Trait("Threat", "T11")]
public sealed class RateLimitingTests : IClassFixture<OneShotFactory>
{
    private readonly OneShotFactory _factory;

    public RateLimitingTests(OneShotFactory factory) => _factory = factory;

    [Fact]
    public async Task Create_AllowsTwentyPerMinutePerClient_ThenRejectsWithRetryAfter()
    {
        using var client = _factory.CreateClient();
        var before = Store.Count;

        for (var i = 0; i < 20; i++)
        {
            using var ok = await client.SendAsync(Create("203.0.113.10"));
            Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
        }
        using var rejected = await client.SendAsync(Create("203.0.113.10"));

        await AssertRateLimited(rejected);
        Assert.Equal(before + 20, Store.Count);
    }

    [Fact]
    public async Task Read_AllowsThirtyPerMinute_SharedByPeekAndReveal()
    {
        using var client = _factory.CreateClient();
        var id = CreateSecret();

        for (var i = 0; i < 29; i++)
        {
            using var ok = await client.SendAsync(Peek(id, "203.0.113.20"));
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        using var lastPeek = await client.SendAsync(Peek(id, "203.0.113.20"));
        using var reveal = await client.SendAsync(Reveal(id, "203.0.113.20"));

        Assert.Equal(HttpStatusCode.OK, lastPeek.StatusCode);
        await AssertRateLimited(reveal);
        Assert.Equal(SecretState.Available, Store.Peek(id).State);
    }

    [Fact]
    public async Task CreateAndRead_HaveIndependentBudgets()
    {
        using var client = _factory.CreateClient();
        var id = CreateSecret();

        for (var i = 0; i < 30; i++)
        {
            using var ok = await client.SendAsync(Peek(id, "203.0.113.30"));
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        using var peek = await client.SendAsync(Peek(id, "203.0.113.30"));
        using var create = await client.SendAsync(Create("203.0.113.30"));

        await AssertRateLimited(peek);
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
    }

    [Fact]
    public async Task DifferentClients_HaveSeparateBudgets()
    {
        using var client = _factory.CreateClient();
        var id = CreateSecret();

        for (var i = 0; i < 30; i++)
        {
            using var ok = await client.SendAsync(Peek(id, "203.0.113.40"));
        }
        using var exhausted = await client.SendAsync(Peek(id, "203.0.113.40"));
        using var other = await client.SendAsync(Peek(id, "203.0.113.41"));

        await AssertRateLimited(exhausted);
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
    }

    [Fact]
    public async Task Ipv6Clients_ShareABudgetPerSlash64()
    {
        using var client = _factory.CreateClient();
        var id = CreateSecret();

        for (var i = 0; i < 30; i++)
        {
            using var ok = await client.SendAsync(Peek(id, $"2001:db8:1:2::{i + 1:x}"));
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        using var sameSlash64 = await client.SendAsync(Peek(id, "2001:db8:1:2:ffff:ffff:ffff:ffff"));
        using var otherSlash64 = await client.SendAsync(Peek(id, "2001:db8:1:3::1"));

        await AssertRateLimited(sameSlash64);
        Assert.Equal(HttpStatusCode.OK, otherSlash64.StatusCode);
    }

    [Fact]
    public async Task Ipv4MappedIpv6_IsBucketedAsTheIpv4Address()
    {
        using var client = _factory.CreateClient();
        var id = CreateSecret();

        for (var i = 0; i < 30; i++)
        {
            using var ok = await client.SendAsync(Peek(id, "203.0.113.50"));
        }
        using var mapped = await client.SendAsync(Peek(id, "::ffff:203.0.113.50"));

        await AssertRateLimited(mapped);
    }

    [Fact]
    public async Task ClientWithoutAnAddress_IsStillLimited()
    {
        using var client = _factory.CreateClient();
        var id = CreateSecret();

        for (var i = 0; i < 30; i++)
        {
            using var ok = await client.SendAsync(Peek(id, "none"));
        }
        using var rejected = await client.SendAsync(Peek(id, "none"));

        await AssertRateLimited(rejected);
    }

    [Theory]
    [InlineData("X-Forwarded-For", "203.0.113.60")]
    [InlineData("X-Real-IP", "203.0.113.61")]
    [InlineData("Forwarded", "203.0.113.62")]
    public async Task WithoutConfiguredProxies_ForwardingHeadersCannotCreateNewBuckets(string header, string clientIp)
    {
        using var client = _factory.CreateClient();
        var id = CreateSecret();

        for (var i = 0; i < 30; i++)
        {
            using var request = Peek(id, clientIp);
            request.Headers.TryAddWithoutValidation(header, header == "Forwarded" ? $"for=198.51.100.{i + 1}" : $"198.51.100.{i + 1}");
            using var ok = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        using var final = Peek(id, clientIp);
        final.Headers.TryAddWithoutValidation(header, "198.51.100.200");
        using var rejected = await client.SendAsync(final);

        await AssertRateLimited(rejected);
    }

    [Fact]
    public async Task WithAKnownProxy_OnlyItsForwardedForIsHonoured()
    {
        using var app = _factory.WithWebHostBuilder(builder => builder.UseSetting("ForwardedHeaders:KnownProxies:0", "10.0.0.1"));
        using var client = app.CreateClient();
        var id = Assert.IsType<Created>(app.Services.GetRequiredService<ISecretStore>().Create(new byte[32], new byte[12], TimeSpan.FromHours(1))).Id;

        for (var i = 0; i < 31; i++)
        {
            using var request = Peek(id, "10.0.0.1");
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", $"198.51.100.{i + 1}");
            using var ok = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        for (var i = 0; i < 30; i++)
        {
            using var request = Peek(id, "10.0.0.2");
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", $"198.51.100.{i + 1}");
            using var ok = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        using var unknownProxy = Peek(id, "10.0.0.2");
        unknownProxy.Headers.TryAddWithoutValidation("X-Forwarded-For", "198.51.100.250");
        using var rejected = await client.SendAsync(unknownProxy);

        await AssertRateLimited(rejected);
    }

    [Fact]
    public async Task WithAKnownProxy_OnlyTheNearestHopIsTrusted()
    {
        using var app = _factory.WithWebHostBuilder(builder => builder.UseSetting("ForwardedHeaders:KnownProxies:0", "10.0.0.1"));
        using var client = app.CreateClient();
        var id = Assert.IsType<Created>(app.Services.GetRequiredService<ISecretStore>().Create(new byte[32], new byte[12], TimeSpan.FromHours(1))).Id;

        for (var i = 0; i < 30; i++)
        {
            using var request = Peek(id, "10.0.0.1");
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", $"198.51.100.{i + 1}, 192.0.2.7");
            using var ok = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        using var final = Peek(id, "10.0.0.1");
        final.Headers.TryAddWithoutValidation("X-Forwarded-For", "198.51.100.250, 192.0.2.7");
        using var rejected = await client.SendAsync(final);

        await AssertRateLimited(rejected);
    }

    [Fact]
    public async Task RejectedResponse_StillCarriesTheSecurityHeaders()
    {
        using var client = _factory.CreateClient();
        for (var i = 0; i < 21; i++)
        {
            using var response = await client.SendAsync(Create("203.0.113.70"));
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                Assert.True(response.Headers.Contains("Content-Security-Policy"));
                Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
                return;
            }
        }

        Assert.Fail("the limiter never rejected");
    }

    private static async Task AssertRateLimited(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var retryAfter = response.Headers.RetryAfter?.Delta;
        Assert.NotNull(retryAfter);
        Assert.InRange(retryAfter.Value, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(60));
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(429, problem.RootElement.GetProperty("status").GetInt32());
        Assert.Equal("rateLimited", problem.RootElement.GetProperty("code").GetString());
    }

    private InMemorySecretStore Store => _factory.Services.GetRequiredService<InMemorySecretStore>();

    private string CreateSecret()
    {
        return Assert.IsType<Created>(Store.Create(new byte[32], new byte[12], TimeSpan.FromHours(1))).Id;
    }

    private static HttpRequestMessage Create(string ip)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/secrets", UriKind.Relative))
        {
            Content = new StringContent("{\"ciphertext\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA\",\"nonce\":\"8PHy8_T19vf4-fr7\"}", Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation(RemoteIpStartupFilter.Header, ip);
        return request;
    }

    private static HttpRequestMessage Peek(string id, string ip)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"/api/secrets/{id}", UriKind.Relative));
        request.Headers.TryAddWithoutValidation(RemoteIpStartupFilter.Header, ip);
        return request;
    }

    private static HttpRequestMessage Reveal(string id, string ip)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"/api/secrets/{id}/reveal", UriKind.Relative))
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation("X-OneShot-Reveal", "1");
        request.Headers.TryAddWithoutValidation(RemoteIpStartupFilter.Header, ip);
        return request;
    }
}
