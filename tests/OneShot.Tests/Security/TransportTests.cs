using System.Net;
using System.Text;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Security;

// SecurityHeadersTests already shows a plain-HTTP request is answered with a 307. What matters for T8 is the
// consequence: the redirect happens before routing, so nothing the request asked for actually runs. A reveal
// that consumed the secret and then told the caller to come back over TLS would have spent it in the clear.
[Trait("Threat", "T8")]
public sealed class TransportTests : IClassFixture<CapturingWebApplicationFactory>
{
    private const string PlainOrigin = "http://oneshot.test";

    private readonly CapturingWebApplicationFactory _factory;

    public TransportTests(CapturingWebApplicationFactory factory) => _factory = factory;

    public static TheoryData<string, string> SecretEndpoints => new()
    {
        { "GET", "/" },
        { "GET", "/s/{id}" },
        { "GET", "/api/secrets/{id}" },
        { "POST", "/api/secrets" },
        { "POST", "/api/secrets/{id}/reveal" },
        { "GET", "/api/whoami" },
    };

    [Theory]
    [MemberData(nameof(SecretEndpoints))]
    public async Task OverPlainHttp_TheRequestIsRedirectedBeforeAnythingItAskedForRuns(string method, string template)
    {
        using var app = Redirecting();
        var store = app.Services.GetRequiredService<InMemorySecretStore>();
        var id = Create(store);
        var before = (store.Count, store.CiphertextBytes);
        _factory.Logs.Clear();
        using var client = PlainClient(app);

        using var response = await client.SendAsync(Request(method, template.Replace("{id}", id, StringComparison.Ordinal)));

        Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
        Assert.Equal("https", response.Headers.Location?.Scheme);
        // Nothing ran: no secret consumed, no capacity taken, no audit written, and no identity handed out
        // before the connection was upgraded.
        Assert.Equal(before, (store.Count, store.CiphertextBytes));
        Assert.Equal(SecretState.Available, store.Peek(id).State);
        Assert.DoesNotContain(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
        Assert.False(response.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task TheSameRequestOverHttps_DoesRun_SoTheRedirectIsWhatStoppedIt()
    {
        // The control: without it, "nothing ran" above could be true because the request was malformed.
        using var app = Redirecting();
        var store = app.Services.GetRequiredService<InMemorySecretStore>();
        var id = Create(store);
        using var client = app.CreateClient(NoRedirects);
        client.BaseAddress = new Uri("https://oneshot.test/");

        using var response = await client.SendAsync(Request("POST", $"/api/secrets/{id}/reveal"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(SecretState.Consumed, store.Peek(id).State);
    }

    [Theory]
    [InlineData("/s/abcdefghijklmnopqrstuv", "/s/abcdefghijklmnopqrstuv")]
    [InlineData("/api/secrets/abcdefghijklmnopqrstuv?note=keep", "/api/secrets/abcdefghijklmnopqrstuv?note=keep")]
    public async Task TheRedirectPreservesThePathAndQuery_SoTheRetryLandsInTheSamePlace(string requested, string expected)
    {
        using var app = Redirecting();
        using var client = PlainClient(app);

        using var response = await client.GetAsync(new Uri(requested, UriKind.Relative));

        Assert.Equal(new Uri($"https://oneshot.test{expected}"), response.Headers.Location);
    }

    [Fact]
    public async Task ARedirectIsNotCachedAsPermanent_SoAMisconfiguredHostCanBeCorrected()
    {
        using var app = Redirecting();
        using var client = PlainClient(app);

        using var response = await client.GetAsync(new Uri("/", UriKind.Relative));

        // 307 rather than 301/308: a permanent redirect is pinned in browser caches for a long time, which is
        // painful to undo if the deployment ever changes.
        Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
        Assert.Null(response.Headers.CacheControl?.MaxAge);
    }

    [Fact]
    public async Task ThePlainHttpRedirect_CarriesNoHstsHeaderOfItsOwn()
    {
        using var app = Redirecting();
        using var client = PlainClient(app);

        using var response = await client.GetAsync(new Uri("/", UriKind.Relative));

        // HSTS over plain HTTP is ignored by browsers and would be a false reassurance in a capture.
        Assert.False(response.Headers.Contains("Strict-Transport-Security"));
    }

    private static readonly WebApplicationFactoryClientOptions NoRedirects = new() { AllowAutoRedirect = false, HandleCookies = false };

    private WebApplicationFactory<Program> Redirecting() =>
        _factory.WithWebHostBuilder(builder => builder.UseSetting("HTTPS_PORT", "443"));

    private static HttpClient PlainClient(WebApplicationFactory<Program> app)
    {
        var client = app.CreateClient(NoRedirects);
        client.BaseAddress = new Uri($"{PlainOrigin}/");
        return client;
    }

    private static string Create(ISecretStore store) =>
        Assert.IsType<Created>(store.Create(new byte[32], new byte[12], TimeSpan.FromHours(1))).Id;

    private static HttpRequestMessage Request(string method, string path)
    {
        var request = new HttpRequestMessage(new HttpMethod(method), new Uri(path, UriKind.Relative));
        if (method == "POST")
        {
            request.Content = new StringContent(
                path.EndsWith("reveal", StringComparison.Ordinal)
                    ? "{}"
                    : "{\"ciphertext\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA\",\"nonce\":\"8PHy8_T19vf4-fr7\"}",
                Encoding.UTF8,
                "application/json");
            request.Headers.TryAddWithoutValidation("X-OneShot-Reveal", "1");
        }

        return request;
    }
}
