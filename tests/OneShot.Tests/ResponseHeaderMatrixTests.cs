using System.Buffers.Text;
using System.Net;
using System.Text;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

using OneShot.Tests.Infrastructure;
using OneShot.Web;
using OneShot.Web.Secrets;

namespace OneShot.Tests;

// Tasks 3 and 4 pinned the header values on a handful of paths. This drives every response the app can
// actually produce — each status of each endpoint, the pages, the bundle, 404, 405, 410, 429 and 500 — and
// holds them all to the same set, because a header that is only right on the happy path is not a mitigation.
[Trait("Threat", "T7")]
[Trait("Threat", "T8")]
public sealed class ResponseHeaderMatrixTests : IClassFixture<OneShotFactory>
{
    private const string PermissionsPolicy =
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), "
        + "geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), "
        + "picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), "
        + "web-share=(), xr-spatial-tracking=()";

    private static readonly string ContentSecurityPolicy =
        $"default-src 'none'; script-src '{ClientBundle.Integrity}'; style-src 'self'; connect-src 'self'; "
        + "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    // Headers that name the stack. Kestrel is configured not to send Server (task 5); the rest are IIS/ASP.NET
    // classic leftovers that must never appear whatever hosts this.
    private static readonly string[] FingerprintHeaders =
        ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-SourceFiles"];

    private readonly OneShotFactory _factory;

    public ResponseHeaderMatrixTests(OneShotFactory factory) => _factory = factory;

    // The third column is the expected caching, written out per scenario rather than derived from the app's
    // own path rule — a test that recomputes the rule it is checking agrees with the rule even when it is wrong.
    public static TheoryData<string, HttpStatusCode, bool> Scenarios => new()
    {
        { "create page", HttpStatusCode.OK, true },
        { "reveal page", HttpStatusCode.OK, true },
        { "reveal page for an unknown id", HttpStatusCode.OK, true },
        { "client bundle", HttpStatusCode.OK, false },
        { "healthz", HttpStatusCode.OK, false },
        { "unrouted path", HttpStatusCode.NotFound, false },
        { "method not allowed", HttpStatusCode.MethodNotAllowed, true },
        { "create", HttpStatusCode.Created, true },
        { "create with malformed json", HttpStatusCode.BadRequest, true },
        { "create with the wrong content type", HttpStatusCode.UnsupportedMediaType, true },
        { "peek an available secret", HttpStatusCode.OK, true },
        { "peek a consumed secret", HttpStatusCode.OK, true },
        { "peek an unknown secret", HttpStatusCode.NotFound, true },
        { "reveal", HttpStatusCode.OK, true },
        { "reveal an already consumed secret", HttpStatusCode.Gone, true },
        { "reveal an unknown secret", HttpStatusCode.NotFound, true },
        { "reveal from a foreign origin", HttpStatusCode.Forbidden, true },
        { "whoami without a cookie", HttpStatusCode.Unauthorized, true },
    };

    [Theory]
    [MemberData(nameof(Scenarios))]
    public async Task EveryResponsePath_CarriesExactlyTheHardeningHeaders(string scenario, HttpStatusCode expected, bool noStore)
    {
        using var client = _factory.CreateClient();

        using var response = await SendAsync(client, scenario);

        Assert.Equal(expected, response.StatusCode);
        AssertHardened(response);
        AssertCaching(response, noStore);
    }

    [Fact]
    public async Task ARateLimitedResponse_CarriesThemToo()
    {
        using var app = _factory.WithWebHostBuilder(builder => builder.UseSetting("RateLimiting:ReadPerWindow", "1"));
        using var client = app.CreateClient();
        var id = SecretId.NewId();

        using var first = await client.SendAsync(Peek(id, "203.0.113.7"));
        using var response = await client.SendAsync(Peek(id, "203.0.113.7"));

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        AssertHardened(response);
        AssertCaching(response, noStore: true);
    }

    [Fact]
    public async Task AFailedResponse_CarriesThemToo_EvenThoughTheHandlerClearsTheResponse()
    {
        using var app = _factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services => services.AddSingleton<ISecretStore>(new FaultyStore())));
        using var client = app.CreateClient();

        using var response = await client.GetAsync(new Uri($"/api/secrets/{SecretId.NewId()}", UriKind.Relative));

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        AssertHardened(response);
        AssertCaching(response, noStore: true);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/healthz")]
    [InlineData("/js/oneshot.js")]
    [InlineData("/nowhere")]
    public async Task EveryHttpsResponse_CarriesOneYearPreloadHsts(string path)
    {
        using var client = _factory.CreateClient();
        client.BaseAddress = new Uri("https://oneshot.test/");

        using var response = await client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.Equal("max-age=31536000; includeSubDomains; preload", Single(response, "Strict-Transport-Security"));
    }

    // The bundle is the one script the CSP admits, so all three copies of its digest have to agree: what the
    // server actually serves, what the CSP allows, and what the browser is told to verify.
    [Theory]
    [InlineData("/")]
    [InlineData("/s/abcdefghijklmnopqrstuv")]
    public async Task TheServedBundleDigest_MatchesBothTheCspHashAndTheIntegrityAttribute(string page)
    {
        using var client = _factory.CreateClient();

        using var bundle = await client.GetAsync(new Uri(ClientBundle.RequestPath, UriKind.Relative));
        var served = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(await bundle.Content.ReadAsByteArrayAsync()));
        using var response = await client.GetAsync(new Uri(page, UriKind.Relative));
        var html = WebUtility.HtmlDecode(await response.Content.ReadAsStringAsync());

        Assert.Contains($"script-src 'sha256-{served}'", Single(response, "Content-Security-Policy"), StringComparison.Ordinal);
        Assert.Contains($"integrity=\"sha256-{served}\"", html, StringComparison.Ordinal);
    }

    private static void AssertCaching(HttpResponseMessage response, bool noStore)
    {
        if (noStore)
        {
            // A secret path must never be written to a proxy or browser cache, whatever it answered (T8).
            Assert.True(response.Headers.CacheControl?.NoStore, "response was cacheable");
            Assert.Equal("no-cache", Assert.Single(response.Headers.Pragma).Name);
        }
        else
        {
            Assert.Null(response.Headers.CacheControl);
            Assert.Empty(response.Headers.Pragma);
        }
    }

    private static void AssertHardened(HttpResponseMessage response)
    {
        Assert.Equal(ContentSecurityPolicy, Single(response, "Content-Security-Policy"));
        Assert.Equal("nosniff", Single(response, "X-Content-Type-Options"));
        Assert.Equal("no-referrer", Single(response, "Referrer-Policy"));
        Assert.Equal("DENY", Single(response, "X-Frame-Options"));
        Assert.Equal(PermissionsPolicy, Single(response, "Permissions-Policy"));
        // Site isolation against Spectre-class side-channel reads (ZAP 90004, issue #50) — held to the same
        // "every response, not just the happy path" standard as the rest of this matrix.
        Assert.Equal("require-corp", Single(response, "Cross-Origin-Embedder-Policy"));
        Assert.Equal("same-origin", Single(response, "Cross-Origin-Opener-Policy"));
        Assert.Equal("same-origin", Single(response, "Cross-Origin-Resource-Policy"));

        // TestServer never adds a Server header of its own, so this guards only against the app adding one;
        // the real Kestrel listener is checked in tests/e2e/specs/headers.spec.ts.
        foreach (var name in FingerprintHeaders)
        {
            // NonValidated: Contains() throws on a name the typed collection considers misused, and asking
            // whether a header is absent must never depend on which collection it would have belonged to.
            Assert.False(response.Headers.NonValidated.Contains(name), $"response carried {name}");
            Assert.False(response.Content.Headers.NonValidated.Contains(name), $"response carried {name}");
        }
    }

    private async Task<HttpResponseMessage> SendAsync(HttpClient client, string scenario)
    {
        var store = _factory.Services.GetRequiredService<ISecretStore>();

        switch (scenario)
        {
            case "create page":
                return await client.GetAsync(new Uri("/", UriKind.Relative));
            case "reveal page":
                return await client.GetAsync(new Uri($"/s/{Available(store)}", UriKind.Relative));
            case "reveal page for an unknown id":
                return await client.GetAsync(new Uri($"/s/{SecretId.NewId()}", UriKind.Relative));
            case "client bundle":
                return await client.GetAsync(new Uri(ClientBundle.RequestPath, UriKind.Relative));
            case "healthz":
                return await client.GetAsync(new Uri("/healthz", UriKind.Relative));
            case "unrouted path":
                return await client.GetAsync(new Uri("/nowhere", UriKind.Relative));
            case "method not allowed":
                return await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, new Uri("/api/secrets", UriKind.Relative)));
            case "create":
                return await client.SendAsync(Create(Json($$"""{"ciphertext":"{{B64(new byte[32])}}","nonce":"{{B64(new byte[12])}}"}""")));
            case "create with malformed json":
                return await client.SendAsync(Create(Json("{ nope")));
            case "create with the wrong content type":
                return await client.SendAsync(Create(new StringContent("{}", Encoding.UTF8, "text/plain")));
            case "peek an available secret":
                return await client.GetAsync(new Uri($"/api/secrets/{Available(store)}", UriKind.Relative));
            case "peek a consumed secret":
                return await client.GetAsync(new Uri($"/api/secrets/{Consumed(store)}", UriKind.Relative));
            case "peek an unknown secret":
                return await client.GetAsync(new Uri($"/api/secrets/{SecretId.NewId()}", UriKind.Relative));
            case "reveal":
                return await client.SendAsync(Reveal(Available(store)));
            case "reveal an already consumed secret":
                return await client.SendAsync(Reveal(Consumed(store)));
            case "reveal an unknown secret":
                return await client.SendAsync(Reveal(SecretId.NewId()));
            case "reveal from a foreign origin":
                var forbidden = Reveal(Available(store));
                forbidden.Headers.Remove("Origin");
                forbidden.Headers.TryAddWithoutValidation("Origin", "https://evil.test");
                return await client.SendAsync(forbidden);
            case "whoami without a cookie":
                return await client.GetAsync(new Uri("/api/whoami", UriKind.Relative));
            default:
                throw new ArgumentOutOfRangeException(nameof(scenario), scenario, "Unknown scenario.");
        }
    }

    private static string B64(byte[] bytes) => Base64Url.EncodeToString(bytes);

    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

    private static HttpRequestMessage Create(HttpContent content) =>
        new(HttpMethod.Post, new Uri("/api/secrets", UriKind.Relative)) { Content = content };

    private static HttpRequestMessage Reveal(string id)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"/api/secrets/{id}/reveal", UriKind.Relative))
        {
            Content = Json("{}"),
        };
        request.Headers.TryAddWithoutValidation("X-OneShot-Reveal", "1");
        return request;
    }

    private static HttpRequestMessage Peek(string id, string clientIp)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"/api/secrets/{id}", UriKind.Relative));
        request.Headers.TryAddWithoutValidation(RemoteIpStartupFilter.Header, clientIp);
        return request;
    }

    private static string Available(ISecretStore store) =>
        Assert.IsType<Created>(store.Create(new byte[32], new byte[12], TimeSpan.FromHours(1))).Id;

    private static string Consumed(ISecretStore store)
    {
        var id = Available(store);
        store.TryConsume(id).Secret!.Dispose();
        return id;
    }

    private static string Single(HttpResponseMessage response, string name)
    {
        var values = response.Headers.TryGetValues(name, out var headers)
            ? headers
            : response.Content.Headers.TryGetValues(name, out var content) ? content : [];

        return Assert.Single(values);
    }

    private sealed class FaultyStore : ISecretStore
    {
        public CreateResult Create(byte[] ciphertext, byte[] nonce, TimeSpan timeToLive) => throw new InvalidOperationException("boom");

        public SecretPeek Peek(string id) => throw new InvalidOperationException("boom");

        public ConsumeResult TryConsume(string id) => throw new InvalidOperationException("boom");
    }
}
