using System.Buffers.Text;
using System.Net;
using System.Text;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests;

// The server is supposed to be structurally incapable of leaking secret material: it never receives a key or
// plaintext at all, and the ciphertext and nonce it does hold must reach exactly one place — the body of a
// successful reveal. Everything else the app emits is swept here for the canaries in every encoding a leak
// would plausibly take. The key half of T1 cannot be shown in process, because the key never arrives; that
// is proved in the browser by tests/e2e/specs/leak.spec.ts.
[Trait("Threat", "T1")]
[Trait("Threat", "T5")]
public sealed class LeakTests : IClassFixture<CapturingWebApplicationFactory>
{
    // Chosen to be ASCII at the right lengths, so a raw memory or body dump would show the text itself and
    // not only its encodings.
    private static readonly byte[] CanaryCiphertext = Encoding.ASCII.GetBytes("CANARY-CIPHERTEXT-2f8d41ab-padding-padding-pad48");
    private static readonly byte[] CanaryNonce = Encoding.ASCII.GetBytes("CANARYNONCE1");
    private const string CanaryQuery = "CANARY-QUERY-9c02be7f";

    private readonly CapturingWebApplicationFactory _factory;

    public LeakTests(CapturingWebApplicationFactory factory) => _factory = factory;

    // Every shape the same bytes could take in a log line, a header, or an error body.
    private static IEnumerable<string> Encodings(byte[] bytes)
    {
        var base64 = Convert.ToBase64String(bytes);
        yield return Encoding.ASCII.GetString(bytes);
        yield return base64;
        yield return Base64Url.EncodeToString(bytes);
        yield return Convert.ToHexString(bytes);
        yield return Convert.ToHexString(bytes).ToLowerInvariant();
        yield return Uri.EscapeDataString(base64);
    }

    private static string[] Needles =>
        [.. Encodings(CanaryCiphertext), .. Encodings(CanaryNonce), CanaryQuery];

    [Fact]
    public async Task AFullCanaryLifecycle_LeaksNothingIntoLogsHeadersOrErrorBodies()
    {
        _factory.Logs.Clear();
        using var client = _factory.CreateClient();
        var id = Create();
        var scanned = new List<string>();

        // Every response the canary's own lifecycle produces, plus the error paths around it.
        using (var peek = await client.GetAsync(new Uri($"/api/secrets/{id}", UriKind.Relative)))
        {
            await Collect(scanned, peek, includeBody: true);
        }

        using (var peekWithQuery = await client.GetAsync(new Uri($"/api/secrets/{id}?note={CanaryQuery}", UriKind.Relative)))
        {
            await Collect(scanned, peekWithQuery, includeBody: true);
        }

        using (var page = await client.GetAsync(new Uri($"/s/{id}", UriKind.Relative)))
        {
            await Collect(scanned, page, includeBody: true);
        }

        using (var reveal = await client.SendAsync(Reveal(id)))
        {
            // The one place the ciphertext is allowed: the body of a successful reveal. Headers are not.
            Assert.Equal(HttpStatusCode.OK, reveal.StatusCode);
            Assert.Contains(Base64Url.EncodeToString(CanaryCiphertext), await reveal.Content.ReadAsStringAsync(), StringComparison.Ordinal);
            await Collect(scanned, reveal, includeBody: false);
        }

        using (var gone = await client.SendAsync(Reveal(id)))
        {
            Assert.Equal(HttpStatusCode.Gone, gone.StatusCode);
            await Collect(scanned, gone, includeBody: true);
        }

        AssertNoCanary(scanned);
        AssertNoCanaryInLogs();
    }

    public static TheoryData<string> EchoAttempts => new()
    {
        "ciphertext is not valid base64url",
        "ciphertext is too short",
        "nonce is the wrong length",
        "an unknown field carries it",
        "the id in the path carries it",
        "the query string carries it",
    };

    [Theory]
    [MemberData(nameof(EchoAttempts))]
    public async Task AnErrorNeverEchoesWhatWasSubmitted(string attempt)
    {
        _factory.Logs.Clear();
        using var client = _factory.CreateClient();
        var scanned = new List<string>();

        using var response = await SendEchoAttempt(client, attempt);

        Assert.True((int)response.StatusCode >= 400, $"{attempt} was accepted");
        await Collect(scanned, response, includeBody: true);
        AssertNoCanary(scanned);
        AssertNoCanaryInLogs();
    }

    [Fact]
    public async Task AnUnhandledFailure_LeaksNothing_EvenWithTheCanaryInTheQueryString()
    {
        using var app = _factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services => services.AddSingleton<ISecretStore>(new FaultyStore())));
        _factory.Logs.Clear();
        using var client = app.CreateClient();
        var scanned = new List<string>();

        using var response = await client.GetAsync(new Uri($"/api/secrets/{SecretId.NewId()}?note={CanaryQuery}", UriKind.Relative));

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        await Collect(scanned, response, includeBody: true);
        AssertNoCanary(scanned);
        // The exception is logged with its stack; the request's query string must not ride along with it.
        Assert.NotEmpty(_factory.Logs.Entries);
        AssertNoCanaryInLogs();
    }

    [Fact]
    public async Task TheAuditTrail_RecordsTheIdAndNothingElseAboutTheSecret()
    {
        _factory.Logs.Clear();
        using var client = _factory.CreateClient();

        // Through the API, not the store, so the create event is written too and the whole trail is scanned.
        string id;
        using (var created = await Post(client, $$"""{"ciphertext":"{{Base64Url.EncodeToString(CanaryCiphertext)}}","nonce":"{{Base64Url.EncodeToString(CanaryNonce)}}"}"""))
        {
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
            using var body = System.Text.Json.JsonDocument.Parse(await created.Content.ReadAsStringAsync());
            id = body.RootElement.GetProperty("id").GetString()!;
        }

        using (var reveal = await client.SendAsync(Reveal(id)))
        {
            Assert.Equal(HttpStatusCode.OK, reveal.StatusCode);
        }

        var audit = _factory.Logs.Entries.Where(entry => entry.EventId.Name == "Audit").ToList();
        Assert.Equal(2, audit.Count);
        foreach (var entry in audit)
        {
            Assert.Equal(["timestampUtc", "action", "secretId", "windowsUser"], entry.State.Select(field => field.Key));
            Assert.Equal(id, entry.State.Single(field => field.Key == "secretId").Value);
        }

        AssertNoCanaryInLogs();
    }

    [Theory]
    [InlineData("GET", "/")]
    [InlineData("GET", "/s/{id}")]
    [InlineData("GET", "/api/secrets/{id}")]
    [InlineData("POST", "/api/secrets")]
    [InlineData("POST", "/api/secrets/{id}/reveal")]
    [InlineData("GET", "/healthz")]
    public async Task NoSecretEndpoint_SetsACookie(string method, string template)
    {
        using var client = _factory.CreateClient();
        var id = Create();
        var path = template.Replace("{id}", id, StringComparison.Ordinal);

        using var request = method == "POST" && path.EndsWith("reveal", StringComparison.Ordinal)
            ? Reveal(id)
            : NewRequest(method, path);
        using var response = await client.SendAsync(request);

        // Only /api/whoami may ever set one; anything else handing out state would outlive the secret.
        Assert.False(response.Headers.Contains("Set-Cookie"), $"{method} {template} set a cookie");
    }

    [Fact]
    public async Task TheOneCookieTheAppDoesSet_CarriesNoSecretMaterial()
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        var id = Create();
        using var request = NewRequest("GET", "/api/whoami");
        request.Headers.TryAddWithoutValidation(TestNegotiateHandler.UserHeader, "CONTOSO\\\\alice");

        using var response = await client.SendAsync(request);

        var cookies = response.Headers.TryGetValues("Set-Cookie", out var values) ? values.ToList() : [];
        Assert.NotEmpty(cookies);
        AssertNoCanary(cookies);
        Assert.DoesNotContain(cookies, cookie => cookie.Contains(id, StringComparison.Ordinal));
    }

    private async Task<HttpResponseMessage> SendEchoAttempt(HttpClient client, string attempt)
    {
        var ciphertext = Base64Url.EncodeToString(CanaryCiphertext);
        var nonce = Base64Url.EncodeToString(CanaryNonce);

        return attempt switch
        {
            "ciphertext is not valid base64url" => await Post(client, $$"""{"ciphertext":"{{ciphertext}}!!","nonce":"{{nonce}}"}"""),
            "ciphertext is too short" => await Post(client, $$"""{"ciphertext":"{{Base64Url.EncodeToString(CanaryCiphertext[..8])}}","nonce":"{{nonce}}"}"""),
            "nonce is the wrong length" => await Post(client, $$"""{"ciphertext":"{{ciphertext}}","nonce":"{{ciphertext}}"}"""),
            "an unknown field carries it" => await Post(client, $$"""{"ciphertext":"{{ciphertext}}","nonce":"{{nonce}}","debug":"{{CanaryQuery}}"}"""),
            "the id in the path carries it" => await client.GetAsync(new Uri($"/api/secrets/{CanaryQuery}", UriKind.Relative)),
            "the query string carries it" => await client.GetAsync(new Uri($"/api/secrets/{SecretId.NewId()}?note={CanaryQuery}", UriKind.Relative)),
            _ => throw new ArgumentOutOfRangeException(nameof(attempt), attempt, "Unknown attempt."),
        };
    }

    private static async Task<HttpResponseMessage> Post(HttpClient client, string body)
    {
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        return await client.PostAsync(new Uri("/api/secrets", UriKind.Relative), content);
    }

    private static async Task Collect(List<string> scanned, HttpResponseMessage response, bool includeBody)
    {
        foreach (var header in response.Headers.Concat(response.Content.Headers))
        {
            scanned.Add($"{header.Key}: {string.Join(", ", header.Value)}");
        }

        if (includeBody)
        {
            scanned.Add(await response.Content.ReadAsStringAsync());
        }
    }

    private static void AssertNoCanary(IEnumerable<string> scanned)
    {
        var haystack = scanned.ToList();
        foreach (var needle in Needles)
        {
            Assert.DoesNotContain(haystack, text => text.Contains(needle, StringComparison.OrdinalIgnoreCase));
        }
    }

    private void AssertNoCanaryInLogs()
    {
        foreach (var needle in Needles)
        {
            Assert.DoesNotContain(_factory.Logs.Entries, entry => entry.Contains(needle));
        }
    }

    private static HttpRequestMessage NewRequest(string method, string path) =>
        new(new HttpMethod(method), new Uri(path, UriKind.Relative))
        {
            Content = method == "POST" ? new StringContent("{}", Encoding.UTF8, "application/json") : null,
        };

    private static HttpRequestMessage Reveal(string id)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"/api/secrets/{id}/reveal", UriKind.Relative))
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation("X-OneShot-Reveal", "1");
        return request;
    }

    private string Create()
    {
        var store = _factory.Services.GetRequiredService<ISecretStore>();
        return Assert.IsType<Created>(store.Create([.. CanaryCiphertext], [.. CanaryNonce], TimeSpan.FromHours(1))).Id;
    }

    private sealed class FaultyStore : ISecretStore
    {
        public CreateResult Create(byte[] ciphertext, byte[] nonce, TimeSpan timeToLive) => throw new InvalidOperationException("boom");

        public SecretPeek Peek(string id) => throw new InvalidOperationException("boom");

        public ConsumeResult TryConsume(string id) => throw new InvalidOperationException("boom");
    }
}
