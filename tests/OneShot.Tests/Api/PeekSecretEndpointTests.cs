using System.Net;
using System.Text.Json;


using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Api;

[Trait("Threat", "T4")]
public sealed class PeekSecretEndpointTests : IClassFixture<CapturingWebApplicationFactory>, IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);

    private static readonly string[] ScannerUserAgents =
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OutlookSafeLinks",
        "Mozilla/5.0 (compatible; ProofpointURLDefense/1.0)",
        "Mozilla/5.0 (compatible; Mimecast Link Scanner)",
        "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
        "Twitterbot/1.0",
        "curl/8.5.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
    ];

    private readonly CapturingWebApplicationFactory _factory;
    private readonly FakeTimeApp _app;

    public PeekSecretEndpointTests(CapturingWebApplicationFactory factory)
    {
        _factory = factory;
        _app = factory.WithFakeTime(Now);
    }

    public void Dispose() => _app.Dispose();

    [Fact]
    public async Task AvailableSecret_Is200_WithStateAndExpiry()
    {
        var id = Create(TimeSpan.FromMinutes(30));
        using var client = _app.CreateClient();

        using var response = await client.GetAsync(Url(id));
        using var body = await Parse(response);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(["expiresAt", "state"], Properties(body));
        Assert.Equal("available", body.RootElement.GetProperty("state").GetString());
        Assert.Equal(Now.AddMinutes(30), body.RootElement.GetProperty("expiresAt").GetDateTimeOffset());
    }

    [Fact]
    public async Task ConsumedSecret_Is200_WithConsumedStateAndTheOriginalExpiry()
    {
        var id = Create(TimeSpan.FromMinutes(30));
        Store.TryConsume(id).Secret!.Dispose();
        using var client = _app.CreateClient();

        using var response = await client.GetAsync(Url(id));
        using var body = await Parse(response);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(["expiresAt", "state"], Properties(body));
        Assert.Equal("consumed", body.RootElement.GetProperty("state").GetString());
        Assert.Equal(Now.AddMinutes(30), body.RootElement.GetProperty("expiresAt").GetDateTimeOffset());
    }

    [Fact]
    public async Task UnknownId_Is404_WithTheSameShapeAndANullExpiry()
    {
        using var client = _app.CreateClient();

        using var response = await client.GetAsync(Url(SecretId.NewId()));
        using var body = await Parse(response);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(["expiresAt", "state"], Properties(body));
        Assert.Equal("unknown", body.RootElement.GetProperty("state").GetString());
        Assert.Equal(JsonValueKind.Null, body.RootElement.GetProperty("expiresAt").ValueKind);
    }

    [Theory]
    [InlineData("abcdefghijklmnopqrstu")]
    [InlineData("abcdefghijklmnopqrstuB")]
    [InlineData("abcdefghijklmnopqrstu=")]
    [InlineData("abcdefghijklmnopqrstuvw")]
    [InlineData("abcdefghijklmnopqrst%20A")]
    [InlineData("abcdefghijklmnopqrstu%C3%84")]
    public async Task MalformedId_Is404_ByteIdenticalToAnUnknownId(string malformed)
    {
        using var client = _app.CreateClient();
        using var unknown = await client.GetAsync(Url(SecretId.NewId()));
        var expected = await unknown.Content.ReadAsByteArrayAsync();

        using var response = await client.GetAsync(new Uri($"/api/secrets/{malformed}", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(expected, await response.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task TenUnknownIds_ProduceByteIdentical404Bodies()
    {
        using var client = _app.CreateClient();
        var bodies = new List<byte[]>();
        for (var i = 0; i < 10; i++)
        {
            using var response = await client.GetAsync(Url(SecretId.NewId()));
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            bodies.Add(await response.Content.ReadAsByteArrayAsync());
        }

        Assert.All(bodies, body => Assert.Equal(bodies[0], body));
    }

    [Fact]
    public async Task ExpiredSecret_Is404Unknown()
    {
        var id = Create(TimeSpan.FromMinutes(1));
        using var client = _app.CreateClient();
        _app.Clock.Advance(TimeSpan.FromMinutes(1));

        using var response = await client.GetAsync(Url(id));
        using var body = await Parse(response);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("unknown", body.RootElement.GetProperty("state").GetString());
    }

    [Fact]
    public async Task ScannersAndPrefetchers_NeverConsume_AndSeeIdenticalResponses()
    {
        var id = Create(TimeSpan.FromHours(1));
        using var client = _app.CreateClient();
        var bodies = new List<string>();

        foreach (var userAgent in ScannerUserAgents)
        {
            foreach (var headers in PrefetchHeaderSets())
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, Url(id));
                request.Headers.TryAddWithoutValidation("User-Agent", userAgent);
                foreach (var (name, value) in headers)
                {
                    request.Headers.TryAddWithoutValidation(name, value);
                }

                using var response = await client.SendAsync(request);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                bodies.Add(await response.Content.ReadAsStringAsync());
            }
        }

        Assert.All(bodies, body => Assert.Equal(bodies[0], body));
        Assert.Equal(SecretState.Available, Store.Peek(id).State);
        var consumed = Store.TryConsume(id);
        Assert.Equal(ConsumeOutcome.Consumed, consumed.Outcome);
        consumed.Secret!.Dispose();
    }

    [Fact]
    public async Task Head_MatchesGet_WithoutABody()
    {
        var id = Create(TimeSpan.FromHours(1));
        using var client = _app.CreateClient();

        foreach (var target in new[] { Url(id), Url(SecretId.NewId()) })
        {
            using var get = await client.GetAsync(target);
            using var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, target));

            Assert.Equal(get.StatusCode, head.StatusCode);
            Assert.Equal(get.Content.Headers.ContentType?.ToString(), head.Content.Headers.ContentType?.ToString());
            Assert.Empty(await head.Content.ReadAsByteArrayAsync());
        }

        Assert.Equal(SecretState.Available, Store.Peek(id).State);
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("PATCH")]
    public async Task OtherMethods_Are405_AndNeverConsume(string method)
    {
        var id = Create(TimeSpan.FromHours(1));
        using var client = _app.CreateClient();

        using var response = await client.SendAsync(new HttpRequestMessage(new HttpMethod(method), Url(id)));

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        Assert.Equal(SecretState.Available, Store.Peek(id).State);
    }

    [Fact]
    public async Task Peek_WritesNoAuditEvent()
    {
        var id = Create(TimeSpan.FromHours(1));
        _factory.Logs.Clear();
        using var client = _app.CreateClient();

        using var response = await client.GetAsync(Url(id));

        Assert.DoesNotContain(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
    }

    private static IEnumerable<(string Name, string Value)[]> PrefetchHeaderSets()
    {
        yield return [];
        yield return [("Purpose", "prefetch")];
        yield return [("Sec-Purpose", "prefetch")];
        yield return [("Sec-Purpose", "prefetch;prerender"), ("Sec-Fetch-Dest", "document"), ("Sec-Fetch-Mode", "navigate")];
        yield return [("X-Purpose", "preview"), ("Accept", "*/*")];
    }

    private ISecretStore Store => _app.Service<ISecretStore>();

    private string Create(TimeSpan timeToLive)
    {
        var ciphertext = Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();
        var nonce = Enumerable.Range(0, 12).Select(i => (byte)(0xF0 + i)).ToArray();
        return Assert.IsType<Created>(Store.Create(ciphertext, nonce, timeToLive)).Id;
    }

    private static Uri Url(string id) => new($"/api/secrets/{id}", UriKind.Relative);

    private static IEnumerable<string> Properties(JsonDocument body)
    {
        return body.RootElement.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal);
    }

    private static async Task<JsonDocument> Parse(HttpResponseMessage response)
    {
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }
}
