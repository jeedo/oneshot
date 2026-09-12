using System.Buffers.Text;
using System.Net;
using System.Text;
using System.Text.Json;


using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Api;

[Trait("Threat", "T2")]
[Trait("Threat", "T4")]
public sealed class RevealSecretEndpointTests : IClassFixture<CapturingWebApplicationFactory>, IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);
    private static readonly byte[] Ciphertext = Enumerable.Range(0, 48).Select(i => (byte)(i * 5 + 1)).ToArray();
    private static readonly byte[] Nonce = Enumerable.Range(0, 12).Select(i => (byte)(0xF0 + i)).ToArray();

    private readonly CapturingWebApplicationFactory _factory;
    private readonly FakeTimeApp _app;

    public RevealSecretEndpointTests(CapturingWebApplicationFactory factory)
    {
        _factory = factory;
        _app = factory.WithFakeTime(Now);
    }

    public void Dispose() => _app.Dispose();

    [Fact]
    public async Task SameOriginReveal_ReturnsTheCiphertextOnce_AndAuditsIt()
    {
        var id = Create();
        _factory.Logs.Clear();
        using var client = _app.CreateClient();

        using var response = await client.SendAsync(Reveal(id));
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(["ciphertext", "nonce"], body.RootElement.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
        Assert.Equal(Base64Url.EncodeToString(Ciphertext), body.RootElement.GetProperty("ciphertext").GetString());
        Assert.Equal(Base64Url.EncodeToString(Nonce), body.RootElement.GetProperty("nonce").GetString());
        Assert.Equal(SecretState.Consumed, Store.Peek(id).State);

        var audit = Assert.Single(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
        Assert.Equal("reveal", audit.State.Single(p => p.Key == "action").Value);
        Assert.Equal(id, audit.State.Single(p => p.Key == "secretId").Value);
        Assert.Equal("anonymous", audit.State.Single(p => p.Key == "windowsUser").Value);
    }

    [Fact]
    public async Task SecondReveal_Is410_WithNoPayloadAndNoSecondAuditEvent()
    {
        var id = Create();
        _factory.Logs.Clear();
        using var client = _app.CreateClient();
        using var first = await client.SendAsync(Reveal(id));

        using var second = await client.SendAsync(Reveal(id));

        var text = await AssertProblem(second, HttpStatusCode.Gone, "consumed");
        Assert.DoesNotContain(Base64Url.EncodeToString(Ciphertext), text, StringComparison.Ordinal);
        Assert.Single(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
    }

    [Fact]
    public async Task UnknownAndMalformedIds_Are404_WithIdenticalBodies_AndNoAudit()
    {
        _factory.Logs.Clear();
        using var client = _app.CreateClient();

        using var unknown = await client.SendAsync(Reveal(SecretId.NewId()));
        using var malformed = await client.SendAsync(Reveal("abcdefghijklmnopqrstuB"));

        await AssertProblem(unknown, HttpStatusCode.NotFound, "unknown");
        Assert.Equal(await unknown.Content.ReadAsByteArrayAsync(), await malformed.Content.ReadAsByteArrayAsync());
        Assert.DoesNotContain(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
    }

    [Fact]
    public async Task ExpiredSecret_Is404()
    {
        var id = Create(TimeSpan.FromMinutes(1));
        using var client = _app.CreateClient();
        _app.Clock.Advance(TimeSpan.FromMinutes(1));

        using var response = await client.SendAsync(Reveal(id));

        await AssertProblem(response, HttpStatusCode.NotFound, "unknown");
    }

    public static TheoryData<string, Action<HttpRequestMessage>> RejectedRequests => new()
    {
        { "missing custom header", request => request.Headers.Remove("X-OneShot-Reveal") },
        { "custom header with another value", request => { request.Headers.Remove("X-OneShot-Reveal"); request.Headers.TryAddWithoutValidation("X-OneShot-Reveal", "true"); } },
        { "form content type", request => request.Content = new StringContent("reveal=1", Encoding.UTF8, "application/x-www-form-urlencoded") },
        { "text content type", request => request.Content = new StringContent("{}", Encoding.UTF8, "text/plain") },
        { "no content type", request => request.Content = null },
        { "foreign origin", request => SetHeader(request, "Origin", "https://evil.test") },
        { "foreign origin with same host on another port", request => SetHeader(request, "Origin", "http://localhost:8080") },
        { "null origin", request => SetHeader(request, "Origin", "null") },
        { "cross-site fetch", request => SetHeader(request, "Sec-Fetch-Site", "cross-site") },
        { "same-site fetch", request => SetHeader(request, "Sec-Fetch-Site", "same-site") },
        { "cross-site fetch with a forged same-origin Origin", request => { SetHeader(request, "Sec-Fetch-Site", "cross-site"); SetHeader(request, "Origin", "http://localhost"); } },
    };

    [Theory]
    [MemberData(nameof(RejectedRequests))]
    public async Task RequestsThatCouldBeForgedOrPrefetched_Are403_AndNeverConsume(string scenario, Action<HttpRequestMessage> mutate)
    {
        var id = Create();
        _factory.Logs.Clear();
        using var client = _app.CreateClient();
        using var request = Reveal(id);
        mutate(request);

        using var response = await client.SendAsync(request);

        var text = await AssertProblem(response, HttpStatusCode.Forbidden, "revealNotAllowed");
        Assert.DoesNotContain(Base64Url.EncodeToString(Ciphertext), text, StringComparison.Ordinal);
        Assert.Equal(SecretState.Available, Store.Peek(id).State);
        Assert.DoesNotContain(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
        Assert.NotEmpty(scenario);
    }

    public static TheoryData<string, Action<HttpRequestMessage>> AcceptedVariants => new()
    {
        { "no Origin and no Sec-Fetch-Site (non-browser client)", request => { request.Headers.Remove("Origin"); request.Headers.Remove("Sec-Fetch-Site"); } },
        { "Sec-Fetch-Site none (user-initiated navigation)", request => SetHeader(request, "Sec-Fetch-Site", "none") },
        { "Origin with different host casing", request => SetHeader(request, "Origin", "http://LOCALHOST") },
        { "empty JSON body", request => request.Content = new StringContent("", Encoding.UTF8, "application/json") },
        { "ignored JSON body", request => request.Content = new StringContent("{\"anything\":true}", Encoding.UTF8, "application/json") },
    };

    [Theory]
    [MemberData(nameof(AcceptedVariants))]
    public async Task LegitimateVariants_StillReveal(string scenario, Action<HttpRequestMessage> mutate)
    {
        var id = Create();
        using var client = _app.CreateClient();
        using var request = Reveal(id);
        mutate(request);

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(SecretState.Consumed, Store.Peek(id).State);
        Assert.NotEmpty(scenario);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task OtherMethods_Are405_AndNeverConsume(string method)
    {
        var id = Create();
        using var client = _app.CreateClient();
        using var request = Reveal(id);
        request.Method = new HttpMethod(method);
        request.Content = null;

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        Assert.Equal(SecretState.Available, Store.Peek(id).State);
    }

    [Fact]
    public async Task ForeignPreflight_GetsNoCorsHeaders_AndNeverConsumes()
    {
        var id = Create();
        using var client = _app.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Options, Url(id));
        request.Headers.TryAddWithoutValidation("Origin", "https://evil.test");
        request.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "POST");
        request.Headers.TryAddWithoutValidation("Access-Control-Request-Headers", "x-oneshot-reveal,content-type");

        using var response = await client.SendAsync(request);

        Assert.DoesNotContain(response.Headers, header => header.Key.StartsWith("Access-Control-", StringComparison.OrdinalIgnoreCase));
        Assert.NotEqual(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(SecretState.Available, Store.Peek(id).State);
    }

    [Fact]
    public void NoCorsPolicy_IsRegisteredAnywhere()
    {
        var sources = Directory.EnumerateFiles(Path.Combine(RepoPaths.Root, "src", "OneShot.Web"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal));

        foreach (var path in sources)
        {
            var text = File.ReadAllText(path);
            Assert.DoesNotContain("AddCors", text, StringComparison.Ordinal);
            Assert.DoesNotContain("UseCors", text, StringComparison.Ordinal);
            Assert.DoesNotContain("RequireCors", text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task ParallelReveals_ExactlyOneSucceeds()
    {
        var id = Create();
        using var client = _app.CreateClient();

        var responses = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => client.SendAsync(Reveal(id))));

        Assert.Equal(1, responses.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.Equal(31, responses.Count(r => r.StatusCode == HttpStatusCode.Gone));
        foreach (var response in responses)
        {
            response.Dispose();
        }
    }

    private static HttpRequestMessage Reveal(string id)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, Url(id))
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation("X-OneShot-Reveal", "1");
        request.Headers.TryAddWithoutValidation("Origin", "http://localhost");
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "same-origin");
        return request;
    }

    private static void SetHeader(HttpRequestMessage request, string name, string value)
    {
        request.Headers.Remove(name);
        request.Headers.TryAddWithoutValidation(name, value);
    }

    private static Uri Url(string id) => new($"/api/secrets/{id}/reveal", UriKind.Relative);

    private static async Task<string> AssertProblem(HttpResponseMessage response, HttpStatusCode status, string code)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var text = await response.Content.ReadAsStringAsync();
        using var problem = JsonDocument.Parse(text);
        Assert.Equal(code, problem.RootElement.GetProperty("code").GetString());
        return text;
    }

    private ISecretStore Store => _app.Service<ISecretStore>();

    private string Create(TimeSpan? timeToLive = null)
    {
        return Assert.IsType<Created>(Store.Create((byte[])Ciphertext.Clone(), (byte[])Nonce.Clone(), timeToLive ?? TimeSpan.FromHours(1))).Id;
    }
}
