using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Api;

[Trait("Threat", "T6")]
[Trait("Threat", "T12")]
public sealed class CreateSecretEndpointTests : IClassFixture<CapturingWebApplicationFactory>
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);
    private static readonly Uri Endpoint = new("/api/secrets", UriKind.Relative);

    private readonly CapturingWebApplicationFactory _factory;
    private readonly WebApplicationFactory<Program> _app;

    public CreateSecretEndpointTests(CapturingWebApplicationFactory factory)
    {
        _factory = factory;
        _app = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services => services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now))));
    }

    [Fact]
    public async Task ValidRequest_StoresTheSecret_AndReturnsIdAndExpiry()
    {
        using var client = _app.CreateClient();

        using var response = await client.PostAsync(Endpoint, Json(Body(ciphertext: 32, ttlSeconds: 120)));
        var body = await Parse(response);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(["expiresAt", "id"], body.RootElement.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
        var id = body.RootElement.GetProperty("id").GetString();
        Assert.True(SecretId.IsValid(id));
        Assert.Equal(Now.AddSeconds(120), body.RootElement.GetProperty("expiresAt").GetDateTimeOffset());
        Assert.Equal(SecretState.Available, _app.Services.GetRequiredService<ISecretStore>().Peek(id!).State);
    }

    [Fact]
    public async Task OmittedTtl_DefaultsToOneHour()
    {
        using var client = _app.CreateClient();

        using var response = await client.PostAsync(Endpoint, Json(Body()));
        var body = await Parse(response);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(Now.AddHours(1), body.RootElement.GetProperty("expiresAt").GetDateTimeOffset());
    }

    [Fact]
    public async Task SuccessfulCreate_WritesOneAnonymousAuditEvent()
    {
        _factory.Logs.Clear();
        using var client = _app.CreateClient();

        using var response = await client.PostAsync(Endpoint, Json(Body()));
        var id = (await Parse(response)).RootElement.GetProperty("id").GetString();

        var audit = Assert.Single(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
        Assert.Equal("create", audit.State.Single(p => p.Key == "action").Value);
        Assert.Equal(id, audit.State.Single(p => p.Key == "secretId").Value);
        Assert.Equal("anonymous", audit.State.Single(p => p.Key == "windowsUser").Value);
    }

    [Theory]
    [InlineData("{")]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("\"text\"")]
    [InlineData("{\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"nonce\":\"AAAAAAAAAAAAAAAA\",\"extra\":1}")]
    [InlineData("{\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"nonce\":\"AAAAAAAAAAAAAAAA\"}")]
    [InlineData("{\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"nonce\":\"AAAAAAAAAAAAAAAA\",\"ttlSeconds\":\"60\"}")]
    [InlineData("{\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"nonce\":\"AAAAAAAAAAAAAAAA\",\"ttlSeconds\":60.5}")]
    [InlineData("{\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"nonce\":\"AAAAAAAAAAAAAAAA\",\"ttlSeconds\":60,}")]
    [InlineData("{\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"nonce\":\"AAAAAAAAAAAAAAAA\" /* c */}")]
    [InlineData("{\"ciphertext\":123,\"nonce\":\"AAAAAAAAAAAAAAAA\"}")]
    public async Task MalformedOrNonStrictJson_Is400_WithoutEchoingTheBody(string json)
    {
        using var client = _app.CreateClient();

        using var response = await client.PostAsync(Endpoint, new StringContent(json, Encoding.UTF8, "application/json"));

        await AssertProblem(response, HttpStatusCode.BadRequest, "malformedJson");
        Assert.Equal(0, StoreCount());
    }

    [Fact]
    public async Task JsonNestedDeeperThanEight_Is400()
    {
        var json = "{\"ciphertext\":" + new string('[', 9) + new string(']', 9) + ",\"nonce\":\"AAAAAAAAAAAAAAAA\"}";
        using var client = _app.CreateClient();

        using var response = await client.PostAsync(Endpoint, new StringContent(json, Encoding.UTF8, "application/json"));

        await AssertProblem(response, HttpStatusCode.BadRequest, "malformedJson");
    }

    [Theory]
    [InlineData("{\"nonce\":\"AAAAAAAAAAAAAAAA\"}", "ciphertextRequired")]
    [InlineData("{\"ciphertext\":null,\"nonce\":\"AAAAAAAAAAAAAAAA\"}", "ciphertextRequired")]
    [InlineData("{\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA\"}", "nonceRequired")]
    [InlineData("{\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAA=\",\"nonce\":\"AAAAAAAAAAAAAAAA\"}", "ciphertextEncoding")]
    [InlineData("{\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAA+A\",\"nonce\":\"AAAAAAAAAAAAAAAA\"}", "ciphertextEncoding")]
    [InlineData("{\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAB\",\"nonce\":\"AAAAAAAAAAAAAAAA\"}", "ciphertextEncoding")]
    [InlineData("{\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"nonce\":\"AAAAAAAAAAAAAAA/\"}", "nonceEncoding")]
    [InlineData("{\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"nonce\":\"not base64url!\"}", "nonceEncoding")]
    public async Task MissingOrMisencodedFields_Are400_WithATypedCode(string json, string code)
    {
        using var client = _app.CreateClient();

        using var response = await client.PostAsync(Endpoint, new StringContent(json, Encoding.UTF8, "application/json"));

        await AssertProblem(response, HttpStatusCode.BadRequest, code);
        Assert.Equal(0, StoreCount());
    }

    [Theory]
    [InlineData(15, 12, 3600, "ciphertextTooShort")]
    [InlineData((64 * 1024) + 1, 12, 3600, "ciphertextTooLong")]
    [InlineData(32, 11, 3600, "nonceLength")]
    [InlineData(32, 16, 3600, "nonceLength")]
    [InlineData(32, 12, 59, "timeToLiveTooShort")]
    [InlineData(32, 12, 0, "timeToLiveTooShort")]
    [InlineData(32, 12, -1, "timeToLiveTooShort")]
    [InlineData(32, 12, (7 * 24 * 3600) + 1, "timeToLiveTooLong")]
    public async Task StoreValidationFailures_Are400_WithATypedCode_AndNeverEchoInput(int ciphertextBytes, int nonceBytes, int ttlSeconds, string code)
    {
        using var client = _app.CreateClient();
        var body = Body(ciphertextBytes, nonceBytes, ttlSeconds);

        using var response = await client.PostAsync(Endpoint, Json(body));

        var text = await AssertProblem(response, HttpStatusCode.BadRequest, code);
        Assert.DoesNotContain(body.Ciphertext[..16], text, StringComparison.Ordinal);
        Assert.DoesNotContain(body.Nonce, text, StringComparison.Ordinal);
        Assert.Equal(0, StoreCount());
    }

    [Fact]
    public async Task NonJsonContentType_Is415()
    {
        using var client = _app.CreateClient();

        using var response = await client.PostAsync(Endpoint, new StringContent("ciphertext=AAAA", Encoding.UTF8, "application/x-www-form-urlencoded"));

        await AssertProblem(response, HttpStatusCode.UnsupportedMediaType, "unsupportedMediaType");
    }

    [Fact]
    public async Task WhenTheStoreIsFull_Is503_WithRetryAfter_AndNothingStored()
    {
        _factory.Logs.Clear();
        using var full = _factory.WithWebHostBuilder(builder => builder.UseSetting("SecretStore:MaxEntries", "1"));
        using var client = full.CreateClient();
        using var first = await client.PostAsync(Endpoint, Json(Body()));
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        using var second = await client.PostAsync(Endpoint, Json(Body()));

        await AssertProblem(second, HttpStatusCode.ServiceUnavailable, "capacityExceeded");
        Assert.Equal(TimeSpan.FromSeconds(30), second.Headers.RetryAfter?.Delta);
        Assert.Equal(1, full.Services.GetRequiredService<InMemorySecretStore>().Count);
        Assert.Single(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
    }

    [Fact]
    public async Task FailedCreates_WriteNoAuditEvent()
    {
        _factory.Logs.Clear();
        using var client = _app.CreateClient();

        using var response = await client.PostAsync(Endpoint, Json(Body(ciphertext: 15)));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
    }

    private int StoreCount() => _app.Services.GetRequiredService<InMemorySecretStore>().Count;

    private static async Task<string> AssertProblem(HttpResponseMessage response, HttpStatusCode status, string code)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var text = await response.Content.ReadAsStringAsync();
        using var problem = JsonDocument.Parse(text);
        Assert.Equal((int)status, problem.RootElement.GetProperty("status").GetInt32());
        Assert.Equal(code, problem.RootElement.GetProperty("code").GetString());
        Assert.False(problem.RootElement.TryGetProperty("exception", out _));
        return text;
    }

    private static async Task<JsonDocument> Parse(HttpResponseMessage response)
    {
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    private static StringContent Json(CreateBody body)
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["ciphertext"] = body.Ciphertext,
            ["nonce"] = body.Nonce,
            ["ttlSeconds"] = body.TtlSeconds,
        }.Where(pair => pair.Value is not null).ToDictionary(pair => pair.Key, pair => pair.Value));
        var content = new StringContent(json, Encoding.UTF8);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    private static CreateBody Body(int ciphertext = 32, int nonce = 12, int? ttlSeconds = null)
    {
        return new CreateBody(
            Base64Url.EncodeToString(Enumerable.Range(0, ciphertext).Select(i => (byte)(i + 1)).ToArray()),
            Base64Url.EncodeToString(Enumerable.Range(0, nonce).Select(i => (byte)(0xF0 + i)).ToArray()),
            ttlSeconds);
    }

    private sealed record CreateBody(string Ciphertext, string Nonce, int? TtlSeconds);
}
