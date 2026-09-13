using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Api;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Api;

// CreateValidationProperties states the domain rules as properties over the store. This is the layer above:
// the bytes on the wire, where the JSON reader, the base64url decoder and the body-size limit sit. Every case
// must be refused without storing anything and without an exception reaching the log — a parser that throws
// its way to a 400 is a denial-of-service lever even when the status code looks right.
[Trait("Threat", "T12")]
public sealed class InputFuzzingTests : IClassFixture<CapturingWebApplicationFactory>
{
    private static readonly string ValidCiphertext = Base64Url.EncodeToString(new byte[32]);
    private static readonly string ValidNonce = Base64Url.EncodeToString(new byte[12]);

    private readonly CapturingWebApplicationFactory _factory;

    public InputFuzzingTests(CapturingWebApplicationFactory factory) => _factory = factory;

    public static TheoryData<string, HttpStatusCode> Corpus => new()
    {
        { "ciphertext is not base64 at all", HttpStatusCode.BadRequest },
        { "ciphertext uses the standard alphabet", HttpStatusCode.BadRequest },
        { "ciphertext is padded", HttpStatusCode.BadRequest },
        { "ciphertext has whitespace", HttpStatusCode.BadRequest },
        { "ciphertext has a newline", HttpStatusCode.BadRequest },
        { "ciphertext is non-canonical", HttpStatusCode.BadRequest },
        { "ciphertext is too short", HttpStatusCode.BadRequest },
        { "ciphertext is one byte too long", HttpStatusCode.BadRequest },
        { "ciphertext is a number", HttpStatusCode.BadRequest },
        { "ciphertext is null", HttpStatusCode.BadRequest },
        { "ciphertext is an object", HttpStatusCode.BadRequest },
        { "ttl is zero", HttpStatusCode.BadRequest },
        { "ttl is negative", HttpStatusCode.BadRequest },
        { "ttl is int.MaxValue", HttpStatusCode.BadRequest },
        { "ttl is fractional", HttpStatusCode.BadRequest },
        { "ttl is a string", HttpStatusCode.BadRequest },
        { "json is a thousand deep", HttpStatusCode.BadRequest },
        { "json has duplicate keys", HttpStatusCode.BadRequest },
        { "json has an unknown field", HttpStatusCode.BadRequest },
        { "json has a trailing comma", HttpStatusCode.BadRequest },
        { "json is a comment", HttpStatusCode.BadRequest },
        { "json is an array", HttpStatusCode.BadRequest },
        { "json is truncated", HttpStatusCode.BadRequest },
        { "body is empty", HttpStatusCode.BadRequest },
        { "body is invalid utf-8", HttpStatusCode.BadRequest },
        { "body is ten megabytes", HttpStatusCode.BadRequest },
        { "content type is text", HttpStatusCode.UnsupportedMediaType },
    };

    [Theory]
    [MemberData(nameof(Corpus))]
    public async Task MalformedInput_IsRefusedWithoutStoringAnythingOrThrowing(string scenario, HttpStatusCode expected)
    {
        _factory.Logs.Clear();
        var store = _factory.Services.GetRequiredService<InMemorySecretStore>();
        var before = (store.Count, store.CiphertextBytes);
        using var client = _factory.CreateClient();

        using var content = Build(scenario);
        using var response = await client.PostAsync(new Uri("/api/secrets", UriKind.Relative), content);

        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(before, (store.Count, store.CiphertextBytes));
        AssertNothingThrew();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(11)]
    [InlineData(13)]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    [InlineData(64)]
    public async Task EveryNonceLengthButTwelve_IsRefused(int length)
    {
        _factory.Logs.Clear();
        var store = _factory.Services.GetRequiredService<InMemorySecretStore>();
        var before = store.Count;
        using var client = _factory.CreateClient();

        using var response = await Post(client, $$"""{"ciphertext":"{{ValidCiphertext}}","nonce":"{{Base64Url.EncodeToString(new byte[length])}}"}""");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, store.Count);
        AssertNothingThrew();
    }

    [Fact]
    public async Task TwelveBytesIsAccepted_SoTheSweepAboveIsRejectingForTheRightReason()
    {
        using var client = _factory.CreateClient();

        using var response = await Post(client, $$"""{"ciphertext":"{{ValidCiphertext}}","nonce":"{{ValidNonce}}"}""");

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Theory]
    [InlineData("ttl is omitted", $$"""{"ciphertext":"CIPHER","nonce":"NONCE"}""")]
    [InlineData("ttl is null", $$"""{"ciphertext":"CIPHER","nonce":"NONCE","ttlSeconds":null}""")]
    [InlineData("ttl is the minimum", $$"""{"ciphertext":"CIPHER","nonce":"NONCE","ttlSeconds":60}""")]
    [InlineData("ttl is the maximum", $$"""{"ciphertext":"CIPHER","nonce":"NONCE","ttlSeconds":604800}""")]
    [InlineData("fields are in another order", $$"""{"ttlSeconds":3600,"nonce":"NONCE","ciphertext":"CIPHER"}""")]
    // A UTF-8 BOM is accepted: System.Text.Json skips it, the document behind it is well formed, and nothing
    // downstream parses the body a second time, so there is no encoding for the two readers to disagree over.
    // Recorded here deliberately rather than left untested.
    [InlineData("a utf-8 bom precedes the object", "\uFEFF" + $$"""{"ciphertext":"CIPHER","nonce":"NONCE"}""")]
    public async Task LegitimateVariants_AreStillAccepted(string scenario, string template)
    {
        using var client = _factory.CreateClient();

        using var response = await Post(client, template.Replace("CIPHER", ValidCiphertext, StringComparison.Ordinal).Replace("NONCE", ValidNonce, StringComparison.Ordinal));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.NotEmpty(scenario);
    }

    [Theory]
    [InlineData(StatusCodes.Status413PayloadTooLarge, "payloadTooLarge")]
    [InlineData(StatusCodes.Status400BadRequest, "malformedRequest")]
    public async Task AProtocolRejectionFromTheServer_KeepsItsOwnStatus_AndIsNotLoggedAsAFault(int status, string code)
    {
        using var app = _factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.AddSingleton<ISecretStore>(new RejectingStore(status))));
        _factory.Logs.Clear();
        using var client = app.CreateClient();

        using var response = await Post(client, $$"""{"ciphertext":"{{ValidCiphertext}}","nonce":"{{ValidNonce}}"}""");
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        // Answering 500 would misreport a client mistake as our fault and log a stack for every one of them.
        Assert.Equal((HttpStatusCode)status, response.StatusCode);
        Assert.Equal(code, problem.RootElement.GetProperty("code").GetString());
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        AssertNothingThrew();
    }

    [Fact]
    public async Task AGenuineFault_IsStillA500_AndIsStillLogged()
    {
        // The control for the test above: suppressing the wrong exceptions would hide real failures.
        using var app = _factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.AddSingleton<ISecretStore>(new ThrowingStore())));
        _factory.Logs.Clear();
        using var client = app.CreateClient();

        using var response = await Post(client, $$"""{"ciphertext":"{{ValidCiphertext}}","nonce":"{{ValidNonce}}"}""");

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Contains(_factory.Logs.Entries, entry => entry.Level >= LogLevel.Error);
    }

    private sealed class RejectingStore(int status) : ISecretStore
    {
        public CreateResult Create(byte[] ciphertext, byte[] nonce, TimeSpan timeToLive) =>
            throw new BadHttpRequestException("Request body too large. The max request body size is 131072 bytes.", status);

        public SecretPeek Peek(string id) => new(SecretState.Unknown, null);

        public ConsumeResult TryConsume(string id) => ConsumeResult.Unknown;
    }

    private sealed class ThrowingStore : ISecretStore
    {
        public CreateResult Create(byte[] ciphertext, byte[] nonce, TimeSpan timeToLive) => throw new InvalidOperationException("boom");

        public SecretPeek Peek(string id) => new(SecretState.Unknown, null);

        public ConsumeResult TryConsume(string id) => ConsumeResult.Unknown;
    }

    private void AssertNothingThrew()
    {
        // A 400 reached by throwing still burns a stack walk per request and logs a trace someone must read.
        Assert.DoesNotContain(_factory.Logs.Entries, entry => entry.Exception is not null);
        Assert.DoesNotContain(_factory.Logs.Entries, entry => entry.Level >= LogLevel.Error);
    }

    private static async Task<HttpResponseMessage> Post(HttpClient client, string body)
    {
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        return await client.PostAsync(new Uri("/api/secrets", UriKind.Relative), content);
    }

    private static HttpContent Build(string scenario)
    {
        switch (scenario)
        {
            case "body is ten megabytes":
                // Valid JSON, so nothing trips before the size check. TestServer does not enforce Kestrel's
                // MaxRequestBodySize, so in process this is the decoder refusing an oversized ciphertext;
                // the limit itself only exists on a real listener and is checked in e2e/specs/body-limit.
                return Json($$"""{"ciphertext":"{{new string('A', 10 * 1024 * 1024)}}","nonce":"{{ValidNonce}}"}""");
            case "content type is text":
                return new StringContent($$"""{"ciphertext":"{{ValidCiphertext}}","nonce":"{{ValidNonce}}"}""", Encoding.UTF8, "text/plain");
            case "body is invalid utf-8":
                return Bytes([0x7B, 0x22, 0xC3, 0x28, 0x22, 0x7D]);
            case "json is a thousand deep":
                return Json($$"""{"ciphertext":{{new string('[', 1000)}}{{new string(']', 1000)}}}""");
            default:
                return Json(Body(scenario));
        }
    }

    private static string Body(string scenario) => scenario switch
    {
        "ciphertext is not base64 at all" => Payload("!!!!????"),
        "ciphertext uses the standard alphabet" => Payload("ab+/cd+/ab+/cd+/ab+/cd+/"),
        "ciphertext is padded" => Payload(Convert.ToBase64String(new byte[32])),
        "ciphertext has whitespace" => Payload($"{ValidCiphertext[..8]} {ValidCiphertext[8..]}"),
        "ciphertext has a newline" => Payload($"{ValidCiphertext}\\n"),
        "ciphertext is non-canonical" => Payload($"{ValidCiphertext}AR"),
        "ciphertext is too short" => Payload(Base64Url.EncodeToString(new byte[15])),
        "ciphertext is one byte too long" => Payload(Base64Url.EncodeToString(new byte[SecretLimits.MaxCiphertextBytes + 1])),
        "ciphertext is a number" => $$"""{"ciphertext":12345,"nonce":"{{ValidNonce}}"}""",
        "ciphertext is null" => $$"""{"ciphertext":null,"nonce":"{{ValidNonce}}"}""",
        "ciphertext is an object" => $$"""{"ciphertext":{"a":1},"nonce":"{{ValidNonce}}"}""",
        "ttl is zero" => Payload(ValidCiphertext, "\"ttlSeconds\":0"),
        "ttl is negative" => Payload(ValidCiphertext, "\"ttlSeconds\":-1"),
        "ttl is int.MaxValue" => Payload(ValidCiphertext, $"\"ttlSeconds\":{int.MaxValue}"),
        "ttl is fractional" => Payload(ValidCiphertext, "\"ttlSeconds\":1.5"),
        "ttl is a string" => Payload(ValidCiphertext, "\"ttlSeconds\":\"3600\""),
        "json has duplicate keys" => $$"""{"ciphertext":"{{ValidCiphertext}}","ciphertext":"{{ValidCiphertext}}","nonce":"{{ValidNonce}}"}""",
        "json has an unknown field" => Payload(ValidCiphertext, "\"debug\":true"),
        "json has a trailing comma" => $$"""{"ciphertext":"{{ValidCiphertext}}","nonce":"{{ValidNonce}}",}""",
        "json is a comment" => $$"""{"ciphertext":"{{ValidCiphertext}}"/* hi */,"nonce":"{{ValidNonce}}"}""",
        "json is an array" => $$"""[{"ciphertext":"{{ValidCiphertext}}","nonce":"{{ValidNonce}}"}]""",
        "json is truncated" => $$"""{"ciphertext":"{{ValidCiphertext}}","nonce":""",
        "body is empty" => "",
        _ => throw new ArgumentOutOfRangeException(nameof(scenario), scenario, "Unknown scenario."),
    };

    private static string Payload(string ciphertext, string? extra = null) =>
        $$"""{"ciphertext":"{{ciphertext}}","nonce":"{{ValidNonce}}"{{(extra is null ? "" : "," + extra)}}}""";

    private static HttpContent Json(string body) => new StringContent(body, Encoding.UTF8, "application/json");

    private static HttpContent Bytes(byte[] body)
    {
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json; charset=utf-8");
        return content;
    }
}
