using System.Net;
using System.Net.Http.Headers;
using System.Text;

using Microsoft.Extensions.DependencyInjection;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Api;

// Task 18 pinned the reveal endpoint's own rejection matrix. This is the surface around it: no endpoint
// anywhere opts into CORS, so a foreign origin gets no usable preflight, no permission to read any response,
// and no reflection of itself back into one. The browser half lives in tests/e2e/specs/cross-origin.spec.ts.
[Trait("Threat", "T4")]
public sealed class CrossOriginTests : IClassFixture<OneShotFactory>
{
    private const string ForeignOrigin = "https://evil.test";

    private static readonly string[] ForeignOrigins =
    [
        "https://evil.test",
        "http://evil.test",
        "https://localhost.evil.test",
        "http://localhost:8080",
        "null",
    ];

    private readonly OneShotFactory _factory;

    public CrossOriginTests(OneShotFactory factory) => _factory = factory;

    public static TheoryData<string> Endpoints => new()
    {
        "/",
        "/s/{id}",
        "/api/secrets",
        "/api/secrets/{id}",
        "/api/secrets/{id}/reveal",
        "/api/whoami",
        "/healthz",
    };

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task ForeignPreflight_IsRefusedOnEveryEndpoint(string template)
    {
        var id = Create();
        using var client = _factory.CreateClient();

        foreach (var origin in ForeignOrigins)
        {
            using var request = new HttpRequestMessage(HttpMethod.Options, Url(template, id));
            request.Headers.TryAddWithoutValidation("Origin", origin);
            request.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "POST");
            request.Headers.TryAddWithoutValidation("Access-Control-Request-Headers", "x-oneshot-reveal,content-type");

            using var response = await client.SendAsync(request);

            // No Access-Control-Allow-* means the browser discards the preflight and never sends the real
            // request, whatever the status code happens to be.
            AssertNoCorsHeaders(response);
            Assert.False(response.IsSuccessStatusCode, $"{template} answered a foreign preflight from {origin} with {(int)response.StatusCode}");
        }

        Assert.Equal(SecretState.Available, Store.Peek(id).State);
    }

    [Fact]
    public async Task ForeignPreflight_OnTheConsumePath_Is405_NotAnEmptySuccess()
    {
        var id = Create();
        using var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Options, Url("/api/secrets/{id}/reveal", id));
        request.Headers.TryAddWithoutValidation("Origin", ForeignOrigin);
        request.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "POST");

        using var response = await client.SendAsync(request);

        // 405 rather than 204: nothing in the pipeline answers OPTIONS, which is what "no CORS registered" looks
        // like from outside. A 204 here would be the signature of a preflight handler having been added.
        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        Assert.Equal(SecretState.Available, Store.Peek(id).State);
    }

    // The pages carry no handlers — they are static markup — so nothing in Razor Pages narrows the methods
    // they answer. Left alone, TRACE renders the whole reveal page and OPTIONS answers a bare 200, neither of
    // which any client of this app ever asks for. The API endpoints already answer 405 with Allow; the pages
    // an attacker actually links to should not be looser than the API behind them.
    [Theory]
    [InlineData("/")]
    [InlineData("/s/{id}")]
    public async Task ThePages_AnswerNothingButGetAndHead(string template)
    {
        var id = Create();
        using var client = _factory.CreateClient();

        foreach (var method in new[] { "OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "POST" })
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), Url(template, id));
            using var response = await client.SendAsync(request);

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
            Assert.Equal("", await response.Content.ReadAsStringAsync());
            var allow = response.Content.Headers.Allow.Concat(Header(response, "Allow")).Order(StringComparer.Ordinal);
            Assert.Equal(["GET", "HEAD"], allow);
        }

        foreach (var method in new[] { HttpMethod.Get, HttpMethod.Head })
        {
            using var request = new HttpRequestMessage(method, Url(template, id));
            using var response = await client.SendAsync(request);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        Assert.Equal(SecretState.Available, Store.Peek(id).State);
    }

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task NoOrdinaryResponse_GrantsAForeignOriginPermissionToReadIt(string template)
    {
        var id = Create();
        using var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, Url(template, id));
        request.Headers.TryAddWithoutValidation("Origin", ForeignOrigin);
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "cross-site");
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Mode", "cors");

        using var response = await client.SendAsync(request);

        // Whether the endpoint answers 200 or 404, the attacker's script cannot read a byte of it without
        // Access-Control-Allow-Origin. Peek even succeeds here — and is still unreadable cross-origin.
        AssertNoCorsHeaders(response);
        Assert.Equal(SecretState.Available, Store.Peek(id).State);
    }

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task NoResponseEverReflectsTheRequestOrigin(string template)
    {
        var id = Create();
        using var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, Url(template, id));
        request.Headers.TryAddWithoutValidation("Origin", ForeignOrigin);

        using var response = await client.SendAsync(request);

        foreach (var (name, value) in AllHeaders(response))
        {
            Assert.DoesNotContain("evil.test", value, StringComparison.OrdinalIgnoreCase);
            // Vary: Origin is the fingerprint of an origin-dependent response — there must not be one.
            Assert.False(
                name.Equals("Vary", StringComparison.OrdinalIgnoreCase) && value.Contains("Origin", StringComparison.OrdinalIgnoreCase),
                $"{template} varies its response on Origin");
        }
    }

    // Exactly what a browser puts on the wire for <form method="post" action="…/reveal"> on an attacker's page:
    // one of the three enctypes a form can produce, no custom header, and navigation-shaped Sec-Fetch metadata.
    public static TheoryData<string, string> FormPosts => new()
    {
        { "application/x-www-form-urlencoded", "ciphertext=x&nonce=y" },
        { "multipart/form-data; boundary=----x", "------x\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n------x--\r\n" },
        { "text/plain", "{\"x\":1}" },
    };

    [Theory]
    [MemberData(nameof(FormPosts))]
    public async Task ACrossSiteFormSubmission_CannotReachTheConsumePath(string contentType, string body)
    {
        var id = Create();
        using var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, Url("/api/secrets/{id}/reveal", id))
        {
            Content = new StringContent(body, Encoding.UTF8),
        };
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        request.Headers.TryAddWithoutValidation("Origin", ForeignOrigin);
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "cross-site");
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Mode", "navigate");
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Dest", "iframe");
        request.Headers.TryAddWithoutValidation("Referer", $"{ForeignOrigin}/csrf.html");

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        AssertNoCorsHeaders(response);
        Assert.Equal(SecretState.Available, Store.Peek(id).State);
    }

    // A no-cors fetch is the only cross-origin fetch a browser sends without a preflight. It can carry no
    // custom header, and its Content-Type is restricted to the three form values — so it lands here.
    [Fact]
    public async Task ANoCorsFetch_CannotReachTheConsumePath()
    {
        var id = Create();
        using var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, Url("/api/secrets/{id}/reveal", id))
        {
            Content = new StringContent("{}", Encoding.UTF8, "text/plain"),
        };
        request.Headers.TryAddWithoutValidation("Origin", ForeignOrigin);
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "cross-site");
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Mode", "no-cors");

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(SecretState.Available, Store.Peek(id).State);
    }

    [Fact]
    public async Task AfterEveryCrossOriginAttempt_TheOwnerStillRevealsExactlyOnce()
    {
        var id = Create();
        using var client = _factory.CreateClient();

        foreach (var method in new[] { HttpMethod.Options, HttpMethod.Get, HttpMethod.Post, HttpMethod.Head })
        {
            using var attack = new HttpRequestMessage(method, Url("/api/secrets/{id}/reveal", id));
            attack.Headers.TryAddWithoutValidation("Origin", ForeignOrigin);
            attack.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "cross-site");
            if (method == HttpMethod.Post)
            {
                attack.Content = new StringContent("{}", Encoding.UTF8, "text/plain");
            }

            using var ignored = await client.SendAsync(attack);
        }

        var consumed = Store.TryConsume(id);
        Assert.Equal(ConsumeOutcome.Consumed, consumed.Outcome);
        consumed.Secret!.Dispose();
    }

    private static void AssertNoCorsHeaders(HttpResponseMessage response)
    {
        var cors = AllHeaders(response)
            .Where(header => header.Name.StartsWith("Access-Control-", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        Assert.Empty(cors);
    }

    private static IEnumerable<string> Header(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues(name, out var values) ? values : [];

    private static IEnumerable<(string Name, string Value)> AllHeaders(HttpResponseMessage response)
    {
        return response.Headers.Concat(response.Content.Headers)
            .SelectMany(header => header.Value.Select(value => (header.Key, value)));
    }

    private static Uri Url(string template, string id) => new(template.Replace("{id}", id, StringComparison.Ordinal), UriKind.Relative);

    private ISecretStore Store => _factory.Services.GetRequiredService<ISecretStore>();

    private string Create() =>
        Assert.IsType<Created>(Store.Create(new byte[32], new byte[12], TimeSpan.FromHours(1))).Id;
}
