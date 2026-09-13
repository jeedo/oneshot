using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Api;

// Task 24 pinned that a failure is generic and task 29 that two unknown ids answer identically. What is left
// is the comparison between different kinds of miss — the place where a difference would tell a prober
// something — and a sweep for the version strings that name what is running.
[Trait("Threat", "T13")]
public sealed partial class InformationDisclosureTests : IClassFixture<CapturingWebApplicationFactory>
{
    private readonly CapturingWebApplicationFactory _factory;

    public InformationDisclosureTests(CapturingWebApplicationFactory factory) => _factory = factory;

    public static TheoryData<string> MalformedIds => new()
    {
        "short",
        "waytoolongtobeavalidsecretidentifier",
        "abcdefghijklmnopqrstu!",
        "abcdefghijklmnopqrstu+",
        "abcdefghijklmnopqrstu=",
        "................",
        "%2e%2e%2f%2e%2e%2f",
        // A null byte is not here: the request never reaches the app, so there is no answer to compare.
    };

    [Theory]
    [MemberData(nameof(MalformedIds))]
    public async Task AMalformedIdAnswersByteForByteTheSameAsAWellFormedUnknownOne(string malformed)
    {
        using var client = _factory.CreateClient();

        var unknown = await Fetch(client, $"/api/secrets/{SecretId.NewId()}");
        var bad = await Fetch(client, $"/api/secrets/{malformed}");

        // Any difference here tells a prober whether their guess was even the right shape, which is the first
        // bit of information an enumeration attack wants.
        Assert.Equal(unknown.Status, bad.Status);
        Assert.Equal(unknown.Body, bad.Body);
        Assert.Equal(unknown.Headers, bad.Headers);
    }

    [Fact]
    public async Task TheTwoKindsOfNotFound_AreDifferentDocumentsByDesign_AndNeitherSaysAnythingMore()
    {
        using var client = _factory.CreateClient();

        var api = await Fetch(client, $"/api/secrets/{SecretId.NewId()}");
        var route = await Fetch(client, "/nonexistent");

        // These two are deliberately unalike, and pinning that is the point. The peek endpoint answers in its
        // one constant shape whatever the outcome (task 17), so an unknown secret is reported the same way an
        // available one is and nothing about the answer depends on whether the id ever existed. The router's
        // miss is a problem document. Telling the two apart reveals only that /api/secrets/{id} is a real
        // endpoint, which the caller knew before asking.
        Assert.Equal(HttpStatusCode.NotFound, api.Status);
        Assert.Equal(HttpStatusCode.NotFound, route.Status);
        Assert.Equal(["state", "expiresAt"], Fields(api.Body).Keys);
        Assert.Equal("unknown", Fields(api.Body)["state"]);
        Assert.Equal(["type", "title", "status", "code"], Fields(route.Body).Keys);
        Assert.Equal("notFound", Fields(route.Body)["code"]);

        // What must hold for both: nothing is echoed, and neither carries anything the other does not except
        // the caching that follows from the path prefix.
        Assert.Equal(
            api.Headers.Where(header => !header.StartsWith("Cache-Control", StringComparison.Ordinal) && !header.StartsWith("Pragma", StringComparison.Ordinal) && !header.StartsWith("Content-Type", StringComparison.Ordinal)),
            route.Headers.Where(header => !header.StartsWith("Content-Type", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("/api/secrets/{id}")]
    [InlineData("/nonexistent")]
    [InlineData("/api/")]
    [InlineData("/s")]
    public async Task NoNotFoundEverNamesThePathThatWasAskedFor(string path)
    {
        using var client = _factory.CreateClient();
        var requested = path.Replace("{id}", SecretId.NewId(), StringComparison.Ordinal);

        var response = await Fetch(client, requested);

        Assert.Equal(HttpStatusCode.NotFound, response.Status);
        // Segments of one or two characters match ordinary words in any fixed document ("s" in "status"),
        // so only segments long enough for their presence to mean an echo are checked.
        foreach (var segment in requested.Split('/', StringSplitOptions.RemoveEmptyEntries).Where(segment => segment.Length > 2))
        {
            Assert.DoesNotContain(segment, response.Body, StringComparison.OrdinalIgnoreCase);
        }
        Assert.DoesNotContain(requested, response.Body, StringComparison.OrdinalIgnoreCase);
    }

    public static TheoryData<string> FaultKinds => new()
    {
        nameof(InvalidOperationException),
        nameof(NullReferenceException),
        nameof(TimeoutException),
        nameof(UnauthorizedAccessException),
        nameof(OutOfMemoryException),
    };

    [Theory]
    [MemberData(nameof(FaultKinds))]
    public async Task EveryKindOfFault_ProducesTheSameDocument_SoTheCauseCannotBeInferred(string kind)
    {
        var baseline = await FaultBody(nameof(InvalidOperationException));

        var actual = await FaultBody(kind);

        Assert.Equal(HttpStatusCode.InternalServerError, actual.Status);
        Assert.Equal(baseline.Body, actual.Body);
        Assert.Equal(baseline.Headers, actual.Headers);
    }

    public static TheoryData<string> EveryKindOfResponse => new()
    {
        "/",
        "/s/abcdefghijklmnopqrstuv",
        "/js/oneshot.js",
        "/healthz",
        "/nonexistent",
        "/api/secrets/abcdefghijklmnopqrstuv",
        "/api/whoami",
    };

    [Theory]
    [MemberData(nameof(EveryKindOfResponse))]
    public async Task NothingInAResponse_NamesTheStackOrItsVersion(string path)
    {
        using var client = _factory.CreateClient();

        var response = await Fetch(client, path);
        // The problem type is a fixed link into RFC 9110 whose section number ("15.5.5") is version shaped
        // but says nothing about what is running, so it is removed before the sweep rather than special-cased
        // inside it.
        var body = RfcLink().Replace(response.Body, "\"type\":\"\"");
        var whole = string.Join("\n", [.. response.Headers, body]);

        foreach (var needle in new[] { "Kestrel", "ASP.NET", "AspNetCore", "netcoreapp", "net10.0", "System.", "Microsoft." })
        {
            Assert.DoesNotContain(needle, whole, StringComparison.OrdinalIgnoreCase);
        }

        // Any dotted version number at all: a build or framework version is as good as a name to an attacker
        // matching against a vulnerability list.
        var version = VersionLike().Match(whole);
        Assert.False(version.Success, $"{path} exposed something version shaped: {version.Value}");
    }

    [Fact]
    public async Task TheVersionSweepWouldNoticeAVersion()
    {
        // Without this, a needle list that matched nothing would let every case above pass while checking
        // nothing at all.
        using var client = _factory.CreateClient();
        var response = await Fetch(client, "/healthz");
        var poisoned = string.Join("\n", [.. response.Headers, "Server: Kestrel/10.0.12"]);

        Assert.Contains("Kestrel", poisoned, StringComparison.OrdinalIgnoreCase);
        Assert.Matches(VersionLike(), poisoned);
        await Task.CompletedTask;
    }

    private static Dictionary<string, string> Fields(string body)
    {
        using var document = JsonDocument.Parse(body);
        return document.RootElement.EnumerateObject().ToDictionary(field => field.Name, field => field.Value.ToString(), StringComparer.Ordinal);
    }

    private async Task<Captured> FaultBody(string kind)
    {
        using var app = _factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services => services.AddSingleton<ISecretStore>(new FaultyStore(kind))));
        using var client = app.CreateClient();
        return await Fetch(client, $"/api/secrets/{SecretId.NewId()}");
    }

    private static async Task<Captured> Fetch(HttpClient client, string path)
    {
        using var response = await client.GetAsync(new Uri(path, UriKind.Relative));
        var headers = response.Headers.Concat(response.Content.Headers)
            // Content-Length and the bundle's caching headers differ by design; everything else must match.
            .Where(header => !header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            .Select(header => $"{header.Key}: {string.Join(", ", header.Value)}")
            .Order(StringComparer.Ordinal)
            .ToList();

        return new Captured(response.StatusCode, await response.Content.ReadAsStringAsync(), headers);
    }

    [GeneratedRegex(@"\b\d+\.\d+\.\d+\b")]
    private static partial Regex VersionLike();

    [GeneratedRegex("\"type\":\"https://tools\\.ietf\\.org/[^\"]*\"")]
    private static partial Regex RfcLink();

    private sealed record Captured(HttpStatusCode Status, string Body, IReadOnlyList<string> Headers);

    private sealed class FaultyStore(string kind) : ISecretStore
    {
        public CreateResult Create(byte[] ciphertext, byte[] nonce, TimeSpan timeToLive) => throw Fault();

        public SecretPeek Peek(string id) => throw Fault();

        public ConsumeResult TryConsume(string id) => throw Fault();

        // Each carries a distinctive message, so a body that echoed anything would differ between them.
        private Exception Fault() => kind switch
        {
            nameof(NullReferenceException) => new NullReferenceException("FAULT-NULL-1a"),
            nameof(TimeoutException) => new TimeoutException("FAULT-TIMEOUT-2b"),
            nameof(UnauthorizedAccessException) => new UnauthorizedAccessException("FAULT-DENIED-3c"),
            nameof(OutOfMemoryException) => new OutOfMemoryException("FAULT-OOM-4d"),
            _ => new InvalidOperationException("FAULT-INVALID-5e"),
        };
    }
}
