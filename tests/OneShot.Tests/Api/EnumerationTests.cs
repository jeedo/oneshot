using System.Net;

using Microsoft.AspNetCore.Hosting;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Api;

// Guessing an Id is the only way in without a link, so the Ids must be unguessable and the answers must be
// indistinguishable from one another.
[Trait("Threat", "T3")]
public sealed class EnumerationTests : IClassFixture<OneShotFactory>
{
    private const int Probes = 10_000;
    private const int Samples = 100_000;
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    private readonly OneShotFactory _factory;

    public EnumerationTests(OneShotFactory factory) => _factory = factory;

    [Fact]
    public async Task TenThousandUnknownIds_AnswerWithByteIdenticalResponses()
    {
        using var client = _factory.CreateClient();
        byte[]? expectedBody = null;
        string? expectedContentType = null;

        for (var i = 0; i < Probes; i++)
        {
            using var response = await client.GetAsync(new Uri($"/api/secrets/{SecretId.NewId()}", UriKind.Relative));
            var body = await response.Content.ReadAsByteArrayAsync();

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            expectedBody ??= body;
            expectedContentType ??= response.Content.Headers.ContentType?.ToString();
            Assert.Equal(expectedBody, body);
            Assert.Equal(expectedContentType, response.Content.Headers.ContentType?.ToString());
        }
    }

    [Fact]
    public async Task AMalformedIdIsIndistinguishableFromAWellFormedUnknownOne()
    {
        using var client = _factory.CreateClient();

        using var wellFormed = await client.GetAsync(new Uri($"/api/secrets/{SecretId.NewId()}", UriKind.Relative));
        using var malformed = await client.GetAsync(new Uri("/api/secrets/abcdefghijklmnopqrstuB", UriKind.Relative));

        Assert.Equal(wellFormed.StatusCode, malformed.StatusCode);
        Assert.Equal(
            await wellFormed.Content.ReadAsByteArrayAsync(),
            await malformed.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public void AHundredThousandIds_AreTwentyTwoCharactersAndAllDistinct()
    {
        var ids = new HashSet<string>(Samples, StringComparer.Ordinal);

        for (var i = 0; i < Samples; i++)
        {
            var id = SecretId.NewId();
            Assert.Equal(22, id.Length);
            Assert.True(ids.Add(id), $"Id {id} was generated twice");
        }

        Assert.Equal(Samples, ids.Count);
    }

    [Fact]
    public void TheFreeCharactersOfAnId_AreUniformAcrossTheAlphabet()
    {
        // The last character carries only two bits of the 128, so it is excluded here and checked below.
        var counts = new int[Alphabet.Length];
        for (var i = 0; i < Samples; i++)
        {
            foreach (var c in SecretId.NewId()[..21])
            {
                var index = Alphabet.IndexOf(c, StringComparison.Ordinal);
                Assert.InRange(index, 0, Alphabet.Length - 1);
                counts[index]++;
            }
        }

        // 63 degrees of freedom: a fair generator exceeds 103.4 about once in a thousand runs, so 150 leaves
        // ample headroom while a biased or truncated generator lands orders of magnitude above it.
        Assert.InRange(ChiSquared(counts), 0, 150);
    }

    [Fact]
    public void TheFinalCharacterOfAnId_IsUniformAcrossItsFourCanonicalValues()
    {
        const string Canonical = "AQgw";
        var counts = new int[Canonical.Length];

        for (var i = 0; i < Samples; i++)
        {
            var index = Canonical.IndexOf(SecretId.NewId()[^1], StringComparison.Ordinal);
            Assert.InRange(index, 0, Canonical.Length - 1);
            counts[index]++;
        }

        // 3 degrees of freedom: 16.3 is the one-in-a-thousand point, so 40 is a wide margin.
        Assert.InRange(ChiSquared(counts), 0, 40);
    }

    [Fact]
    public async Task TheReadLimiter_RejectsAfterItsBurst_AndRecoversAfterTheWindow()
    {
        // A one second window keeps the recovery observable without the test sleeping for a minute; the
        // limiter replenishes on real time, so the fake clock cannot stand in here.
        using var app = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("RateLimiting:ReadPerWindow", "5");
            builder.UseSetting("RateLimiting:Window", "00:00:01");
        });
        using var client = app.CreateClient();

        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.NotFound, (await Probe(client)).StatusCode);
        }

        var rejected = await Probe(client);
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.NotNull(rejected.Headers.RetryAfter);

        await Task.Delay(TimeSpan.FromSeconds(1.5));

        Assert.Equal(HttpStatusCode.NotFound, (await Probe(client)).StatusCode);
    }

    private static async Task<HttpResponseMessage> Probe(HttpClient client)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"/api/secrets/{SecretId.NewId()}", UriKind.Relative));
        request.Headers.TryAddWithoutValidation(RemoteIpStartupFilter.Header, "198.51.100.99");
        return await client.SendAsync(request);
    }

    private static double ChiSquared(int[] counts)
    {
        var expected = (double)counts.Sum() / counts.Length;
        return counts.Sum(count => Math.Pow(count - expected, 2) / expected);
    }
}
