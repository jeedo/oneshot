using System.Net;

using Microsoft.Extensions.DependencyInjection;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Pages;

// The link a scanner actually follows is /s/{id}, not the API, so the page itself is driven here with the
// corpus. Task 17 covers the API endpoint and task 18 the reveal rejection matrix.
[Trait("Threat", "T4")]
public sealed class PreBurnTests : IClassFixture<OneShotFactory>
{
    private static readonly string[] ScannerUserAgents =
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OutlookSafeLinks",
        "Mozilla/5.0 (compatible; ProofpointURLDefense/1.0)",
        "Mozilla/5.0 (compatible; Mimecast Link Scanner)",
        "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
        "Twitterbot/1.0",
        "facebookexternalhit/1.1",
        "curl/8.5.0",
        "Wget/1.21",
        "python-requests/2.32",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Barracuda Link Protection",
    ];

    private static readonly (string Name, string Value)[][] PrefetchHeaderSets =
    [
        [],
        [("Purpose", "prefetch")],
        [("Sec-Purpose", "prefetch")],
        [("Sec-Purpose", "prefetch;prerender")],
        [("X-Purpose", "preview")],
        [("X-Moz", "prefetch")],
        [("Sec-Fetch-Dest", "document"), ("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-Site", "none")],
    ];

    private readonly OneShotFactory _factory;

    public PreBurnTests(OneShotFactory factory) => _factory = factory;

    [Fact]
    public async Task NoScannerOrPrefetcher_CanBurnTheLinkItFollows()
    {
        var store = _factory.Services.GetRequiredService<ISecretStore>();
        var id = Assert.IsType<Created>(store.Create(new byte[32], new byte[12], TimeSpan.FromHours(1))).Id;
        using var client = _factory.CreateClient();
        var requests = 0;

        foreach (var userAgent in ScannerUserAgents)
        {
            foreach (var headers in PrefetchHeaderSets)
            {
                foreach (var path in new[] { $"/s/{id}", $"/api/secrets/{id}" })
                {
                    foreach (var method in new[] { HttpMethod.Get, HttpMethod.Head })
                    {
                        using var request = new HttpRequestMessage(method, new Uri(path, UriKind.Relative));
                        request.Headers.TryAddWithoutValidation("User-Agent", userAgent);
                        foreach (var (name, value) in headers)
                        {
                            request.Headers.TryAddWithoutValidation(name, value);
                        }

                        using var response = await client.SendAsync(request);
                        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                        requests++;
                    }
                }
            }
        }

        // Every one of those was a safe method, so the secret must still be sealed and consumable exactly once.
        Assert.Equal(ScannerUserAgents.Length * PrefetchHeaderSets.Length * 4, requests);
        Assert.Equal(SecretState.Available, store.Peek(id).State);

        var consumed = store.TryConsume(id);
        Assert.Equal(ConsumeOutcome.Consumed, consumed.Outcome);
        consumed.Secret!.Dispose();
    }

    [Fact]
    public async Task RepeatedScansOfTheSameLink_LeaveItUntouched()
    {
        var store = _factory.Services.GetRequiredService<ISecretStore>();
        var id = Assert.IsType<Created>(store.Create(new byte[32], new byte[12], TimeSpan.FromHours(1))).Id;
        using var client = _factory.CreateClient();

        for (var i = 0; i < 50; i++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"/s/{id}", UriKind.Relative));
            request.Headers.TryAddWithoutValidation("User-Agent", "Mozilla/5.0 (compatible; Mimecast Link Scanner)");
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        Assert.Equal(SecretState.Available, store.Peek(id).State);
    }

    [Fact]
    public async Task TheRevealPage_TellsAScannerNothingAboutTheSecret()
    {
        var store = _factory.Services.GetRequiredService<ISecretStore>();
        var ciphertext = Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();
        var id = Assert.IsType<Created>(store.Create(ciphertext, new byte[12], TimeSpan.FromHours(1))).Id;
        using var client = _factory.CreateClient();

        var html = await client.GetStringAsync(new Uri($"/s/{id}", UriKind.Relative));

        // The page is the same static markup for every secret: no id, no ciphertext, no state.
        Assert.DoesNotContain(id, html, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(ciphertext), html, StringComparison.Ordinal);
        Assert.DoesNotContain("available", html, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(SecretState.Available, store.Peek(id).State);
    }
}
