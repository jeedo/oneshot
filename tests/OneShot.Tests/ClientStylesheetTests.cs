using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

using OneShot.Tests.Infrastructure;
using OneShot.Web;

namespace OneShot.Tests;

// Mirrors BundleIntegrityTests/ClientBundleTests exactly, for the second and last client asset (issue #80).
// style-src 'self' already permits a same-origin stylesheet with no CSP change (SecurityHeadersTests pins the
// CSP string and would fail if that were no longer true) — the integrity attribute here is the same
// defense-in-depth the script already gets, not something the CSP depends on.
[Trait("Threat", "T7")]
public sealed partial class ClientStylesheetTests : IClassFixture<OneShotFactory>
{
    private readonly OneShotFactory _factory;

    public ClientStylesheetTests(OneShotFactory factory) => _factory = factory;

    [Fact]
    public void RecordedHash_IsBase64Sha256Digest()
    {
        Assert.Equal(32, Convert.FromBase64String(ClientStylesheet.Sha256).Length);
        Assert.Equal($"sha256-{ClientStylesheet.Sha256}", ClientStylesheet.Integrity);
    }

    [Fact]
    public async Task Stylesheet_IsServedAsCss()
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri("/css/oneshot.css", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/css", response.Content.Headers.ContentType?.MediaType);
        Assert.NotEmpty(await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task RecordedHash_MatchesServedStylesheet()
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri("/css/oneshot.css", UriKind.Relative));
        var served = Convert.ToBase64String(SHA256.HashData(await response.Content.ReadAsByteArrayAsync()));

        Assert.Equal(ClientStylesheet.Sha256, served);
    }

    [Fact]
    public async Task IndexPage_LinksOnlyTheStylesheet_WithMatchingIntegrity()
    {
        using var client = _factory.CreateClient();

        var html = await client.GetStringAsync(new Uri("/", UriKind.Relative));
        var links = LinkTag().Matches(html);

        var link = Assert.Single(links);
        Assert.Equal(
            $"<link rel=\"stylesheet\" href=\"/css/oneshot.css\" integrity=\"{ClientStylesheet.Integrity}\" crossorigin=\"anonymous\" />",
            WebUtility.HtmlDecode(link.Value));
    }

    [GeneratedRegex("<link\\b[^>]*>")]
    private static partial Regex LinkTag();
}
