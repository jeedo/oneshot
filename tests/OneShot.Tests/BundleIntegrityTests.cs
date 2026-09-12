using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

using OneShot.Tests.Infrastructure;
using OneShot.Web;

namespace OneShot.Tests;

[Trait("Threat", "T7")]
public sealed partial class BundleIntegrityTests : IClassFixture<OneShotFactory>
{
    private readonly OneShotFactory _factory;

    public BundleIntegrityTests(OneShotFactory factory) => _factory = factory;

    [Fact]
    public void RecordedHash_IsBase64Sha256Digest()
    {
        Assert.Equal(32, Convert.FromBase64String(ClientBundle.Sha256).Length);
        Assert.Equal($"sha256-{ClientBundle.Sha256}", ClientBundle.Integrity);
    }

    [Fact]
    public async Task RecordedHash_MatchesServedBundle()
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri("/js/oneshot.js", UriKind.Relative));
        var served = Convert.ToBase64String(SHA256.HashData(await response.Content.ReadAsByteArrayAsync()));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(ClientBundle.Sha256, served);
    }

    [Fact]
    public async Task IndexPage_LoadsOnlyTheBundle_WithMatchingIntegrity()
    {
        using var client = _factory.CreateClient();

        var html = await client.GetStringAsync(new Uri("/", UriKind.Relative));
        var scripts = ScriptTag().Matches(html);

        var script = Assert.Single(scripts);
        Assert.Equal(
            $"<script src=\"/js/oneshot.js\" integrity=\"{ClientBundle.Integrity}\" crossorigin=\"anonymous\" defer></script>",
            WebUtility.HtmlDecode(script.Value));
    }

    [GeneratedRegex("<script\\b[^>]*>.*?</script>", RegexOptions.Singleline)]
    private static partial Regex ScriptTag();
}
