using System.Net;
using System.Text.RegularExpressions;

using OneShot.Tests.Infrastructure;

namespace OneShot.Tests.Pages;

[Trait("Threat", "T1")]
public sealed partial class CreatePageTests : IClassFixture<OneShotFactory>
{
    private readonly OneShotFactory _factory;

    public CreatePageTests(OneShotFactory factory) => _factory = factory;

    [Fact]
    public async Task Page_HasTheCreateControls()
    {
        var html = await Html();

        Assert.Contains("data-page=\"create\"", html, StringComparison.Ordinal);
        Assert.Contains("<textarea id=\"secret\"", html, StringComparison.Ordinal);
        Assert.Contains("<select id=\"ttl\"", html, StringComparison.Ordinal);
        Assert.Contains("<button type=\"button\" id=\"create\"", html, StringComparison.Ordinal);
        Assert.Contains("<input id=\"link\"", html, StringComparison.Ordinal);
        Assert.Contains("<button type=\"button\" id=\"copy\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Page_HasNoFormAndNoInlineScript_SoNothingCanPostPlaintextWithoutTheBundle()
    {
        var html = await Html();

        Assert.DoesNotContain("<form", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(" action=", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("type=\"submit\"", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotMatch(InlineHandler(), html);
        Assert.DoesNotContain("javascript:", html, StringComparison.OrdinalIgnoreCase);
        Assert.Single(ScriptTag().Matches(html));
    }

    [Fact]
    public async Task Textarea_DoesNotInviteTheBrowserToRememberTheSecret()
    {
        var html = await Html();

        var textarea = Regex.Match(html, "<textarea[^>]*>").Value;
        Assert.Contains("autocomplete=\"off\"", textarea, StringComparison.Ordinal);
        Assert.Contains("spellcheck=\"false\"", textarea, StringComparison.Ordinal);
        Assert.DoesNotContain(" name=", textarea, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TtlOptions_StayWithinTheStoreBounds_AndDefaultToOneHour()
    {
        var html = await Html();

        var values = OptionValue().Matches(html).Select(m => int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture)).ToList();
        Assert.NotEmpty(values);
        Assert.All(values, v => Assert.InRange(v, 60, 7 * 24 * 3600));
        Assert.Contains("value=\"3600\" selected", html, StringComparison.Ordinal);
    }

    private async Task<string> Html()
    {
        using var client = _factory.CreateClient();
        using var response = await client.GetAsync(new Uri("/", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync();
    }

    [GeneratedRegex("\\son[a-z]+\\s*=", RegexOptions.IgnoreCase)]
    private static partial Regex InlineHandler();

    [GeneratedRegex("<script\\b", RegexOptions.IgnoreCase)]
    private static partial Regex ScriptTag();

    [GeneratedRegex("<option value=\"(\\d+)\"")]
    private static partial Regex OptionValue();
}
