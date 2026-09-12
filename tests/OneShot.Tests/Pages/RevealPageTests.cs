using System.Net;
using System.Text.RegularExpressions;

using Microsoft.Extensions.DependencyInjection;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Pages;

[Trait("Threat", "T4")]
[Trait("Threat", "T8")]
public sealed partial class RevealPageTests : IClassFixture<OneShotFactory>
{
    private readonly OneShotFactory _factory;

    public RevealPageTests(OneShotFactory factory) => _factory = factory;

    [Fact]
    public async Task Page_HasTheRevealControls_WithRevealDisabledUntilTheScriptEnablesIt()
    {
        var html = await Html(SecretId.NewId());

        Assert.Contains("data-page=\"reveal\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"status\"", html, StringComparison.Ordinal);
        Assert.Contains("<button type=\"button\" id=\"reveal\" disabled", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Page_HasNoFormAndNoInlineScript()
    {
        var html = await Html(SecretId.NewId());

        Assert.DoesNotContain("<form", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(" action=", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotMatch(InlineHandler(), html);
        Assert.Single(ScriptTag().Matches(html));
    }

    [Fact]
    public async Task Page_NeverEchoesTheIdIntoTheMarkup()
    {
        var id = SecretId.NewId();

        var html = await Html(id);

        Assert.DoesNotContain(id, html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Page_RendersForAMalformedId_WithoutTouchingTheStore()
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri("/s/not-a-valid-id", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("data-page=\"reveal\"", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task LoadingThePage_NeverConsumesTheSecret()
    {
        var store = _factory.Services.GetRequiredService<ISecretStore>();
        var id = Assert.IsType<Created>(store.Create(new byte[32], new byte[12], TimeSpan.FromHours(1))).Id;

        for (var i = 0; i < 5; i++)
        {
            await Html(id);
        }

        Assert.Equal(SecretState.Available, store.Peek(id).State);
    }

    [Fact]
    public async Task Page_IsNeverCached()
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri($"/s/{SecretId.NewId()}", UriKind.Relative));

        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy")));
    }

    private async Task<string> Html(string id)
    {
        using var client = _factory.CreateClient();
        using var response = await client.GetAsync(new Uri($"/s/{id}", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync();
    }

    [GeneratedRegex("\\son[a-z]+\\s*=", RegexOptions.IgnoreCase)]
    private static partial Regex InlineHandler();

    [GeneratedRegex("<script\\b", RegexOptions.IgnoreCase)]
    private static partial Regex ScriptTag();
}
