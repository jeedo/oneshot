using OneShot.Tests.Infrastructure;

namespace OneShot.Tests;

// Issue #77's split-channel key delivery is client-side and per-secret opt-in already, but an operator can
// also turn the whole option off deployment-wide via Features:SplitKeyDelivery (task 57 follow-up), checked
// once at startup. T1/T8/T9 hold identically either way — the key never touches the server regardless — so
// this is a UI/config test, not a distinct security mitigation, matching LaunchSettingsTests' precedent for
// an untagged test class.
public sealed class FeatureFlagTests : IClassFixture<OneShotFactory>
{
    private readonly OneShotFactory _factory;

    public FeatureFlagTests(OneShotFactory factory) => _factory = factory;

    [Fact]
    public async Task SplitKeyDelivery_IsOnByDefault_OnTheCreatePage()
    {
        using var client = _factory.CreateClient();

        var html = await client.GetStringAsync(new Uri("/", UriKind.Relative));

        Assert.Contains("id=\"splitKey\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"keyField\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SplitKeyDelivery_IsOnByDefault_OnTheRevealPage()
    {
        using var client = _factory.CreateClient();

        var html = await client.GetStringAsync(new Uri("/s/abcdefghijklmnopqrstuv", UriKind.Relative));

        Assert.Contains("id=\"keyEntry\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"manualKey\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SplitKeyDelivery_CanBeDisabledDeploymentWide_OnBothPages()
    {
        using var factory = _factory.WithWebHostBuilder(builder => builder.UseSetting("Features:SplitKeyDelivery", "false"));
        using var client = factory.CreateClient();

        var createHtml = await client.GetStringAsync(new Uri("/", UriKind.Relative));
        var revealHtml = await client.GetStringAsync(new Uri("/s/abcdefghijklmnopqrstuv", UriKind.Relative));

        Assert.DoesNotContain("splitKey", createHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("keyField", createHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("keyEntry", revealHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("manualKey", revealHtml, StringComparison.Ordinal);
        // The rest of each page is unaffected: the ordinary single-link flow keeps working with the option off.
        Assert.Contains("id=\"secret\"", createHtml, StringComparison.Ordinal);
        Assert.Contains("id=\"reveal\"", revealHtml, StringComparison.Ordinal);
    }
}
