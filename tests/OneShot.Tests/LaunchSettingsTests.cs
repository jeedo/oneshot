using System.Text.Json;

using OneShot.Tests.Infrastructure;

namespace OneShot.Tests;

// There is no other way `dotnet run`/IDE debugging gets ASPNETCORE_ENVIRONMENT=Development: this file is the
// only source of that default. Without it, a bare `dotnet run` silently starts in Production (issue #78) —
// confirmed by running it and reading "Hosting environment: Production" out of the actual startup log, not
// assumed from documentation.
public sealed class LaunchSettingsTests
{
    private static JsonElement HttpProfile()
    {
        var path = Path.Join(RepoPaths.Root, "src", "OneShot.Web", "Properties", "launchSettings.json");
        using var document = JsonDocument.Parse(File.ReadAllText(path));

        return document.RootElement.Clone().GetProperty("profiles").GetProperty("http");
    }

    [Fact]
    public void TheHttpProfile_DefaultsToDevelopment()
    {
        var environmentVariables = HttpProfile().GetProperty("environmentVariables");

        Assert.Equal("Development", environmentVariables.GetProperty("ASPNETCORE_ENVIRONMENT").GetString());
    }

    [Fact]
    public void TheHttpProfile_MatchesTheDocumentedLocalUrl()
    {
        // README.md and CLAUDE.md both document http://localhost:5000 as where `dotnet run` serves locally.
        Assert.Equal("http://localhost:5000", HttpProfile().GetProperty("applicationUrl").GetString());
    }

    [Fact]
    public void TheHttpProfile_DoesNotTryToLaunchABrowser()
    {
        // dotnet run honours this even from a plain CLI invocation. A headless dev/CI/container environment
        // has no browser to open, and this file's whole purpose is CLI/IDE parity, not a GUI convenience.
        Assert.False(HttpProfile().GetProperty("launchBrowser").GetBoolean());
    }
}
