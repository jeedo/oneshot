using System.Text.Json;

using OneShot.Tests.Infrastructure;

namespace OneShot.Tests;

// scripts/check_supply_chain.py runs the two vulnerability scanners, which need a network and a registry.
// These are the parts that can be asserted from the repository alone: that the resolved graph is recorded,
// that a restore cannot quietly change it, and that the runtime surface is the small set we think it is.
[Trait("Threat", "T14")]
public sealed class SupplyChainTests
{
    // Everything OneShot.Web is allowed to carry into production. The client adds nothing: its dependencies
    // map is empty and the bundle is first-party (T7, T14).
    private static readonly string[] AllowedRuntimePackages =
    [
        "Microsoft.AspNetCore.Authentication.Negotiate",
        "System.DirectoryServices.Protocols",
    ];

    public static TheoryData<string> Projects => new()
    {
        Path.Combine("src", "OneShot.Web"),
        Path.Combine("tests", "OneShot.Tests"),
    };

    [Theory]
    [MemberData(nameof(Projects))]
    public void EveryProjectRecordsItsResolvedGraph_WithAHashForEveryPackage(string project)
    {
        var path = Path.Combine(RepoPaths.Root, project, "packages.lock.json");

        Assert.True(File.Exists(path), $"{project} has no packages.lock.json; run dotnet restore");
        using var lockFile = JsonDocument.Parse(File.ReadAllText(path));
        var frameworks = lockFile.RootElement.GetProperty("dependencies").EnumerateObject().ToList();

        Assert.NotEmpty(frameworks);
        foreach (var package in frameworks.SelectMany(framework => framework.Value.EnumerateObject()))
        {
            var type = package.Value.GetProperty("type").GetString();
            if (type == "Project")
            {
                // A project reference is built from this repository, so there is nothing downloaded to hash.
                // It is checked here so a downloaded package cannot be recorded as one to skip the next check.
                Assert.False(package.Value.TryGetProperty("resolved", out _), $"{project}: {package.Name} is marked a project but was resolved from a feed");
                continue;
            }

            // A lock file without content hashes pins a version but not the bytes behind it, which is the
            // half that matters if a published package is ever replaced.
            Assert.True(
                package.Value.TryGetProperty("contentHash", out var hash) && hash.GetString()?.Length > 0,
                $"{project}: {package.Name} is recorded without a content hash");
        }
    }

    [Fact]
    public void TheWebProjectCarriesOnlyTheRuntimePackagesWeExpect()
    {
        var packages = LockedPackages(Path.Combine("src", "OneShot.Web"));

        // Direct and transitive together: something arriving through another package still ships.
        Assert.Equal(AllowedRuntimePackages, packages.Order(StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public void TheTestProjectsPackagesNeverReachTheWebProject()
    {
        // FsCheck, xunit and the coverage collector are large surfaces that must stay out of the deployed app.
        var web = LockedPackages(Path.Combine("src", "OneShot.Web"));
        var tests = LockedPackages(Path.Combine("tests", "OneShot.Tests"));

        Assert.Contains("FsCheck", tests);
        Assert.DoesNotContain(web, package => tests.Contains(package) && !AllowedRuntimePackages.Contains(package));
    }

    [Fact]
    public void ARestoreCannotQuietlyChangeTheGraph()
    {
        var props = File.ReadAllText(Path.Combine(RepoPaths.Root, "Directory.Build.props"));

        Assert.Contains("<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>", props, StringComparison.Ordinal);
        // Locked mode on CI is what makes it a lock rather than a cache: without it a restore just rewrites
        // the file and the change never reaches a diff.
        Assert.Contains("<RestoreLockedMode Condition=\"'$(ContinuousIntegrationBuild)' == 'true'\">true</RestoreLockedMode>", props, StringComparison.Ordinal);
    }

    [Fact]
    public void TheClientShipsNoRuntimeDependencies()
    {
        var path = Path.Combine(RepoPaths.Root, "src", "OneShot.Web", "Client", "package.json");
        using var package = JsonDocument.Parse(File.ReadAllText(path));

        Assert.Empty(package.RootElement.GetProperty("dependencies").EnumerateObject());
        Assert.NotEmpty(package.RootElement.GetProperty("devDependencies").EnumerateObject());
    }

    private static HashSet<string> LockedPackages(string project)
    {
        using var lockFile = JsonDocument.Parse(File.ReadAllText(Path.Combine(RepoPaths.Root, project, "packages.lock.json")));

        return [.. lockFile.RootElement.GetProperty("dependencies")
            .EnumerateObject()
            .SelectMany(framework => framework.Value.EnumerateObject())
            .Select(package => package.Name)];
    }
}
