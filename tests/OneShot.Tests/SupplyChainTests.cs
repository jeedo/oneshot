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

    // Path.Join throughout rather than Path.Combine: Combine silently discards everything before a segment
    // that turns out to be rooted, so a path built from a member-data argument can end up pointing outside the
    // repository. Join only concatenates, which is all these need.
    public static TheoryData<string> Projects => new()
    {
        Path.Join("src", "OneShot.Web"),
        Path.Join("tests", "OneShot.Tests"),
    };

    [Theory]
    [MemberData(nameof(Projects))]
    public void EveryProjectRecordsItsResolvedGraph_WithAHashForEveryPackage(string project)
    {
        var path = Path.Join(RepoPaths.Root, project, "packages.lock.json");

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
        var packages = LockedPackages(Path.Join("src", "OneShot.Web"));

        // Direct and transitive together: something arriving through another package still ships.
        Assert.Equal(AllowedRuntimePackages, packages.Order(StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public void TheTestProjectsPackagesNeverReachTheWebProject()
    {
        // FsCheck, xunit and the coverage collector are large surfaces that must stay out of the deployed app.
        var web = LockedPackages(Path.Join("src", "OneShot.Web"));
        var tests = LockedPackages(Path.Join("tests", "OneShot.Tests"));

        Assert.Contains("FsCheck", tests);
        Assert.DoesNotContain(web, package => tests.Contains(package) && !AllowedRuntimePackages.Contains(package));
    }

    [Fact]
    public void ARestoreCannotQuietlyChangeTheGraph()
    {
        var props = File.ReadAllText(Path.Join(RepoPaths.Root, "Directory.Build.props"));

        Assert.Contains("<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>", props, StringComparison.Ordinal);
        // Locked mode on CI is what makes it a lock rather than a cache: without it a restore just rewrites
        // the file and the change never reaches a diff.
        Assert.Contains("<RestoreLockedMode Condition=\"'$(ContinuousIntegrationBuild)' == 'true'\">true</RestoreLockedMode>", props, StringComparison.Ordinal);
    }

    [Fact]
    public void TheClientShipsNoRuntimeDependencies()
    {
        var path = Path.Join(RepoPaths.Root, "src", "OneShot.Web", "Client", "package.json");
        using var package = JsonDocument.Parse(File.ReadAllText(path));

        Assert.Empty(package.RootElement.GetProperty("dependencies").EnumerateObject());
        Assert.NotEmpty(package.RootElement.GetProperty("devDependencies").EnumerateObject());
    }

    [Fact]
    public void EveryWorkflowActionIsPinnedToACommit_NotATag()
    {
        // A tag is mutable: whoever controls the action can move v7 to new code, and CI runs with a checkout
        // of this repository. A 40-character commit is the only reference that cannot be repointed.
        var workflows = Directory.GetFiles(Path.Join(RepoPaths.Root, ".github", "workflows"), "*.yml");
        var unpinned = new List<string>();

        Assert.NotEmpty(workflows);
        foreach (var workflow in workflows)
        {
            foreach (var line in File.ReadLines(workflow))
            {
                var trimmed = line.Trim();
                if (!trimmed.StartsWith("- uses:", StringComparison.Ordinal) && !trimmed.StartsWith("uses:", StringComparison.Ordinal))
                {
                    continue;
                }

                var reference = trimmed[(trimmed.IndexOf("uses:", StringComparison.Ordinal) + 5)..].Split('#')[0].Trim();
                var version = reference.Contains('@', StringComparison.Ordinal) ? reference[(reference.IndexOf('@', StringComparison.Ordinal) + 1)..] : "";
                if (version.Length != 40 || !version.All(character => char.IsAsciiHexDigitLower(character)))
                {
                    unpinned.Add($"{Path.GetFileName(workflow)}: {reference}");
                }
            }
        }

        Assert.Empty(unpinned);
    }

    [Fact]
    public void TheWorkflowRunsEveryGateThisRepositoryHas()
    {
        // A gate nobody runs is decoration. If a check is added to CLAUDE.md's local list it belongs here too.
        var ci = File.ReadAllText(Path.Join(RepoPaths.Root, ".github", "workflows", "ci.yml"));

        foreach (var gate in new[]
        {
            "dotnet restore OneShot.sln --locked-mode",
            "dotnet build OneShot.sln",
            "dotnet format OneShot.sln",
            "dotnet test OneShot.sln",
            "scripts/check_coverage.py",
            "scripts/check_docs.py",
            "scripts/check_threat_coverage.py",
            "unittest discover -s scripts",
            "src/OneShot.Web/Client run check",
            "tests/e2e run check",
        })
        {
            Assert.Contains(gate, ci, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void EveryZapSuppressionSaysWhyItIsThere()
    {
        // An allowlist without reasons is how a scanner stops meaning anything: the entries outlive whoever
        // understood them. Each line has to carry a justification long enough to be one.
        var rules = Path.Join(RepoPaths.Root, ".github", "zap-rules.tsv");
        var bare = new List<string>();
        var entries = 0;

        foreach (var line in File.ReadLines(rules))
        {
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            entries++;
            var fields = line.Split('\t');
            if (fields.Length < 3 || fields[2].Trim().Length < 40)
            {
                bare.Add(line);
            }
        }

        Assert.Empty(bare);
        // A file of nothing but comments would pass the loop above while suppressing nothing, which is fine —
        // but it would also pass if the file were emptied by accident, so the count is pinned.
        Assert.Equal(1, entries);
    }

    private static HashSet<string> LockedPackages(string project)
    {
        using var lockFile = JsonDocument.Parse(File.ReadAllText(Path.Join(RepoPaths.Root, project, "packages.lock.json")));

        return [.. lockFile.RootElement.GetProperty("dependencies")
            .EnumerateObject()
            .SelectMany(framework => framework.Value.EnumerateObject())
            .Select(package => package.Name)];
    }
}
