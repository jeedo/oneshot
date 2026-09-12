using System.Net;
using System.Text.Json;

using Microsoft.AspNetCore.Mvc.Testing;

namespace OneShot.Tests;

[Trait("Threat", "T14")]
public sealed class ClientBundleTests : IClassFixture<WebApplicationFactory<Program>>
{
    private static readonly string ClientRoot = Path.Combine(RepoRoot(), "src", "OneShot.Web", "Client");

    private readonly WebApplicationFactory<Program> _factory;

    public ClientBundleTests(WebApplicationFactory<Program> factory) => _factory = factory;

    [Fact]
    public void PackageJson_HasNoRuntimeDependencies()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(ClientRoot, "package.json")));

        Assert.True(document.RootElement.TryGetProperty("dependencies", out var dependencies));
        Assert.Equal(JsonValueKind.Object, dependencies.ValueKind);
        Assert.Empty(dependencies.EnumerateObject());
    }

    [Fact]
    public void PackageLock_IsCommitted()
    {
        Assert.True(File.Exists(Path.Combine(ClientRoot, "package-lock.json")));
    }

    [Fact]
    public async Task Bundle_IsServedAsJavaScript()
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri("/js/oneshot.js", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/javascript", response.Content.Headers.ContentType?.MediaType);
        Assert.NotEmpty(await response.Content.ReadAsStringAsync());
    }

    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "OneShot.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("OneShot.sln not found above the test directory.");
    }
}
