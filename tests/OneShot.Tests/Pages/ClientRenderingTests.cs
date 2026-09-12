using System.Net;

using OneShot.Tests.Infrastructure;

namespace OneShot.Tests.Pages;

[Trait("Threat", "T7")]
public sealed class ClientRenderingTests : IClassFixture<OneShotFactory>
{
    private static readonly string[] UnsafeApis =
    [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function(",
        "createContextualFragment",
        "srcdoc",
    ];

    private readonly OneShotFactory _factory;

    public ClientRenderingTests(OneShotFactory factory) => _factory = factory;

    [Fact]
    public void ClientSources_NeverUseAnHtmlSinkOrDynamicEvaluation()
    {
        var sources = Directory.EnumerateFiles(Path.Combine(RepoPaths.Root, "src", "OneShot.Web", "Client", "src"), "*.ts", SearchOption.AllDirectories).ToList();

        Assert.NotEmpty(sources);
        foreach (var path in sources)
        {
            var text = File.ReadAllText(path);
            foreach (var api in UnsafeApis)
            {
                Assert.DoesNotContain(api, text, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public async Task RevealPage_RendersThePlaintextIntoAPreElement()
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri("/s/abcdefghijklmnopqrstuA", UriKind.Relative));
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("<pre id=\"plaintext\"", html, StringComparison.Ordinal);
        Assert.Contains("<button type=\"button\" id=\"copy\"", html, StringComparison.Ordinal);
    }
}
