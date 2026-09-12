using System.Net;

using OneShot.Tests.Infrastructure;

namespace OneShot.Tests;

public sealed class SmokeTests : IClassFixture<OneShotFactory>
{
    private readonly OneShotFactory _factory;

    public SmokeTests(OneShotFactory factory) => _factory = factory;

    [Fact]
    public async Task IndexPage_ReturnsOkHtml()
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri("/", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
    }
}
