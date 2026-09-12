using System.Net;
using System.Text;
using System.Text.Json;

using Microsoft.Extensions.Logging;

using OneShot.Web.Secrets;

namespace OneShot.Tests.Infrastructure;

// The fixtures below are what every security test depends on, so their guarantees are themselves tested.
public sealed class TestInfrastructureTests : IClassFixture<CapturingWebApplicationFactory>
{
    private readonly CapturingWebApplicationFactory _factory;

    public TestInfrastructureTests(CapturingWebApplicationFactory factory) => _factory = factory;

    [Fact]
    public void FakeTimeApp_DrivesTheClockTheApplicationActuallyUses()
    {
        using var app = _factory.WithFakeTime();

        var created = Assert.IsType<Created>(app.Service<ISecretStore>().Create(new byte[32], new byte[12], TimeSpan.FromMinutes(30)));

        Assert.Equal(FakeTimeApp.DefaultNow.AddMinutes(30), created.ExpiresAtUtc);
    }

    [Fact]
    public void FakeTimeApp_AdvancesExpiryWithoutWaiting()
    {
        using var app = _factory.WithFakeTime();
        var store = app.Service<ISecretStore>();
        var id = Assert.IsType<Created>(store.Create(new byte[32], new byte[12], TimeSpan.FromMinutes(1))).Id;

        app.Clock.Advance(TimeSpan.FromMinutes(1));

        Assert.Equal(SecretState.Unknown, store.Peek(id).State);
    }

    [Fact]
    public void FakeTimeApp_InstancesDoNotShareAClock()
    {
        using var first = _factory.WithFakeTime();
        using var second = _factory.WithFakeTime();

        first.Clock.Advance(TimeSpan.FromDays(1));

        Assert.Equal(FakeTimeApp.DefaultNow, second.Clock.GetUtcNow());
    }

    [Fact]
    public async Task CapturingHandler_SeesThePathQueryHeadersAndBodyOfEveryRequest()
    {
        using var capture = new CapturingHandler();
        using var app = _factory.WithFakeTime();
        using var client = app.CreateClient(capture);
        using var content = new StringContent("{\"canary\":\"BODYCANARY\"}", Encoding.UTF8, "application/json");
        content.Headers.Add("X-Canary-Header", "HEADERCANARY");

        using var response = await client.PostAsync(new Uri("/api/secrets?q=QUERYCANARY", UriKind.Relative), content);

        var request = Assert.Single(capture.Requests);
        Assert.Equal("POST", request.Method);
        Assert.Contains("/api/secrets", request.Uri, StringComparison.Ordinal);
        Assert.True(capture.AnyContains("QUERYCANARY"));
        Assert.True(capture.AnyContains("BODYCANARY"));
        Assert.True(capture.AnyContains("HEADERCANARY"));
        Assert.False(capture.AnyContains("NEVERSENT"));
    }

    [Fact]
    public async Task CapturingHandler_StillDeliversTheRequest()
    {
        using var capture = new CapturingHandler();
        using var app = _factory.WithFakeTime();
        using var client = app.CreateClient(capture);

        using var response = await client.GetAsync(new Uri("/healthz", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task TestNegotiateHandler_ImpersonatesAWindowsAccount()
    {
        using var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/whoami", UriKind.Relative));
        request.Headers.TryAddWithoutValidation(TestNegotiateHandler.UserHeader, "CORP\\fixture");

        using var response = await client.SendAsync(request);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("CORP\\fixture", body.RootElement.GetProperty("windowsUser").GetString());
    }

    [Fact]
    public async Task LogSink_CapturesStructuredStateAndSurvivesClearing()
    {
        _factory.Logs.Clear();
        using var client = _factory.CreateClient();

        using var response = await client.PostAsync(
            new Uri("/api/secrets", UriKind.Relative),
            new StringContent("{\"ciphertext\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA\",\"nonce\":\"8PHy8_T19vf4-fr7\"}", Encoding.UTF8, "application/json"));

        var audit = Assert.Single(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
        Assert.Equal(LogLevel.Information, audit.Level);
        Assert.Contains(audit.State, pair => pair.Key == "secretId");
        Assert.True(audit.Contains("create"));

        _factory.Logs.Clear();
        Assert.Empty(_factory.Logs.Entries);
    }

    [Fact]
    public async Task RemoteIpStartupFilter_GivesUnpinnedRequestsTheirOwnAddress()
    {
        using var client = _factory.CreateClient();

        // Without a pinned address each request lands in its own rate-limit bucket, so unrelated tests
        // can never exhaust one another's budget.
        for (var i = 0; i < 40; i++)
        {
            using var response = await client.GetAsync(new Uri($"/api/secrets/{SecretId.NewId()}", UriKind.Relative));
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
    }
}
