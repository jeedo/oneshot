using System.Net;

using OneShot.Web.Api;

namespace OneShot.Tests;

// The chiseled container image (plan task 48) has no shell, curl, or wget for Docker's HEALTHCHECK to use, so
// the app probes itself: this is the logic behind `dotnet OneShot.Web.dll --healthcheck`.
public sealed class HealthCheckProbeTests
{
    [Fact]
    public async Task RunAsync_ReturnsZero_WhenHealthzRespondsSuccessfully()
    {
        var exitCode = await HealthCheckProbe.RunAsync(new StubHandler(HttpStatusCode.OK));

        Assert.Equal(0, exitCode);
    }

    [Fact]
    public async Task RunAsync_ReturnsOne_WhenHealthzRespondsWithAnErrorStatus()
    {
        var exitCode = await HealthCheckProbe.RunAsync(new StubHandler(HttpStatusCode.ServiceUnavailable));

        Assert.Equal(1, exitCode);
    }

    [Fact]
    public async Task RunAsync_ReturnsOne_WhenTheRequestCannotBeSent()
    {
        var exitCode = await HealthCheckProbe.RunAsync(new ThrowingHandler());

        Assert.Equal(1, exitCode);
    }

    [Fact]
    public async Task RunAsync_RequestsHealthzOnTheDocumentedPort()
    {
        var handler = new StubHandler(HttpStatusCode.OK);

        await HealthCheckProbe.RunAsync(handler);

        Assert.NotNull(handler.LastRequest);
        Assert.Equal($"http://127.0.0.1:{HealthCheckProbe.Port}/healthz", handler.LastRequest.RequestUri?.ToString());
    }

    private sealed class StubHandler(HttpStatusCode status) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new HttpResponseMessage(status));
        }
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => throw new HttpRequestException("connection refused");
    }
}
