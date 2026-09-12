using System.Net;
using System.Text.Json;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Api;

[Trait("Threat", "T13")]
public sealed class ErrorHandlingTests : IClassFixture<CapturingWebApplicationFactory>
{
    private const string Canary = "CANARY-EXCEPTION-9f3a";

    private readonly CapturingWebApplicationFactory _factory;

    public ErrorHandlingTests(CapturingWebApplicationFactory factory) => _factory = factory;

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Development")]
    public async Task AnExceptionInAHandler_Is500_WithNoStackTypeOrMessage_InEveryEnvironment(string environment)
    {
        using var app = Faulty(environment);
        using var client = app.CreateClient();

        using var response = await client.GetAsync(new Uri($"/api/secrets/{SecretId.NewId()}", UriKind.Relative));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.DoesNotContain(Canary, body, StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(FaultyStore), body, StringComparison.Ordinal);
        Assert.DoesNotContain("Exception", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("   at ", body, StringComparison.Ordinal);
        Assert.DoesNotContain("OneShot.Web", body, StringComparison.Ordinal);
        Assert.DoesNotContain("<html", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AnExceptionInAHandler_ProducesTheSameBodyInDevelopmentAsInProduction()
    {
        using var development = Faulty(Environments.Development);
        using var production = Faulty(Environments.Production);
        using var devClient = development.CreateClient();
        using var prodClient = production.CreateClient();
        var id = SecretId.NewId();

        using var dev = await devClient.GetAsync(new Uri($"/api/secrets/{id}", UriKind.Relative));
        using var prod = await prodClient.GetAsync(new Uri($"/api/secrets/{id}", UriKind.Relative));

        Assert.Equal(await prod.Content.ReadAsByteArrayAsync(), await dev.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task TheFailure_IsStillLoggedServerSide_SoOperatorsCanDiagnoseIt()
    {
        _factory.Logs.Clear();
        using var app = Faulty(Environments.Production);
        using var client = app.CreateClient();

        using var response = await client.GetAsync(new Uri($"/api/secrets/{SecretId.NewId()}", UriKind.Relative));

        Assert.Contains(_factory.Logs.Entries, entry => entry.Exception?.Contains(Canary, StringComparison.Ordinal) == true);
    }

    [Fact]
    public async Task AProblemBody_CarriesOnlyTheDocumentedFields()
    {
        using var client = _factory.CreateClient();

        using var response = await client.PostAsync(new Uri("/api/secrets", UriKind.Relative), new StringContent("{", System.Text.Encoding.UTF8, "application/json"));
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        var names = problem.RootElement.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToList();
        Assert.Equal(["code", "status", "title", "type"], names);
        Assert.DoesNotContain("traceId", names);
    }

    [Theory]
    [InlineData("/nonexistent")]
    [InlineData("/api/")]
    [InlineData("/api/secrets/abcdefghijklmnopqrstuA/extra")]
    [InlineData("/s")]
    [InlineData("/a-much-longer-path-that-does-not-exist")]
    public async Task AnUnmatchedRoute_Is404_WithTheSameFixedBodyEveryTime(string path)
    {
        using var client = _factory.CreateClient();
        using var reference = await client.GetAsync(new Uri("/nonexistent", UriKind.Relative));
        var expected = await reference.Content.ReadAsByteArrayAsync();

        using var response = await client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(expected, await response.Content.ReadAsByteArrayAsync());
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("notFound", problem.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task AMethodMismatch_KeepsItsOwnMeaning_RatherThanBecomingNotFound()
    {
        using var client = _factory.CreateClient();

        using var response = await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, new Uri("/api/secrets", UriKind.Relative)));

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }

    [Fact]
    public async Task AFailedRequest_StillCarriesTheHardeningHeaders()
    {
        using var app = Faulty("Production");
        using var client = app.CreateClient();

        using var response = await client.GetAsync(new Uri($"/api/secrets/{SecretId.NewId()}", UriKind.Relative));

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.True(response.Headers.Contains("Content-Security-Policy"));
        Assert.Equal("nosniff", Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
        // The framework adds its own no-cache to error responses alongside ours; no-store is the one that matters.
        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    [Fact]
    public async Task Healthz_IsABare200_WithNoCountsOrVersions()
    {
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri("/healthz", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        Assert.False(response.Headers.Contains("Server"));
    }

    [Fact]
    public async Task Healthz_IsExemptFromRateLimiting()
    {
        using var client = _factory.CreateClient();

        for (var i = 0; i < 60; i++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/healthz", UriKind.Relative));
            request.Headers.TryAddWithoutValidation(RemoteIpStartupFilter.Header, "198.51.100.77");
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    [Fact]
    public async Task Healthz_WritesNoAuditEvent()
    {
        _factory.Logs.Clear();
        using var client = _factory.CreateClient();

        using var response = await client.GetAsync(new Uri("/healthz", UriKind.Relative));

        Assert.DoesNotContain(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
    }

    private WebApplicationFactory<Program> Faulty(string environment)
    {
        return _factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment(environment);
            builder.ConfigureServices(services => services.AddSingleton<ISecretStore>(new FaultyStore()));
        });
    }

    private sealed class FaultyStore : ISecretStore
    {
        public CreateResult Create(byte[] ciphertext, byte[] nonce, TimeSpan timeToLive) => throw new InvalidOperationException(Canary);

        public SecretPeek Peek(string id) => throw new InvalidOperationException(Canary);

        public ConsumeResult TryConsume(string id) => throw new InvalidOperationException(Canary);
    }
}
