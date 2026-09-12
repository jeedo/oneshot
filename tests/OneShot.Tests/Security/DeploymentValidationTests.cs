using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Security;

namespace OneShot.Tests.Security;

[Trait("Threat", "T15")]
public sealed class DeploymentValidationTests : IClassFixture<OneShotFactory>
{
    private readonly OneShotFactory _factory;

    public DeploymentValidationTests(OneShotFactory factory) => _factory = factory;

    private static DeploymentSettings Production => new()
    {
        IsDevelopment = false,
        DetailedErrors = false,
        Urls = ["https://oneshot.example"],
        ForwardedHeadersConfigured = false,
        TrustedProxiesConfigured = false,
        HstsMaxAge = TimeSpan.FromDays(365),
        MaxRequestBodySize = 128 * 1024,
        MaxRequestHeaderCount = 64,
        MaxRequestHeadersTotalSize = 16 * 1024,
        MaxEntries = 10_000,
        MaxTotalCiphertextBytes = 64L * 1024 * 1024,
        CreatePerWindow = 20,
        ReadPerWindow = 30,
    };

    [Fact]
    public void AProductionDeploymentWithTheShippedDefaults_Passes()
    {
        Assert.Empty(DeploymentValidation.Validate(Production));
    }

    [Fact]
    public void Development_IsNeverValidated_SoLocalRunsAreNotObstructed()
    {
        var reckless = Production with
        {
            IsDevelopment = true,
            DetailedErrors = true,
            Urls = ["http://localhost:5000"],
            HstsMaxAge = TimeSpan.Zero,
            MaxRequestBodySize = null,
            MaxEntries = 0,
        };

        Assert.Empty(DeploymentValidation.Validate(reckless));
    }

    [Fact]
    public void ServingPlainHttpWithNoTrustedProxy_IsRefused()
    {
        var problems = DeploymentValidation.Validate(Production with { Urls = ["http://oneshot.example"] });

        Assert.Contains(problems, problem => problem.Contains("HTTPS", StringComparison.Ordinal));
    }

    [Fact]
    public void ServingPlainHttpBehindAConfiguredProxy_IsAllowed_BecauseTlsEndsUpstream()
    {
        var settings = Production with
        {
            Urls = ["http://10.0.0.5:8080"],
            ForwardedHeadersConfigured = true,
            TrustedProxiesConfigured = true,
        };

        Assert.Empty(DeploymentValidation.Validate(settings));
    }

    [Fact]
    public void AHostWithNoConfiguredAddresses_SkipsTheTransportCheck()
    {
        // An in-memory host has no transport to validate; every other rule still applies.
        Assert.Empty(DeploymentValidation.Validate(Production with { Urls = [] }));
    }

    [Fact]
    public void OneHttpsAddressAmongSeveral_IsEnough()
    {
        var settings = Production with { Urls = ["http://oneshot.example", "https://oneshot.example"] };

        Assert.Empty(DeploymentValidation.Validate(settings));
    }

    [Fact]
    public void DetailedErrors_IsRefused_BecauseItWouldLeakInternals()
    {
        var problems = DeploymentValidation.Validate(Production with { DetailedErrors = true });

        Assert.Contains(problems, problem => problem.Contains("DetailedErrors", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(23)]
    public void AnHstsMaxAgeUnderADay_IsRefused(int hours)
    {
        var problems = DeploymentValidation.Validate(Production with { HstsMaxAge = TimeSpan.FromHours(hours) });

        Assert.Contains(problems, problem => problem.Contains("HSTS", StringComparison.Ordinal));
    }

    [Fact]
    public void AnUnboundedRequestBody_IsRefused()
    {
        var problems = DeploymentValidation.Validate(Production with { MaxRequestBodySize = null });

        Assert.Contains(problems, problem => problem.Contains("request body", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ARequestBodyLimitAboveTheDocumentedCeiling_IsRefused()
    {
        var problems = DeploymentValidation.Validate(Production with { MaxRequestBodySize = (128 * 1024) + 1 });

        Assert.Contains(problems, problem => problem.Contains("request body", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void UnboundedRequestHeaders_AreRefused()
    {
        var problems = DeploymentValidation.Validate(Production with { MaxRequestHeaderCount = 0, MaxRequestHeadersTotalSize = 0 });

        Assert.Equal(2, problems.Count(problem => problem.Contains("header", StringComparison.OrdinalIgnoreCase)));
    }

    [Theory]
    [InlineData(0, 64L * 1024 * 1024)]
    [InlineData(-1, 64L * 1024 * 1024)]
    [InlineData(10_000, 0)]
    public void ACapacityCapThatIsNotPositive_IsRefused(int maxEntries, long maxBytes)
    {
        var settings = Production with { MaxEntries = maxEntries, MaxTotalCiphertextBytes = maxBytes };

        Assert.Contains(DeploymentValidation.Validate(settings), problem => problem.Contains("capacity", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(0, 30)]
    [InlineData(20, 0)]
    public void ADisabledRateLimit_IsRefused(int create, int read)
    {
        var settings = Production with { CreatePerWindow = create, ReadPerWindow = read };

        Assert.Contains(DeploymentValidation.Validate(settings), problem => problem.Contains("rate limit", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ForwardedHeadersConfiguredWithoutKnownProxies_IsRefused()
    {
        var settings = Production with { ForwardedHeadersConfigured = true, TrustedProxiesConfigured = false };

        Assert.Contains(DeploymentValidation.Validate(settings), problem => problem.Contains("forwarded", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void EveryProblemIsReportedTogether_SoOneRestartShowsThemAll()
    {
        var settings = Production with
        {
            Urls = ["http://oneshot.example"],
            DetailedErrors = true,
            HstsMaxAge = TimeSpan.Zero,
            MaxRequestBodySize = null,
            MaxEntries = 0,
        };

        Assert.Equal(5, DeploymentValidation.Validate(settings).Count);
    }

    [Fact]
    public void AMisconfiguredProductionHost_RefusesToStart_AndNamesTheProblem()
    {
        using var app = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("urls", "http://127.0.0.1:5999");
        });

        var error = Assert.Throws<OptionsValidationException>(() => app.CreateClient());

        Assert.Contains(error.Failures, failure => failure.Contains("HTTPS", StringComparison.Ordinal));
    }

    [Fact]
    public void AProductionHostBehindAConfiguredProxy_Starts()
    {
        using var app = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("urls", "http://127.0.0.1:5999");
            builder.UseSetting("ForwardedHeaders:KnownProxies:0", "127.0.0.1");
        });

        using var client = app.CreateClient();

        Assert.NotNull(client);
    }

    [Fact]
    public void TheSameMisconfigurationInDevelopment_Starts()
    {
        using var app = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("urls", "http://127.0.0.1:5999");
        });

        using var client = app.CreateClient();

        Assert.NotNull(client);
    }
}
