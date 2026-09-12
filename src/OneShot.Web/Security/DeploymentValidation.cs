using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;

using OneShot.Web.Secrets;

namespace OneShot.Web.Security;

// A deployment that is wrong should never serve a single secret, so the host refuses to start rather than
// running on weakened settings (T15). Development is exempt: local runs are not deployments.
internal sealed record DeploymentSettings
{
    public required bool IsDevelopment { get; init; }

    public required bool DetailedErrors { get; init; }

    /// <summary>Addresses the host was told to bind. Empty for an in-memory host, which has no transport to check.</summary>
    public required IReadOnlyList<string> Urls { get; init; }

    public required bool ForwardedHeadersConfigured { get; init; }

    public required bool TrustedProxiesConfigured { get; init; }

    public required TimeSpan HstsMaxAge { get; init; }

    public required long? MaxRequestBodySize { get; init; }

    public required int MaxRequestHeaderCount { get; init; }

    public required long MaxRequestHeadersTotalSize { get; init; }

    public required int MaxEntries { get; init; }

    public required long MaxTotalCiphertextBytes { get; init; }

    public required int CreatePerWindow { get; init; }

    public required int ReadPerWindow { get; init; }
}

internal sealed class DeploymentOptions;

internal static class DeploymentValidation
{
    public static IReadOnlyList<string> Validate(DeploymentSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        if (settings.IsDevelopment)
        {
            return [];
        }

        var problems = new List<string>();

        // An address list that is entirely plain HTTP means secrets would cross the network in the clear,
        // unless TLS is terminated by a proxy this deployment has declared.
        if (settings.Urls.Count > 0
            && !settings.Urls.Any(url => url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            && !settings.TrustedProxiesConfigured)
        {
            problems.Add(
                "No HTTPS address is configured and no trusted proxy is declared, so secrets would travel in "
                + "the clear. Serve HTTPS, or set ForwardedHeaders:KnownProxies when TLS ends at a proxy.");
        }

        if (settings.DetailedErrors)
        {
            problems.Add("DetailedErrors is enabled, which would expose exception detail to clients.");
        }

        if (settings.HstsMaxAge < TimeSpan.FromDays(1))
        {
            problems.Add($"The HSTS max-age is {settings.HstsMaxAge}, which is too short to protect returning visitors.");
        }

        if (settings.MaxRequestBodySize is not { } bodyLimit)
        {
            problems.Add("The maximum request body size is unbounded.");
        }
        else if (bodyLimit > KestrelHardening.MaxRequestBodyBytes)
        {
            problems.Add($"The maximum request body size is {bodyLimit} bytes, above the {KestrelHardening.MaxRequestBodyBytes} this app is designed for.");
        }

        if (settings.MaxRequestHeaderCount <= 0)
        {
            problems.Add("The request header count limit is not set.");
        }

        if (settings.MaxRequestHeadersTotalSize <= 0)
        {
            problems.Add("The request header size limit is not set.");
        }

        if (settings.MaxEntries <= 0 || settings.MaxTotalCiphertextBytes <= 0)
        {
            problems.Add("A store capacity cap is not positive, so the store would be unbounded or unusable.");
        }

        if (settings.CreatePerWindow <= 0 || settings.ReadPerWindow <= 0)
        {
            problems.Add("A rate limit is not positive, so enumeration would be unthrottled.");
        }

        if (settings.ForwardedHeadersConfigured && !settings.TrustedProxiesConfigured)
        {
            problems.Add("Forwarded headers are configured without KnownProxies or KnownNetworks, so they would be silently ignored.");
        }

        return problems;
    }

    public static IServiceCollection AddStartupValidation(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<DeploymentOptions>().ValidateOnStart();
        services.AddSingleton<IValidateOptions<DeploymentOptions>, DeploymentValidator>();
        return services;
    }
}

internal sealed class DeploymentValidator(
    IHostEnvironment environment,
    IConfiguration configuration,
    IOptions<KestrelServerOptions> kestrel,
    IOptions<HstsOptions> hsts,
    IOptions<SecretStoreOptions> store,
    IOptions<RateLimitOptions> rateLimits) : IValidateOptions<DeploymentOptions>
{
    public ValidateOptionsResult Validate(string? name, DeploymentOptions options)
    {
        var forwarded = configuration.GetSection("ForwardedHeaders");
        var settings = new DeploymentSettings
        {
            IsDevelopment = environment.IsDevelopment(),
            DetailedErrors = configuration.GetValue("DetailedErrors", false),
            Urls = (configuration["urls"] ?? configuration["ASPNETCORE_URLS"] ?? string.Empty)
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            ForwardedHeadersConfigured = forwarded.GetChildren().Any(),
            TrustedProxiesConfigured = forwarded.GetSection("KnownProxies").GetChildren().Any()
                || forwarded.GetSection("KnownNetworks").GetChildren().Any(),
            HstsMaxAge = hsts.Value.MaxAge,
            MaxRequestBodySize = kestrel.Value.Limits.MaxRequestBodySize,
            MaxRequestHeaderCount = kestrel.Value.Limits.MaxRequestHeaderCount,
            MaxRequestHeadersTotalSize = kestrel.Value.Limits.MaxRequestHeadersTotalSize,
            MaxEntries = store.Value.MaxEntries,
            MaxTotalCiphertextBytes = store.Value.MaxTotalCiphertextBytes,
            CreatePerWindow = rateLimits.Value.CreatePerWindow,
            ReadPerWindow = rateLimits.Value.ReadPerWindow,
        };

        var problems = DeploymentValidation.Validate(settings);
        return problems.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(problems);
    }
}
