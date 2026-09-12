using System.Net;
using System.Net.Sockets;
using System.Threading.RateLimiting;

using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

using OneShot.Web.Api;

namespace OneShot.Web.Security;

internal sealed class RateLimitOptions
{
    public int CreatePerWindow { get; init; } = 20;

    public int ReadPerWindow { get; init; } = 30;

    public TimeSpan Window { get; init; } = TimeSpan.FromMinutes(1);
}

internal static class RateLimiting
{
    public const string CreatePolicy = "create";

    public const string ReadPolicy = "read";

    public static IServiceCollection AddOneShotRateLimiting(this IServiceCollection services)
    {
        services.AddRateLimiter(_ => { });
        services.AddOptions<RateLimiterOptions>().Configure<IOptions<RateLimitOptions>>((limiter, options) => Configure(limiter, options.Value));
        return services;
    }

    // IPv6 clients are bucketed on their /64 so rotating interface identifiers within one allocation share a budget.
    public static string ClientPartition(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var address = context.Connection.RemoteIpAddress;
        if (address is null)
        {
            return "unknown";
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return address.ToString();
        }

        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out _);
        bytes[8..].Clear();
        return $"{new IPAddress(bytes)}/64";
    }

    private static void Configure(RateLimiterOptions limiter, RateLimitOptions options)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(options.CreatePerWindow);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(options.ReadPerWindow);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(options.Window, TimeSpan.Zero);

        limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        limiter.OnRejected = (context, cancellationToken) =>
        {
            var retryAfter = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var delay) ? delay : (TimeSpan?)null;
            return ApiProblems.WriteTooManyRequestsAsync(context.HttpContext, retryAfter, cancellationToken);
        };
        limiter.AddPolicy(CreatePolicy, context => Partition(context, options.CreatePerWindow, options.Window));
        limiter.AddPolicy(ReadPolicy, context => Partition(context, options.ReadPerWindow, options.Window));
    }

    private static RateLimitPartition<string> Partition(HttpContext context, int permits, TimeSpan window)
    {
        return RateLimitPartition.GetFixedWindowLimiter(ClientPartition(context), _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permits,
            Window = window,
            QueueLimit = 0,
            AutoReplenishment = true,
        });
    }
}
