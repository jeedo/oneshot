using System.Security.Authentication;

using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace OneShot.Web.Security;

internal static class KestrelHardening
{
    public const long MaxRequestBodyBytes = 128 * 1024;

    public static void Apply(KestrelServerOptions options)
    {
        options.AddServerHeader = false;
        options.Limits.MaxRequestBodySize = MaxRequestBodyBytes;
        options.Limits.MaxRequestLineSize = 4 * 1024;
        options.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
        options.Limits.MaxRequestHeaderCount = 64;
        options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(60);
        options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(15);
        options.ConfigureHttpsDefaults(ConfigureHttps);
    }

    public static void ConfigureHttps(HttpsConnectionAdapterOptions https)
    {
        // CA5398 prefers SslProtocols.None (OS default), which can still admit TLS 1.0/1.1 on older hosts.
        // The threat model (T8) requires TLS 1.2+ only, so the floor is pinned here; see docs/threat-model.md.
#pragma warning disable CA5398
        https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
#pragma warning restore CA5398
    }
}
