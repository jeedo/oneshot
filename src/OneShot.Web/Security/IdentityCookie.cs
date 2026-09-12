using Microsoft.AspNetCore.Authentication.Cookies;

namespace OneShot.Web.Security;

internal static class IdentityCookie
{
    // The only authentication type the audit logger trusts; issued solely by /api/whoami after a Negotiate handshake.
    public const string Scheme = "OneShot.IdentityCookie";

    public const string CookieName = "oneshot.identity";

    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    public static void Configure(CookieAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.Cookie.Name = CookieName;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.Path = "/api";
        options.Cookie.IsEssential = true;
        options.ExpireTimeSpan = Lifetime;
        options.SlidingExpiration = false;

        // The cookie scheme is never challenged, but if it ever were, it must not redirect a JSON client anywhere.
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    }
}
