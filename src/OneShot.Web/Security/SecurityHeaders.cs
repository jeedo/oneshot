namespace OneShot.Web.Security;

internal static class SecurityHeaders
{
    public const string PermissionsPolicy =
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), "
        + "geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), "
        + "picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), "
        + "web-share=(), xr-spatial-tracking=()";

    public static readonly string ContentSecurityPolicy =
        $"default-src 'none'; script-src '{ClientBundle.Integrity}'; style-src 'self'; connect-src 'self'; "
        + "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
    {
        return app.Use((context, next) =>
        {
            Apply(context);
            return next(context);
        });
    }

    // Also called from the exception handler, which clears the response and would otherwise drop these.
    public static void Apply(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var headers = context.Response.Headers;
        headers.ContentSecurityPolicy = ContentSecurityPolicy;
        headers.XContentTypeOptions = "nosniff";
        headers.XFrameOptions = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Permissions-Policy"] = PermissionsPolicy;
        // Site isolation against Spectre-class side-channel reads (T8, ZAP 90004, issue #50). The page has no
        // cross-origin subresources at all (CSP already limits every fetch to 'self' and one first-party
        // script hash), so the strict values cost nothing here and there is no legitimate reason for another
        // origin to embed or read this app's responses.
        headers["Cross-Origin-Embedder-Policy"] = "require-corp";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";
        headers["Cross-Origin-Resource-Policy"] = "same-origin";

        if (IsSecretPath(context.Request.Path))
        {
            headers.CacheControl = "no-store";
            headers.Pragma = "no-cache";
        }
    }

    private static bool IsSecretPath(PathString path)
    {
        return !path.HasValue
            || path == "/"
            || path.StartsWithSegments("/s")
            || path.StartsWithSegments("/api");
    }
}
