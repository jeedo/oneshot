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
            var headers = context.Response.Headers;
            headers.ContentSecurityPolicy = ContentSecurityPolicy;
            headers.XContentTypeOptions = "nosniff";
            headers.XFrameOptions = "DENY";
            headers["Referrer-Policy"] = "no-referrer";
            headers["Permissions-Policy"] = PermissionsPolicy;

            if (IsSecretPath(context.Request.Path))
            {
                headers.CacheControl = "no-store";
                headers.Pragma = "no-cache";
            }

            return next(context);
        });
    }

    private static bool IsSecretPath(PathString path)
    {
        return !path.HasValue
            || path == "/"
            || path.StartsWithSegments("/s")
            || path.StartsWithSegments("/api");
    }
}
