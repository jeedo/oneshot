namespace OneShot.Web.Api;

// A reveal must look like our own page's fetch: JSON, the custom header no form or prefetch can send, and no
// evidence of a foreign origin. Absent Origin/Sec-Fetch-Site headers mean a non-browser client, which cannot
// be a CSRF vector; a browser always sends at least one of them on a cross-site POST.
internal static class RevealPolicy
{
    public const string HeaderName = "X-OneShot-Reveal";

    public static bool Allows(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!request.HasJsonContentType())
        {
            return false;
        }

        if (request.Headers[HeaderName] is not [var marker] || marker != "1")
        {
            return false;
        }

        if (request.Headers.TryGetValue("Sec-Fetch-Site", out var site)
            && !(site is [var siteValue] && siteValue is "same-origin" or "none"))
        {
            return false;
        }

        if (request.Headers.TryGetValue("Origin", out var origin) && !IsOwnOrigin(request, origin))
        {
            return false;
        }

        return true;
    }

    private static bool IsOwnOrigin(HttpRequest request, Microsoft.Extensions.Primitives.StringValues origin)
    {
        if (origin is not [var value] || !Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var host = request.Host;
        var port = host.Port ?? (request.IsHttps ? 443 : 80);

        return string.Equals(uri.Scheme, request.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(uri.Host, host.Host, StringComparison.OrdinalIgnoreCase)
            && uri.Port == port;
    }
}
