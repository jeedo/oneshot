using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;

using OneShot.Web.Security;

namespace OneShot.Web.Api;

// The one endpoint that ever challenges: a domain-joined client answers silently and receives the identity
// cookie; everyone else gets a 401 the page treats as "anonymous". Create and reveal read the cookie only.
internal static class WhoAmIApi
{
    public static IEndpointRouteBuilder MapWhoAmI(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/whoami", (Delegate)HandleAsync);
        return app;
    }

    private static async Task<IResult> HandleAsync(HttpContext context)
    {
        var result = await context.AuthenticateAsync(NegotiateDefaults.AuthenticationScheme);
        if (!result.Succeeded || result.Principal.Identity?.Name is not { Length: > 0 } account)
        {
            await context.ChallengeAsync(NegotiateDefaults.AuthenticationScheme);
            return Results.Empty;
        }

        var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, account)], IdentityCookie.Scheme);
        await context.SignInAsync(IdentityCookie.Scheme, new ClaimsPrincipal(identity), new AuthenticationProperties { IsPersistent = false });

        return Results.Json(new WhoAmIResponse(account));
    }

    private sealed record WhoAmIResponse(string WindowsUser);
}
