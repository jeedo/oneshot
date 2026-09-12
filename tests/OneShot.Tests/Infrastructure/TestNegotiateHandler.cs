using System.Security.Claims;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OneShot.Tests.Infrastructure;

// Stands in for the real Negotiate handler: a request carrying X-Test-Negotiate-User is treated as a completed
// Kerberos/NTLM handshake for that account; anything else is challenged exactly like the real handler.
public sealed class TestNegotiateHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Negotiate";
    public const string UserHeader = "X-Test-Negotiate-User";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Request.Headers[UserHeader] is not [var user] || string.IsNullOrEmpty(user))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, user)], SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = SchemeName;
        return Task.CompletedTask;
    }
}

public static class TestNegotiate
{
    public static IWebHostBuilder UseTestNegotiate(this IWebHostBuilder builder)
    {
        return builder.ConfigureServices(services =>
        {
            services.AddTransient<TestNegotiateHandler>();
            services.PostConfigure<AuthenticationOptions>(options => options.SchemeMap[TestNegotiateHandler.SchemeName].HandlerType = typeof(TestNegotiateHandler));
        });
    }
}
