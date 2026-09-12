using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;
using OneShot.Web.Security;

namespace OneShot.Tests.Api;

[Trait("Threat", "T10")]
public sealed class WhoAmITests : IClassFixture<CapturingWebApplicationFactory>, IDisposable
{
    private const string Account = "CORP\\alice";

    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);
    private static readonly Uri WhoAmI = new("/api/whoami", UriKind.Relative);
    private static readonly Uri Secrets = new("/api/secrets", UriKind.Relative);

    private readonly CapturingWebApplicationFactory _factory;
    private readonly FakeTimeApp _app;

    public WhoAmITests(CapturingWebApplicationFactory factory)
    {
        _factory = factory;
        _app = factory.WithFakeTime(Now);
    }

    public void Dispose() => _app.Dispose();

    [Fact]
    public async Task WithoutCredentials_WhoAmIChallengesWithNegotiate_AndSetsNoCookie()
    {
        using var client = Client();

        using var response = await client.GetAsync(WhoAmI);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Negotiate", Assert.Single(response.Headers.WwwAuthenticate).Scheme);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.Empty(await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task WithNegotiateIdentity_WhoAmIReturnsTheAccount_AndSetsAHardenedCookie()
    {
        using var client = Client();

        using var response = await client.SendAsync(Authenticated(HttpMethod.Get, WhoAmI));
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(["windowsUser"], body.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(Account, body.RootElement.GetProperty("windowsUser").GetString());

        var setCookie = Assert.Single(response.Headers.GetValues("Set-Cookie"));
        Assert.StartsWith($"{IdentityCookie.CookieName}=", setCookie, StringComparison.Ordinal);
        var attributes = setCookie.Split(';').Skip(1).Select(a => a.Trim().ToLowerInvariant()).ToList();
        Assert.Contains("httponly", attributes);
        Assert.Contains("secure", attributes);
        Assert.Contains("samesite=strict", attributes);
        Assert.Contains("path=/api", attributes);
        Assert.DoesNotContain(attributes, a => a.StartsWith("max-age", StringComparison.Ordinal) || a.StartsWith("expires", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Cookie_HoldsOnlyTheAccountName_AndExpiresInFiveMinutes()
    {
        using var client = Client();
        var cookie = await IdentityCookieFor(client);

        var protector = _app.Service<IDataProtectionProvider>()
            .CreateProtector("Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", IdentityCookie.Scheme, "v2");
        var ticket = new TicketDataFormat(protector).Unprotect(cookie);

        Assert.NotNull(ticket);
        var identity = Assert.IsType<ClaimsIdentity>(ticket.Principal.Identity);
        Assert.Equal(IdentityCookie.Scheme, identity.AuthenticationType);
        var claim = Assert.Single(identity.Claims);
        Assert.Equal(ClaimTypes.Name, claim.Type);
        Assert.Equal(Account, claim.Value);
        Assert.Equal(Now.AddMinutes(5), ticket.Properties.ExpiresUtc);
        Assert.False(ticket.Properties.IsPersistent);
    }

    [Fact]
    public async Task CreateAndReveal_TakeTheIdentityFromTheCookie()
    {
        using var client = Client();
        var cookie = await IdentityCookieFor(client);
        _factory.Logs.Clear();

        using var create = await client.SendAsync(WithCookie(CreateRequest(), cookie));
        var id = JsonDocument.Parse(await create.Content.ReadAsStringAsync()).RootElement.GetProperty("id").GetString()!;
        using var reveal = await client.SendAsync(WithCookie(RevealRequest(id), cookie));

        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        Assert.Equal(HttpStatusCode.OK, reveal.StatusCode);
        var events = _factory.Logs.Entries.Where(e => e.EventId.Name == "Audit").ToList();
        Assert.Equal(["create", "reveal"], events.Select(e => e.State.Single(p => p.Key == "action").Value));
        Assert.All(events, e => Assert.Equal(Account, e.State.Single(p => p.Key == "windowsUser").Value));
    }

    [Fact]
    public async Task ExpiredCookie_IsAnonymous_WithoutAChallenge()
    {
        using var client = Client();
        var cookie = await IdentityCookieFor(client);
        _app.Clock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));
        _factory.Logs.Clear();

        using var create = await client.SendAsync(WithCookie(CreateRequest(), cookie));

        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        Assert.False(create.Headers.Contains("WWW-Authenticate"));
        Assert.Equal("anonymous", AuditUser());
    }

    [Theory]
    [InlineData("tampered")]
    [InlineData("garbage")]
    [InlineData("empty")]
    public async Task InvalidCookie_IsAnonymous_WithoutErrorOrChallenge(string kind)
    {
        using var client = Client();
        var cookie = await IdentityCookieFor(client);
        cookie = kind switch
        {
            "tampered" => cookie[..^4] + (cookie[^4] == 'A' ? "BBBB" : "AAAA"),
            "garbage" => "not-a-ticket",
            _ => "",
        };
        _factory.Logs.Clear();

        using var create = await client.SendAsync(WithCookie(CreateRequest(), cookie));

        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        Assert.False(create.Headers.Contains("WWW-Authenticate"));
        Assert.Equal("anonymous", AuditUser());
        Assert.DoesNotContain(_factory.Logs.Entries, e => e.Level >= LogLevel.Warning);
    }

    [Fact]
    public async Task CreateAndReveal_NeverChallenge_AndIgnoreNegotiateCredentials()
    {
        using var client = Client();
        _factory.Logs.Clear();
        using var request = Authenticated(HttpMethod.Post, Secrets);
        request.Content = CreateRequest().Content;
        request.Headers.Authorization = new AuthenticationHeaderValue("Negotiate", "YIIBigYGKwYBBQUCoIIBfjCCAXo=");

        using var create = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        Assert.False(create.Headers.Contains("WWW-Authenticate"));
        Assert.False(create.Headers.Contains("Set-Cookie"));
        Assert.Equal("anonymous", AuditUser());
    }

    [Fact]
    public async Task WhoAmI_IsGetOnly()
    {
        using var client = Client();

        using var response = await client.SendAsync(Authenticated(HttpMethod.Post, WhoAmI));

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
    }

    private HttpClient Client() => _app.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false });

    private static HttpRequestMessage Authenticated(HttpMethod method, Uri uri)
    {
        var request = new HttpRequestMessage(method, uri);
        request.Headers.TryAddWithoutValidation(TestNegotiateHandler.UserHeader, Account);
        return request;
    }

    private static async Task<string> IdentityCookieFor(HttpClient client)
    {
        using var response = await client.SendAsync(Authenticated(HttpMethod.Get, WhoAmI));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var setCookie = Assert.Single(response.Headers.GetValues("Set-Cookie"));
        return setCookie.Split(';')[0][(IdentityCookie.CookieName.Length + 1)..];
    }

    private static HttpRequestMessage WithCookie(HttpRequestMessage request, string cookie)
    {
        request.Headers.TryAddWithoutValidation("Cookie", $"{IdentityCookie.CookieName}={cookie}");
        return request;
    }

    private static HttpRequestMessage CreateRequest()
    {
        return new HttpRequestMessage(HttpMethod.Post, Secrets)
        {
            Content = new StringContent("{\"ciphertext\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA\",\"nonce\":\"8PHy8_T19vf4-fr7\"}", Encoding.UTF8, "application/json"),
        };
    }

    private static HttpRequestMessage RevealRequest(string id)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"/api/secrets/{id}/reveal", UriKind.Relative))
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation("X-OneShot-Reveal", "1");
        return request;
    }

    private string AuditUser()
    {
        var audit = Assert.Single(_factory.Logs.Entries, e => e.EventId.Name == "Audit");
        return audit.State.Single(p => p.Key == "windowsUser").Value!;
    }
}
