using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;
using OneShot.Web.Security;

namespace OneShot.Tests.Audit;

// WhoAmITests covers the cookie the app issues and what happens when it is tampered with, missing or expired.
// This covers the case that is not a corruption at all: a well-formed, correctly-signed ticket that someone
// else minted. If the audit trail believed one of those, every name in it would be worth nothing.
[Trait("Threat", "T10")]
public sealed class AuditIdentityTests : IClassFixture<CapturingWebApplicationFactory>, IDisposable
{
    private const string Account = "CORP\\alice";
    private const string Impersonated = "CORP\\administrator";
    private const string CookiePurpose = "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware";

    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);

    private readonly CapturingWebApplicationFactory _factory;
    private readonly FakeTimeApp _app;

    public AuditIdentityTests(CapturingWebApplicationFactory factory)
    {
        _factory = factory;
        _app = factory.WithFakeTime(Now);
    }

    public void Dispose() => _app.Dispose();

    [Fact]
    public async Task ATicketSignedByAnotherKeyRing_IsAnonymous_NotTheNameItClaims()
    {
        // The forgery that matters: not a corrupted cookie but a perfectly well-formed one, minted by someone
        // who has their own keys and simply asserts they are the administrator.
        var forged = Mint(new EphemeralDataProtectionProvider(), Impersonated, IdentityCookie.Scheme);
        _factory.Logs.Clear();
        using var client = Client();

        using var create = await client.SendAsync(WithCookie(CreateRequest(), forged));

        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        Assert.Equal("anonymous", AuditUser());
        AssertNothingComplained();
    }

    [Fact]
    public async Task ATicketSignedByThisKeyRingButClaimingAnotherScheme_IsAnonymous()
    {
        // A valid signature is not enough: only a ticket the whoami endpoint issued carries the cookie scheme,
        // so a ticket minted under Negotiate — the scheme create and reveal must never trust — is ignored.
        var wrongScheme = Mint(_app.Service<IDataProtectionProvider>(), Impersonated, "Negotiate");
        _factory.Logs.Clear();
        using var client = Client();

        using var create = await client.SendAsync(WithCookie(CreateRequest(), wrongScheme));

        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        Assert.Equal("anonymous", AuditUser());
        AssertNothingComplained();
    }

    [Fact]
    public async Task ATicketMintedByThisKeyRing_IsBelieved_SoTheTwoTestsAboveFailForTheRightReason()
    {
        // The control: the same minting code with the app's own keys and the app's own scheme is accepted, so
        // the rejections above are about the key and the scheme, not about the ticket being unreadable.
        var genuine = Mint(_app.Service<IDataProtectionProvider>(), Account, IdentityCookie.Scheme);
        _factory.Logs.Clear();
        using var client = Client();

        using var create = await client.SendAsync(WithCookie(CreateRequest(), genuine));

        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        Assert.Equal(Account, AuditUser());
    }

    [Fact]
    public async Task ACookieDoesNotSurviveARestart_BecauseTheKeyRingIsEphemeral()
    {
        // The deployment consequence of the ephemeral key ring (T5): identity cookies are scoped to one
        // process lifetime, so a restart signs everybody out rather than honouring tickets it cannot vouch for.
        using var first = _factory.WithFakeTime(Now);
        using var firstClient = first.CreateClient(NoCookies);
        var cookie = await IdentityCookieFor(firstClient);

        using var restarted = new CapturingWebApplicationFactory();
        using var second = restarted.WithFakeTime(Now);
        using var secondClient = second.CreateClient(NoCookies);

        using var create = await secondClient.SendAsync(WithCookie(CreateRequest(), cookie));

        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var audit = Assert.Single(restarted.Logs.Entries, entry => entry.EventId.Name == "Audit");
        Assert.Equal("anonymous", audit.State.Single(field => field.Key == "windowsUser").Value);
    }

    [Fact]
    public async Task EveryAuditEventAcrossAWholeSession_HasExactlyTheFourDocumentedFields()
    {
        using var client = Client();
        var cookie = await IdentityCookieFor(client);
        _factory.Logs.Clear();

        var ids = new List<string>();
        for (var i = 0; i < 3; i++)
        {
            using var create = await client.SendAsync(WithCookie(CreateRequest(), cookie));
            ids.Add(JsonDocument.Parse(await create.Content.ReadAsStringAsync()).RootElement.GetProperty("id").GetString()!);
        }

        foreach (var id in ids)
        {
            using var reveal = await client.SendAsync(WithCookie(RevealRequest(id), cookie));
            Assert.Equal(HttpStatusCode.OK, reveal.StatusCode);
        }

        var events = _factory.Logs.Entries.Where(entry => entry.EventId.Name == "Audit").ToList();
        Assert.Equal(6, events.Count);
        foreach (var entry in events)
        {
            Assert.Equal(["timestampUtc", "action", "secretId", "windowsUser"], entry.State.Select(field => field.Key));
            Assert.Equal(Account, entry.State.Single(field => field.Key == "windowsUser").Value);
            Assert.Equal(Now.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture), entry.State.Single(field => field.Key == "timestampUtc").Value);
            Assert.Contains(entry.State.Single(field => field.Key == "secretId").Value, ids);
        }

        Assert.Equal(["create", "create", "create", "reveal", "reveal", "reveal"], events.Select(entry => entry.State.Single(field => field.Key == "action").Value));
    }

    public static TheoryData<string> NonEvents => new()
    {
        "a reveal of an unknown secret",
        "a reveal of an already consumed secret",
        "a reveal refused as cross-origin",
        "a create rejected as malformed",
        "a peek",
    };

    [Theory]
    [MemberData(nameof(NonEvents))]
    public async Task NothingThatDidNotHappen_IsWrittenToTheAuditTrail(string scenario)
    {
        // An audit trail that records attempts as if they were reveals is worse than none: it would show a
        // secret consumed by a name that never consumed it.
        using var client = Client();
        var cookie = await IdentityCookieFor(client);
        var id = await CreatedId(client, cookie);
        if (scenario == "a reveal of an already consumed secret")
        {
            using var first = await client.SendAsync(WithCookie(RevealRequest(id), cookie));
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        _factory.Logs.Clear();
        using var response = await client.SendAsync(WithCookie(Request(scenario, id), cookie));

        Assert.NotEqual(HttpStatusCode.Created, response.StatusCode);
        Assert.DoesNotContain(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
        AssertNothingComplained();
    }

    private static HttpRequestMessage Request(string scenario, string id) => scenario switch
    {
        "a reveal of an unknown secret" => RevealRequest(SecretId.NewId()),
        "a reveal of an already consumed secret" => RevealRequest(id),
        "a reveal refused as cross-origin" => Foreign(RevealRequest(id)),
        "a create rejected as malformed" => new HttpRequestMessage(HttpMethod.Post, new Uri("/api/secrets", UriKind.Relative))
        {
            Content = new StringContent("{\"ciphertext\":\"!!\",\"nonce\":\"!!\"}", Encoding.UTF8, "application/json"),
        },
        "a peek" => new HttpRequestMessage(HttpMethod.Get, new Uri($"/api/secrets/{id}", UriKind.Relative)),
        _ => throw new ArgumentOutOfRangeException(nameof(scenario), scenario, "Unknown scenario."),
    };

    // Builds the exact wire format the cookie handler reads, so the only thing that varies is who signed it.
    private static string Mint(IDataProtectionProvider provider, string account, string authenticationType)
    {
        var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, account)], authenticationType);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), IdentityCookie.Scheme);
        ticket.Properties.ExpiresUtc = Now.AddMinutes(5);
        var protector = provider.CreateProtector(CookiePurpose, IdentityCookie.Scheme, "v2");
        return new TicketDataFormat(protector).Protect(ticket);
    }

    private void AssertNothingComplained()
    {
        // A rejected cookie is an ordinary event, not a fault: it must not log or challenge.
        // The HTTPS-redirect warning is excluded deliberately: TestServer configures no HTTPS port, so the
        // host logs one per app instance whatever the request was. That is a property of the harness, and
        // letting it in here would make this assertion depend on which test ran first.
        var complaints = _factory.Logs.Entries
            .Where(entry => entry.Level >= LogLevel.Warning)
            .Where(entry => !entry.Category.StartsWith("Microsoft.AspNetCore.HttpsPolicy", StringComparison.Ordinal))
            .Select(entry => $"[{entry.Level}] {entry.Category}: {entry.Message}")
            .ToList();

        Assert.Empty(complaints);
        Assert.DoesNotContain(_factory.Logs.Entries, entry => entry.Exception is not null);
    }

    private static readonly WebApplicationFactoryClientOptions NoCookies = new() { HandleCookies = false, AllowAutoRedirect = false };

    private HttpClient Client() => _app.CreateClient(NoCookies);

    private static async Task<string> IdentityCookieFor(HttpClient client)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/whoami", UriKind.Relative));
        request.Headers.TryAddWithoutValidation(TestNegotiateHandler.UserHeader, Account);
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var setCookie = Assert.Single(response.Headers.GetValues("Set-Cookie"));
        return setCookie.Split(';')[0][(IdentityCookie.CookieName.Length + 1)..];
    }

    private static async Task<string> CreatedId(HttpClient client, string cookie)
    {
        using var response = await client.SendAsync(WithCookie(CreateRequest(), cookie));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("id").GetString()!;
    }

    private static HttpRequestMessage WithCookie(HttpRequestMessage request, string cookie)
    {
        request.Headers.TryAddWithoutValidation("Cookie", $"{IdentityCookie.CookieName}={cookie}");
        return request;
    }

    private static HttpRequestMessage Foreign(HttpRequestMessage request)
    {
        request.Headers.TryAddWithoutValidation("Origin", "https://evil.test");
        return request;
    }

    private static HttpRequestMessage CreateRequest() =>
        new(HttpMethod.Post, new Uri("/api/secrets", UriKind.Relative))
        {
            Content = new StringContent("{\"ciphertext\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA\",\"nonce\":\"8PHy8_T19vf4-fr7\"}", Encoding.UTF8, "application/json"),
        };

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
        var audit = Assert.Single(_factory.Logs.Entries, entry => entry.EventId.Name == "Audit");
        return audit.State.Single(field => field.Key == "windowsUser").Value!;
    }
}
