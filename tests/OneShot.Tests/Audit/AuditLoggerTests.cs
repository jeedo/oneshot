using System.Security.Claims;

using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Audit;
using OneShot.Web.Security;

namespace OneShot.Tests.Audit;

[Trait("Threat", "T1")]
[Trait("Threat", "T10")]
public sealed class AuditLoggerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Id = "abcdefghijklmnopqrstuA";

    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 34, 56, 789, TimeSpan.Zero);

    private readonly LogSink _sink = new();
    private readonly AuditLogger _audit;
    private readonly WebApplicationFactory<Program> _factory;

    public AuditLoggerTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        var logger = LoggerFactory.Create(builder => builder.AddProvider(_sink)).CreateLogger<AuditLogger>();
        _audit = new AuditLogger(logger, new FakeTimeProvider(Now));
    }

    [Fact]
    public void Event_HasExactlyTheFourDocumentedFields()
    {
        _audit.Log(AuditAction.Create, Id, IdentityCookieUser("CORP\\alice"));

        var entry = Assert.Single(_sink.Entries);
        Assert.Equal(["timestampUtc", "action", "secretId", "windowsUser"], entry.State.Select(pair => pair.Key));
        Assert.Equal("2026-09-12T12:34:56.789Z", entry.State[0].Value);
        Assert.Equal("create", entry.State[1].Value);
        Assert.Equal(Id, entry.State[2].Value);
        Assert.Equal("CORP\\alice", entry.State[3].Value);
    }

    [Fact]
    public void Event_IsInformational_WithAStableCategoryEventIdAndMessage()
    {
        _audit.Log(AuditAction.Reveal, Id, IdentityCookieUser("CORP\\bob"));

        var entry = Assert.Single(_sink.Entries);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Equal("OneShot.Web.Audit.AuditLogger", entry.Category);
        Assert.Equal(new EventId(1002, "Audit"), entry.EventId);
        Assert.Equal($"audit reveal {Id} CORP\\bob", entry.Message);
        Assert.Null(entry.Exception);
    }

    [Fact]
    public void CreateAndReveal_UseDistinctEventIds()
    {
        _audit.Log(AuditAction.Create, Id, null);
        _audit.Log(AuditAction.Reveal, Id, null);

        Assert.Equal([1001, 1002], _sink.Entries.Select(entry => entry.EventId.Id));
    }

    [Fact]
    public void NullOrUnauthenticatedPrincipal_IsAnonymous()
    {
        _audit.Log(AuditAction.Create, Id, null);
        _audit.Log(AuditAction.Create, Id, new ClaimsPrincipal());
        _audit.Log(AuditAction.Create, Id, new ClaimsPrincipal(new ClaimsIdentity()));
        _audit.Log(AuditAction.Create, Id, new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "CORP\\mallory")])));

        Assert.All(_sink.Entries, entry => Assert.Equal("anonymous", WindowsUser(entry)));
    }

    [Theory]
    [InlineData("Negotiate")]
    [InlineData("Cookies")]
    [InlineData("Bearer")]
    public void IdentityFromAnyOtherScheme_IsAnonymous(string scheme)
    {
        var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, "CORP\\alice")], scheme);

        _audit.Log(AuditAction.Reveal, Id, new ClaimsPrincipal(identity));

        Assert.Equal("anonymous", WindowsUser(Assert.Single(_sink.Entries)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void IdentityCookieWithABlankName_IsAnonymous(string name)
    {
        _audit.Log(AuditAction.Reveal, Id, IdentityCookieUser(name));

        Assert.Equal("anonymous", WindowsUser(Assert.Single(_sink.Entries)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("abcdefghijklmnopqrstu")]
    [InlineData("abcdefghijklmnopqrstuB")]
    [InlineData("../etc/passwd\n")]
    public void MalformedSecretId_IsRejected_AndNothingIsLogged(string secretId)
    {
        Assert.Throws<ArgumentException>(() => _audit.Log(AuditAction.Create, secretId, null));

        Assert.Empty(_sink.Entries);
    }

    [Fact]
    public void AuditCode_CannotSeeSecretPayloads()
    {
        var sources = Directory.EnumerateFiles(Path.Combine(RepoPaths.Root, "src", "OneShot.Web", "Audit"), "*.cs");

        Assert.NotEmpty(sources);
        foreach (var path in sources)
        {
            var text = File.ReadAllText(path);
            Assert.DoesNotContain("SecretRecord", text, StringComparison.Ordinal);
            Assert.DoesNotContain("ConsumedSecret", text, StringComparison.Ordinal);
            Assert.DoesNotContain("Ciphertext", text, StringComparison.Ordinal);
            Assert.DoesNotContain("Nonce", text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void AuditLogger_IsRegisteredAsASingleton()
    {
        Assert.Same(_factory.Services.GetRequiredService<AuditLogger>(), _factory.Services.GetRequiredService<AuditLogger>());
    }

    private static ClaimsPrincipal IdentityCookieUser(string name)
    {
        return new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, name)], IdentityCookie.Scheme));
    }

    private static string? WindowsUser(LogEntry entry) => entry.State.Single(pair => pair.Key == "windowsUser").Value;
}
