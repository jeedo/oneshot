using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace OneShot.Tests;

[Trait("Threat", "T5")]
public sealed class DataProtectionTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public DataProtectionTests(WebApplicationFactory<Program> factory) => _factory = factory;

    [Fact]
    public void KeyRing_IsEphemeral_AndNeverPersisted()
    {
        var provider = _factory.Services.GetRequiredService<IDataProtectionProvider>();

        Assert.Equal("Microsoft.AspNetCore.DataProtection.EphemeralDataProtectionProvider", provider.GetType().FullName);
    }

    [Fact]
    public void EphemeralProvider_StillRoundTripsProtectedData()
    {
        var protector = _factory.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("OneShot.Tests");

        Assert.Equal("payload", protector.Unprotect(protector.Protect("payload")));
    }
}
