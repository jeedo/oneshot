using System.Net;

using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;

using OneShot.Web.Security;

namespace OneShot.Tests.Security;

[Trait("Threat", "T11")]
public sealed class ForwardedHeadersSetupTests
{
    [Fact]
    public void WithoutAnyConfiguredProxyOrNetwork_ForwardedHeadersAreNotUsedAtAll()
    {
        var configuration = new ConfigurationBuilder().Build();

        Assert.Null(ForwardedHeadersSetup.Build(configuration));
    }

    [Fact]
    public void ConfiguredProxiesAndNetworks_ReplaceTheLoopbackDefaults_AndTrustOneHop()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ForwardedHeaders:KnownProxies:0"] = "10.0.0.1",
            ["ForwardedHeaders:KnownNetworks:0"] = "192.168.0.0/16",
        }).Build();

        var options = ForwardedHeadersSetup.Build(configuration);

        Assert.NotNull(options);
        Assert.Equal(ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto, options.ForwardedHeaders);
        Assert.Equal(1, options.ForwardLimit);
        Assert.Equal([IPAddress.Parse("10.0.0.1")], options.KnownProxies);
        Assert.Equal([System.Net.IPNetwork.Parse("192.168.0.0/16")], options.KnownIPNetworks);
    }

    [Fact]
    public void AnInvalidProxyAddress_FailsFast()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ForwardedHeaders:KnownProxies:0"] = "not-an-ip",
        }).Build();

        Assert.ThrowsAny<FormatException>(() => ForwardedHeadersSetup.Build(configuration));
    }
}
