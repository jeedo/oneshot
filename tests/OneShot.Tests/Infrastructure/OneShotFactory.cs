using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace OneShot.Tests.Infrastructure;

// Base fixture for every in-process test: the real Negotiate handler needs Kestrel's connection features, so
// it is replaced by TestNegotiateHandler, which impersonates an account from a request header, and TestServer
// has no client address, so RemoteIpStartupFilter supplies one.
public class OneShotFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseTestNegotiate();
        builder.ConfigureServices(services => services.AddTransient<IStartupFilter, RemoteIpStartupFilter>());
    }
}
