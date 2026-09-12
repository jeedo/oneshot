using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace OneShot.Tests.Infrastructure;

// Base fixture for every in-process test: the real Negotiate handler needs Kestrel's connection features, so
// it is replaced by TestNegotiateHandler, which impersonates an account from a request header.
public class OneShotFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseTestNegotiate();
    }
}
