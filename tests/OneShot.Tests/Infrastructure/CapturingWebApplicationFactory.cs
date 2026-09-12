using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OneShot.Tests.Infrastructure;

public class CapturingWebApplicationFactory : WebApplicationFactory<Program>
{
    public LogSink Logs { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureLogging(logging => logging.Services.AddSingleton<ILoggerProvider>(Logs));
    }
}
