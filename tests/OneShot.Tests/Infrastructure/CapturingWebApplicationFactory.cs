using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OneShot.Tests.Infrastructure;

public class CapturingWebApplicationFactory : OneShotFactory
{
    public LogSink Logs { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureLogging(logging => logging.Services.AddSingleton<ILoggerProvider>(Logs));
    }
}
