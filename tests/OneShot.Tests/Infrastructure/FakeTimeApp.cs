using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace OneShot.Tests.Infrastructure;

// An app whose clock the test drives: expiry, tombstone lifetime, and sweeper passes all follow Clock.Advance
// instead of wall time. Each instance gets its own clock, so advancing time never leaks between tests.
public sealed class FakeTimeApp : IDisposable
{
    public static readonly DateTimeOffset DefaultNow = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);

    private readonly WebApplicationFactory<Program> _app;

    public FakeTimeApp(WebApplicationFactory<Program> factory, DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(factory);

        Clock = new FakeTimeProvider(now ?? DefaultNow);
        _app = factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services => services.AddSingleton<TimeProvider>(Clock)));
    }

    public FakeTimeProvider Clock { get; }

    public IServiceProvider Services => _app.Services;

    public T Service<T>() where T : notnull => _app.Services.GetRequiredService<T>();

    public HttpClient CreateClient() => _app.CreateClient();

    public HttpClient CreateClient(CapturingHandler capture) => _app.CreateDefaultClient(capture);

    public HttpClient CreateClient(WebApplicationFactoryClientOptions options) => _app.CreateClient(options);

    public void Dispose() => _app.Dispose();
}

public static class FakeTimeAppExtensions
{
    public static FakeTimeApp WithFakeTime(this WebApplicationFactory<Program> factory, DateTimeOffset? now = null) => new(factory, now);
}
