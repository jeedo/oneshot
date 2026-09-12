using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Secrets;

[Trait("Threat", "T5")]
[Trait("Threat", "T6")]
public sealed class ExpirySweeperServiceTests : IClassFixture<OneShotFactory>
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _clock = new(Now);
    private readonly InMemorySecretStore _store;
    private readonly OneShotFactory _factory;

    public ExpirySweeperServiceTests(OneShotFactory factory)
    {
        _factory = factory;
        _store = new InMemorySecretStore(_clock);
    }

    [Fact]
    public void SweepExpired_EvictsAndZeroesExpiredSecretsAndTombstones_LeavingLiveOnes()
    {
        var expiredCiphertext = Ciphertext();
        var expiredNonce = Nonce();
        Create(TimeSpan.FromMinutes(1), expiredCiphertext, expiredNonce);
        var tombstoned = Create(TimeSpan.FromMinutes(1));
        _store.TryConsume(tombstoned).Secret!.Dispose();
        var live = Create(TimeSpan.FromHours(1));
        var liveTombstone = Create(TimeSpan.FromHours(1));
        _store.TryConsume(liveTombstone).Secret!.Dispose();

        _clock.Advance(TimeSpan.FromMinutes(1));
        var evicted = _store.SweepExpired(int.MaxValue);

        Assert.Equal(2, evicted);
        Assert.Equal(2, _store.Count);
        Assert.Equal(32, _store.CiphertextBytes);
        Assert.All(expiredCiphertext, b => Assert.Equal(0, b));
        Assert.All(expiredNonce, b => Assert.Equal(0, b));
        Assert.Equal(SecretState.Available, _store.Peek(live).State);
        Assert.Equal(SecretState.Consumed, _store.Peek(liveTombstone).State);
    }

    [Fact]
    public void SweepExpired_WithNothingExpired_EvictsNothing()
    {
        Create(TimeSpan.FromHours(1));
        Create(TimeSpan.FromHours(1));

        Assert.Equal(0, _store.SweepExpired(int.MaxValue));
        Assert.Equal(2, _store.Count);
    }

    [Fact]
    public void SweepExpired_ScansAtMostTheBound_AndRotatesUntilEverythingIsCovered()
    {
        for (var i = 0; i < 10; i++)
        {
            Create(TimeSpan.FromMinutes(1));
        }
        _clock.Advance(TimeSpan.FromMinutes(1));

        Assert.Equal(4, _store.SweepExpired(4));
        Assert.Equal(6, _store.Count);
        Assert.Equal(4, _store.SweepExpired(4));
        Assert.Equal(2, _store.SweepExpired(4));
        Assert.Equal(0, _store.Count);
    }

    [Fact]
    public void SweepExpired_RotatesPastLiveEntries_SoTheTailIsEventuallyScanned()
    {
        for (var i = 0; i < 6; i++)
        {
            Create(TimeSpan.FromHours(1));
        }
        var late = Create(TimeSpan.FromMinutes(1));
        _clock.Advance(TimeSpan.FromMinutes(1));

        var evictedOverThreePasses = _store.SweepExpired(3) + _store.SweepExpired(3) + _store.SweepExpired(3);

        Assert.Equal(1, evictedOverThreePasses);
        Assert.Equal(SecretState.Unknown, _store.Peek(late).State);
        Assert.Equal(6, _store.Count);
    }

    [Fact]
    public void SweepExpired_RejectsANonPositiveBound()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _store.SweepExpired(0));
    }

    [Fact]
    public void Options_DefaultToThirtySecondsAndTenThousandEntriesPerPass()
    {
        var options = new SweeperOptions();

        Assert.Equal(TimeSpan.FromSeconds(30), options.Period);
        Assert.Equal(10_000, options.MaxScanPerPass);
    }

    [Fact]
    public async Task Service_SweepsOnceEveryPeriod_OfTheInjectedClock()
    {
        var sink = new LogSink();
        using var service = new ExpirySweeperService(_store, _clock, new SweeperOptions(), Logger(sink));
        Create(TimeSpan.FromSeconds(90));

        await service.StartAsync(CancellationToken.None);
        await service.Ready;
        _clock.Advance(TimeSpan.FromSeconds(29));
        await Task.Delay(50);
        Assert.Equal(0, service.Passes);

        _clock.Advance(TimeSpan.FromSeconds(1));
        await WaitForPasses(service, 1);
        Assert.Equal(1, _store.Count);

        _clock.Advance(TimeSpan.FromSeconds(30));
        await WaitForPasses(service, 2);
        Assert.Equal(1, _store.Count);

        _clock.Advance(TimeSpan.FromSeconds(30));
        await WaitForPasses(service, 3);
        Assert.Equal(0, _store.Count);
        await service.StopAsync(CancellationToken.None);

        var entry = Assert.Single(sink.Entries, e => e.Level == LogLevel.Information);
        Assert.Equal("Evicted 1 expired secret entries", entry.Message);
    }

    [Fact]
    public async Task Service_KeepsSweeping_AfterAPassThrows()
    {
        var sink = new LogSink();
        var store = new ThrowingStore(failures: 1);
        using var service = new ExpirySweeperService(store, _clock, new SweeperOptions(), Logger(sink));

        await service.StartAsync(CancellationToken.None);
        await service.Ready;
        _clock.Advance(TimeSpan.FromSeconds(30));
        await WaitForPasses(service, 1);
        _clock.Advance(TimeSpan.FromSeconds(30));
        await WaitForPasses(service, 2);
        _clock.Advance(TimeSpan.FromSeconds(30));
        await WaitForPasses(service, 3);
        await service.StopAsync(CancellationToken.None);

        Assert.Equal(3, store.Calls);
        var error = Assert.Single(sink.Entries, e => e.Level == LogLevel.Error);
        Assert.Equal("Expiry sweep failed; the next pass will run as scheduled", error.Message);
        Assert.Contains("simulated sweep failure", error.Exception, StringComparison.Ordinal);
    }

    [Fact]
    public void Service_IsRegisteredAsAHostedService_OverTheSharedStore()
    {
        var hosted = _factory.Services.GetServices<IHostedService>();

        Assert.Contains(hosted, service => service is ExpirySweeperService);
        Assert.Same(_factory.Services.GetRequiredService<ISecretStore>(), _factory.Services.GetRequiredService<ISweepableSecretStore>());
    }

    private static async Task WaitForPasses(ExpirySweeperService service, int expected)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (service.Passes < expected && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        Assert.Equal(expected, service.Passes);
    }

    private static ILogger<ExpirySweeperService> Logger(LogSink sink)
    {
        return LoggerFactory.Create(builder => builder.AddProvider(sink)).CreateLogger<ExpirySweeperService>();
    }

    private string Create(TimeSpan timeToLive, byte[]? ciphertext = null, byte[]? nonce = null)
    {
        return Assert.IsType<Created>(_store.Create(ciphertext ?? Ciphertext(), nonce ?? Nonce(), timeToLive)).Id;
    }

    private static byte[] Ciphertext() => Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();

    private static byte[] Nonce() => Enumerable.Range(0, 12).Select(i => (byte)(0xF0 + i)).ToArray();

    private sealed class ThrowingStore(int failures) : ISweepableSecretStore
    {
        public int Calls { get; private set; }

        public int SweepExpired(int maxScan)
        {
            Calls++;
            if (Calls <= failures)
            {
                throw new InvalidOperationException("simulated sweep failure");
            }

            return 0;
        }
    }
}
