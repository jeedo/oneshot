using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Secrets;

[Trait("Threat", "T6")]
public sealed class InMemorySecretStoreCapacityTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);

    private readonly TestTimeProvider _clock = new(Now);

    [Fact]
    public void Defaults_MatchTheArchitecture()
    {
        var options = new SecretStoreOptions();

        Assert.Equal(10_000, options.MaxEntries);
        Assert.Equal(64L * 1024 * 1024, options.MaxTotalCiphertextBytes);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(-1, 1)]
    [InlineData(1, 0)]
    [InlineData(1, -1)]
    public void NonPositiveLimits_AreRejected(int maxEntries, long maxBytes)
    {
        var options = new SecretStoreOptions { MaxEntries = maxEntries, MaxTotalCiphertextBytes = maxBytes };

        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemorySecretStore(_clock, options));
    }

    [Fact]
    public void Create_RefusesTheEntryThatWouldCrossTheEntryCap()
    {
        var store = Store(maxEntries: 3);

        for (var i = 0; i < 3; i++)
        {
            Assert.IsType<Created>(store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1)));
        }
        var rejected = store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1));

        Assert.Equal(CapacityLimit.Entries, Assert.IsType<CapacityExceeded>(rejected).Limit);
        Assert.Equal(3, store.Count);
    }

    [Fact]
    public void Create_RefusesTheSecretThatWouldCrossTheByteCap()
    {
        var store = Store(maxBytes: 64);

        Assert.IsType<Created>(store.Create(Ciphertext(32), Nonce(), TimeSpan.FromHours(1)));
        Assert.IsType<Created>(store.Create(Ciphertext(32), Nonce(), TimeSpan.FromHours(1)));
        var rejected = store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1));

        Assert.Equal(CapacityLimit.Bytes, Assert.IsType<CapacityExceeded>(rejected).Limit);
        Assert.Equal(2, store.Count);
        Assert.Equal(64, store.CiphertextBytes);
    }

    [Fact]
    public void Consume_ReleasesTheBytes_ButTheTombstoneStillCountsAsAnEntry()
    {
        var store = Store(maxEntries: 3, maxBytes: 64);
        var first = Assert.IsType<Created>(store.Create(Ciphertext(32), Nonce(), TimeSpan.FromHours(1))).Id;
        Assert.IsType<Created>(store.Create(Ciphertext(32), Nonce(), TimeSpan.FromHours(1)));

        store.TryConsume(first).Secret!.Dispose();

        Assert.Equal(32, store.CiphertextBytes);
        Assert.IsType<Created>(store.Create(Ciphertext(32), Nonce(), TimeSpan.FromHours(1)));
        Assert.Equal(3, store.Count);
        Assert.Equal(CapacityLimit.Entries, Assert.IsType<CapacityExceeded>(store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1))).Limit);
    }

    [Fact]
    public void EvictingAnExpiredSecret_ReleasesItsEntryAndBytes()
    {
        var store = Store(maxEntries: 1, maxBytes: 32);
        var id = Assert.IsType<Created>(store.Create(Ciphertext(32), Nonce(), TimeSpan.FromMinutes(1))).Id;
        Assert.IsType<CapacityExceeded>(store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1)));

        _clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(SecretState.Unknown, store.Peek(id).State);

        Assert.Equal(0, store.CiphertextBytes);
        Assert.IsType<Created>(store.Create(Ciphertext(32), Nonce(), TimeSpan.FromHours(1)));
    }

    [Fact]
    public void EvictingAnExpiredTombstone_ReleasesItsEntry()
    {
        var store = Store(maxEntries: 1);
        var id = Assert.IsType<Created>(store.Create(Ciphertext(16), Nonce(), TimeSpan.FromMinutes(1))).Id;
        store.TryConsume(id).Secret!.Dispose();
        Assert.IsType<CapacityExceeded>(store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1)));

        _clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(SecretState.Unknown, store.Peek(id).State);

        Assert.IsType<Created>(store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1)));
    }

    [Fact]
    public void RejectedCreates_LeaveNoReservationBehind()
    {
        var store = Store(maxEntries: 1, maxBytes: 16);
        var id = Assert.IsType<Created>(store.Create(Ciphertext(16), Nonce(), TimeSpan.FromMinutes(1))).Id;

        for (var i = 0; i < 100; i++)
        {
            Assert.IsType<CapacityExceeded>(store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1)));
        }
        Assert.IsType<ValidationError>(store.Create(Ciphertext(1), Nonce(), TimeSpan.FromHours(1)));

        Assert.Equal(1, store.Count);
        Assert.Equal(16, store.CiphertextBytes);
        _clock.Advance(TimeSpan.FromMinutes(1));
        store.Peek(id);
        Assert.IsType<Created>(store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1)));
    }

    [Fact]
    public void ValidationFailures_ConsumeNoCapacity()
    {
        var store = Store(maxEntries: 1);

        Assert.IsType<ValidationError>(store.Create(Ciphertext(15), Nonce(), TimeSpan.FromHours(1)));
        Assert.IsType<ValidationError>(store.Create(Ciphertext(16), new byte[11], TimeSpan.FromHours(1)));

        Assert.IsType<Created>(store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1)));
    }

    [Fact]
    public async Task ParallelCreates_NeverOvershootTheEntryCap()
    {
        var store = Store(maxEntries: 50);

        var results = await RunInParallel(64, () => store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1)));

        Assert.Equal(50, results.Count(r => r is Created));
        Assert.Equal(14, results.Count(r => r is CapacityExceeded { Limit: CapacityLimit.Entries }));
        Assert.Equal(50, store.Count);
    }

    [Fact]
    public async Task ParallelCreates_NeverOvershootTheByteCap()
    {
        var store = Store(maxBytes: 50 * 32);

        var results = await RunInParallel(64, () => store.Create(Ciphertext(32), Nonce(), TimeSpan.FromHours(1)));

        Assert.Equal(50, results.Count(r => r is Created));
        Assert.Equal(14, results.Count(r => r is CapacityExceeded { Limit: CapacityLimit.Bytes }));
        Assert.Equal(50 * 32, store.CiphertextBytes);
    }

    [Fact]
    public void CapacityExceeded_CarriesOnlyTheLimitKind()
    {
        Assert.Equal(["Limit"], typeof(CapacityExceeded).GetProperties().Select(p => p.Name));
    }

    private InMemorySecretStore Store(int maxEntries = 10_000, long maxBytes = 64L * 1024 * 1024)
    {
        return new InMemorySecretStore(_clock, new SecretStoreOptions { MaxEntries = maxEntries, MaxTotalCiphertextBytes = maxBytes });
    }

    private static async Task<CreateResult[]> RunInParallel(int count, Func<CreateResult> action)
    {
        using var gate = new ManualResetEventSlim(false);
        var tasks = Enumerable.Range(0, count).Select(_ => Task.Run(() =>
        {
            gate.Wait();
            return action();
        })).ToArray();
        gate.Set();
        return await Task.WhenAll(tasks);
    }

    private static byte[] Ciphertext(int length) => Enumerable.Range(0, length).Select(i => (byte)(i + 1)).ToArray();

    private static byte[] Nonce() => Enumerable.Range(0, 12).Select(i => (byte)(0xF0 + i)).ToArray();
}
