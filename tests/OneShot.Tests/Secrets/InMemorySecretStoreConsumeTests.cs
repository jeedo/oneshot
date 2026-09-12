using OneShot.Tests.Infrastructure;
using OneShot.Web.Secrets;

namespace OneShot.Tests.Secrets;

[Trait("Threat", "T2")]
public sealed class InMemorySecretStoreConsumeTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);

    private readonly TestTimeProvider _clock = new(Now);
    private readonly InMemorySecretStore _store;

    public InMemorySecretStoreConsumeTests() => _store = new InMemorySecretStore(_clock);

    [Fact]
    public void FirstConsume_ReturnsTheExactPayload()
    {
        var ciphertext = Ciphertext();
        var nonce = Nonce();
        var id = Create(ciphertext, nonce);

        var result = _store.TryConsume(id);

        Assert.Equal(ConsumeOutcome.Consumed, result.Outcome);
        using var secret = Assert.IsType<ConsumedSecret>(result.Secret);
        Assert.Equal(ciphertext, secret.Ciphertext.ToArray());
        Assert.Equal(nonce, secret.Nonce.ToArray());
    }

    [Fact]
    public void SecondConsume_SeesTheTombstone_NeverThePayload()
    {
        var id = Create();
        using var first = _store.TryConsume(id).Secret;

        var second = _store.TryConsume(id);
        var third = _store.TryConsume(id);

        Assert.Equal(ConsumeOutcome.AlreadyConsumed, second.Outcome);
        Assert.Null(second.Secret);
        Assert.Equal(ConsumeOutcome.AlreadyConsumed, third.Outcome);
        Assert.Equal(1, _store.Count);
    }

    [Fact]
    public void Tombstone_KeepsTheOriginalExpiry()
    {
        var id = Create(timeToLive: TimeSpan.FromMinutes(10));
        using var first = _store.TryConsume(id).Secret;

        _clock.Advance(TimeSpan.FromMinutes(10) - TimeSpan.FromSeconds(1));
        Assert.Equal(ConsumeOutcome.AlreadyConsumed, _store.TryConsume(id).Outcome);

        _clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(ConsumeOutcome.Unknown, _store.TryConsume(id).Outcome);
        Assert.Equal(0, _store.Count);
    }

    [Theory]
    [InlineData("abcdefghijklmnopqrstuA")]
    [InlineData("")]
    [InlineData("not an id")]
    public void UnknownOrMalformedId_ReadsAsUnknown(string id)
    {
        var result = _store.TryConsume(id);

        Assert.Equal(ConsumeOutcome.Unknown, result.Outcome);
        Assert.Null(result.Secret);
    }

    [Fact]
    public void NullId_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => _store.TryConsume(null!));
    }

    [Fact]
    [Trait("Threat", "T5")]
    public void ExpiredSecret_IsUnknown_AndItsBuffersAreZeroed()
    {
        var ciphertext = Ciphertext();
        var nonce = Nonce();
        var id = Create(ciphertext, nonce, TimeSpan.FromMinutes(1));

        _clock.Advance(TimeSpan.FromMinutes(1));
        var result = _store.TryConsume(id);

        Assert.Equal(ConsumeOutcome.Unknown, result.Outcome);
        Assert.Equal(0, _store.Count);
        Assert.All(ciphertext, b => Assert.Equal(0, b));
        Assert.All(nonce, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task ParallelConsumers_ExactlyOneWins_TheRestSeeTheTombstone()
    {
        for (var iteration = 0; iteration < 200; iteration++)
        {
            var id = Create();
            using var gate = new ManualResetEventSlim(false);

            var tasks = Enumerable.Range(0, 64).Select(_ => Task.Run(() =>
            {
                gate.Wait();
                return _store.TryConsume(id);
            })).ToArray();
            gate.Set();
            var results = await Task.WhenAll(tasks);

            Assert.Equal(1, results.Count(r => r.Outcome == ConsumeOutcome.Consumed));
            Assert.Equal(63, results.Count(r => r.Outcome == ConsumeOutcome.AlreadyConsumed));
            Assert.DoesNotContain(results, r => r.Outcome == ConsumeOutcome.Unknown);
            foreach (var result in results)
            {
                result.Secret?.Dispose();
            }
        }
    }

    [Fact]
    public void Tombstone_CarriesNoPayload()
    {
        var properties = typeof(Tombstone).GetProperties().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal);

        Assert.Equal(["ConsumedAtUtc", "ExpiresAtUtc", "Id"], properties);
    }

    private string Create(byte[]? ciphertext = null, byte[]? nonce = null, TimeSpan? timeToLive = null)
    {
        return Assert.IsType<Created>(_store.Create(ciphertext ?? Ciphertext(), nonce ?? Nonce(), timeToLive ?? TimeSpan.FromHours(1))).Id;
    }

    private static byte[] Ciphertext() => Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();

    private static byte[] Nonce() => Enumerable.Range(0, 12).Select(i => (byte)(0xF0 + i)).ToArray();
}
