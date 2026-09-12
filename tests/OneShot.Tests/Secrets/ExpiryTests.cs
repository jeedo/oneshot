using Microsoft.Extensions.Time.Testing;

using OneShot.Web.Secrets;

namespace OneShot.Tests.Secrets;

// Expiry is what bounds how long unread ciphertext can exist at all, so the boundary is checked to the tick
// and every path that removes an entry is checked to leave its buffers zeroed.
[Trait("Threat", "T2")]
[Trait("Threat", "T5")]
public sealed class ExpiryTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private readonly FakeTimeProvider _clock = new(Now);
    private readonly InMemorySecretStore _store;

    public ExpiryTests() => _store = new InMemorySecretStore(_clock);

    [Theory]
    [InlineData(-1, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    public void ASecretIsReadableUntilTheExactTickItExpires(int ticksFromExpiry, bool expired)
    {
        var id = Create();

        _clock.Advance(Ttl + TimeSpan.FromTicks(ticksFromExpiry));

        Assert.Equal(expired ? SecretState.Unknown : SecretState.Available, _store.Peek(id).State);
    }

    [Theory]
    [InlineData(-1, nameof(ConsumeOutcome.Consumed))]
    [InlineData(0, nameof(ConsumeOutcome.Unknown))]
    [InlineData(1, nameof(ConsumeOutcome.Unknown))]
    public void ASecretIsConsumableUntilTheExactTickItExpires(int ticksFromExpiry, string expected)
    {
        var id = Create();

        _clock.Advance(Ttl + TimeSpan.FromTicks(ticksFromExpiry));
        var result = _store.TryConsume(id);

        Assert.Equal(Enum.Parse<ConsumeOutcome>(expected), result.Outcome);
        result.Secret?.Dispose();
    }

    [Theory]
    [InlineData(-1, nameof(SecretState.Consumed))]
    [InlineData(0, nameof(SecretState.Unknown))]
    public void ATombstoneSurvivesOnlyUntilTheOriginalExpiry(int ticksFromExpiry, string expected)
    {
        var id = Create();
        _store.TryConsume(id).Secret!.Dispose();

        _clock.Advance(Ttl + TimeSpan.FromTicks(ticksFromExpiry));

        // Consuming must not extend the entry's life: the tombstone inherits the secret's original expiry.
        Assert.Equal(Enum.Parse<SecretState>(expected), _store.Peek(id).State);
    }

    [Fact]
    public void AnExpiredSecretNeverYieldsItsPayload()
    {
        var ciphertext = Ciphertext();
        var id = Create(ciphertext);

        _clock.Advance(Ttl);
        var result = _store.TryConsume(id);

        Assert.Equal(ConsumeOutcome.Unknown, result.Outcome);
        Assert.Null(result.Secret);
        Assert.All(ciphertext, b => Assert.Equal(0, b));
    }

    public static TheoryData<string> RemovalPaths => ["peek", "consume", "sweep"];

    [Theory]
    [MemberData(nameof(RemovalPaths))]
    public void EveryPathThatRemovesAnExpiredSecret_ZeroesItsBuffers(string path)
    {
        var ciphertext = Ciphertext();
        var nonce = Nonce();
        var id = Create(ciphertext, nonce);
        _clock.Advance(Ttl);

        switch (path)
        {
            case "peek":
                Assert.Equal(SecretState.Unknown, _store.Peek(id).State);
                break;
            case "consume":
                Assert.Equal(ConsumeOutcome.Unknown, _store.TryConsume(id).Outcome);
                break;
            default:
                Assert.Equal(1, _store.SweepExpired(int.MaxValue));
                break;
        }

        Assert.All(ciphertext, b => Assert.Equal(0, b));
        Assert.All(nonce, b => Assert.Equal(0, b));
        Assert.Equal(0, _store.Count);
        Assert.Equal(0, _store.CiphertextBytes);
    }

    [Fact]
    public void ConsumingThenDisposing_ZeroesTheSameBuffersTheStoreHeld()
    {
        var ciphertext = Ciphertext();
        var nonce = Nonce();
        var id = Create(ciphertext, nonce);

        var result = _store.TryConsume(id);
        Assert.Equal(ciphertext, result.Secret!.Ciphertext.ToArray());
        result.Secret.Dispose();

        Assert.All(ciphertext, b => Assert.Equal(0, b));
        Assert.All(nonce, b => Assert.Equal(0, b));
    }

    [Fact]
    public void SweepingDrainsAMixedStoreToNothing_WithEveryBufferZeroed()
    {
        const int Secrets = 500;
        var buffers = new List<(byte[] Ciphertext, byte[] Nonce)>();

        for (var i = 0; i < Secrets; i++)
        {
            var ciphertext = Ciphertext();
            var nonce = Nonce();
            buffers.Add((ciphertext, nonce));

            // Staggered lifetimes, and every third secret consumed first, so the sweep meets both live and
            // tombstoned entries at different stages.
            var id = Create(ciphertext, nonce, TimeSpan.FromMinutes(1 + (i % 10)));
            if (i % 3 == 0)
            {
                _store.TryConsume(id).Secret!.Dispose();
            }
        }

        Assert.Equal(Secrets, _store.Count);

        _clock.Advance(TimeSpan.FromMinutes(11));
        while (_store.SweepExpired(64) > 0)
        {
        }

        Assert.Equal(0, _store.Count);
        Assert.Equal(0, _store.CiphertextBytes);
        Assert.All(buffers, buffer =>
        {
            Assert.All(buffer.Ciphertext, b => Assert.Equal(0, b));
            Assert.All(buffer.Nonce, b => Assert.Equal(0, b));
        });
    }

    [Fact]
    public void ASweepLeavesEntriesThatHaveNotYetExpired()
    {
        var expiring = Create(timeToLive: TimeSpan.FromMinutes(1));
        var surviving = Create(timeToLive: TimeSpan.FromHours(2));

        _clock.Advance(TimeSpan.FromMinutes(1));

        Assert.Equal(1, _store.SweepExpired(int.MaxValue));
        Assert.Equal(SecretState.Unknown, _store.Peek(expiring).State);
        Assert.Equal(SecretState.Available, _store.Peek(surviving).State);
    }

    private string Create(byte[]? ciphertext = null, byte[]? nonce = null, TimeSpan? timeToLive = null)
    {
        return Assert.IsType<Created>(_store.Create(ciphertext ?? Ciphertext(), nonce ?? Nonce(), timeToLive ?? Ttl)).Id;
    }

    private static byte[] Ciphertext() => Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();

    private static byte[] Nonce() => Enumerable.Range(0, 12).Select(i => (byte)(0xF0 + i)).ToArray();
}
