using Microsoft.Extensions.Time.Testing;

using OneShot.Web.Secrets;

namespace OneShot.Tests.Secrets;

[Trait("Threat", "T2")]
[Trait("Threat", "T5")]
public sealed class InMemorySecretStorePeekTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _clock = new(Now);
    private readonly InMemorySecretStore _store;

    public InMemorySecretStorePeekTests() => _store = new InMemorySecretStore(_clock);

    [Fact]
    public void FreshSecret_ReadsAsAvailable_WithItsExpiry()
    {
        var id = Create(TimeSpan.FromMinutes(30));

        var peek = _store.Peek(id);

        Assert.Equal(SecretState.Available, peek.State);
        Assert.Equal(Now.AddMinutes(30), peek.ExpiresAtUtc);
    }

    [Fact]
    public void Peek_NeverConsumes()
    {
        var id = Create();

        for (var i = 0; i < 100; i++)
        {
            Assert.Equal(SecretState.Available, _store.Peek(id).State);
        }

        var consumed = _store.TryConsume(id);
        Assert.Equal(ConsumeOutcome.Consumed, consumed.Outcome);
        consumed.Secret!.Dispose();
    }

    [Fact]
    public void ConsumedSecret_ReadsAsConsumed_WithTheOriginalExpiry()
    {
        var id = Create(TimeSpan.FromMinutes(30));
        _store.TryConsume(id).Secret!.Dispose();

        var peek = _store.Peek(id);

        Assert.Equal(SecretState.Consumed, peek.State);
        Assert.Equal(Now.AddMinutes(30), peek.ExpiresAtUtc);
    }

    [Theory]
    [InlineData("abcdefghijklmnopqrstuA")]
    [InlineData("")]
    [InlineData("not an id")]
    public void UnknownOrMalformedId_ReadsAsUnknown_WithNoExpiry(string id)
    {
        var peek = _store.Peek(id);

        Assert.Equal(SecretState.Unknown, peek.State);
        Assert.Null(peek.ExpiresAtUtc);
    }

    [Fact]
    public void NullId_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => _store.Peek(null!));
    }

    [Fact]
    public void Secret_IsAvailableUntilTheInstantItExpires()
    {
        var id = Create(TimeSpan.FromMinutes(1));

        _clock.Advance(TimeSpan.FromMinutes(1) - TimeSpan.FromTicks(1));
        Assert.Equal(SecretState.Available, _store.Peek(id).State);

        _clock.Advance(TimeSpan.FromTicks(1));
        Assert.Equal(SecretState.Unknown, _store.Peek(id).State);
    }

    [Fact]
    public void ExpiredSecret_IsEvictedAndZeroed_OnPeek()
    {
        var ciphertext = Ciphertext();
        var nonce = Nonce();
        var id = Create(TimeSpan.FromMinutes(1), ciphertext, nonce);

        _clock.Advance(TimeSpan.FromMinutes(1));
        var peek = _store.Peek(id);

        Assert.Equal(SecretState.Unknown, peek.State);
        Assert.Null(peek.ExpiresAtUtc);
        Assert.Equal(0, _store.Count);
        Assert.All(ciphertext, b => Assert.Equal(0, b));
        Assert.All(nonce, b => Assert.Equal(0, b));
        Assert.Equal(ConsumeOutcome.Unknown, _store.TryConsume(id).Outcome);
    }

    [Fact]
    public void ExpiredTombstone_IsEvicted_OnPeek()
    {
        var id = Create(TimeSpan.FromMinutes(1));
        _store.TryConsume(id).Secret!.Dispose();
        Assert.Equal(SecretState.Consumed, _store.Peek(id).State);

        _clock.Advance(TimeSpan.FromMinutes(1));
        var peek = _store.Peek(id);

        Assert.Equal(SecretState.Unknown, peek.State);
        Assert.Equal(0, _store.Count);
    }

    private string Create(TimeSpan? timeToLive = null, byte[]? ciphertext = null, byte[]? nonce = null)
    {
        return Assert.IsType<Created>(_store.Create(ciphertext ?? Ciphertext(), nonce ?? Nonce(), timeToLive ?? TimeSpan.FromHours(1))).Id;
    }

    private static byte[] Ciphertext() => Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();

    private static byte[] Nonce() => Enumerable.Range(0, 12).Select(i => (byte)(0xF0 + i)).ToArray();
}
