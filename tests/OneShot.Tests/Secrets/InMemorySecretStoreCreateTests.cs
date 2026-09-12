using Microsoft.Extensions.Time.Testing;

using OneShot.Web.Secrets;

namespace OneShot.Tests.Secrets;

[Trait("Threat", "T12")]
public sealed class InMemorySecretStoreCreateTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _clock = new(Now);
    private readonly InMemorySecretStore _store;

    public InMemorySecretStoreCreateTests() => _store = new InMemorySecretStore(_clock);

    [Fact]
    public void Create_StoresTheSecret_AndReturnsIdAndExpiry()
    {
        var result = _store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1));

        var created = Assert.IsType<Created>(result);
        Assert.True(SecretId.IsValid(created.Id));
        Assert.Equal(Now.AddHours(1), created.ExpiresAtUtc);
        Assert.Equal(1, _store.Count);
    }

    [Fact]
    public void Create_IssuesADistinctIdEveryTime()
    {
        var ids = Enumerable.Range(0, 100)
            .Select(_ => Assert.IsType<Created>(_store.Create(Ciphertext(16), Nonce(), TimeSpan.FromHours(1))).Id)
            .ToList();

        Assert.Equal(100, ids.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(100, _store.Count);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(64 * 1024)]
    public void Create_AcceptsCiphertextAtTheBounds(int length)
    {
        Assert.IsType<Created>(_store.Create(Ciphertext(length), Nonce(), TimeSpan.FromHours(1)));
    }

    [Theory]
    [InlineData(0, nameof(ValidationFailure.CiphertextTooShort))]
    [InlineData(15, nameof(ValidationFailure.CiphertextTooShort))]
    [InlineData((64 * 1024) + 1, nameof(ValidationFailure.CiphertextTooLong))]
    public void Create_RejectsCiphertextOutsideTheBounds(int length, string expected)
    {
        var result = _store.Create(Ciphertext(length), Nonce(), TimeSpan.FromHours(1));

        Assert.Equal(Enum.Parse<ValidationFailure>(expected), Assert.IsType<ValidationError>(result).Failure);
        Assert.Equal(0, _store.Count);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(11)]
    [InlineData(13)]
    [InlineData(16)]
    public void Create_RejectsAnyNonceThatIsNotTwelveBytes(int length)
    {
        var result = _store.Create(Ciphertext(16), new byte[length], TimeSpan.FromHours(1));

        Assert.Equal(ValidationFailure.NonceLength, Assert.IsType<ValidationError>(result).Failure);
        Assert.Equal(0, _store.Count);
    }

    [Theory]
    [InlineData(60)]
    [InlineData(3600)]
    [InlineData(7 * 24 * 3600)]
    public void Create_AcceptsTimeToLiveAtTheBounds(int seconds)
    {
        var created = Assert.IsType<Created>(_store.Create(Ciphertext(16), Nonce(), TimeSpan.FromSeconds(seconds)));

        Assert.Equal(Now.AddSeconds(seconds), created.ExpiresAtUtc);
    }

    [Theory]
    [InlineData(-1, nameof(ValidationFailure.TimeToLiveTooShort))]
    [InlineData(0, nameof(ValidationFailure.TimeToLiveTooShort))]
    [InlineData(59, nameof(ValidationFailure.TimeToLiveTooShort))]
    [InlineData((7 * 24 * 3600) + 1, nameof(ValidationFailure.TimeToLiveTooLong))]
    public void Create_RejectsTimeToLiveOutsideTheBounds(int seconds, string expected)
    {
        var result = _store.Create(Ciphertext(16), Nonce(), TimeSpan.FromSeconds(seconds));

        Assert.Equal(Enum.Parse<ValidationFailure>(expected), Assert.IsType<ValidationError>(result).Failure);
        Assert.Equal(0, _store.Count);
    }

    [Fact]
    public void Create_ChecksCiphertextBeforeNonceBeforeTimeToLive()
    {
        Assert.Equal(ValidationFailure.CiphertextTooShort, Assert.IsType<ValidationError>(_store.Create(Ciphertext(1), new byte[1], TimeSpan.Zero)).Failure);
        Assert.Equal(ValidationFailure.NonceLength, Assert.IsType<ValidationError>(_store.Create(Ciphertext(16), new byte[1], TimeSpan.Zero)).Failure);
    }

    [Fact]
    public void ValidationError_CarriesOnlyTheFailureKind()
    {
        var error = Assert.IsType<ValidationError>(_store.Create(Ciphertext(16), [0xAB, 0xCD], TimeSpan.FromHours(1)));

        Assert.Equal(["Failure"], typeof(ValidationError).GetProperties().Select(p => p.Name));
        Assert.Equal("ValidationError { Failure = NonceLength }", error.ToString());
    }

    [Fact]
    public void Create_RejectsNullBuffers()
    {
        Assert.Throws<ArgumentNullException>(() => _store.Create(null!, Nonce(), TimeSpan.FromHours(1)));
        Assert.Throws<ArgumentNullException>(() => _store.Create(Ciphertext(16), null!, TimeSpan.FromHours(1)));
    }

    [Fact]
    public void Limits_MatchTheArchitecture()
    {
        Assert.Equal(16, SecretLimits.MinCiphertextBytes);
        Assert.Equal(64 * 1024, SecretLimits.MaxCiphertextBytes);
        Assert.Equal(12, SecretLimits.NonceBytes);
        Assert.Equal(TimeSpan.FromSeconds(60), SecretLimits.MinTimeToLive);
        Assert.Equal(TimeSpan.FromDays(7), SecretLimits.MaxTimeToLive);
        Assert.Equal(TimeSpan.FromHours(1), SecretLimits.DefaultTimeToLive);
    }

    private static byte[] Ciphertext(int length) => Enumerable.Range(0, length).Select(i => (byte)(i + 1)).ToArray();

    private static byte[] Nonce() => Enumerable.Range(0, 12).Select(i => (byte)(0xF0 + i)).ToArray();
}
