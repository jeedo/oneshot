using OneShot.Web.Secrets;

namespace OneShot.Tests.Secrets;

[Trait("Threat", "T1")]
public sealed class SecretStoreContractTests
{
    [Fact]
    public void Contract_ExposesOnlyCreatePeekAndTryConsume()
    {
        var methods = typeof(ISecretStore).GetMethods().Select(method => method.Name).OrderBy(name => name, StringComparer.Ordinal);

        Assert.Equal(["Create", "Peek", "TryConsume"], methods);
    }

    [Fact]
    public void Peek_CarriesNoPayload()
    {
        var peek = new SecretPeek(SecretState.Available, DateTimeOffset.UnixEpoch);

        Assert.Equal(["ExpiresAtUtc", "State"], typeof(SecretPeek).GetProperties().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
        Assert.Equal(SecretState.Available, peek.State);
    }

    [Fact]
    public void ConsumeResult_OnlyCarriesASecretWhenConsumed()
    {
        using var secret = new ConsumedSecret([1], [2]);

        var consumed = ConsumeResult.Consumed(secret);
        var already = ConsumeResult.AlreadyConsumed;
        var unknown = ConsumeResult.Unknown;

        Assert.Same(secret, consumed.Secret);
        Assert.Equal(ConsumeOutcome.Consumed, consumed.Outcome);
        Assert.Null(already.Secret);
        Assert.Equal(ConsumeOutcome.AlreadyConsumed, already.Outcome);
        Assert.Null(unknown.Secret);
        Assert.Equal(ConsumeOutcome.Unknown, unknown.Outcome);
    }
}
