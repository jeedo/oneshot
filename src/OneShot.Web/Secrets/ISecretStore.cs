namespace OneShot.Web.Secrets;

internal enum SecretState
{
    Available,
    Consumed,
    Unknown,
}

internal readonly record struct SecretPeek(SecretState State, DateTimeOffset? ExpiresAtUtc);

internal enum ConsumeOutcome
{
    Consumed,
    AlreadyConsumed,
    Unknown,
}

internal sealed class ConsumeResult
{
    public static readonly ConsumeResult AlreadyConsumed = new(ConsumeOutcome.AlreadyConsumed, null);

    public static readonly ConsumeResult Unknown = new(ConsumeOutcome.Unknown, null);

    private ConsumeResult(ConsumeOutcome outcome, ConsumedSecret? secret)
    {
        Outcome = outcome;
        Secret = secret;
    }

    public ConsumeOutcome Outcome { get; }

    public ConsumedSecret? Secret { get; }

    public static ConsumeResult Consumed(ConsumedSecret secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        return new ConsumeResult(ConsumeOutcome.Consumed, secret);
    }
}

internal abstract record CreateResult;

internal sealed record Created(string Id, DateTimeOffset ExpiresAtUtc) : CreateResult;

internal interface ISecretStore
{
    CreateResult Create(byte[] ciphertext, byte[] nonce, TimeSpan timeToLive);

    SecretPeek Peek(string id);

    ConsumeResult TryConsume(string id);
}
