using System.Collections.Concurrent;

namespace OneShot.Web.Secrets;

internal sealed class InMemorySecretStore : ISecretStore
{
    private readonly ConcurrentDictionary<string, SecretRecord> _records = new(StringComparer.Ordinal);
    private readonly TimeProvider _clock;

    public InMemorySecretStore(TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);
        _clock = clock;
    }

    public int Count => _records.Count;

    // The store takes ownership of both buffers so it can zero them on consume or evict.
    public CreateResult Create(byte[] ciphertext, byte[] nonce, TimeSpan timeToLive)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(nonce);

        if (Validate(ciphertext, nonce, timeToLive) is { } failure)
        {
            return new ValidationError(failure);
        }

        var now = _clock.GetUtcNow();
        var expiresAtUtc = now + timeToLive;

        while (true)
        {
            var record = new SecretRecord(SecretId.NewId(), ciphertext, nonce, now, expiresAtUtc);
            if (_records.TryAdd(record.Id, record))
            {
                return new Created(record.Id, expiresAtUtc);
            }
        }
    }

    public SecretPeek Peek(string id) => throw new NotImplementedException();

    public ConsumeResult TryConsume(string id) => throw new NotImplementedException();

    private static ValidationFailure? Validate(byte[] ciphertext, byte[] nonce, TimeSpan timeToLive)
    {
        if (ciphertext.Length < SecretLimits.MinCiphertextBytes)
        {
            return ValidationFailure.CiphertextTooShort;
        }

        if (ciphertext.Length > SecretLimits.MaxCiphertextBytes)
        {
            return ValidationFailure.CiphertextTooLong;
        }

        if (nonce.Length != SecretLimits.NonceBytes)
        {
            return ValidationFailure.NonceLength;
        }

        if (timeToLive < SecretLimits.MinTimeToLive)
        {
            return ValidationFailure.TimeToLiveTooShort;
        }

        if (timeToLive > SecretLimits.MaxTimeToLive)
        {
            return ValidationFailure.TimeToLiveTooLong;
        }

        return null;
    }
}
