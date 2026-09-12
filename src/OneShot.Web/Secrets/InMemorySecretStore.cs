using System.Collections.Concurrent;

namespace OneShot.Web.Secrets;

internal sealed class InMemorySecretStore : ISecretStore
{
    private readonly ConcurrentDictionary<string, ISecretEntry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _clock;

    public InMemorySecretStore(TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);
        _clock = clock;
    }

    public int Count => _entries.Count;

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
            if (_entries.TryAdd(record.Id, record))
            {
                return new Created(record.Id, expiresAtUtc);
            }
        }
    }

    public SecretPeek Peek(string id)
    {
        ArgumentNullException.ThrowIfNull(id);

        if (!_entries.TryGetValue(id, out var entry))
        {
            return new SecretPeek(SecretState.Unknown, null);
        }

        if (_clock.GetUtcNow() >= entry.ExpiresAtUtc)
        {
            Evict(entry);
            return new SecretPeek(SecretState.Unknown, null);
        }

        var state = entry is SecretRecord ? SecretState.Available : SecretState.Consumed;
        return new SecretPeek(state, entry.ExpiresAtUtc);
    }

    // Consumption is a compare-and-swap of the record for its tombstone: exactly one caller's TryUpdate can
    // succeed against the same record instance, and no caller ever observes a gap where the Id is missing.
    public ConsumeResult TryConsume(string id)
    {
        ArgumentNullException.ThrowIfNull(id);

        while (true)
        {
            if (!_entries.TryGetValue(id, out var entry))
            {
                return ConsumeResult.Unknown;
            }

            var now = _clock.GetUtcNow();
            if (now >= entry.ExpiresAtUtc)
            {
                Evict(entry);
                return ConsumeResult.Unknown;
            }

            if (entry is not SecretRecord record)
            {
                return ConsumeResult.AlreadyConsumed;
            }

            var tombstone = new Tombstone(id, now, record.ExpiresAtUtc);
            if (_entries.TryUpdate(id, tombstone, record))
            {
                return ConsumeResult.Consumed(new ConsumedSecret(record.Ciphertext, record.Nonce));
            }
        }
    }

    private void Evict(ISecretEntry entry)
    {
        if (_entries.TryRemove(new KeyValuePair<string, ISecretEntry>(entry.Id, entry)) && entry is SecretRecord record)
        {
            record.Zero();
        }
    }

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
