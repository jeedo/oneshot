using System.Collections.Concurrent;

namespace OneShot.Web.Secrets;

internal sealed class InMemorySecretStore : ISecretStore, ISweepableSecretStore
{
    private readonly ConcurrentDictionary<string, ISecretEntry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _clock;
    private readonly int _maxEntries;
    private readonly long _maxCiphertextBytes;
    private int _entryCount;
    private long _ciphertextBytes;
    private int _sweepOffset;

    public InMemorySecretStore(TimeProvider clock, SecretStoreOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(clock);
        options ??= new SecretStoreOptions();
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(options.MaxEntries);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(options.MaxTotalCiphertextBytes);

        _clock = clock;
        _maxEntries = options.MaxEntries;
        _maxCiphertextBytes = options.MaxTotalCiphertextBytes;
    }

    public int Count => _entries.Count;

    public long CiphertextBytes => Interlocked.Read(ref _ciphertextBytes);

    // The store takes ownership of both buffers so it can zero them on consume or evict.
    public CreateResult Create(byte[] ciphertext, byte[] nonce, TimeSpan timeToLive)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(nonce);

        if (Validate(ciphertext, nonce, timeToLive) is { } failure)
        {
            return new ValidationError(failure);
        }

        if (Reserve(ciphertext.Length) is { } limit)
        {
            return new CapacityExceeded(limit);
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
                Interlocked.Add(ref _ciphertextBytes, -record.Ciphertext.Length);
                return ConsumeResult.Consumed(new ConsumedSecret(record.Ciphertext, record.Nonce));
            }
        }
    }

    // Each pass scans at most maxScan entries and resumes after the surviving entries it already scanned,
    // so a bounded pass still visits every entry over successive passes.
    public int SweepExpired(int maxScan)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxScan);

        var now = _clock.GetUtcNow();
        var offset = _sweepOffset;
        var index = 0;
        var scanned = 0;
        var evicted = 0;

        foreach (var pair in _entries)
        {
            if (index++ < offset)
            {
                continue;
            }

            if (scanned == maxScan)
            {
                _sweepOffset = offset + scanned - evicted;
                return evicted;
            }

            scanned++;
            if (now >= pair.Value.ExpiresAtUtc && Evict(pair.Value))
            {
                evicted++;
            }
        }

        _sweepOffset = 0;
        return evicted;
    }

    // Capacity is reserved before insertion and released on rejection, consume, or evict, so concurrent
    // creates can never overshoot either cap.
    private CapacityLimit? Reserve(int ciphertextLength)
    {
        if (Interlocked.Increment(ref _entryCount) > _maxEntries)
        {
            Interlocked.Decrement(ref _entryCount);
            return CapacityLimit.Entries;
        }

        if (Interlocked.Add(ref _ciphertextBytes, ciphertextLength) > _maxCiphertextBytes)
        {
            Interlocked.Add(ref _ciphertextBytes, -ciphertextLength);
            Interlocked.Decrement(ref _entryCount);
            return CapacityLimit.Bytes;
        }

        return null;
    }

    private bool Evict(ISecretEntry entry)
    {
        if (!_entries.TryRemove(new KeyValuePair<string, ISecretEntry>(entry.Id, entry)))
        {
            return false;
        }

        Interlocked.Decrement(ref _entryCount);
        if (entry is SecretRecord record)
        {
            Interlocked.Add(ref _ciphertextBytes, -record.Ciphertext.Length);
            record.Zero();
        }

        return true;
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
