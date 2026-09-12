using System.Security.Cryptography;

namespace OneShot.Web.Secrets;

internal sealed class SecretRecord : ISecretEntry
{
    public SecretRecord(string id, byte[] ciphertext, byte[] nonce, DateTimeOffset createdAtUtc, DateTimeOffset expiresAtUtc)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(expiresAtUtc, createdAtUtc);

        Id = id;
        Ciphertext = ciphertext;
        Nonce = nonce;
        CreatedAtUtc = createdAtUtc;
        ExpiresAtUtc = expiresAtUtc;
    }

    public string Id { get; }

    public byte[] Ciphertext { get; }

    public byte[] Nonce { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset ExpiresAtUtc { get; }

    public bool IsExpiredAt(DateTimeOffset now) => now >= ExpiresAtUtc;

    public void Zero()
    {
        CryptographicOperations.ZeroMemory(Ciphertext);
        CryptographicOperations.ZeroMemory(Nonce);
    }

    public override string ToString() => $"SecretRecord {Id}";
}
