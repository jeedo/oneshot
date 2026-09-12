namespace OneShot.Web.Secrets;

internal interface ISecretEntry
{
    string Id { get; }

    DateTimeOffset ExpiresAtUtc { get; }
}

internal sealed record Tombstone(string Id, DateTimeOffset ConsumedAtUtc, DateTimeOffset ExpiresAtUtc) : ISecretEntry;
