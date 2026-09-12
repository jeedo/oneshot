namespace OneShot.Web.Secrets;

internal sealed class SecretStoreOptions
{
    public int MaxEntries { get; init; } = 10_000;

    public long MaxTotalCiphertextBytes { get; init; } = 64L * 1024 * 1024;
}
