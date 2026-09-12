namespace OneShot.Web.Secrets;

internal static class SecretLimits
{
    // AES-GCM ciphertext always ends with the 16-byte authentication tag, so nothing shorter can be valid.
    public const int MinCiphertextBytes = 16;

    public const int MaxCiphertextBytes = 64 * 1024;

    public const int NonceBytes = 12;

    public static readonly TimeSpan MinTimeToLive = TimeSpan.FromSeconds(60);

    public static readonly TimeSpan MaxTimeToLive = TimeSpan.FromDays(7);

    public static readonly TimeSpan DefaultTimeToLive = TimeSpan.FromHours(1);
}
