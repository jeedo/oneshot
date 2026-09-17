namespace OneShot.Web;

internal static class ClientStylesheet
{
    public const string RequestPath = "/css/oneshot.css";

    public static string Sha256 { get; } = LoadRecordedHash();

    public static string Integrity { get; } = $"sha256-{Sha256}";

    private static string LoadRecordedHash()
    {
        using var stream = typeof(ClientStylesheet).Assembly.GetManifestResourceStream("OneShot.Web.styles.sha256")
            ?? throw new InvalidOperationException("The client stylesheet hash resource is missing from the assembly.");
        using var reader = new StreamReader(stream);

        var hash = reader.ReadToEnd().Trim();
        if (Convert.FromBase64String(hash).Length != 32)
        {
            throw new InvalidOperationException("The recorded client stylesheet hash is not a base64 SHA-256 digest.");
        }

        return hash;
    }
}
