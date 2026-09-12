using System.Buffers.Text;
using System.Security.Cryptography;

namespace OneShot.Web.Secrets;

internal static class SecretId
{
    public const int Length = 22;

    private const int EntropyBytes = 16;

    // 128 bits leave two data bits in the 22nd character, so only these four spellings are canonical.
    private const string CanonicalLastCharacters = "AQgw";

    public static string NewId()
    {
        Span<byte> bytes = stackalloc byte[EntropyBytes];
        RandomNumberGenerator.Fill(bytes);
        return Base64Url.EncodeToString(bytes);
    }

    public static bool IsValid(string? id)
    {
        if (id is null || id.Length != Length || !CanonicalLastCharacters.Contains(id[^1], StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var c in id)
        {
            if (!IsUrlSafe(c))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsUrlSafe(char c) => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
}
