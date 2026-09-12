using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;

namespace OneShot.Web.Api;

// Accepts only unpadded, canonical base64url so every byte sequence has exactly one accepted spelling.
internal static class Base64UrlStrict
{
    public static bool TryDecode(string text, [NotNullWhen(true)] out byte[]? bytes)
    {
        ArgumentNullException.ThrowIfNull(text);
        bytes = null;

        if (text.Length % 4 == 1)
        {
            return false;
        }

        foreach (var c in text)
        {
            if (c is not ((>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_'))
            {
                return false;
            }
        }

        var buffer = new byte[Base64Url.GetMaxDecodedLength(text.Length)];
        int written;
        try
        {
            // Despite its name, TryDecodeFromChars throws on malformed input and only returns false for a short buffer.
            if (!Base64Url.TryDecodeFromChars(text, buffer, out written))
            {
                return false;
            }
        }
        catch (FormatException)
        {
            return false;
        }

        var decoded = buffer.AsSpan(0, written).ToArray();
        if (!Base64Url.EncodeToString(decoded).Equals(text, StringComparison.Ordinal))
        {
            return false;
        }

        bytes = decoded;
        return true;
    }
}
