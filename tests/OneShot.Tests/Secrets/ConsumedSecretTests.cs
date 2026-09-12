using OneShot.Web.Secrets;

namespace OneShot.Tests.Secrets;

[Trait("Threat", "T1")]
public sealed class ConsumedSecretTests
{
    [Fact]
    public void ExposesTheBuffers_UntilDisposed()
    {
        var ciphertext = new byte[] { 1, 2, 3, 4 };
        var nonce = new byte[] { 9, 8, 7 };

        using var secret = new ConsumedSecret(ciphertext, nonce);

        Assert.Equal(ciphertext, secret.Ciphertext.ToArray());
        Assert.Equal(nonce, secret.Nonce.ToArray());
    }

    [Fact]
    public void Dispose_ZeroesBothBuffersInPlace()
    {
        var ciphertext = new byte[] { 1, 2, 3, 4 };
        var nonce = new byte[] { 9, 8, 7 };
        var secret = new ConsumedSecret(ciphertext, nonce);

        secret.Dispose();

        Assert.All(ciphertext, b => Assert.Equal(0, b));
        Assert.All(nonce, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Buffers_AreUnreachableAfterDispose()
    {
        var secret = new ConsumedSecret([1, 2, 3], [4, 5, 6]);
        secret.Dispose();

        Assert.Throws<ObjectDisposedException>(() => secret.Ciphertext);
        Assert.Throws<ObjectDisposedException>(() => secret.Nonce);
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var secret = new ConsumedSecret([1, 2, 3], [4, 5, 6]);

        secret.Dispose();
        secret.Dispose();
    }

    [Fact]
    public void ToString_NeverRendersTheBuffers()
    {
        using var secret = new ConsumedSecret([0xAB, 0xCD, 0xEF], [0x12, 0x34, 0x56]);

        var text = secret.ToString();

        Assert.DoesNotContain("171", text, StringComparison.Ordinal);
        Assert.DoesNotContain("AB", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("q83v", text, StringComparison.Ordinal);
    }
}
