using System.Security.Cryptography;

namespace OneShot.Web.Secrets;

internal sealed class ConsumedSecret : IDisposable
{
    private readonly byte[] _ciphertext;
    private readonly byte[] _nonce;
    private bool _disposed;

    public ConsumedSecret(byte[] ciphertext, byte[] nonce)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(nonce);

        _ciphertext = ciphertext;
        _nonce = nonce;
    }

    public ReadOnlyMemory<byte> Ciphertext
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _ciphertext;
        }
    }

    public ReadOnlyMemory<byte> Nonce
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _nonce;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_ciphertext);
        CryptographicOperations.ZeroMemory(_nonce);
    }

    public override string ToString() => nameof(ConsumedSecret);
}
