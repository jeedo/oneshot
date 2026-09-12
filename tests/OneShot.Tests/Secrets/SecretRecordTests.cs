using System.Diagnostics;

using OneShot.Web.Secrets;

namespace OneShot.Tests.Secrets;

[Trait("Threat", "T1")]
public sealed class SecretRecordTests
{
    private static readonly DateTimeOffset Created = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Expires = Created.AddHours(1);

    [Fact]
    public void ExposesItsFields()
    {
        var record = new SecretRecord("abcdefghijklmnopqrstuv", [1, 2, 3], [4, 5, 6], Created, Expires);

        Assert.Equal("abcdefghijklmnopqrstuv", record.Id);
        Assert.Equal([1, 2, 3], record.Ciphertext);
        Assert.Equal([4, 5, 6], record.Nonce);
        Assert.Equal(Created, record.CreatedAtUtc);
        Assert.Equal(Expires, record.ExpiresAtUtc);
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    public void IsExpiredAt_IsInclusiveOfTheExpiryInstant(int secondsAfterExpiry, bool expected)
    {
        var record = new SecretRecord("abcdefghijklmnopqrstuv", [1], [2], Created, Expires);

        Assert.Equal(expected, record.IsExpiredAt(Expires.AddSeconds(secondsAfterExpiry)));
    }

    [Fact]
    public void Zero_ClearsBothBuffersInPlace()
    {
        var ciphertext = new byte[] { 1, 2, 3 };
        var nonce = new byte[] { 4, 5, 6 };
        var record = new SecretRecord("abcdefghijklmnopqrstuv", ciphertext, nonce, Created, Expires);

        record.Zero();

        Assert.All(ciphertext, b => Assert.Equal(0, b));
        Assert.All(nonce, b => Assert.Equal(0, b));
    }

    [Fact]
    public void ToString_RendersOnlyTheId()
    {
        var record = new SecretRecord("abcdefghijklmnopqrstuv", [0xAB, 0xCD, 0xEF], [0x12, 0x34, 0x56], Created, Expires);

        Assert.Equal("SecretRecord abcdefghijklmnopqrstuv", record.ToString());
    }

    [Fact]
    public void HasNoDebuggerDisplay_ThatCouldRenderTheBuffers()
    {
        Assert.Empty(typeof(SecretRecord).GetCustomAttributes(typeof(DebuggerDisplayAttribute), inherit: false));
        Assert.Empty(typeof(ConsumedSecret).GetCustomAttributes(typeof(DebuggerDisplayAttribute), inherit: false));
    }

    [Fact]
    public void Expiry_MustFollowCreation()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecretRecord("abcdefghijklmnopqrstuv", [1], [2], Created, Created));
    }

    [Fact]
    public void Id_IsRequired()
    {
        Assert.Throws<ArgumentException>(() => new SecretRecord("", [1], [2], Created, Expires));
    }
}
