using System.Buffers.Text;
using System.Text.RegularExpressions;

using OneShot.Web.Secrets;

namespace OneShot.Tests.Secrets;

[Trait("Threat", "T3")]
[Trait("Threat", "T9")]
public sealed partial class SecretIdTests
{
    [Fact]
    public void NewId_IsTwentyTwoUrlSafeCharacters_Encoding128Bits()
    {
        for (var i = 0; i < 1_000; i++)
        {
            var id = SecretId.NewId();

            Assert.Equal(22, id.Length);
            Assert.Matches(UrlSafeAlphabet(), id);
            Assert.Equal(16, Base64Url.DecodeFromChars(id).Length);
        }
    }

    [Fact]
    public void NewId_IsCanonical_SoEveryIdHasExactlyOneSpelling()
    {
        for (var i = 0; i < 1_000; i++)
        {
            var id = SecretId.NewId();

            Assert.Contains(id[^1], "AQgw");
        }
    }

    [Fact]
    public void NewId_NeverRepeats_AndUsesTheWholeAlphabet()
    {
        var ids = Enumerable.Range(0, 10_000).Select(_ => SecretId.NewId()).ToList();

        Assert.Equal(ids.Count, ids.Distinct(StringComparer.Ordinal).Count());
        var seen = ids.SelectMany(id => id[..21]).Distinct().Count();
        Assert.Equal(64, seen);
    }

    [Theory]
    [InlineData("abcdefghijklmnopqrstuA")]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUQ")]
    [InlineData("0123456789-_012345678g")]
    [InlineData("_____________________w")]
    public void IsValid_AcceptsCanonicalTwentyTwoCharacterIds(string id)
    {
        Assert.Equal(22, id.Length);
        Assert.True(SecretId.IsValid(id));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("abcdefghijklmnopqrstu")]
    [InlineData("abcdefghijklmnopqrstuvw")]
    [InlineData("abcdefghijklmnopqrstu=")]
    [InlineData("abcdefghijklmnopqrst+A")]
    [InlineData("abcdefghijklmnopqrst/A")]
    [InlineData("abcdefghijklmnopqrstuB")]
    [InlineData("abcdefghijklmnopqrstu\n")]
    [InlineData("abcdefghijklmnopqrstuÄ")]
    public void IsValid_RejectsMalformedOrNonCanonicalIds(string? id)
    {
        Assert.False(SecretId.IsValid(id));
    }

    [Fact]
    public void GeneratedIds_AlwaysPassValidation()
    {
        for (var i = 0; i < 1_000; i++)
        {
            Assert.True(SecretId.IsValid(SecretId.NewId()));
        }
    }

    [Fact]
    public void WebProject_NeverUsesGuidOrSystemRandom()
    {
        var root = RepoPaths.Root;
        var sources = Directory.EnumerateFiles(Path.Combine(root, "src", "OneShot.Web"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                        && !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal));

        foreach (var path in sources)
        {
            var text = File.ReadAllText(path);
            Assert.DoesNotContain("Guid.NewGuid", text, StringComparison.Ordinal);
            Assert.DoesNotContain("new Random", text, StringComparison.Ordinal);
            Assert.DoesNotContain("Random.Shared", text, StringComparison.Ordinal);
        }
    }

    [GeneratedRegex("^[A-Za-z0-9_-]{22}$")]
    private static partial Regex UrlSafeAlphabet();
}
