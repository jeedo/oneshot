using System.Buffers.Text;

using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;

using Microsoft.Extensions.Time.Testing;

using OneShot.Web.Secrets;

namespace OneShot.Tests.Secrets;

// The store's validation is the last line before secret material is accepted, and it is synchronous, so it
// can be stated as properties over arbitrary input rather than a list of cases someone thought of. The
// generators lean on the boundaries deliberately: uniformly random lengths would almost never land on 12,
// 16 or 65,536, which is exactly where an off-by-one lives.
[Trait("Threat", "T12")]
public sealed class CreateValidationProperties
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);

    private static InMemorySecretStore NewStore() => new(new FakeTimeProvider(Now));

    private static bool IsValid(byte[] ciphertext, byte[] nonce, TimeSpan timeToLive) =>
        ciphertext.Length >= SecretLimits.MinCiphertextBytes
        && ciphertext.Length <= SecretLimits.MaxCiphertextBytes
        && nonce.Length == SecretLimits.NonceBytes
        && timeToLive >= SecretLimits.MinTimeToLive
        && timeToLive <= SecretLimits.MaxTimeToLive;

    private static Gen<byte[]> Bytes(IEnumerable<int> interestingLengths)
    {
        var lengths = Gen.OneOf(Gen.Elements(interestingLengths), Gen.Choose(0, 128));
        return lengths.Select(length => System.Security.Cryptography.RandomNumberGenerator.GetBytes(length));
    }

    private static Gen<byte[]> Ciphertexts() =>
        Bytes([0, 1, 15, 16, 17, 1024, SecretLimits.MaxCiphertextBytes - 1, SecretLimits.MaxCiphertextBytes, SecretLimits.MaxCiphertextBytes + 1]);

    private static Gen<byte[]> Nonces() => Bytes([0, 1, 11, 12, 13, 16, 24, 32, 64]);

    private static Gen<TimeSpan> TimeToLives() =>
        Gen.OneOf(
            Gen.Elements<TimeSpan>([
                TimeSpan.Zero,
                TimeSpan.FromTicks(-1),
                TimeSpan.MinValue,
                TimeSpan.MaxValue,
                SecretLimits.MinTimeToLive - TimeSpan.FromTicks(1),
                SecretLimits.MinTimeToLive,
                SecretLimits.MaxTimeToLive,
                SecretLimits.MaxTimeToLive + TimeSpan.FromTicks(1),
            ]),
            Gen.Choose(-1000, 700_000).Select(seconds => TimeSpan.FromSeconds(seconds)));

    private static Arbitrary<(byte[] Ciphertext, byte[] Nonce, TimeSpan TimeToLive)> Inputs() =>
        Arb.From(from ciphertext in Ciphertexts()
                 from nonce in Nonces()
                 from timeToLive in TimeToLives()
                 select (ciphertext, nonce, timeToLive));

    [Property(MaxTest = 500)]
    public Property CreateNeverThrows() =>
        Prop.ForAll(Inputs(), input =>
        {
            var store = NewStore();
            var result = store.Create(input.Ciphertext, input.Nonce, input.TimeToLive);
            return result is Created or ValidationError or CapacityExceeded;
        });

    [Property(MaxTest = 500)]
    public Property AcceptedExactlyWhenWithinEveryBound() =>
        Prop.ForAll(Inputs(), input =>
        {
            var store = NewStore();
            var accepted = store.Create(input.Ciphertext, input.Nonce, input.TimeToLive) is Created;
            return accepted == IsValid(input.Ciphertext, input.Nonce, input.TimeToLive);
        });

    [Property(MaxTest = 500)]
    public Property NothingIsStoredUnlessItWasAccepted() =>
        Prop.ForAll(Inputs(), input =>
        {
            var store = NewStore();
            var result = store.Create(input.Ciphertext, input.Nonce, input.TimeToLive);
            var expected = result is Created ? 1 : 0;
            return store.Count == expected && store.CiphertextBytes == (result is Created ? input.Ciphertext.Length : 0);
        });

    [Property(MaxTest = 300)]
    public Property AnAcceptedSecretGetsAWellFormedIdAndReadsBackAvailable() =>
        Prop.ForAll(Inputs(), input =>
        {
            var store = NewStore();
            if (store.Create(input.Ciphertext, input.Nonce, input.TimeToLive) is not Created created)
            {
                return true;
            }

            return created.Id.Length == 22
                && Base64Url.IsValid(created.Id)
                && created.ExpiresAtUtc == Now + input.TimeToLive
                && store.Peek(created.Id).State == SecretState.Available;
        });

    [Property(MaxTest = 300)]
    public Property ARejectionNeverCarriesTheSubmittedBytes() =>
        Prop.ForAll(Inputs(), input =>
        {
            var store = NewStore();
            if (store.Create(input.Ciphertext, input.Nonce, input.TimeToLive) is not ValidationError error)
            {
                return true;
            }

            // The typed failure is the whole payload of a rejection: no lengths, no encodings, no content.
            var text = error.ToString();
            return text == $"ValidationError {{ Failure = {error.Failure} }}"
                && (input.Ciphertext.Length == 0 || !text.Contains(Convert.ToBase64String(input.Ciphertext), StringComparison.Ordinal));
        });
}
