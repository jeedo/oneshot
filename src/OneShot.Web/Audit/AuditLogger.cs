using System.Collections;
using System.Globalization;
using System.Security.Claims;

using OneShot.Web.Secrets;
using OneShot.Web.Security;

namespace OneShot.Web.Audit;

// Deliberately takes only an action, an Id, and a principal: it has no way to reach a payload, so it cannot log one.
internal sealed class AuditLogger
{
    private const string Anonymous = "anonymous";

    private static readonly EventId CreateEvent = new(1001, "Audit");
    private static readonly EventId RevealEvent = new(1002, "Audit");

    private readonly ILogger<AuditLogger> _logger;
    private readonly TimeProvider _clock;

    public AuditLogger(ILogger<AuditLogger> logger, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(clock);

        _logger = logger;
        _clock = clock;
    }

    public void Log(AuditAction action, string secretId, ClaimsPrincipal? user)
    {
        if (!SecretId.IsValid(secretId))
        {
            throw new ArgumentException("The secret Id is not a valid OneShot Id.", nameof(secretId));
        }

        var timestamp = _clock.GetUtcNow().ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        var name = action == AuditAction.Create ? "create" : "reveal";
        var eventId = action == AuditAction.Create ? CreateEvent : RevealEvent;

        _logger.Log(LogLevel.Information, eventId, new AuditEvent(timestamp, name, secretId, WindowsUser(user)), null, static (state, _) => state.ToString());
    }

    private static string WindowsUser(ClaimsPrincipal? user)
    {
        return user?.Identity is { IsAuthenticated: true, AuthenticationType: IdentityCookie.Scheme, Name: { } name }
            && !string.IsNullOrWhiteSpace(name)
            ? name
            : Anonymous;
    }

    private sealed class AuditEvent(string timestampUtc, string action, string secretId, string windowsUser)
        : IReadOnlyList<KeyValuePair<string, object?>>
    {
        private readonly KeyValuePair<string, object?>[] _fields =
        [
            new("timestampUtc", timestampUtc),
            new("action", action),
            new("secretId", secretId),
            new("windowsUser", windowsUser),
        ];

        public int Count => _fields.Length;

        public KeyValuePair<string, object?> this[int index] => _fields[index];

        public IEnumerator<KeyValuePair<string, object?>> GetEnumerator() => ((IEnumerable<KeyValuePair<string, object?>>)_fields).GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public override string ToString() => $"audit {action} {secretId} {windowsUser}";
    }
}
