using System.Collections.Concurrent;

namespace OneShot.Tests.Infrastructure;

// Records everything that leaves the client, so leak tests can assert that key or plaintext material never
// appears in a path, query string, header, or body.
public sealed class CapturingHandler : DelegatingHandler
{
    private readonly ConcurrentQueue<CapturedRequest> _requests = new();

    public IReadOnlyCollection<CapturedRequest> Requests => _requests;

    public void Clear() => _requests.Clear();

    public bool AnyContains(string text)
    {
        ArgumentException.ThrowIfNullOrEmpty(text);
        return _requests.Any(request => request.Contains(text));
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        var headers = request.Headers
            .Concat(request.Content?.Headers ?? Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>())
            .Select(header => new KeyValuePair<string, string>(header.Key, string.Join(", ", header.Value)))
            .ToList();

        _requests.Enqueue(new CapturedRequest(request.Method.Method, request.RequestUri?.ToString() ?? string.Empty, headers, body));

        return await base.SendAsync(request, cancellationToken);
    }
}

public sealed record CapturedRequest(string Method, string Uri, IReadOnlyList<KeyValuePair<string, string>> Headers, string? Body)
{
    public bool Contains(string text)
    {
        return Uri.Contains(text, StringComparison.Ordinal)
            || (Body?.Contains(text, StringComparison.Ordinal) ?? false)
            || Headers.Any(header => header.Value.Contains(text, StringComparison.Ordinal));
    }
}
