using System.Collections.Concurrent;

using Microsoft.Extensions.Logging;

namespace OneShot.Tests.Infrastructure;

public sealed record LogEntry(
    string Category,
    LogLevel Level,
    EventId EventId,
    string Message,
    IReadOnlyList<KeyValuePair<string, string?>> State,
    string? Exception)
{
    public bool Contains(string text)
    {
        return Message.Contains(text, StringComparison.Ordinal)
            || (Exception?.Contains(text, StringComparison.Ordinal) ?? false)
            || State.Any(pair => pair.Value?.Contains(text, StringComparison.Ordinal) ?? false);
    }
}

public sealed class LogSink : ILoggerProvider
{
    private readonly ConcurrentQueue<LogEntry> _entries = new();

    public IReadOnlyCollection<LogEntry> Entries => _entries;

    public void Clear() => _entries.Clear();

    public ILogger CreateLogger(string categoryName) => new SinkLogger(categoryName, _entries);

    public void Dispose()
    {
    }

    private sealed class SinkLogger(string category, ConcurrentQueue<LogEntry> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var values = state is IReadOnlyList<KeyValuePair<string, object?>> pairs
                ? pairs.Select(pair => new KeyValuePair<string, string?>(pair.Key, pair.Value?.ToString())).ToArray()
                : [];

            entries.Enqueue(new LogEntry(category, logLevel, eventId, formatter(state, exception), values, exception?.ToString()));
        }
    }
}
