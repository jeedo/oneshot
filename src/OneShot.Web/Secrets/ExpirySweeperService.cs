namespace OneShot.Web.Secrets;

internal sealed class ExpirySweeperService : BackgroundService
{
    private readonly ISweepableSecretStore _store;
    private readonly TimeProvider _clock;
    private readonly SweeperOptions _options;
    private readonly ILogger<ExpirySweeperService> _logger;
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _passes;

    public ExpirySweeperService(ISweepableSecretStore store, TimeProvider clock, SweeperOptions options, ILogger<ExpirySweeperService> logger)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(options.Period, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(options.MaxScanPerPass);

        _store = store;
        _clock = clock;
        _options = options;
        _logger = logger;
    }

    public int Passes => Volatile.Read(ref _passes);

    // Completes once the periodic timer is armed; ExecuteAsync may start after StartAsync returns.
    public Task Ready => _ready.Task;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(_options.Period, _clock);
        _ready.TrySetResult();
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                SweepOnce();
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void SweepOnce()
    {
        try
        {
            var evicted = _store.SweepExpired(_options.MaxScanPerPass);
            if (evicted > 0)
            {
                _logger.LogInformation("Evicted {Count} expired secret entries", evicted);
            }
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Expiry sweep failed; the next pass will run as scheduled");
        }
        finally
        {
            Interlocked.Increment(ref _passes);
        }
    }
}
