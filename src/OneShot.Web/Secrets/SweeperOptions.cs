namespace OneShot.Web.Secrets;

internal sealed class SweeperOptions
{
    public TimeSpan Period { get; init; } = TimeSpan.FromSeconds(30);

    public int MaxScanPerPass { get; init; } = 10_000;
}
