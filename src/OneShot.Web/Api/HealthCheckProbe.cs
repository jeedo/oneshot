namespace OneShot.Web.Api;

// Docker's HEALTHCHECK needs an executable to run, and the chiseled runtime image (plan task 48) ships no
// shell, curl, or wget — only dotnet itself. Re-invoking this same binary with --healthcheck makes the app
// its own probe: a plain GET against /healthz, translated into an exit code Docker understands.
internal static class HealthCheckProbe
{
    // Must match the ASPNETCORE_URLS port set in the Dockerfile.
    public const int Port = 8080;

    public static async Task<int> RunAsync(HttpMessageHandler? handler = null)
    {
        using var client = handler is null ? new HttpClient() : new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(3);

        try
        {
            using var response = await client.GetAsync($"http://127.0.0.1:{Port}/healthz");
            return response.IsSuccessStatusCode ? 0 : 1;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return 1;
        }
    }
}
