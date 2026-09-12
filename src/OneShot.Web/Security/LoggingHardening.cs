namespace OneShot.Web.Security;

internal static class LoggingHardening
{
    public static void Apply(ILoggingBuilder logging)
    {
        logging.ClearProviders();
        logging.AddJsonConsole(options =>
        {
            options.UseUtcTimestamp = true;
            options.TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";
        });

        // Request logging would print URLs, headers, and bodies (T1); hosting diagnostics print the full URL
        // including the query string on every request (T5). Neither may ever be enabled by configuration.
        logging.AddFilter("Microsoft.AspNetCore.HttpLogging", LogLevel.None);
        logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Warning);
    }
}
