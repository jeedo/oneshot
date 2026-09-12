using System.Net;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

namespace OneShot.Tests.Infrastructure;

// TestServer has no client address. A request may pin one with X-Test-Remote-Ip ("none" leaves it null);
// every other request gets its own loopback address so unrelated tests never share a rate-limit bucket.
public sealed class RemoteIpStartupFilter : IStartupFilter
{
    public const string Header = "X-Test-Remote-Ip";

    private static int s_counter;

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, pipeline) =>
        {
            context.Connection.RemoteIpAddress = context.Request.Headers[Header] switch
            {
                [var value] when value == "none" => null,
                [var value] => IPAddress.Parse(value!),
                _ => NextLoopback(),
            };
            await pipeline(context);
        });
        next(app);
    };

    private static IPAddress NextLoopback()
    {
        var n = Interlocked.Increment(ref s_counter);
        return new IPAddress([127, (byte)((n >> 16) & 0xFF), (byte)((n >> 8) & 0xFF), (byte)(1 + (n & 0x7F))]);
    }
}
