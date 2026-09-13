using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http.Features;

using OneShot.Web.Security;

namespace OneShot.Web.Api;

// Every failure leaves the process as the same fixed document, in every environment: no stack, no exception
// type, no internal message, and nothing echoed from the request (T13).
internal static class ErrorHandling
{
    public static IApplicationBuilder UseOneShotErrorHandling(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.UseExceptionHandler(new ExceptionHandlerOptions
        {
            AllowStatusCode404Response = true,

            // A rejected request is not a fault of ours, so it must not be logged at Error with a stack:
            // otherwise anyone can fill the log by posting oversized bodies. Genuine faults still log.
            SuppressDiagnosticsCallback = static context => context.Exception is BadHttpRequestException,
            ExceptionHandler = async context =>
            {
                // UseExceptionHandler clears the response before invoking this, so the hardening headers
                // have to be written again or a 500 would ship bare.
                SecurityHeaders.Apply(context);

                // Kestrel signals a client-side protocol failure — an oversized body, a bad request line,
                // bad chunking — by throwing, and the exception carries the status it chose. Answering 500
                // would both mislead the caller and log an error for every one of them, which turns the
                // body-size limit into a cheap way to fill the log (T6, T13).
                if (context.Features.Get<IExceptionHandlerFeature>()?.Error is BadHttpRequestException rejected)
                {
                    await ApiProblems.WriteRequestRejectedAsync(context, rejected.StatusCode, context.RequestAborted);
                    return;
                }

                await ApiProblems.WriteServerErrorAsync(context, context.RequestAborted);
            },
        });
    }

    // Gives an unmatched route the same fixed not-found document every other miss gets. Restricted to 404 so
    // a 405 keeps its honest meaning and the Negotiate 401 challenge keeps its empty body.
    public static IApplicationBuilder UseUniformNotFound(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.UseStatusCodePages(async context =>
        {
            if (context.HttpContext.Response.StatusCode == StatusCodes.Status404NotFound)
            {
                await ApiProblems.WriteNotFoundAsync(context.HttpContext, context.HttpContext.RequestAborted);
            }
        });
    }

    public static IEndpointRouteBuilder MapOperationalEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Liveness only: a bare 200 that reveals no counts, versions, or dependency state, and is exempt
        // from rate limiting so a probe can never be throttled out of service.
        app.MapGet("/healthz", () => Results.StatusCode(StatusCodes.Status200OK)).DisableRateLimiting();
        return app;
    }
}
