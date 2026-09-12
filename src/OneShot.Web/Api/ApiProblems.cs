namespace OneShot.Web.Api;

// Every error is a fixed RFC 7807 body keyed by a stable code; nothing from the request is ever echoed.
internal static class ApiProblems
{
    public static IResult BadRequest(string code) => Problem(StatusCodes.Status400BadRequest, "The request was rejected.", code);

    public static IResult UnsupportedMediaType() => Problem(StatusCodes.Status415UnsupportedMediaType, "The request body must be JSON.", "unsupportedMediaType");

    public static IResult Forbidden(string code) => Problem(StatusCodes.Status403Forbidden, "The request is not allowed.", code);

    public static IResult NotFound(string code) => Problem(StatusCodes.Status404NotFound, "There is no such secret.", code);

    public static IResult Gone(string code) => Problem(StatusCodes.Status410Gone, "The secret has already been revealed.", code);

    public static IResult ServiceUnavailable(HttpResponse response, string code, TimeSpan retryAfter)
    {
        ArgumentNullException.ThrowIfNull(response);
        response.Headers.RetryAfter = ((int)retryAfter.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture);
        return Problem(StatusCodes.Status503ServiceUnavailable, "The service cannot accept new secrets right now.", code);
    }

    public static async Task WriteNotFoundAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var problem = new Microsoft.AspNetCore.Mvc.ProblemDetails
        {
            Type = "https://tools.ietf.org/html/rfc9110#section-15.5.5",
            Status = StatusCodes.Status404NotFound,
            Title = "There is no such resource.",
            Extensions = { ["code"] = "notFound" },
        };
        await context.Response.WriteAsJsonAsync(problem, options: null, contentType: "application/problem+json", cancellationToken);
    }

    public static async Task WriteServerErrorAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        var problem = new Microsoft.AspNetCore.Mvc.ProblemDetails
        {
            Type = "https://tools.ietf.org/html/rfc9110#section-15.6.1",
            Status = StatusCodes.Status500InternalServerError,
            Title = "The request could not be completed.",
            Extensions = { ["code"] = "internalError" },
        };
        await context.Response.WriteAsJsonAsync(problem, options: null, contentType: "application/problem+json", cancellationToken);
    }

    public static async ValueTask WriteTooManyRequestsAsync(HttpContext context, TimeSpan? retryAfter, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var response = context.Response;
        response.StatusCode = StatusCodes.Status429TooManyRequests;
        if (retryAfter is { } delay)
        {
            response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling(delay.TotalSeconds)).ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        var problem = new Microsoft.AspNetCore.Mvc.ProblemDetails
        {
            Status = StatusCodes.Status429TooManyRequests,
            Title = "Too many requests.",
            Extensions = { ["code"] = "rateLimited" },
        };
        await response.WriteAsJsonAsync(problem, options: null, contentType: "application/problem+json", cancellationToken);
    }

    private static IResult Problem(int status, string title, string code)
    {
        return Results.Problem(statusCode: status, title: title, extensions: new Dictionary<string, object?> { ["code"] = code });
    }
}
