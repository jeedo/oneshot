namespace OneShot.Web.Api;

// Every error is a fixed RFC 7807 body keyed by a stable code; nothing from the request is ever echoed.
internal static class ApiProblems
{
    public static IResult BadRequest(string code) => Problem(StatusCodes.Status400BadRequest, "The request was rejected.", code);

    public static IResult UnsupportedMediaType() => Problem(StatusCodes.Status415UnsupportedMediaType, "The request body must be JSON.", "unsupportedMediaType");

    public static IResult ServiceUnavailable(HttpResponse response, string code, TimeSpan retryAfter)
    {
        ArgumentNullException.ThrowIfNull(response);
        response.Headers.RetryAfter = ((int)retryAfter.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture);
        return Problem(StatusCodes.Status503ServiceUnavailable, "The service cannot accept new secrets right now.", code);
    }

    private static IResult Problem(int status, string title, string code)
    {
        return Results.Problem(statusCode: status, title: title, extensions: new Dictionary<string, object?> { ["code"] = code });
    }
}
