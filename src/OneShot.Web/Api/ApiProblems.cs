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

    private static IResult Problem(int status, string title, string code)
    {
        return Results.Problem(statusCode: status, title: title, extensions: new Dictionary<string, object?> { ["code"] = code });
    }
}
