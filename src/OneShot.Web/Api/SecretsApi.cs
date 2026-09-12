using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

using OneShot.Web.Audit;
using OneShot.Web.Secrets;

namespace OneShot.Web.Api;

internal static class SecretsApi
{
    private static readonly TimeSpan CapacityRetryAfter = TimeSpan.FromSeconds(30);

    private static readonly JsonSerializerOptions StrictJson = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 8,
        NumberHandling = JsonNumberHandling.Strict,
        AllowDuplicateProperties = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
    };

    public static IEndpointRouteBuilder MapSecretsApi(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/secrets", CreateAsync);
        return app;
    }

    private static async Task<IResult> CreateAsync(HttpContext context, ISecretStore store, AuditLogger audit, CancellationToken cancellationToken)
    {
        if (!context.Request.HasJsonContentType())
        {
            return ApiProblems.UnsupportedMediaType();
        }

        CreateSecretRequest? request;
        try
        {
            request = await context.Request.ReadFromJsonAsync<CreateSecretRequest>(StrictJson, cancellationToken);
        }
        catch (JsonException)
        {
            return ApiProblems.BadRequest("malformedJson");
        }

        if (request is null)
        {
            return ApiProblems.BadRequest("malformedJson");
        }

        if (request.Ciphertext is null)
        {
            return ApiProblems.BadRequest("ciphertextRequired");
        }

        if (request.Nonce is null)
        {
            return ApiProblems.BadRequest("nonceRequired");
        }

        if (!Base64UrlStrict.TryDecode(request.Ciphertext, out var ciphertext))
        {
            return ApiProblems.BadRequest("ciphertextEncoding");
        }

        if (!Base64UrlStrict.TryDecode(request.Nonce, out var nonce))
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            return ApiProblems.BadRequest("nonceEncoding");
        }

        var timeToLive = request.TtlSeconds is { } seconds ? TimeSpan.FromSeconds(seconds) : SecretLimits.DefaultTimeToLive;

        switch (store.Create(ciphertext, nonce, timeToLive))
        {
            case Created created:
                audit.Log(AuditAction.Create, created.Id, context.User);
                return Results.Json(new CreateSecretResponse(created.Id, created.ExpiresAtUtc), statusCode: StatusCodes.Status201Created);

            case ValidationError error:
                CryptographicOperations.ZeroMemory(ciphertext);
                CryptographicOperations.ZeroMemory(nonce);
                return ApiProblems.BadRequest(JsonNamingPolicy.CamelCase.ConvertName(error.Failure.ToString()));

            case CapacityExceeded:
                CryptographicOperations.ZeroMemory(ciphertext);
                CryptographicOperations.ZeroMemory(nonce);
                return ApiProblems.ServiceUnavailable(context.Response, "capacityExceeded", CapacityRetryAfter);

            default:
                throw new InvalidOperationException("Unknown create result.");
        }
    }

    private sealed record CreateSecretRequest(string? Ciphertext, string? Nonce, int? TtlSeconds);

    private sealed record CreateSecretResponse(string Id, DateTimeOffset ExpiresAt);
}
