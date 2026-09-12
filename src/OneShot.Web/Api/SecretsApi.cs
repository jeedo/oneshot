using System.Buffers;
using System.Buffers.Text;
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
        app.MapMethods("/api/secrets/{id}", [HttpMethods.Get, HttpMethods.Head], Peek);
        app.MapPost("/api/secrets/{id}/reveal", RevealAsync);
        return app;
    }

    // The only code path that ever returns ciphertext; the policy runs before the store is touched.
    private static async Task<IResult> RevealAsync(HttpContext context, string id, ISecretStore store, AuditLogger audit, CancellationToken cancellationToken)
    {
        if (!RevealPolicy.Allows(context.Request))
        {
            return ApiProblems.Forbidden("revealNotAllowed");
        }

        if (!SecretId.IsValid(id))
        {
            return ApiProblems.NotFound("unknown");
        }

        var result = store.TryConsume(id);
        switch (result.Outcome)
        {
            case ConsumeOutcome.AlreadyConsumed:
                return ApiProblems.Gone("consumed");
            case ConsumeOutcome.Unknown:
                return ApiProblems.NotFound("unknown");
        }

        using var secret = result.Secret!;
        audit.Log(AuditAction.Reveal, id, context.User);

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/json; charset=utf-8";
        await using (var writer = new Utf8JsonWriter(context.Response.BodyWriter))
        {
            writer.WriteStartObject();
            WriteBase64Url(writer, "ciphertext", secret.Ciphertext.Span);
            WriteBase64Url(writer, "nonce", secret.Nonce.Span);
            writer.WriteEndObject();
            await writer.FlushAsync(cancellationToken);
        }

        await context.Response.BodyWriter.FlushAsync(cancellationToken);
        return Results.Empty;
    }

    private static void WriteBase64Url(Utf8JsonWriter writer, string name, ReadOnlySpan<byte> bytes)
    {
        var chars = ArrayPool<char>.Shared.Rent(Base64Url.GetEncodedLength(bytes.Length));
        try
        {
            var written = Base64Url.EncodeToChars(bytes, chars);
            writer.WriteString(name, chars.AsSpan(0, written));
        }
        finally
        {
            Array.Clear(chars);
            ArrayPool<char>.Shared.Return(chars);
        }
    }

    // Read-only by construction: it only ever calls Peek, so scanners and prefetchers cannot burn a secret.
    private static IResult Peek(HttpContext context, string id, ISecretStore store)
    {
        var peek = SecretId.IsValid(id) ? store.Peek(id) : new SecretPeek(SecretState.Unknown, null);
        var status = peek.State == SecretState.Unknown ? StatusCodes.Status404NotFound : StatusCodes.Status200OK;

        if (HttpMethods.IsHead(context.Request.Method))
        {
            context.Response.StatusCode = status;
            context.Response.ContentType = "application/json; charset=utf-8";
            return Results.Empty;
        }

        var state = peek.State switch
        {
            SecretState.Available => "available",
            SecretState.Consumed => "consumed",
            _ => "unknown",
        };
        return Results.Json(new PeekSecretResponse(state, peek.ExpiresAtUtc), statusCode: status);
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

    private sealed record PeekSecretResponse(string State, DateTimeOffset? ExpiresAt);
}
