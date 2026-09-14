using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

using OneShot.Web.Api;
using OneShot.Web.Audit;
using OneShot.Web.Secrets;
using OneShot.Web.Security;

if (args is ["--healthcheck"])
{
    return await HealthCheckProbe.RunAsync();
}

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(KestrelHardening.Apply);
LoggingHardening.Apply(builder.Logging);

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.Configure<SecretStoreOptions>(builder.Configuration.GetSection("SecretStore"));
builder.Services.Configure<SweeperOptions>(builder.Configuration.GetSection("Sweeper"));
builder.Services.AddSingleton(provider => new InMemorySecretStore(
    provider.GetRequiredService<TimeProvider>(),
    provider.GetRequiredService<IOptions<SecretStoreOptions>>().Value));
builder.Services.AddSingleton<ISecretStore>(provider => provider.GetRequiredService<InMemorySecretStore>());
builder.Services.AddSingleton<ISweepableSecretStore>(provider => provider.GetRequiredService<InMemorySecretStore>());
builder.Services.AddHostedService(provider => new ExpirySweeperService(
    provider.GetRequiredService<ISweepableSecretStore>(),
    provider.GetRequiredService<TimeProvider>(),
    provider.GetRequiredService<IOptions<SweeperOptions>>().Value,
    provider.GetRequiredService<ILogger<ExpirySweeperService>>()));
builder.Services.AddSingleton<AuditLogger>();
builder.Services.Configure<RateLimitOptions>(builder.Configuration.GetSection("RateLimiting"));
builder.Services.AddOneShotRateLimiting();
builder.Services.AddStartupValidation();

builder.Services.AddAuthentication(IdentityCookie.Scheme)
    .AddNegotiate()
    .AddCookie(IdentityCookie.Scheme, IdentityCookie.Configure);
builder.Services.AddOptions<CookieAuthenticationOptions>(IdentityCookie.Scheme)
    .Configure<TimeProvider>((options, clock) => options.TimeProvider = clock);

builder.Services.AddRazorPages();
builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
    options.Preload = true;
});

var app = builder.Build();

if (ForwardedHeadersSetup.Build(builder.Configuration) is { } forwardedHeaders)
{
    app.UseForwardedHeaders(forwardedHeaders);
}

app.UseOneShotErrorHandling();
app.UseHsts();
app.UseHttpsRedirection();
app.UseSecurityHeaders();
app.UseUniformNotFound();
app.UseStaticFiles();
app.UseAuthentication();
app.UseRateLimiter();
app.MapSecretsApi();
app.MapWhoAmI();
// The pages are static markup with no handlers, so Razor Pages narrows nothing: left alone, every method
// matches — TRACE renders the whole reveal page and OPTIONS answers a bare 200. Constraining the endpoints
// makes routing answer 405 with Allow, the same as the API behind them. (T4)
app.MapRazorPages().WithMetadata(new HttpMethodMetadata([HttpMethods.Get, HttpMethods.Head]));
app.MapOperationalEndpoints();

app.Run();
return 0;

public partial class Program;
