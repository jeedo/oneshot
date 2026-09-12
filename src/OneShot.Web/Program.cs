using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

using OneShot.Web.Api;
using OneShot.Web.Audit;
using OneShot.Web.Secrets;
using OneShot.Web.Security;

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

app.UseHsts();
app.UseHttpsRedirection();
app.UseSecurityHeaders();
app.UseStaticFiles();
app.UseAuthentication();
app.MapSecretsApi();
app.MapWhoAmI();
app.MapRazorPages();

app.Run();

public partial class Program;
