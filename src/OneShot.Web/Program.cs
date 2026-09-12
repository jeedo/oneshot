using OneShot.Web.Security;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
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
app.MapRazorPages();

app.Run();

public partial class Program;
