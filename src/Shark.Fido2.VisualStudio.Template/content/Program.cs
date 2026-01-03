using Shark.Fido2.Core;
using Shark.Fido2.InMemory;
using Shark.Fido2.Sample.VisualStudio.Template.Services;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
});

builder.Services.AddRazorPages();
builder.Services.AddControllers();

builder.Services.AddSession(options =>
{
    options.Cookie.SameSite = SameSiteMode.Unspecified;
    options.IdleTimeout = TimeSpan.FromMinutes(5);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddRouting(options => options.LowercaseUrls = true);

builder.Services.AddFido2(builder.Configuration);
builder.Services.AddFido2InMemoryStore();

builder.Services.AddTransient<ICredentialService, CredentialService>();

var app = builder.Build();

app.UseExceptionHandler("/Error");
app.UseHsts();
app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.UseSession();

app.MapRazorPages();
app.MapControllers();

await app.RunAsync();
