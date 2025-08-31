using Microsoft.AspNetCore.Authentication.Cookies;
using Shark.Fido2.Core;
using Shark.Fido2.InMemory;
using Shark.Fido2.Sample.Abstractions.Services;
using Shark.Fido2.Sample.Middlewares;
using Shark.Fido2.Sample.Services;
using Shark.Fido2.Sample.Swagger;
using Shark.Fido2.SqlServer;
using Swashbuckle.AspNetCore.Filters;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
});

builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = false;
    options.TimestampFormat = "dd-MM-yyyy HH:mm:ss ";
    options.SingleLine = true;
});
builder.Logging.Configure(options =>
{
    options.ActivityTrackingOptions = ActivityTrackingOptions.None;
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

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Index";
        options.LogoutPath = "/Logout";
        options.ExpireTimeSpan = TimeSpan.FromDays(1);
        options.SlidingExpiration = true;
        options.Cookie.Name = "AspNetCore.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.Cookie.SameSite = SameSiteMode.Lax;
    });

builder.Services.AddRouting(options => options.LowercaseUrls = true);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.ExampleFilters();
    c.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, "Shark.Fido2.Sample.xml"));
});
builder.Services.AddSwaggerExamplesFromAssemblyOf<ServerPublicKeyCredentialCreationOptionsRequestExample>();

if (!builder.Environment.IsDevelopment())
{
    builder.Services.AddHsts(options =>
    {
        options.Preload = true;
        options.IncludeSubDomains = true;
        options.MaxAge = TimeSpan.FromDays(365);
    });

    builder.Services.AddHttpsRedirection(options =>
    {
        options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
        options.HttpsPort = 443;
    });
}

builder.Services.AddFido2(builder.Configuration);
builder.Services.AddFido2SqlServer();

builder.Services.AddTransient<ILoginService, LoginService>();
builder.Services.AddTransient<ICredentialService, CredentialService>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");

    app.UseHsts();

    app.Use(async (context, next) =>
    {
        context.Response.Headers.Append("X-Frame-Options", "DENY");
        context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none';");
        context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
        context.Response.Headers.Append("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
        context.Response.Headers.Append("Referrer-Policy", "no-referrer");

        await next();
    });

    app.UseHttpsRedirection();
}

app.UseSwagger();
app.UseSwaggerUI();

app.UseStaticFiles();

app.UseMiddleware<DisableTrackMiddleware>();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseSession();

app.MapRazorPages();
app.MapControllers();

await app.RunAsync();
