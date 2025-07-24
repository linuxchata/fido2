using Shark.Fido2.Core;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.InMemory;
using Shark.Fido2.Portal;
using Shark.Fido2.Portal.Services;

var builder = WebApplication.CreateBuilder(args);

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

builder.Services.AddWebOptimizer(pipeline =>
{
    pipeline.AddCssBundle("/css/site.min.css", "css/site.css").MinifyCss();
    pipeline.AddCssBundle("/css/landing.min.css", "css/landing.css").MinifyCss();
    pipeline.AddJavaScriptBundle("/js/site-dc.min.js", "js/dc/*.js").MinifyJavaScript();
    pipeline.AddJavaScriptBundle("/js/site-ndc.min.js", "js/ndc/*.js").MinifyJavaScript();
    pipeline.AddJavaScriptBundle("/js/shared.min.js", "js/shared/*.js").MinifyJavaScript();
});

builder.Services.AddRazorPages();
builder.Services.AddControllers();

builder.Services.AddApplicationInsightsTelemetry();

builder.Services.AddSession(options =>
{
    options.Cookie.SameSite = SameSiteMode.Unspecified;
});

builder.Services.AddFido2InMemoryStore();
builder.Services.AddFido2(builder.Configuration);
builder.Services.AddTransient<IChallengeGenerator, CustomChallengeGenerator>();
builder.Services.AddTransient<ICredentialService, CredentialService>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();

    app.Use(async (context, next) =>
    {
        context.Response.Headers.Append("X-Frame-Options", "DENY");
        context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'; img-src 'self' data:;");
        context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
        context.Response.Headers.Append("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
        context.Response.Headers.Append("Referrer-Policy", "no-referrer");

        await next();
    });
}

app.UseHttpsRedirection();
app.UseWebOptimizer();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.UseSession();

await app.RunAsync();
