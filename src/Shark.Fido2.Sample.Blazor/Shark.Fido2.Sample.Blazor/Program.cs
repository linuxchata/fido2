using Shark.Fido2.Core;
using Shark.Fido2.InMemory;
using Shark.Fido2.Sample.Blazor.Abstractions.Services;
using Shark.Fido2.Sample.Blazor.Client.Abstractions.Services;
using Shark.Fido2.Sample.Blazor.Client.Services;
using Shark.Fido2.Sample.Blazor.Components;
using Shark.Fido2.Sample.Blazor.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddRazorComponents()
    .AddInteractiveWebAssemblyComponents();

builder.Services.AddRazorPages();
builder.Services.AddControllers();

builder.Services.AddSession(options =>
{
    options.Cookie.SameSite = SameSiteMode.Unspecified;
});

builder.Services.AddFido2(builder.Configuration);
builder.Services.AddFido2InMemoryStore();
builder.Services.AddScoped<ICredentialService, CredentialService>();

// Client's dependencies
builder.Services.AddScoped<ICredentialClientService, CredentialClientService>();
builder.Services.AddHttpClient();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(Shark.Fido2.Sample.Blazor.Client._Imports).Assembly);

app.MapControllers();

app.UseSession();

app.Run();
