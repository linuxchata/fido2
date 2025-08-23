using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Shark.Fido2.Sample.Blazor.Client.Abstractions.Services;
using Shark.Fido2.Sample.Blazor.Client.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
builder.Services.AddScoped<ICredentialClientService, CredentialClientService>();

await builder.Build().RunAsync();