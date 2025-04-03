using Shark.Fido2.Core;
using Shark.Fido2.InMemory;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();

builder.Services.RegisterInMemoryRepositories();
builder.Services.AddFido2(builder.Configuration);

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();

app.Run();
