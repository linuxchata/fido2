using Shark.Fido2.Core;
using Shark.Fido2.InMemory;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddWebOptimizer(pipeline =>
{
    pipeline.AddCssBundle("/css/site.min.css", "css/site.css").MinifyCss();
    pipeline.AddJavaScriptBundle("/js/site.min.js", "js/*.js").MinifyJavaScript();
});

builder.Services.AddRazorPages();
builder.Services.AddControllers();

builder.Services.AddSession(options =>
{
    options.Cookie.SameSite = SameSiteMode.Unspecified;
});

builder.Services.RegisterInMemoryRepositories();
builder.Services.AddFido2(builder.Configuration);

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseWebOptimizer();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.UseSession();

app.Run();
