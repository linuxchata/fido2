using Shark.Fido2.Core;
using Shark.Fido2.Repositories.InMemory;
using Shark.Sample.Fido2.Swagger;
using Swashbuckle.AspNetCore.Filters;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddControllers();

builder.Services.AddSession(options =>
{
    options.Cookie.SameSite = SameSiteMode.Unspecified;
});

// Swagger
builder.Services.AddRouting(options => options.LowercaseUrls = true);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.ExampleFilters();
    c.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, "Shark.Sample.Fido2.xml"));
});
builder.Services.AddSwaggerExamplesFromAssemblyOf<ServerPublicKeyCredentialCreationOptionsRequestExample>();

builder.Services.AddDistributedMemoryCache();
builder.Services.RegisterInMemoryRepositories();
builder.Services.AddFido2(builder.Configuration);

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.UseSession();

app.Run();
