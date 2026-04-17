using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions.Repositories;
using Shark.Fido2.ConvenienceMetadata.Core.Configurations;
using Shark.Fido2.ConvenienceMetadata.Core.Repositories;
using Shark.Fido2.ConvenienceMetadata.Core.Services;

namespace Shark.Fido2.ConvenienceMetadata.Core;

[ExcludeFromCodeCoverage]
public static class DependencyInjection
{
    public static void AddFido2ConvenienceMetadataService(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var configurationSection = configuration.GetSection(ConvenienceMetadataServiceConfiguration.Name);
        services.Configure<ConvenienceMetadataServiceConfiguration>(configurationSection);

        services.AddDistributedMemoryCache();
        services.AddMemoryCache();

        services.AddHttpClient();

        services.AddTransient<IHttpClientRepository, HttpClientRepository>();
        services.AddTransient<IConvenienceMetadataService, ConvenienceMetadataService>();
        services.AddTransient<IConvenienceMetadataReaderService, ConvenienceMetadataReaderService>();
        services.AddTransient<IConvenienceMetadataCachedService, ConvenienceMetadataCachedService>();
    }
}
