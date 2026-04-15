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
    public static void AddConvenienceMetadataService(this IServiceCollection services, IConfigurationSection configurationSection)
    {
        var convenienceMetadataServiceConfigurationSection = configurationSection.GetSection(ConvenienceMetadataServiceConfiguration.Name);
        services.Configure<ConvenienceMetadataServiceConfiguration>(convenienceMetadataServiceConfigurationSection);

        services.AddDistributedMemoryCache();
        services.AddMemoryCache();

        services.AddHttpClient();

        services.AddTransient<IHttpClientRepository, HttpClientRepository>();
        services.AddTransient<IConvenienceMetadataReaderService, ConvenienceMetadataReaderService>();
        services.AddTransient<IConvenienceMetadataService, ConvenienceMetadataService>();
        services.AddTransient<IConvenienceMetadataCachedService, ConvenienceMetadataCachedService>();
    }
}
