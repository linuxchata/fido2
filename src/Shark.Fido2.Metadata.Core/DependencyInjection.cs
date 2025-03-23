using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Configurations;
using Shark.Fido2.Metadata.Core.Repositories;

namespace Shark.Fido2.Metadata.Core;

public static class DependencyInjection
{
    public static void AddMetadataService(this IServiceCollection services, IConfigurationSection configurationSection)
    {
        var metadataServiceConfigurationSection = configurationSection.GetSection(MetadataServiceConfiguration.Name);
        services.Configure<MetadataServiceConfiguration>(metadataServiceConfigurationSection);

        services.AddDistributedMemoryCache();

        services.AddTransient<IHttpClientRepository, HttpClientRepository>();
        services.AddTransient<IMetadataBlobService, MetadataBlobService>();
        services.AddTransient<ICertificateValidator, CertificateValidator>();
        services.AddTransient<IMetadataService, MetadataService>();
        services.AddTransient<IMetadataCachedService, MetadataCachedService>();
    }
}
