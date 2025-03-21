using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Repositories;

namespace Shark.Fido2.Metadata.Core;

public static class DependencyInjection
{
    public static void RegisterMetadataService(this IServiceCollection services)
    {
        services.AddTransient<IHttpClientRepository, HttpClientRepository>();
        services.AddTransient<IMetadataBlobService, MetadataBlobService>();
        services.AddTransient<ICertificateValidator, CertificateValidator>();
        services.AddTransient<IMetadataService, MetadataService>();
    }
}
