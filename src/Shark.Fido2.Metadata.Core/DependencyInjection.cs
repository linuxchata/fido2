﻿using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;

namespace Shark.Fido2.Metadata.Core;

public static class DependencyInjection
{
    public static void RegisterMetadataService(this IServiceCollection services)
    {
        services.AddTransient<IHttpClientRepository, HttpClientRepository>();
        services.AddTransient<ICertificateValidator, CertificateValidator>();
        services.AddTransient<IMetadataService, MetadataService>();
    }
}
