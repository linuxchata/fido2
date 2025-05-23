﻿using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Metadata.Core.Abstractions;
using Shark.Fido2.Metadata.Core.Abstractions.Repositories;
using Shark.Fido2.Metadata.Core.Configurations;
using Shark.Fido2.Metadata.Core.Repositories;
using Shark.Fido2.Metadata.Core.Services;
using Shark.Fido2.Metadata.Core.Validators;

namespace Shark.Fido2.Metadata.Core;

public static class DependencyInjection
{
    private const string EnvironmentVariableName = "ASPNETCORE_ENVIRONMENT";

    public static void AddMetadataService(this IServiceCollection services, IConfigurationSection configurationSection)
    {
        var metadataServiceConfigurationSection = configurationSection.GetSection(MetadataServiceConfiguration.Name);
        services.Configure<MetadataServiceConfiguration>(metadataServiceConfigurationSection);

        services.AddDistributedMemoryCache();
        services.AddMemoryCache();

        services.AddTransient<IHttpClientRepository, HttpClientRepository>();
        services.AddTransient<ICertificateValidator, CertificateValidator>();
        services.AddTransient<IMetadataService, MetadataService>();
        services.AddTransient<IMetadataReaderService, MetadataReaderService>();
        services.AddTransient<IMetadataCachedService, MetadataCachedService>();

        if (IsConformanceTest())
        {
            services.AddTransient<IHttpClientConformanceTestRepository, HttpClientConformanceTestRepository>();
            services.AddTransient<IMetadataCachedService, MetadataCachedTestService>();
        }
    }

    public static void AddNullMetadataService(this IServiceCollection services)
    {
        services.AddTransient<IMetadataCachedService, MetadataCachedNullService>();
    }

    private static bool IsConformanceTest()
    {
        var environment = Environment.GetEnvironmentVariable(EnvironmentVariableName);
        return string.Equals(environment, "Test", StringComparison.OrdinalIgnoreCase);
    }
}
