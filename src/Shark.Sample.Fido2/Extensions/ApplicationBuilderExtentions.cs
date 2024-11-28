using Shark.Fido2.Core;
using Shark.Fido2.Core.Configurations;

namespace Shark.Sample.Fido2.Extensions;

public static class ApplicationBuilderExtentions
{
    public static IServiceCollection AddFido2(this IServiceCollection services, IConfiguration configuration)
    {
        DependencyInjection.Register(services, configuration);

        services.AddOptions<Fido2Configuration>().Bind(configuration.GetSection(Fido2Configuration.Name));

        return services;
    }
}