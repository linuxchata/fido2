using Shark.Fido2.Core;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Helpers;

namespace Shark.Sample.Fido2.Extensions
{
    public static class ApplicationBuilderExtentions
    {
        public static IServiceCollection AddFido2(
            this IServiceCollection services,
            IConfiguration configuration)
        {
            services.AddTransient<IChallengeGenerator, ChallengeGenerator>();
            services.AddTransient<IAttestation, Attestation>();
            services.AddOptions<Fido2Configuration>().Bind(configuration.GetSection(Fido2Configuration.Name));

            return services;
        }
    }
}
