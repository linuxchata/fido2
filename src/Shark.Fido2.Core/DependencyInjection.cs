using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Helpers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Validators;

namespace Shark.Fido2.Core
{
    public static class DependencyInjection
    {
        public static void Register(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddTransient<IChallengeGenerator, ChallengeGenerator>();

            services.AddTransient<IClientDataValidator, ClientDataValidator>();
            services.AddTransient<IClientDataHandler, ClientDataHandler>();

            services.AddTransient<IAuthenticatorDataProvider, AuthenticatorDataProvider>();
            services.AddTransient<IAttestationObjectValidator, AttestationObjectValidator>();
            services.AddTransient<IAttestationObjectHandler, AttestationObjectHandler>();

            services.AddTransient<IAttestation, Attestation>();
        }
    }
}
