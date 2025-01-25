using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Helpers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;

namespace Shark.Fido2.Core;

public static class DependencyInjection
{
    public static void Register(this IServiceCollection services)
    {
        services.AddTransient<IChallengeGenerator, ChallengeGenerator>();

        services.AddTransient<IClientDataValidator, ClientDataValidator>();
        services.AddTransient<IClientDataHandler, ClientDataHandler>();

        services.AddTransient<IAuthenticatorDataProvider, AuthenticatorDataProvider>();
        services.AddTransient<IAttestationObjectValidator, AttestationObjectValidator>();
        services.AddTransient<IAttestationStatementValidator, AttestationStatementValidator>();
        services.AddTransient<IAttestationObjectHandler, AttestationObjectHandler>();

        services.AddKeyedTransient<ICryptographyValidator, RsaCryptographyValidator>("rsa");
        services.AddKeyedTransient<ICryptographyValidator, Ec2CryptographyValidator>("ec2");

        services.AddTransient<IAlgorithmAttestationStatementValidator, AlgorithmAttestationStatementValidator>();

        services.AddKeyedTransient<IAttestationStatementStategy, PackedAttestationStatementStategy>(
            AttestationStatementFormatIdentifier.Packed);
        services.AddKeyedTransient<IAttestationStatementStategy, NoneAttestationStatementStategy>(
            AttestationStatementFormatIdentifier.None);

        services.AddTransient<IAttestation, Attestation>();
        services.AddTransient<IAssertion, Assertion>();
    }
}
