using Microsoft.Extensions.DependencyInjection;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Services;
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

        services.AddTransient<IAuthenticatorDataParserService, AuthenticatorDataParserService>();
        services.AddTransient<IAttestationObjectValidator, AttestationObjectValidator>();
        services.AddTransient<IAttestationStatementValidator, AttestationStatementValidator>();
        services.AddTransient<IAttestationObjectHandler, AttestationObjectHandler>();

        services.AddKeyedTransient<ICryptographyValidator, RsaCryptographyValidator>("rsa");
        services.AddKeyedTransient<ICryptographyValidator, Ec2CryptographyValidator>("ec2");

        services.AddTransient<IAlgorithmAttestationStatementValidator, AlgorithmAttestationStatementValidator>();
        services.AddTransient<ISignatureAttestationStatementValidator, SignatureAttestationStatementValidator>();
        services.AddTransient<ICertificateAttestationStatementService, CertificateAttestationStatementService>();
        services.AddTransient<ICertificateAttestationStatementValidator, CertificateAttestationStatementValidator>();

        services.AddTransient<ITpmtPublicAreaParserService, TpmtPublicAreaParserService>();

        services.AddKeyedTransient<IAttestationStatementStrategy, PackedAttestationStatementStrategy>(
            AttestationStatementFormatIdentifier.Packed);
        services.AddKeyedTransient<IAttestationStatementStrategy, TpmAttestationStatementStrategy>(
            AttestationStatementFormatIdentifier.Tpm);
        services.AddKeyedTransient<IAttestationStatementStrategy, NoneAttestationStatementStrategy>(
            AttestationStatementFormatIdentifier.None);

        services.AddTransient<IAttestation, Attestation>();
        services.AddTransient<IAssertion, Assertion>();
    }
}
