using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Core.Validators;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;
using Shark.Fido2.Metadata.Core;

namespace Shark.Fido2.Core;

public static class DependencyInjection
{
    public static void AddFido2(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddSingleton<IValidateOptions<Fido2Configuration>, Fido2ConfigurationValidator>();
        var fido2ConfigurationSection = configuration.GetSection(Fido2Configuration.Name);
        services.Configure<Fido2Configuration>(fido2ConfigurationSection)
            .AddOptionsWithValidateOnStart<Fido2Configuration>();

        services.AddSingleton(TimeProvider.System);

        services.AddTransient<IChallengeGenerator, ChallengeGenerator>();
        services.AddTransient<IUserIdGenerator, UserIdGenerator>();

        services.AddTransient<IClientDataValidator, ClientDataValidator>();
        services.AddTransient<IClientDataHandler, ClientDataHandler>();
        services.AddTransient<IUserHandlerValidator, UserHandlerValidator>();

        services.AddTransient<IAuthenticatorDataParserService, AuthenticatorDataParserService>();
        services.AddTransient<IAttestationObjectValidator, AttestationObjectValidator>();
        services.AddTransient<IAssertionObjectValidator, AssertionResponseValidator>();
        services.AddTransient<IAttestationTrustworthinessValidator, AttestationTrustworthinessValidator>();
        services.AddTransient<IAttestationStatementValidator, AttestationStatementValidator>();
        services.AddTransient<IAttestationObjectHandler, AttestationObjectHandler>();
        services.AddTransient<IAssertionObjectHandler, AssertionObjectHandler>();

        services.AddTransient<IRsaCryptographyValidator, RsaCryptographyValidator>();
        services.AddTransient<IEc2CryptographyValidator, Ec2CryptographyValidator>();
        services.AddTransient<IOkpCryptographyValidator, OkpCryptographyValidator>();

        services.AddTransient<ISignatureAttestationStatementValidator, SignatureAttestationStatementValidator>();
        services.AddTransient<IAttestationCertificateProviderService, AttestationCertificateProviderService>();
        services.AddTransient<IAttestationCertificateValidator, AttestationCertificateValidator>();
        services.AddTransient<ICertificatePublicKeyValidator, CertificatePublicKeyValidator>();
        services.AddTransient<ISubjectAlternativeNameParserService, SubjectAlternativeNameParserService>();
        services.AddTransient<IAndroidSafetyNetJwsResponseParserService, AndroidSafetyNetJwsResponseParserService>();
        services.AddTransient<IAndroidSafetyNetJwsResponseValidator, AndroidSafetyNetJwsResponseValidator>();
        services.AddTransient<IAndroidKeyAttestationExtensionParserService, AndroidKeyAttestationExtensionParserService>();
        services.AddTransient<IAppleAnonymousExtensionParserService, AppleAnonymousExtensionParserService>();

        services.AddTransient<ITpmtPublicAreaParserService, TpmtPublicAreaParserService>();
        services.AddTransient<ITpmsAttestationParserService, TpmsAttestationParserService>();

        services.AddKeyedTransient<IAttestationStatementStrategy, PackedAttestationStatementStrategy>(
            AttestationStatementFormatIdentifier.Packed);
        services.AddKeyedTransient<IAttestationStatementStrategy, TpmAttestationStatementStrategy>(
            AttestationStatementFormatIdentifier.Tpm);
        services.AddKeyedTransient<IAttestationStatementStrategy, AndroidKeyAttestationStatementStrategy>(
            AttestationStatementFormatIdentifier.AndroidKey);
        services.AddKeyedTransient<IAttestationStatementStrategy, AndroidSafetyNetAttestationStatementStrategy>(
            AttestationStatementFormatIdentifier.AndroidSafetyNet);
        services.AddKeyedTransient<IAttestationStatementStrategy, NoneAttestationStatementStrategy>(
            AttestationStatementFormatIdentifier.None);
        services.AddKeyedTransient<IAttestationStatementStrategy, FidoU2FAttestationStatementStrategy>(
            AttestationStatementFormatIdentifier.FidoU2F);
        services.AddKeyedTransient<IAttestationStatementStrategy, AppleAnonymousAttestationStatementStrategy>(
            AttestationStatementFormatIdentifier.Apple);

        services.AddTransient<IAttestationParametersValidator, AttestationParametersValidator>();
        services.AddTransient<IAssertionParametersValidator, AssertionParametersValidator>();

        services.AddTransient<IAttestation, Attestation>();
        services.AddTransient<IAssertion, Assertion>();

        var fido2Configuration = fido2ConfigurationSection.Get<Fido2Configuration>();
        if (fido2Configuration?.EnableMetadataService ?? true)
        {
            services.AddMetadataService(fido2ConfigurationSection);
        }
        else
        {
            services.AddNullMetadataService();
        }
    }
}
