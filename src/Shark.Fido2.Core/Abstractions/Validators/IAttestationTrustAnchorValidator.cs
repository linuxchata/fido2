using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

public interface IAttestationTrustAnchorValidator
{
    Task<ValidatorInternalResult> Validate(AuthenticatorData authenticatorData);

    Task<ValidatorInternalResult> ValidateBasicAttestation(
        AuthenticatorData authenticatorData,
        X509Certificate2[]? trustPath);
}
