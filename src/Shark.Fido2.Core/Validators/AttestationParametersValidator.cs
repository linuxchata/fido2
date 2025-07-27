using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Validators;

public sealed class AttestationParametersValidator : IAttestationParametersValidator
{
    public void Validate(PublicKeyCredentialCreationOptionsRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(request.UserName);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(request.DisplayName);
    }

    public void Validate(
        PublicKeyCredentialAttestation publicKeyCredentialAttestation,
        PublicKeyCredentialCreationOptions creationOptions)
    {
        ArgumentNullException.ThrowIfNull(publicKeyCredentialAttestation);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(publicKeyCredentialAttestation.Id);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(publicKeyCredentialAttestation.RawId);

        ArgumentNullException.ThrowIfNull(creationOptions);
        ArgumentNullException.ThrowIfNull(creationOptions.RelyingParty);
        ArgumentNullException.ThrowIfNull(creationOptions.User);
        ArgumentNullException.ThrowIfNull(creationOptions.PublicKeyCredentialParams);
        ArgumentNullException.ThrowIfNull(creationOptions.ExcludeCredentials);
        ArgumentNullException.ThrowIfNull(creationOptions.AuthenticatorSelection);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(creationOptions.Attestation);
    }
}
