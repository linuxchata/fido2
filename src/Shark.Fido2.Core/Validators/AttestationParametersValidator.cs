using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Validators;

public sealed class AttestationParametersValidator : IAttestationParametersValidator
{
    public void Validate(PublicKeyCredentialCreationOptionsRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(request.UserName);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(request.DisplayName);

        if (request.UserName.Length > 256)
        {
            throw new ArgumentException("Username cannot be more than 256 characters", nameof(request));
        }

        if (request.DisplayName.Length > 64)
        {
            throw new ArgumentException("Display name be more than 64 characters", nameof(request));
        }
    }

    public AttestationCompleteResult Validate(
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

        if (!publicKeyCredentialAttestation.Id.IsBase64Url())
        {
            return AttestationCompleteResult.CreateFailure("Attestation identifier is not Base64URL-encoded");
        }

        if (!string.Equals(publicKeyCredentialAttestation.Type, PublicKeyCredentialType.PublicKey))
        {
            return AttestationCompleteResult.CreateFailure("Attestation type is not set to \"public-key\"");
        }

        return AttestationCompleteResult.Create();
    }
}
